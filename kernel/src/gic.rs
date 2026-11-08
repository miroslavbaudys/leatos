//! GICv3 interrupt controller: distributor (GICD), this core's
//! redistributor (GICR), and the system-register CPU interface (ICC_*).
//!
//! All interrupts are Group 1 Non-secure with a single default priority.
//! The register layouts work both with the GIC's security extensions off
//! (QEMU virt default, GICD_CTLR.DS=1) and with the non-secure view.

use crate::dtb::GicInfo;
use crate::println;
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

// Distributor registers
const GICD_CTLR: usize = 0x0000;
const GICD_TYPER: usize = 0x0004;
const GICD_IGROUPR: usize = 0x0080;
const GICD_ISENABLER: usize = 0x0100;
const GICD_ICENABLER: usize = 0x0180;
const GICD_ICPENDR: usize = 0x0280;
const GICD_IPRIORITYR: usize = 0x0400;
const GICD_ICFGR: usize = 0x0c00;
const GICD_IROUTER: usize = 0x6000;
const CTLR_RWP: u32 = 1 << 31;
// bit0/bit1 = group enables, bit4 = ARE (affinity routing), see module doc.
const CTLR_ENABLE: u32 = (1 << 4) | (1 << 1) | (1 << 0);

// Redistributor registers (RD_base frame)
const GICR_CTLR: usize = 0x0000;
const GICR_TYPER: usize = 0x0008;
const GICR_WAKER: usize = 0x0014;
const WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;
const GICR_RWP: u32 = 1 << 3;
// SGI_base frame = RD_base + 64 KiB
const SGI_BASE: usize = 0x1_0000;
const GICR_IGROUPR0: usize = 0x0080;
const GICR_ISENABLER0: usize = 0x0100;
const GICR_ICENABLER0: usize = 0x0180;
const GICR_ICPENDR0: usize = 0x0280;
const GICR_IPRIORITYR: usize = 0x0400;

/// Default priority for every interrupt (lower = more urgent; PMR is 0xff).
const DEFAULT_PRIO: u8 = 0xa0;

static GICD: AtomicUsize = AtomicUsize::new(0);
static GICR: AtomicUsize = AtomicUsize::new(0); // this core's RD_base

/// Edge or level triggering for SPIs.
#[allow(dead_code)] // Edge is used by M2 drivers (MSI-style SPIs)
#[derive(Clone, Copy)]
pub enum Trigger {
    Level,
    Edge,
}

fn rd32(addr: usize) -> u32 {
    // SAFETY: callers pass GIC MMIO addresses, mapped as device memory.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}
fn wr32(addr: usize, v: u32) {
    // SAFETY: callers pass GIC MMIO addresses, mapped as device memory.
    unsafe { core::ptr::write_volatile(addr as *mut u32, v) }
}
fn rd64(addr: usize) -> u64 {
    // SAFETY: callers pass GIC MMIO addresses, mapped as device memory.
    unsafe { core::ptr::read_volatile(addr as *const u64) }
}
fn wr64(addr: usize, v: u64) {
    // SAFETY: callers pass GIC MMIO addresses, mapped as device memory.
    unsafe { core::ptr::write_volatile(addr as *mut u64, v) }
}

fn mpidr() -> u64 {
    let v: u64;
    // SAFETY: reading MPIDR_EL1 has no side effects.
    unsafe { asm!("mrs {}, mpidr_el1", out(reg) v, options(nomem, nostack)) };
    v
}

/// Affinity as used by GICD_IROUTER / GICR_TYPER: Aff3.Aff2.Aff1.Aff0.
fn affinity() -> u64 {
    let m = mpidr();
    (m & 0xff_ffff) | ((m >> 32) & 0xff) << 24
}

fn wait_rwp_d(gicd: usize) {
    while rd32(gicd + GICD_CTLR) & CTLR_RWP != 0 {
        core::hint::spin_loop();
    }
}
fn wait_rwp_r(gicr: usize) {
    while rd32(gicr + GICR_CTLR) & GICR_RWP != 0 {
        core::hint::spin_loop();
    }
}

/// Find this core's redistributor by walking the GICR frames.
fn find_redistributor(info: &GicInfo) -> Option<usize> {
    let me = affinity();
    let mut frame = info.gicr;
    let end = info.gicr + info.gicr_size.max(0x2_0000);
    while frame < end {
        let typer = rd64(frame + GICR_TYPER);
        if typer >> 32 == me {
            return Some(frame);
        }
        if typer & (1 << 4) != 0 {
            break; // Last
        }
        // VLPIS (bit 1) frames are 256 KiB, otherwise 128 KiB.
        frame += if typer & (1 << 1) != 0 {
            0x4_0000
        } else {
            0x2_0000
        };
    }
    None
}

pub fn init(info: &GicInfo) {
    let gicd = info.gicd;
    GICD.store(gicd, Ordering::Relaxed);

    // ---- Distributor ----------------------------------------------------------
    wr32(gicd + GICD_CTLR, 0);
    wait_rwp_d(gicd);
    let lines = ((rd32(gicd + GICD_TYPER) & 0x1f) as usize + 1) * 32;
    let lines = lines.min(crate::irq::MAX_INTID);
    // SPIs (32..): group 1, disabled, not pending, default priority, level.
    for i in (32..lines).step_by(32) {
        wr32(gicd + GICD_IGROUPR + i / 8, 0xffff_ffff);
        wr32(gicd + GICD_ICENABLER + i / 8, 0xffff_ffff);
        wr32(gicd + GICD_ICPENDR + i / 8, 0xffff_ffff);
    }
    for i in (32..lines).step_by(4) {
        wr32(
            gicd + GICD_IPRIORITYR + i,
            u32::from_ne_bytes([DEFAULT_PRIO; 4]),
        );
    }
    for i in (32..lines).step_by(16) {
        wr32(gicd + GICD_ICFGR + i / 4, 0); // level-sensitive
    }
    wait_rwp_d(gicd);
    wr32(gicd + GICD_CTLR, CTLR_ENABLE);
    wait_rwp_d(gicd);

    // ---- Redistributor (this core) --------------------------------------------
    let gicr = find_redistributor(info).expect("gic: no redistributor for this core");
    GICR.store(gicr, Ordering::Relaxed);
    wr32(
        gicr + GICR_WAKER,
        rd32(gicr + GICR_WAKER) & !WAKER_PROCESSOR_SLEEP,
    );
    while rd32(gicr + GICR_WAKER) & WAKER_CHILDREN_ASLEEP != 0 {
        core::hint::spin_loop();
    }
    let sgi = gicr + SGI_BASE;
    wr32(sgi + GICR_IGROUPR0, 0xffff_ffff);
    wr32(sgi + GICR_ICENABLER0, 0xffff_ffff);
    wr32(sgi + GICR_ICPENDR0, 0xffff_ffff);
    for i in (0..32).step_by(4) {
        wr32(
            sgi + GICR_IPRIORITYR + i,
            u32::from_ne_bytes([DEFAULT_PRIO; 4]),
        );
    }
    wait_rwp_r(gicr);

    // ---- CPU interface (system registers) -------------------------------------
    // SAFETY: standard GICv3 CPU-interface bring-up; affects only this core.
    unsafe {
        asm!(
            "mrs {t}, icc_sre_el1",
            "orr {t}, {t}, #1", // SRE: use system-register interface
            "msr icc_sre_el1, {t}",
            "isb",
            "msr icc_pmr_el1, {pmr}",   // accept all priorities
            "msr icc_bpr1_el1, xzr",    // no priority grouping
            "msr icc_igrpen1_el1, {one}",
            "isb",
            t = out(reg) _,
            pmr = in(reg) 0xffu64,
            one = in(reg) 1u64,
            options(nostack),
        );
    }

    println!("  gic             : GICv3, {lines} lines, redistributor {gicr:#x}");
}

/// Enable a PPI (16..31) or SGI (0..15) on this core.
pub fn enable_ppi(intid: u32) {
    assert!(intid < 32);
    let sgi = GICR.load(Ordering::Relaxed) + SGI_BASE;
    wr32(sgi + GICR_ISENABLER0, 1 << intid);
}

/// Enable an SPI (32..), routed to this core.
#[allow(dead_code)] // used by M2 drivers
pub fn enable_spi(intid: u32, trigger: Trigger) {
    assert!(intid >= 32 && (intid as usize) < crate::irq::MAX_INTID);
    let gicd = GICD.load(Ordering::Relaxed);
    let i = intid as usize;
    let cfg = gicd + GICD_ICFGR + (i / 16) * 4;
    let shift = (i % 16) * 2 + 1;
    let v = rd32(cfg) & !(1 << shift);
    let v = match trigger {
        Trigger::Edge => v | (1 << shift),
        Trigger::Level => v,
    };
    wr32(cfg, v);
    wr64(gicd + GICD_IROUTER + i * 8, affinity());
    wr32(gicd + GICD_ISENABLER + (i / 32) * 4, 1 << (i % 32));
}

/// Disable any interrupt. Safe to call from IRQ context.
pub fn disable(intid: u32) {
    let i = intid as usize;
    if i < 32 {
        let sgi = GICR.load(Ordering::Relaxed) + SGI_BASE;
        wr32(sgi + GICR_ICENABLER0, 1 << i);
    } else {
        let gicd = GICD.load(Ordering::Relaxed);
        wr32(gicd + GICD_ICENABLER + (i / 32) * 4, 1 << (i % 32));
    }
}

/// Acknowledge the highest-priority pending interrupt (returns the raw IAR).
#[inline]
pub fn ack() -> u32 {
    let v: u64;
    // SAFETY: reading ICC_IAR1_EL1 acknowledges an interrupt; only called from rust_irq.
    unsafe { asm!("mrs {}, icc_iar1_el1", out(reg) v, options(nomem, nostack)) };
    v as u32
}

/// Signal end of interrupt for a value returned by [`ack`].
#[inline]
pub fn eoi(iar: u32) {
    // SAFETY: writing ICC_EOIR1_EL1 completes the acknowledged interrupt.
    unsafe { asm!("msr icc_eoir1_el1, {}", in(reg) iar as u64, options(nomem, nostack)) };
}
