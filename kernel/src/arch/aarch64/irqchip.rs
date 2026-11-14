//! GICv3 interrupt controller: distributor (GICD), this core's
//! redistributor (GICR), and the system-register CPU interface (ICC_*).
//!
//! All interrupts are Group 1 Non-secure with one default priority. The
//! register layouts work both with security extensions off (QEMU virt
//! default, GICD_CTLR.DS=1) and with the non-secure view.
//!
//! Locking: the GIC state is used from thread context (enable) and IRQ
//! context (disable, for NAPI-style masking), so every access runs with IRQs
//! masked (`with_gic`). On a single core that makes the lock deadlock-free.

use crate::irq::Trigger;
use crate::mmio::Region;
use crate::platform::{BootInfo, IrqChipInfo};
use crate::println;
use aarch64_cpu::registers::{MPIDR_EL1, Readable};
use core::arch::asm;
use spin::Mutex;

// Distributor registers
const GICD_SIZE: usize = 0x1_0000;
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
const GICR_FRAME: usize = 0x2_0000;
const GICR_FRAME_VLPI: usize = 0x4_0000;
// SGI_base frame = RD_base + 64 KiB
const SGI_BASE: usize = 0x1_0000;
const GICR_IGROUPR0: usize = SGI_BASE + 0x0080;
const GICR_ISENABLER0: usize = SGI_BASE + 0x0100;
const GICR_ICENABLER0: usize = SGI_BASE + 0x0180;
const GICR_ICPENDR0: usize = SGI_BASE + 0x0280;
const GICR_IPRIORITYR: usize = SGI_BASE + 0x0400;

/// Default priority for every interrupt (lower = more urgent; PMR is 0xff).
const DEFAULT_PRIO: u32 = 0xa0a0_a0a0;
pub const MAX_INTID: usize = 1020;

struct Gic {
    gicd: Region,
    /// Covers the whole redistributor area; `rd[core]` is that core's frame offset.
    gicr: Region,
    gicr_size: usize,
    rd: [usize; crate::smp::MAX_CORES],
    lines: usize,
}

/// The wake/stop IPI (`smp`): SGI 0.
pub const IPI_INTID: u32 = 0;

static GIC: Mutex<Option<Gic>> = Mutex::new(None);

/// Run `f` on the GIC with IRQs masked (see module doc).
fn with_gic<R>(f: impl FnOnce(&mut Gic) -> R) -> R {
    let was_enabled = super::cpu::irqs_enabled();
    super::cpu::irq_disable();
    let r = f(GIC.lock().as_mut().expect("gic: not initialised"));
    if was_enabled {
        super::cpu::irq_enable();
    }
    r
}

/// Affinity as used by GICD_IROUTER / GICR_TYPER: Aff3.Aff2.Aff1.Aff0.
fn affinity() -> u64 {
    let m = MPIDR_EL1.get();
    (m & 0xff_ffff) | ((m >> 32) & 0xff) << 24
}

impl Gic {
    fn wait_rwp_d(&mut self) {
        while self.gicd.read32(GICD_CTLR) & CTLR_RWP != 0 {
            core::hint::spin_loop();
        }
    }

    fn wait_rwp_r(&mut self) {
        while self.gicr.read32(self.rd[super::cpu::core_id()] + GICR_CTLR) & GICR_RWP != 0 {
            core::hint::spin_loop();
        }
    }

    /// Find this core's redistributor frame by matching affinity.
    fn find_rd(gicr: &mut Region, size: usize) -> Option<usize> {
        let me = affinity();
        let mut off = 0;
        while off + GICR_FRAME <= size {
            let typer = gicr.read64(off + GICR_TYPER);
            if typer >> 32 == me {
                return Some(off);
            }
            if typer & (1 << 4) != 0 {
                break; // Last
            }
            off += if typer & (1 << 1) != 0 {
                GICR_FRAME_VLPI
            } else {
                GICR_FRAME
            };
        }
        None
    }

    fn init_distributor(&mut self) {
        self.gicd.write32(GICD_CTLR, 0);
        self.wait_rwp_d();
        // SPIs (32..): group 1, disabled, not pending, default priority, level.
        for i in (32..self.lines).step_by(32) {
            self.gicd.write32(GICD_IGROUPR + i / 8, 0xffff_ffff);
            self.gicd.write32(GICD_ICENABLER + i / 8, 0xffff_ffff);
            self.gicd.write32(GICD_ICPENDR + i / 8, 0xffff_ffff);
        }
        for i in (32..self.lines).step_by(4) {
            self.gicd.write32(GICD_IPRIORITYR + i, DEFAULT_PRIO);
        }
        for i in (32..self.lines).step_by(16) {
            self.gicd.write32(GICD_ICFGR + i / 4, 0);
        }
        self.wait_rwp_d();
        self.gicd.write32(GICD_CTLR, CTLR_ENABLE);
        self.wait_rwp_d();
    }

    fn init_redistributor(&mut self) {
        let rd = self.rd[super::cpu::core_id()];
        self.gicr
            .modify32(rd + GICR_WAKER, |v| v & !WAKER_PROCESSOR_SLEEP);
        while self.gicr.read32(rd + GICR_WAKER) & WAKER_CHILDREN_ASLEEP != 0 {
            core::hint::spin_loop();
        }
        self.gicr.write32(rd + GICR_IGROUPR0, 0xffff_ffff);
        self.gicr.write32(rd + GICR_ICENABLER0, 0xffff_ffff);
        self.gicr.write32(rd + GICR_ICPENDR0, 0xffff_ffff);
        for i in (0..32).step_by(4) {
            self.gicr.write32(rd + GICR_IPRIORITYR + i, DEFAULT_PRIO);
        }
        self.wait_rwp_r();
    }

    fn set_enabled(&mut self, intid: u32, on: bool) {
        let i = intid as usize;
        if i < 32 {
            let reg = if on { GICR_ISENABLER0 } else { GICR_ICENABLER0 };
            self.gicr
                .write32(self.rd[super::cpu::core_id()] + reg, 1 << i);
        } else {
            let reg = if on { GICD_ISENABLER } else { GICD_ICENABLER };
            self.gicd.write32(reg + (i / 32) * 4, 1 << (i % 32));
        }
    }
}

fn init_cpu_interface() {
    // SAFETY: standard GICv3 CPU-interface bring-up; affects only this core.
    unsafe {
        asm!(
            "mrs {t}, icc_sre_el1",
            "orr {t}, {t}, #1", // SRE: use the system-register interface
            "msr icc_sre_el1, {t}",
            "isb",
            "msr icc_pmr_el1, {pmr}", // accept all priorities
            "msr icc_bpr1_el1, xzr",  // no priority grouping
            "msr icc_igrpen1_el1, {one}",
            "isb",
            t = out(reg) _,
            pmr = in(reg) 0xffu64,
            one = in(reg) 1u64,
            options(nostack),
        );
    }
}

pub fn init(info: &BootInfo) {
    let Some(IrqChipInfo::GicV3 {
        gicd,
        gicr,
        gicr_size,
    }) = info.irqchip
    else {
        panic!("irqchip: GICv3 required");
    };
    let gicr_size = gicr_size.max(GICR_FRAME);
    // SAFETY: the distributor is device memory from the DTB, mapped by
    // mm::mmu, and owned exclusively by this module from here on.
    let mut d = unsafe { Region::new(gicd, GICD_SIZE) };
    // SAFETY: as above, for the redistributor area.
    let mut r = unsafe { Region::new(gicr, gicr_size) };
    let lines = (((d.read32(GICD_TYPER) & 0x1f) as usize + 1) * 32).min(MAX_INTID);
    let rd = Gic::find_rd(&mut r, gicr_size).expect("gic: no redistributor for this core");
    let mut rds = [0; crate::smp::MAX_CORES];
    rds[0] = rd;
    super::smp::set_boot_mpidr(super::cpu::hw_core_id());
    let mut gic = Gic {
        gicd: d,
        gicr: r,
        gicr_size,
        rd: rds,
        lines,
    };
    gic.init_distributor();
    gic.init_redistributor();
    *GIC.lock() = Some(gic);
    init_cpu_interface();
    println!(
        "  irqchip         : GICv3 up, {lines} lines, redistributor {:#x}",
        gicr + rd
    );
}

/// Bring up this (secondary) core's redistributor and CPU interface.
pub fn init_secondary() {
    let core = super::cpu::core_id();
    with_gic(|g| {
        let size = g.gicr_size;
        let Some(rd) = Gic::find_rd(&mut g.gicr, size) else {
            panic!(
                "gic: no redistributor for affinity {:#x} in {size:#x} bytes",
                affinity()
            );
        };
        g.rd[core] = rd;
        g.init_redistributor();
    });
    init_cpu_interface();
}

/// Send the wake/stop IPI (SGI 0) to `core`.
pub fn send_ipi(core: usize) {
    let id = super::smp::mpidr(core);
    let (aff0, aff1, aff2, aff3) = (
        id & 0xff,
        (id >> 8) & 0xff,
        (id >> 16) & 0xff,
        (id >> 32) & 0xff,
    );
    debug_assert!(aff0 < 16, "SGI target list covers Aff0 0..15");
    let v = aff3 << 48 | aff2 << 32 | (IPI_INTID as u64) << 24 | aff1 << 16 | 1 << aff0;
    // SAFETY: writing ICC_SGI1R_EL1 sends a software interrupt; no memory effects.
    unsafe { asm!("msr icc_sgi1r_el1, {}", "isb", in(reg) v, options(nostack, preserves_flags)) };
}

/// Enable an interrupt. SPIs (>= 32) are routed to this core with `trigger`.
/// MSI-X isn't used on aarch64 (QEMU virt routes INTx through the GIC;
/// MSI would need the GICv3 ITS).
pub fn msi_vector(_n: usize) -> Option<u32> {
    None
}

pub fn msi_message(_vector: u32, _core: usize) -> Option<(u64, u32)> {
    None
}

pub fn attach_msix(_vector: u32, _entry: crate::mmio::Region) {
    unreachable!("aarch64: msi_message() is None, so MSI-X is never attached")
}

pub fn enable(intid: u32, trigger: Trigger) {
    assert!((intid as usize) < MAX_INTID);
    with_gic(|g| {
        let i = intid as usize;
        if i >= 32 {
            let cfg = GICD_ICFGR + (i / 16) * 4;
            let bit = 1 << ((i % 16) * 2 + 1);
            g.gicd.modify32(cfg, |v| match trigger {
                Trigger::Edge => v | bit,
                Trigger::Level => v & !bit,
            });
            // IROUTER: Aff3 in bits 32..40 (not GICR_TYPER's layout).
            g.gicd
                .write64(GICD_IROUTER + i * 8, super::cpu::hw_core_id());
        }
        g.set_enabled(intid, true);
    });
}

/// Disable an interrupt. Safe to call from IRQ context.
pub fn disable(intid: u32) {
    with_gic(|g| g.set_enabled(intid, false));
}

/// Acknowledge the highest-priority pending interrupt (raw ICC_IAR1 value).
#[inline]
pub(super) fn ack() -> u32 {
    let v: u64;
    // SAFETY: reading ICC_IAR1_EL1 acknowledges an interrupt (IRQ entry only).
    unsafe { asm!("mrs {}, icc_iar1_el1", out(reg) v, options(nomem, nostack)) };
    v as u32
}

/// End of interrupt for a value returned by [`ack`].
#[inline]
pub(super) fn eoi(iar: u32) {
    // SAFETY: writing ICC_EOIR1_EL1 completes the acknowledged interrupt.
    unsafe { asm!("msr icc_eoir1_el1, {}", in(reg) iar as u64, options(nomem, nostack)) };
}
