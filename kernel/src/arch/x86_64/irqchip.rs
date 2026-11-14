//! Local APIC (xAPIC, MMIO) with the legacy 8259 PICs masked.
//!
//! Interrupt IDs are **vectors**: 32 = local APIC timer, 48-63 = device
//! MSI-X (`crate::pci`), 255 = spurious. Legacy INTx via the IOAPIC
//! is not used: on PCs its routing needs the ACPI `_PRT` (AML), while MSI-X
//! works on every device rrouter targets (virtio-net, Intel i211).
//!
//! Locking: the APIC is used from thread context (timer programming,
//! enable) and IRQ context (EOI, NAPI-style disable), so every access runs
//! with IRQs masked (`with_lapic`). On a single core that is deadlock-free.

use super::exceptions::{MSI_VECTORS, PIC_VECTORS, SPURIOUS_VECTOR, TIMER_VECTOR};
use super::port::{inb, outb};
use crate::irq::Trigger;
use crate::mmio::Region;
use crate::platform::{BootInfo, IrqChipInfo};
use crate::println;
use spin::Mutex;

const ID: usize = 0x020;
const VERSION: usize = 0x030;
const TPR: usize = 0x080;
const EOI: usize = 0x0b0;
const SVR: usize = 0x0f0;
const ESR: usize = 0x280;
const LVT_TIMER: usize = 0x320;
const LVT_LINT0: usize = 0x350;
const LVT_LINT1: usize = 0x360;
const LVT_ERROR: usize = 0x370;
pub(super) const TIMER_INITIAL: usize = 0x380;
pub(super) const TIMER_CURRENT: usize = 0x390;
const TIMER_DIVIDE: usize = 0x3e0;
const MASKED: u32 = 1 << 16;
const SVR_ENABLE: u32 = 1 << 8;

static LAPIC: Mutex<Option<Region>> = Mutex::new(None);
/// MSI-X table entries per device vector (index = vector - 48).
static MSIX: Mutex<[Option<Region>; 16]> = Mutex::new([const { None }; 16]);
/// Local APIC ID of this CPU (MSI destination).
static APIC_ID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

const MSIX_CTRL: usize = 12;
const MSIX_MASKED: u32 = 1;

/// Run `f` on the local APIC with IRQs masked (see the module docs).
pub(super) fn with_lapic<R>(f: impl FnOnce(&mut Region) -> R) -> R {
    let was = super::cpu::irqs_enabled();
    super::cpu::irq_disable();
    let r = f(LAPIC.lock().as_mut().expect("lapic not initialised"));
    if was {
        super::cpu::irq_enable();
    }
    r
}

const PIC1: u16 = 0x20;
const PIC2: u16 = 0xa0;
const PIC_EOI: u8 = 0x20;

fn pic_wait() {
    outb(0x80, 0); // POST port: a short delay between PIC commands
}

fn remap_and_mask_pics() {
    let base = *PIC_VECTORS.start() as u8;
    for (port, icw2, icw3) in [(PIC1, base, 1 << 2), (PIC2, base + 8, 2)] {
        outb(port, 0x11); // ICW1: init, cascade, ICW4 follows
        pic_wait();
        outb(port + 1, icw2); // vector base
        pic_wait();
        outb(port + 1, icw3); // master: slave on IRQ 2; slave: cascade identity
        pic_wait();
        outb(port + 1, 0x01); // ICW4: 8086 mode
        pic_wait();
        outb(port + 1, 0xff); // mask all
    }
    // Clear anything the BIOS left in service.
    outb(PIC2, PIC_EOI);
    outb(PIC1, PIC_EOI);
}

/// A legacy PIC vector arrived (`irq` 0-15). A spurious IRQ 7/15 has no
/// in-service bit and takes no EOI from that PIC (a spurious IRQ 15 still
/// takes one from the master: the cascade IRQ 2 was acknowledged). Called
/// from the trap handler.
pub(super) fn legacy_pic_ack(irq: u8) {
    let (port, bit) = if irq < 8 {
        (PIC1, irq)
    } else {
        (PIC2, irq - 8)
    };
    outb(port, 0x0b); // OCW3: next read returns the in-service register
    let in_service = inb(port) & (1 << bit) != 0;
    if in_service {
        outb(port, PIC_EOI);
    }
    if irq >= 8 {
        outb(PIC1, PIC_EOI);
    }
}

pub fn init(info: &BootInfo) {
    let Some(IrqChipInfo::Apic { lapic, .. }) = info.irqchip else {
        panic!("irqchip: no local APIC described");
    };
    // Every interrupt comes through the local APIC: remap the 8259 PICs
    // away from the CPU exception vectors (BIOS leaves them at 8-15, where
    // a spurious IRQ 7 looks like exception 15) and mask them.
    remap_and_mask_pics();
    // SAFETY: the MADT's local APIC page, mapped as device memory by
    // mm::mmu (PLATFORM_MMIO), owned exclusively by this module.
    *LAPIC.lock() = Some(unsafe { Region::new(lapic, 0x1000) });
    let (id, version) = with_lapic(|r| {
        r.write32(TPR, 0); // accept all priorities
        r.write32(LVT_TIMER, MASKED | TIMER_VECTOR);
        r.write32(LVT_LINT0, MASKED);
        r.write32(LVT_LINT1, MASKED);
        r.write32(LVT_ERROR, MASKED);
        r.write32(ESR, 0);
        r.write32(TIMER_DIVIDE, 0b1011); // divide by 1
        r.write32(TIMER_INITIAL, 0);
        r.write32(SVR, SVR_ENABLE | SPURIOUS_VECTOR);
        (r.read32(ID) >> 24, r.read32(VERSION) & 0xff)
    });
    APIC_ID.store(id, core::sync::atomic::Ordering::Relaxed);
    super::timer::calibrate_lapic();
    println!(
        "  irqchip         : local APIC id {id}, version {version:#x}, timer {} MHz (8259 PICs masked)",
        super::timer::lapic_hz() / 1_000_000
    );
}

/// The `n`-th device interrupt vector (MSI-X), if there is one.
pub fn msi_vector(n: usize) -> Option<u32> {
    let v = MSI_VECTORS.start() + n as u32;
    MSI_VECTORS.contains(&v).then_some(v)
}

/// MSI message for `vector`: fixed delivery, edge, physical destination =
/// this CPU's local APIC.
pub fn msi_message(vector: u32) -> Option<(u64, u32)> {
    MSI_VECTORS.contains(&vector).then(|| {
        let id = APIC_ID.load(core::sync::atomic::Ordering::Relaxed);
        (0xfee0_0000 | (id as u64) << 12, vector)
    })
}

/// Take ownership of the (masked) MSI-X table entry that raises `vector`.
pub fn attach_msix(vector: u32, entry: Region) {
    let i = (vector - MSI_VECTORS.start()) as usize;
    with_msix(|t| t[i] = Some(entry));
}

fn with_msix<R>(f: impl FnOnce(&mut [Option<Region>; 16]) -> R) -> R {
    let was = super::cpu::irqs_enabled();
    super::cpu::irq_disable();
    let r = f(&mut MSIX.lock());
    if was {
        super::cpu::irq_enable();
    }
    r
}

fn set_msix_mask(vector: u32, masked: bool) {
    let i = (vector - MSI_VECTORS.start()) as usize;
    with_msix(|t| {
        if let Some(e) = t[i].as_mut() {
            e.write32(MSIX_CTRL, if masked { MSIX_MASKED } else { 0 });
        }
    });
}

/// Unmask: the LVT timer, or a device's MSI-X entry. A message that came in
/// while masked is pending in the device and is delivered now.
pub fn enable(intid: u32, _trigger: Trigger) {
    if intid == TIMER_VECTOR {
        with_lapic(|r| r.modify32(LVT_TIMER, |v| v & !MASKED));
    } else if MSI_VECTORS.contains(&intid) {
        set_msix_mask(intid, false);
    }
}

/// Mask (also from IRQ context, NAPI-style).
pub fn disable(intid: u32) {
    if intid == TIMER_VECTOR {
        with_lapic(|r| r.modify32(LVT_TIMER, |v| v | MASKED));
    } else if MSI_VECTORS.contains(&intid) {
        set_msix_mask(intid, true);
    }
}

/// The wake/stop IPI vector (`smp`). Nothing sends it until the x86_64
/// SMP backend exists (M11 step 2b); `enable` ignores it.
pub const IPI_INTID: u32 = 33;

/// Secondary cores' local APIC setup (M11 step 2b).
pub fn init_secondary() {}

/// Send the wake/stop IPI to `core` (M11 step 2b: no other cores yet).
pub fn send_ipi(_core: usize) {}

/// End of interrupt (IRQ context).
pub(super) fn eoi() {
    with_lapic(|r| r.write32(EOI, 0));
}
