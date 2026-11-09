//! Local APIC (xAPIC, MMIO) with the legacy 8259 PICs masked.
//!
//! Interrupt IDs are **vectors**: 32 = local APIC timer, 48-63 = device
//! MSI-X (PCI port, next step), 255 = spurious. Legacy INTx via the IOAPIC
//! is not used: on PCs its routing needs the ACPI `_PRT` (AML), while MSI-X
//! works on every device rrouter targets (virtio-net, Intel i211).
//!
//! Locking: the APIC is used from thread context (timer programming,
//! enable) and IRQ context (EOI, NAPI-style disable), so every access runs
//! with IRQs masked (`with_lapic`). On a single core that is deadlock-free.

use super::exceptions::{SPURIOUS_VECTOR, TIMER_VECTOR};
use super::port::outb;
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

pub fn init(info: &BootInfo) {
    let Some(IrqChipInfo::Apic { lapic, .. }) = info.irqchip else {
        panic!("irqchip: no local APIC described");
    };
    // Mask both 8259 PICs: every interrupt comes through the local APIC.
    outb(0x21, 0xff);
    outb(0xa1, 0xff);
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
    super::timer::calibrate_lapic();
    println!(
        "  irqchip         : local APIC id {id}, version {version:#x}, timer {} MHz (8259 PICs masked)",
        super::timer::lapic_hz() / 1_000_000
    );
}

pub fn enable(intid: u32, _trigger: Trigger) {
    if intid == TIMER_VECTOR {
        with_lapic(|r| r.modify32(LVT_TIMER, |v| v & !MASKED));
    }
}

pub fn disable(intid: u32) {
    if intid == TIMER_VECTOR {
        with_lapic(|r| r.modify32(LVT_TIMER, |v| v | MASKED));
    }
}

/// End of interrupt (IRQ context).
pub(super) fn eoi() {
    with_lapic(|r| r.write32(EOI, 0));
}
