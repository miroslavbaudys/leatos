//! Local APIC + IOAPIC (TODO). Drivers will use MSI-X behind the same
//! `enable`/`disable` interface (docs/safety-and-portability.md §3.3).

use crate::irq::Trigger;
use crate::platform::BootInfo;

pub fn init(_info: &BootInfo) {
    todo!("x86_64: LAPIC/IOAPIC init")
}

pub fn enable(_intid: u32, _trigger: Trigger) {
    todo!("x86_64: IOAPIC redirection / MSI-X enable")
}

pub fn disable(_intid: u32) {
    todo!("x86_64: IOAPIC mask / MSI-X mask")
}
