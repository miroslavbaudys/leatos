//! x86_64 backend: **compile-only skeleton**.
//!
//! Purpose today: `cargo kcheck-x86` type-checks all arch-neutral code
//! against this API, so aarch64 assumptions cannot creep into neutral
//! modules. Trivially correct pieces are real (CPU flags, 16550 console,
//! page-table encoding, TSC read); the rest are `todo!()` with the plan in
//! docs/safety-and-portability.md §3 (Limine boot, ACPI MADT/MCFG,
//! LAPIC + IOAPIC, TSC-deadline timer, MSI-X).

pub mod console;
pub mod cpu;
pub mod irqchip;
pub mod mmu;
pub mod power;
pub mod timer;

use crate::platform::BootInfo;

/// Discover the machine from ACPI tables (RSDP from the boot protocol).
pub fn discover(_boot_arg: usize) -> Result<BootInfo, &'static str> {
    Err("x86_64: ACPI discovery not implemented yet")
}
