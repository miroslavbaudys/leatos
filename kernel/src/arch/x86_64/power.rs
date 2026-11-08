//! ACPI power control (TODO: S5 via FADT / PM1a_CNT; QEMU isa-debug-exit for tests).

use crate::platform::PowerMethod;

pub fn init(_method: PowerMethod) {}

#[allow(dead_code)]
pub fn off() -> ! {
    todo!("x86_64: ACPI S5 power off")
}
