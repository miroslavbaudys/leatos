//! ACPI S5 (soft off): `SLP_TYP | SLP_EN` into PM1a/PM1b control. In QEMU
//! this exits the emulator.

use super::port::outw;
use crate::platform::PowerMethod;
use spin::Once;

static METHOD: Once<PowerMethod> = Once::new();

pub fn init(method: PowerMethod) {
    METHOD.call_once(|| method);
}

#[cfg_attr(not(feature = "smoke-test"), allow(dead_code))] // used by smoke tests; later by the CLI
pub fn off() -> ! {
    const SLP_EN: u16 = 1 << 13;
    if let Some(&PowerMethod::AcpiS5 {
        pm1a_cnt,
        pm1b_cnt,
        slp_typ_a,
        slp_typ_b,
    }) = METHOD.get()
    {
        super::cpu::irq_disable();
        if pm1a_cnt != 0 {
            outw(pm1a_cnt, slp_typ_a << 10 | SLP_EN);
        }
        if pm1b_cnt != 0 {
            outw(pm1b_cnt, slp_typ_b << 10 | SLP_EN);
        }
    }
    crate::fatal_println!("power off failed (no ACPI S5); halting");
    super::cpu::halt()
}
