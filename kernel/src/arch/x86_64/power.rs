//! ACPI S5 (soft off): `SLP_TYP | SLP_EN` into PM1a/PM1b control. In QEMU
//! this exits the emulator.

use super::port::{inb, outb, outw};
use crate::platform::PowerMethod;
use spin::Once;

static METHOD: Once<PowerMethod> = Once::new();

pub fn init(method: PowerMethod) {
    METHOD.call_once(|| method);
}

/// Reset the machine: the PCI reset control register (0xcf9, chipsets
/// since the PIIX, including the apu4's AMD FCH and QEMU q35), then the
/// keyboard controller's reset line as a fallback.
pub fn reset() -> ! {
    super::cpu::irq_disable();
    outb(0xcf9, 0x02); // reset type: hard, not yet
    outb(0xcf9, 0x06); // + do it
    for _ in 0..1_000_000 {
        core::hint::spin_loop();
    }
    for _ in 0..10_000 {
        if inb(0x64) & 0x02 == 0 {
            break; // input buffer empty
        }
    }
    outb(0x64, 0xfe); // 8042: pulse the reset line
    crate::fatal_println!("reset failed; halting");
    super::cpu::halt()
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
