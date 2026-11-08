//! PSCI (Power State Coordination Interface) calls to the hypervisor/firmware.

use core::arch::asm;

const SYSTEM_OFF: u64 = 0x8400_0008;

/// How PSCI calls reach the firmware (from the DTB `/psci` `method`).
#[derive(Clone, Copy, Debug)]
pub enum Conduit {
    Hvc,
    Smc,
}

/// Power the machine off. In QEMU this exits the emulator.
#[cfg_attr(not(feature = "smoke-test"), allow(dead_code))]
pub fn system_off(conduit: Conduit) -> ! {
    // SAFETY: PSCI SYSTEM_OFF does not return on success.
    unsafe {
        match conduit {
            Conduit::Hvc => asm!("hvc #0", in("x0") SYSTEM_OFF, options(nomem, nostack)),
            Conduit::Smc => asm!("smc #0", in("x0") SYSTEM_OFF, options(nomem, nostack)),
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
