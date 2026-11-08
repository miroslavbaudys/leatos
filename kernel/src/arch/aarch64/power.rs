//! PSCI power control.

use crate::platform::PowerMethod;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg_attr(not(feature = "smoke-test"), allow(dead_code))]
const SYSTEM_OFF: u64 = 0x8400_0008;
static USE_SMC: AtomicBool = AtomicBool::new(false);

pub fn init(method: PowerMethod) {
    USE_SMC.store(matches!(method, PowerMethod::PsciSmc), Ordering::Relaxed);
}

/// Power the machine off. In QEMU this exits the emulator.
#[cfg_attr(not(feature = "smoke-test"), allow(dead_code))] // used by smoke tests; later by the CLI
pub fn off() -> ! {
    if USE_SMC.load(Ordering::Relaxed) {
        // SAFETY: PSCI SYSTEM_OFF via the secure monitor; does not return on success.
        unsafe { asm!("smc #0", in("x0") SYSTEM_OFF, options(nomem, nostack)) };
    } else {
        // SAFETY: PSCI SYSTEM_OFF via the hypervisor; does not return on success.
        unsafe { asm!("hvc #0", in("x0") SYSTEM_OFF, options(nomem, nostack)) };
    }
    loop {
        core::hint::spin_loop();
    }
}
