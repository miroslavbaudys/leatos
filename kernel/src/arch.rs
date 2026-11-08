//! Small aarch64 helpers (system registers, power states).

use core::arch::asm;

/// Current exception level (0–3).
pub fn current_el() -> u64 {
    let el: u64;
    // SAFETY: reading CurrentEL has no side effects.
    unsafe { asm!("mrs {}, CurrentEL", out(reg) el, options(nomem, nostack)) };
    (el >> 2) & 0b11
}

/// Sleep until an interrupt (or event) is pending.
#[cfg_attr(feature = "idle-poll", allow(dead_code))]
pub fn wait_for_interrupt() {
    // SAFETY: `wfi` only suspends the core.
    unsafe { asm!("wfi", options(nomem, nostack)) };
}

/// Stop this core forever. With the `smoke-test` feature, power off instead
/// so an automated QEMU run terminates.
pub fn halt() -> ! {
    #[cfg(feature = "smoke-test")]
    crate::psci::system_off(crate::psci::Conduit::Hvc);
    #[allow(unreachable_code)]
    loop {
        // SAFETY: `wfe` only suspends the core.
        unsafe { asm!("wfe", options(nomem, nostack)) };
    }
}
