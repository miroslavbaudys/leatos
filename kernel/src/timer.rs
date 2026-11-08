//! ARM generic timer (virtual counter). Interrupt-driven timers come later
//! together with the GIC driver; for now this is a monotonic clock.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

static BOOT_TICKS: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    BOOT_TICKS.store(ticks(), Ordering::Relaxed);
}

/// Counter frequency in Hz (CNTFRQ_EL0).
pub fn frequency() -> u64 {
    let f: u64;
    // SAFETY: reading CNTFRQ_EL0 has no side effects.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
    f
}

/// Raw virtual counter value (CNTVCT_EL0).
pub fn ticks() -> u64 {
    let t: u64;
    // SAFETY: `isb` + reading CNTVCT_EL0 has no side effects.
    unsafe { asm!("isb", "mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack)) };
    t
}

/// Microseconds since [`init`].
pub fn uptime_us() -> u64 {
    let dt = ticks() - BOOT_TICKS.load(Ordering::Relaxed);
    (dt as u128 * 1_000_000 / frequency().max(1) as u128) as u64
}
