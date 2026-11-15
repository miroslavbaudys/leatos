//! The end of every fatal path (panic, unhandled exception, watchdog):
//! stop the other cores, give the serial console time to drain, reset.
//!
//! A router that halts stays down until someone power-cycles it; one that
//! reboots is back in seconds (docs/architecture.md, "no isolation").
//! Boot argument `panic=halt` keeps the machine stopped instead
//! (debugging: the message stays on the console, the state stays in RAM).
//!
//! [`enter`] before the report (`fatal_println!`), [`die`] after it. Allocates
//! nothing and takes no locks, so it works from any context, including an
//! exception on the exception stack.

use crate::{arch, config, fatal_println, smp, timer};
use core::sync::atomic::{AtomicBool, Ordering};

/// Seconds between the report and the reset.
const REBOOT_DELAY_SECS: u64 = 3;

static DYING: AtomicBool = AtomicBool::new(false);

/// Start a fatal report: call before printing it. Only the first core to
/// get here reports (two watchdog checkers may notice the same stall at
/// once); any other, and a second fault while dying, parks.
pub fn enter() {
    arch::cpu::irq_disable();
    if DYING.swap(true, Ordering::AcqRel) {
        arch::cpu::park();
    }
}

/// Finish a fatal path ([`enter`] first, then the report).
pub fn die() -> ! {
    arch::cpu::irq_disable();
    DYING.store(true, Ordering::Release);
    smp::stop_others();
    // What led up to it, if log output went to RAM (`console::log_to_ram`).
    crate::console::fatal_dump_log();
    // Before the clock runs (very early boot) there is no way to wait, and
    // a fault that early would only fault again: halt.
    let freq = timer::frequency();
    if config::panic_halts() || freq <= 1 {
        fatal_println!("!!! halted ({})", if freq <= 1 { "early boot" } else { "panic=halt" });
        arch::cpu::halt();
    }
    fatal_println!("!!! rebooting in {REBOOT_DELAY_SECS} s (boot argument panic=halt stops instead)");
    let until = timer::ticks().saturating_add(REBOOT_DELAY_SECS * freq);
    while timer::ticks() < until {
        core::hint::spin_loop();
    }
    // Some chipset watchdogs survive a reset and would cut the next
    // firmware boot short.
    crate::watchdog::stop();
    arch::power::reset()
}
