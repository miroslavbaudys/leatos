//! No real-time clock in use on aarch64 (QEMU `virt`'s PL031 is not
//! mapped): the time is unknown until SNTP, as before.

use crate::wallclock::DateTime;

pub fn read() -> Option<DateTime> {
    None
}

pub fn write(_: &DateTime) {}
