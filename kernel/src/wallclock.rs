//! Wall-clock time (UTC), once SNTP has set it (`net::ntp`).
//!
//! The kernel's clock is monotonic (`timer`, from power-on). SNTP finds
//! the Unix time at monotonic 0 and stores it here; the wall clock is
//! that plus the uptime. Unknown until the first sync: no RTC is read
//! (the apu4's is not trusted, QEMU's PL031/CMOS would only hide a broken
//! SNTP in the lab).

use crate::timer;
use core::fmt;
use core::sync::atomic::{AtomicI64, Ordering};

/// Unix ns at monotonic 0; `i64::MIN` = not set.
static OFFSET: AtomicI64 = AtomicI64::new(i64::MIN);

/// Set from an SNTP sample (`proto_sntp::Sample::offset`). The monotonic
/// base must be the one `net::ntp` measures with: `timer::uptime`.
pub fn set(unix_ns_at_boot: i64) {
    OFFSET.store(unix_ns_at_boot, Ordering::Release);
}

/// The time, if known.
pub fn now() -> Option<UnixTime> {
    let off = OFFSET.load(Ordering::Acquire);
    (off != i64::MIN).then(|| UnixTime(off.saturating_add(timer::uptime().as_nanos() as i64)))
}

/// Nanoseconds since 1970-01-01T00:00:00Z.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTime(pub i64);

impl UnixTime {
    pub fn secs(self) -> i64 {
        self.0.div_euclid(1_000_000_000)
    }
}

/// ISO 8601 in UTC, to the second: `2026-11-14T12:34:56Z`.
impl fmt::Display for UnixTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.secs();
        let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            rem / 3600,
            rem / 60 % 60,
            rem % 60
        )
    }
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}
