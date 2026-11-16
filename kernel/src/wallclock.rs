//! Wall-clock time (UTC), once SNTP has set it (`net::ntp`).
//!
//! The kernel's clock is monotonic (`timer`, from power-on). SNTP finds
//! the Unix time at monotonic 0 and stores it here; the wall clock is
//! that plus the uptime. Unknown until the first sync.
//!
//! The battery-backed RTC (`arch::rtc`: the apu4's CMOS clock) is read
//! once at boot ([`init_rtc`]) but is **not** the wall clock: a dead
//! battery or a clock set wrong must not pass for the time, and in the lab
//! it would hide a broken SNTP. It is only a hint ([`rtc_hint`]) for
//! checking DNS-over-TLS certificate dates before SNTP
//! (`proto_dot::verify`), used only where it cannot lock DNS out. After
//! each SNTP sync the RTC is set from the wall clock if it is off by more
//! than [`RTC_TOLERANCE_S`], so it stays right across power cuts.

use crate::{println, timer};
use core::fmt;
use core::sync::atomic::{AtomicI64, Ordering};

/// Unix ns at monotonic 0; `i64::MIN` = not set.
static OFFSET: AtomicI64 = AtomicI64::new(i64::MIN);
/// The RTC's reading as Unix ns at monotonic 0; `i64::MIN` = none.
static RTC_OFFSET: AtomicI64 = AtomicI64::new(i64::MIN);

/// RTC error tolerated before it is rewritten (it counts whole seconds).
pub const RTC_TOLERANCE_S: i64 = 2;

/// Set from an SNTP sample (`proto_sntp::Sample::offset`). The monotonic
/// base must be the one `net::ntp` measures with: `timer::uptime`.
pub fn set(unix_ns_at_boot: i64) {
    OFFSET.store(unix_ns_at_boot, Ordering::Release);
    sync_rtc();
}

/// The time, if known.
pub fn now() -> Option<UnixTime> {
    let off = OFFSET.load(Ordering::Acquire);
    (off != i64::MIN).then(|| UnixTime(off.saturating_add(timer::uptime().as_nanos() as i64)))
}

/// Read the RTC once at boot (after `timer::init_clock`).
pub fn init_rtc() {
    match crate::arch::rtc::read().filter(DateTime::is_valid) {
        Some(d) => {
            let unix_ns = d.unix_secs() * 1_000_000_000;
            RTC_OFFSET.store(unix_ns - timer::uptime().as_nanos() as i64, Ordering::Release);
            println!("  rtc             : {d} (a hint until SNTP, not the clock)");
        }
        None => println!("  rtc             : none"),
    }
}

/// What the RTC says now (its boot reading plus the uptime), if it read
/// as a date. Unverified: see the module comment.
pub fn rtc_hint() -> Option<UnixTime> {
    let off = RTC_OFFSET.load(Ordering::Acquire);
    (off != i64::MIN).then(|| UnixTime(off.saturating_add(timer::uptime().as_nanos() as i64)))
}

/// After a sync: set the RTC if it is off (or was unreadable).
fn sync_rtc() {
    let Some(t) = now() else { return };
    let off_s = rtc_hint().map(|r| (r.0 - t.0) / 1_000_000_000);
    if off_s.is_some_and(|d| d.abs() <= RTC_TOLERANCE_S) {
        return;
    }
    let d = DateTime::from_unix_secs(t.secs());
    crate::arch::rtc::write(&d);
    if crate::arch::rtc::read().is_some() {
        RTC_OFFSET.store(OFFSET.load(Ordering::Acquire), Ordering::Release);
        match off_s {
            Some(s) => println!("  rtc             : was {s} s off, set to {d}"),
            None => println!("  rtc             : set to {d}"),
        }
    }
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
        DateTime::from_unix_secs(self.secs()).fmt(f)
    }
}

/// A calendar date and time in UTC (the RTC's registers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub min: u8,
    pub sec: u8,
}

impl DateTime {
    pub fn is_valid(&self) -> bool {
        let dim = match self.month {
            2 if self.year.is_multiple_of(4) && (!self.year.is_multiple_of(100) || self.year.is_multiple_of(400)) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            1..=12 => 31,
            _ => 0,
        };
        (1..=dim).contains(&self.day) && self.hour < 24 && self.min < 60 && self.sec < 60
    }

    pub fn unix_secs(&self) -> i64 {
        days_from_civil(i64::from(self.year), u32::from(self.month), u32::from(self.day)) * 86_400
            + i64::from(self.hour) * 3600
            + i64::from(self.min) * 60
            + i64::from(self.sec)
    }

    pub fn from_unix_secs(secs: i64) -> Self {
        let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        let (y, m, d) = civil_from_days(days);
        DateTime {
            year: y.clamp(0, i64::from(u16::MAX)) as u16,
            month: m as u8,
            day: d as u8,
            hour: (rem / 3600) as u8,
            min: (rem / 60 % 60) as u8,
            sec: (rem % 60) as u8,
        }
    }
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.min, self.sec
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

/// (year, month, day) → days since 1970-01-01 (Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
