//! The battery-backed CMOS real-time clock (MC146818-compatible: the apu4's
//! FCH, QEMU's q35), ports 0x70 (index) / 0x71 (data). Kept in UTC:
//! `wallclock` writes it after SNTP syncs.
//!
//! Only the time registers (0x00–0x09) and status A/B are touched; the
//! century byte's location is firmware-specific (ACPI FADT), so the
//! century is taken as 20 and never written. The rest of CMOS belongs to
//! the firmware (coreboot's options) and is left alone.

use super::port::{inb, outb};
use crate::wallclock::DateTime;

const INDEX: u16 = 0x70;
const DATA: u16 = 0x71;
const SEC: u8 = 0x00;
const MIN: u8 = 0x02;
const HOUR: u8 = 0x04;
const DAY: u8 = 0x07;
const MONTH: u8 = 0x08;
const YEAR: u8 = 0x09;
const STATUS_A: u8 = 0x0a;
const STATUS_B: u8 = 0x0b;
/// Status A: an update is in progress (registers unstable for ≤ 2 ms).
const UIP: u8 = 0x80;
/// Status B: halt updates while setting; binary (not BCD); 24-hour.
const SET: u8 = 0x80;
const BINARY: u8 = 0x04;
const H24: u8 = 0x02;

/// Serialises index/data pairs (boot reads, `svc` writes).
static LOCK: spin::Mutex<()> = spin::Mutex::new(());

fn reg(r: u8) -> u8 {
    // Bit 7 of the index is the NMI mask: kept clear.
    outb(INDEX, r & 0x7f);
    inb(DATA)
}

fn set_reg(r: u8, v: u8) {
    outb(INDEX, r & 0x7f);
    outb(DATA, v);
}

fn from_bcd(v: u8) -> u8 {
    (v >> 4) * 10 + (v & 0x0f)
}

fn to_bcd(v: u8) -> u8 {
    ((v / 10) << 4) | (v % 10)
}

fn raw() -> Option<[u8; 6]> {
    // Wait out an update in progress (bounded: a dead RTC never clears it).
    let mut n = 0u32;
    while reg(STATUS_A) & UIP != 0 {
        n += 1;
        if n > 100_000 {
            return None;
        }
    }
    Some([reg(SEC), reg(MIN), reg(HOUR), reg(DAY), reg(MONTH), reg(YEAR)])
}

/// The RTC's time, if it reads as a valid date (a dead battery gives
/// garbage or the firmware's default date; the caller judges plausibility).
pub fn read() -> Option<DateTime> {
    let _g = LOCK.lock();
    // Two equal reads: no update happened in between.
    let mut t = raw()?;
    let mut stable = false;
    for _ in 0..5 {
        let u = raw()?;
        if u == t {
            stable = true;
            break;
        }
        t = u;
    }
    if !stable {
        return None;
    }
    let b = reg(STATUS_B);
    let bin = |v: u8| if b & BINARY != 0 { v } else { from_bcd(v) };
    let [sec, min, hour, day, month, year] = t;
    let hour = if b & H24 != 0 {
        bin(hour)
    } else {
        // 12-hour mode: bit 7 = PM, 12 means 0.
        bin(hour & 0x7f) % 12 + if hour & 0x80 != 0 { 12 } else { 0 }
    };
    let d = DateTime {
        year: 2000 + u16::from(bin(year)),
        month: bin(month),
        day: bin(day),
        hour,
        min: bin(min),
        sec: bin(sec),
    };
    d.is_valid().then_some(d)
}

/// Set the RTC (UTC), in the register format it already uses.
pub fn write(d: &DateTime) {
    if !d.is_valid() || !(2000..2100).contains(&d.year) {
        return;
    }
    let _g = LOCK.lock();
    let b = reg(STATUS_B);
    let enc = |v: u8| if b & BINARY != 0 { v } else { to_bcd(v) };
    let hour = if b & H24 != 0 {
        enc(d.hour)
    } else {
        let h12 = match d.hour % 12 {
            0 => 12,
            h => h,
        };
        enc(h12) | if d.hour >= 12 { 0x80 } else { 0 }
    };
    set_reg(STATUS_B, b | SET);
    set_reg(SEC, enc(d.sec));
    set_reg(MIN, enc(d.min));
    set_reg(HOUR, hour);
    set_reg(DAY, enc(d.day));
    set_reg(MONTH, enc(d.month));
    set_reg(YEAR, enc((d.year - 2000) as u8));
    set_reg(STATUS_B, b & !SET);
}
