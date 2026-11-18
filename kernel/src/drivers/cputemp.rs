//! CPU die temperature of AMD family 16h processors (the apu4's GX-412TC),
//! as Linux's `k10temp` reads it: PCI function 00:18.3 (northbridge
//! "misc"), no other sensor on the board (its NCT5104D Super I/O has no
//! hardware monitor). Absent in QEMU: [`read`] returns `None` there.
//!
//! - D18F3xA4 (Reported Temperature Control): `CurTmp` = bits 31:21 in
//!   0.125 °C steps; 49 °C lower when the range-select bit 19 is set or
//!   `CurTmpTjSel` (bits 17:16) is `11b`. This is "Tctl", on family 16h
//!   the die temperature without offset (a few degrees accurate).
//! - D18F3x64 (HTC): with `HtcEn` (bit 0) the CPU throttles at
//!   52 °C + 0.5 °C × `HtcTmpLmt` (bits 22:16).
//!
//! Config space only, read-only: the A4 dword through
//! [`Pci::config_dword`], read once a second by `cpuload`'s sampler into a
//! history like the CPU load's.

use crate::cpuload::Ring;
use crate::mmio::Region;
use crate::pci::Pci;
use crate::println;
use spin::{Mutex, Once};

const AMD: u16 = 0x1022;
/// Family 16h models 00h–0Fh and 30h–3Fh, function 3.
const NB_F3: [u16; 2] = [0x1533, 0x1583];
const REG_HTC: u8 = 0x64;
const REG_TEMP: u8 = 0xa4;

struct Sensor {
    reg: Region,
    hist: Ring<i32>,
}

static SENSOR: Once<Mutex<Sensor>> = Once::new();
static HTC_MC: Once<Option<i32>> = Once::new();

/// D18F3xA4 → milli-°C.
pub fn decode_temp(reg: u32) -> i32 {
    let mut mc = (reg >> 21) as i32 * 125;
    if reg & (1 << 19) != 0 || (reg >> 16) & 3 == 3 {
        mc -= 49_000;
    }
    mc
}

/// D18F3x64 → the throttle limit in milli-°C, if HTC is enabled.
pub fn decode_htc(reg: u32) -> Option<i32> {
    (reg & 1 != 0).then(|| 52_000 + ((reg >> 16) & 0x7f) as i32 * 500)
}

pub fn probe(pci: &mut Pci) {
    let Some(df) = pci
        .devices
        .iter()
        .find(|d| d.info.vendor_id == AMD && NB_F3.contains(&d.info.device_id))
        .map(|d| d.df)
    else {
        return;
    };
    let htc = decode_htc(pci.config_read(df, REG_HTC));
    let mut reg = pci.config_dword(df, REG_TEMP);
    let now = decode_temp(reg.read32(0));
    HTC_MC.call_once(|| htc);
    SENSOR.call_once(|| {
        Mutex::new(Sensor {
            reg,
            hist: Ring::new(0),
        })
    });
    println!(
        "  cpu temperature : {}{}",
        fmt_mc(now),
        htc.map(|h| alloc::format!(" (throttles at {})", fmt_mc(h)))
            .unwrap_or_default()
    );
}

/// The current temperature in milli-°C; `None` without a sensor.
pub fn read() -> Option<i32> {
    let mut s = SENSOR.get()?.lock();
    Some(decode_temp(s.reg.read32(0)))
}

/// The hardware throttle (HTC) limit in milli-°C, if enabled.
pub fn htc() -> Option<i32> {
    HTC_MC.get().copied().flatten()
}

/// Read and append to the history (called once per `cpuload::INTERVAL`).
pub fn sample() {
    let Some(m) = SENSOR.get() else { return };
    let mut s = m.lock();
    let t = decode_temp(s.reg.read32(0));
    s.hist.push(t);
}

/// The history in milli-°C, oldest first; `false` without a sensor.
pub fn history(f: impl FnMut(i32)) -> bool {
    let Some(m) = SENSOR.get() else { return false };
    m.lock().hist.for_each(f);
    true
}

/// "54.1 °C".
pub fn fmt_mc(mc: i32) -> alloc::string::String {
    let t = mc.unsigned_abs() / 100;
    let sign = if mc < 0 && t > 0 { "-" } else { "" };
    alloc::format!("{sign}{}.{} °C", t / 10, t % 10)
}
