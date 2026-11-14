//! Hardware watchdog timers: the last line of defence when every core is
//! stuck (the software check in `crate::watchdog` needs one healthy core).
//!
//! - [`i6300esb`](super::i6300esb): QEMU's `-device i6300esb` (PCI, both
//!   arches), so the hardware path is testable in the lab
//! - the apu4's AMD FCH watchdog: `arch::watchdog` (x86_64 only, port I/O)
//!
//! Once started, a hardware watchdog resets the machine unless it is
//! petted within its timeout.

use crate::pci::Pci;
use alloc::boxed::Box;

pub trait HwWatchdog: Send {
    fn name(&self) -> &'static str;
    /// Arm with `secs` until reset.
    fn start(&mut self, secs: u32);
    /// Restart the countdown.
    fn pet(&mut self);
    /// Disarm (before a deliberate reboot, so a slow firmware boot is not
    /// cut short).
    fn stop(&mut self);
    /// The previous reset was this watchdog's doing.
    fn fired_last_boot(&self) -> bool;
}

/// The machine's hardware watchdog, if it has one we drive.
pub fn probe(pci: &mut Pci) -> Option<Box<dyn HwWatchdog>> {
    if let Some(w) = super::i6300esb::probe(pci) {
        return Some(Box::new(w));
    }
    // AMD FCH: identified by its SMBus controller (function 0x14.0).
    let smbus = pci
        .devices
        .iter()
        .find(|d| d.info.vendor_id == 0x1022 && d.info.device_id == 0x780b)
        .map(|d| d.info.revision);
    crate::arch::watchdog::probe(smbus)
}
