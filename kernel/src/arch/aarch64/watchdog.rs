//! Platform watchdog: QEMU `virt` has none of its own (the lab uses the
//! PCI i6300esb, `drivers::i6300esb`).

use crate::drivers::watchdog::HwWatchdog;
use alloc::boxed::Box;

pub fn probe(_smbus_rev: Option<u8>) -> Option<Box<dyn HwWatchdog>> {
    None
}
