//! The AMD FCH watchdog (the apu4's GX-412TC "Steppe Eagle" FCH, SMBus
//! PCI 1022:780b rev ≥ 0x41: the "EFCH" layout of Linux's
//! `drivers/watchdog/sp5100_tco.c`). Untestable in QEMU.
//!
//! - Power-management registers through the index/data ports
//!   0xcd6/0xcd7: PM 0x00 bit 7 decodes the watchdog at 0xfeb00000; else
//!   PM 0x04 bit 1 (ACPI MMIO) puts it at 0xfed80b00. PM 0x03 bits 3:2
//!   disable the timer, bits 1:0 = 3 select a 1 s tick.
//! - Two MMIO registers: CONTROL (+0: run, fired, action, disabled,
//!   trigger) and COUNT (+4: seconds, reloaded on a trigger).
//! - The action bit (Linux: `SP5100_WDT_ACTION_RESET`, despite the name)
//!   **set = power off**, clear = reset (Linux `action` parameter: "0 to
//!   reset, 1 to poweroff"). Seen on the apu4: with it set, the watchdog
//!   switched the board off.

use super::port::{inb, outb};
use crate::drivers::watchdog::HwWatchdog;
use crate::mmio::Region;
use alloc::boxed::Box;

const PM_INDEX: u16 = 0xcd6;
const PM_DATA: u16 = 0xcd7;
const PM_DECODEEN: u8 = 0x00;
const PM_DECODEEN_WDT: u8 = 1 << 7;
const PM_DECODEEN3: u8 = 0x03;
const PM_WDT_DISABLE: u8 = 0b1100;
const PM_WDT_SECOND_RES: u8 = 0b0011;
const PM_ISACONTROL: u8 = 0x04;
const PM_ISACONTROL_MMIOEN: u8 = 1 << 1;

const WDT_ADDR: usize = 0xfeb0_0000;
const ACPI_MMIO_WDT: usize = 0xfed8_0000 + 0xb00;

const CONTROL: usize = 0x00;
const COUNT: usize = 0x04;
const RUN: u32 = 1 << 0;
const FIRED: u32 = 1 << 1;
/// Set: power off on expiry; clear: reset. We always clear it.
const ACTION_POWEROFF: u32 = 1 << 2;
const DISABLED: u32 = 1 << 3;
const TRIGGER: u32 = 1 << 7;

fn pm_read(index: u8) -> u8 {
    outb(PM_INDEX, index);
    inb(PM_DATA)
}

fn pm_update(index: u8, clear: u8, set: u8) {
    let v = (pm_read(index) & !clear) | set;
    outb(PM_INDEX, index);
    outb(PM_DATA, v);
}

pub struct FchWdt {
    regs: Region,
    fired: bool,
}

/// `smbus_rev`: the revision of the FCH SMBus function, if present.
pub fn probe(smbus_rev: Option<u8>) -> Option<Box<dyn HwWatchdog>> {
    if smbus_rev? < 0x41 {
        return None; // older SB800 layout: not on any board we run on
    }
    let base = if pm_read(PM_DECODEEN) & PM_DECODEEN_WDT != 0 {
        WDT_ADDR
    } else if pm_read(PM_ISACONTROL) & PM_ISACONTROL_MMIOEN != 0 {
        ACPI_MMIO_WDT
    } else {
        // Firmware left both windows off: turn the dedicated one on.
        pm_update(PM_DECODEEN, 0, PM_DECODEEN_WDT);
        if pm_read(PM_DECODEEN) & PM_DECODEEN_WDT == 0 {
            return None;
        }
        WDT_ADDR
    };
    crate::mm::mmu::map_device(base, base + 8);
    // SAFETY: the FCH watchdog's two registers at a fixed chipset address,
    // just mapped as device memory; this driver (probed once) is their
    // only user.
    let mut regs = unsafe { Region::new(base, 8) };
    // 1 s resolution, timer enabled (it only counts once started).
    pm_update(PM_DECODEEN3, PM_WDT_DISABLE, PM_WDT_SECOND_RES);
    let ctl = regs.read32(CONTROL);
    if ctl & DISABLED != 0 {
        return None;
    }
    // Writing FIRED back clears it; stop until `start`.
    regs.write32(CONTROL, ctl & !(RUN | ACTION_POWEROFF));
    Some(Box::new(FchWdt {
        regs,
        fired: ctl & FIRED != 0,
    }))
}

impl HwWatchdog for FchWdt {
    fn name(&self) -> &'static str {
        "amd-fch"
    }

    fn start(&mut self, secs: u32) {
        self.regs.write32(COUNT, secs.clamp(1, 0xffff));
        self.regs.modify32(CONTROL, |c| (c | RUN) & !(FIRED | ACTION_POWEROFF));
        // The trigger must be a separate write (Linux sp5100_tco).
        self.pet();
    }

    fn pet(&mut self) {
        self.regs.modify32(CONTROL, |c| (c | TRIGGER) & !FIRED);
    }

    fn stop(&mut self) {
        self.regs.modify32(CONTROL, |c| c & !(RUN | FIRED));
    }

    fn fired_last_boot(&self) -> bool {
        self.fired
    }
}
