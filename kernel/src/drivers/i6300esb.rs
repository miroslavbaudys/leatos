//! Intel 6300ESB watchdog (PCI 8086:25ab), as QEMU emulates it
//! (`-device i6300esb`, `hw/watchdog/wdt_i6300esb.c`; Linux
//! `drivers/watchdog/i6300esb.c`). On both arches: it is the lab's
//! hardware watchdog.
//!
//! Two stages, each loaded from its preload register on a reload: stage
//! 1 expires (an interrupt we leave unrouted), then stage 2 resets the
//! machine. In the 1 kHz scale (the reset default) a unit is 2^15 PCI
//! clocks ≈ 1 ms, so `secs << 9` per stage makes the total ≈ `secs`.
//!
//! The registers only react to the right access width: preloads 32-bit,
//! reload/status 16-bit, the config lock register 8-bit. Writes to the
//! preloads and the reload register need the unlock sequence first.

use super::watchdog::HwWatchdog;
use crate::mmio::Region;
use crate::pci::Pci;

const TIMER1: usize = 0x00;
const TIMER2: usize = 0x04;
const RELOAD: usize = 0x0c;
const UNLOCK1: u16 = 0x80;
const UNLOCK2: u16 = 0x86;
const RELOAD_BIT: u16 = 1 << 8;
/// Status: the previous reset was a watchdog timeout (write 1 to clear).
const TIMEOUT_BIT: u16 = 1 << 9;

/// Config space: lock register (byte).
const LOCK_REG: u8 = 0x68;
const LOCK_ENABLE: u8 = 1 << 1;

pub struct I6300esb {
    regs: Region,
    /// The config dword holding the lock register.
    lock: Region,
    fired: bool,
}

pub fn probe(pci: &mut Pci) -> Option<I6300esb> {
    let dev = pci
        .devices
        .iter()
        .find(|d| d.info.vendor_id == 0x8086 && d.info.device_id == 0x25ab)?
        .clone();
    let bar = dev.bars[0]?;
    if bar.size < 16 {
        return None;
    }
    // SAFETY: BAR0 of the watchdog function, mapped as device memory by
    // pci::init; this driver (one instance, probed once) is its only user.
    let regs = unsafe { Region::new(bar.addr as usize, 16) };
    let lock = pci.config_dword(dev.df, LOCK_REG);
    let mut w = I6300esb {
        regs,
        lock,
        fired: false,
    };
    w.fired = w.regs.read16(RELOAD) & TIMEOUT_BIT != 0;
    // Clear the flag and reload. A watchdog left running by the previous
    // kernel (in-RAM upgrade, kernel from the store) keeps running: this
    // kernel gets the full timeout to reach `watchdog::start`, and a hang
    // on the way resets the machine.
    w.unlock();
    w.regs.write16(RELOAD, TIMEOUT_BIT | RELOAD_BIT);
    Some(w)
}

impl I6300esb {
    fn unlock(&mut self) {
        self.regs.write16(RELOAD, UNLOCK1);
        self.regs.write16(RELOAD, UNLOCK2);
    }
}

impl HwWatchdog for I6300esb {
    fn name(&self) -> &'static str {
        "i6300esb"
    }

    fn start(&mut self, secs: u32) {
        let units = secs.clamp(1, 2046) << 9;
        self.unlock();
        self.regs.write32(TIMER1, units);
        self.unlock();
        self.regs.write32(TIMER2, units);
        self.pet();
        self.lock.write8(usize::from(LOCK_REG & 3), LOCK_ENABLE);
    }

    fn pet(&mut self) {
        self.unlock();
        self.regs.write16(RELOAD, RELOAD_BIT);
    }

    fn stop(&mut self) {
        self.lock.write8(usize::from(LOCK_REG & 3), 0);
    }

    fn fired_last_boot(&self) -> bool {
        self.fired
    }
}
