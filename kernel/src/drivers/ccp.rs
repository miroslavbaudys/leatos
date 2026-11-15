//! The TRNG of AMD's Cryptographic Coprocessor (PCI 1022:1537, the apu4's
//! GX-412TC at 00:08.0; Linux `drivers/crypto/ccp`: sp-pci uses BAR 2 for
//! this ID, ccp-dev-v3 reads `TRNG_OUT_REG` at offset 0x0c, where 0 means
//! "no new value yet").
//!
//! Only ever an extra input to `crate::entropy` (mixed through SHA-256 with
//! the other sources), and health-checked on every read: AMD family
//! 15h/16h hardware random numbers have been seen stuck at 0xffffffff
//! (the reason Linux hides RDRAND on these CPUs, which this driver does not
//! use). A failing source is switched off for the rest of the boot.

use crate::mmio::Region;
use crate::pci::Pci;

/// Queue mask (CCPv3 `Q_MASK_REG`): read only for the diagnosis (a live
/// coprocessor shows its queues, an absent one 0xffffffff).
const Q_MASK: usize = 0x00;
const TRNG_OUT: usize = 0x0c;
/// The first value may take a while after power-up.
const FIRST_VALUE_MS: u64 = 500;
/// Reads of 0 ("not ready") before a read gives up.
const RETRIES: usize = 10_000;
/// Startup test: this many values, all valid and none repeated.
const STARTUP_WORDS: usize = 64;

pub struct CcpTrng {
    regs: Region,
    last: u32,
    words: u64,
    /// Why the source was switched off.
    failed: Option<alloc::string::String>,
}

/// The CCP, if present, after its startup test (a failed one is returned
/// too, so its state can be reported).
pub fn probe(pci: &mut Pci) -> Option<CcpTrng> {
    let dev = pci
        .devices
        .iter()
        .find(|d| d.info.vendor_id == 0x1022 && d.info.device_id == 0x1537)?;
    let bar = dev.bars[2].filter(|b| b.size >= 0x10)?;
    // SAFETY: BAR 2 of the CCP function, assigned and mapped as device
    // memory by pci::init; this driver (one instance, probed once) is its
    // only user, and only reads the TRNG output register.
    let regs = unsafe { Region::new(bar.addr as usize, 0x10) };
    let mut t = CcpTrng {
        regs,
        last: 0,
        words: 0,
        failed: None,
    };
    // Wait for the first value (busy: early boot, no tasks yet).
    let start = crate::timer::uptime();
    let mut first = 0;
    while first == 0 && (crate::timer::uptime() - start).as_millis() < u128::from(FIRST_VALUE_MS) {
        first = t.regs.read32(TRNG_OUT);
    }
    if first == 0 {
        let qmask = t.regs.read32(Q_MASK);
        // Queue mask 0: the firmware left the CCP disabled (Linux: "you
        // might be running a broken BIOS"); PC Engines coreboot v4.16.0.1
        // and newer enable it.
        t.failed = Some(if qmask == 0 {
            alloc::format!(
                "queue mask 0: the firmware has not enabled the CCP (PC Engines coreboot v4.16.0.1 or newer enables it); BAR2 {:#x}",
                bar.addr
            )
        } else {
            alloc::format!(
                "always 0 for {FIRST_VALUE_MS} ms; BAR2 {:#x}+{:#x}, queue mask {qmask:#010x}",
                bar.addr, bar.size
            )
        });
        return Some(t);
    }
    let mut seen = alloc::vec::Vec::with_capacity(STARTUP_WORDS);
    for _ in 0..STARTUP_WORDS {
        match t.read() {
            Some(v) if seen.contains(&v) => {
                t.failed = Some("startup test: a value repeated".into());
                break;
            }
            Some(v) => seen.push(v),
            None => break,
        }
    }
    Some(t)
}

impl CcpTrng {
    pub fn words(&self) -> u64 {
        self.words
    }

    pub fn failure(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    /// One checked 32-bit value; `None` once the source failed (and from
    /// then on).
    pub fn read(&mut self) -> Option<u32> {
        if self.failed.is_some() {
            return None;
        }
        for _ in 0..RETRIES {
            let v = self.regs.read32(TRNG_OUT);
            if v == 0 {
                continue; // no new value yet
            }
            if v == u32::MAX {
                self.failed = Some("stuck at 0xffffffff".into());
                return None;
            }
            if self.words > 0 && v == self.last {
                self.failed = Some("the same value twice".into());
                return None;
            }
            self.last = v;
            self.words += 1;
            return Some(v);
        }
        self.failed = Some(alloc::format!("no value in {RETRIES} reads after {} good ones", self.words));
        None
    }
}
