//! The TRNG of AMD's Cryptographic Coprocessor (PCI 1022:1537, the apu4's
//! GX-412TC at 00:08.0). Linux `drivers/crypto/ccp`: sp-pci maps BAR 2 for
//! this ID, and the `ccpv3` (PCI) variant's registers start at offset
//! 0x20000 into it (`ccpv3.offset`, `io_regs = io_map + offset`; only the
//! platform variant has them at 0). ccp-dev-v3 reads `TRNG_OUT_REG` (0x0c)
//! there, where 0 means "no new value yet or bad entropy".
//!
//! Linux registers the hwrng only after finding command queues (`Q_MASK_REG`
//! non-zero), but the TRNG read is a plain register read that uses no
//! queue, DMA or interrupt, so it is tried with any mask; the mask is
//! reported.
//!
//! Only ever an extra input to `crate::entropy` (mixed through SHA-256 with
//! the other sources), and health-checked on every read: AMD family
//! 15h/16h hardware random numbers have been seen stuck at 0xffffffff
//! (the reason Linux hides RDRAND on these CPUs, which this driver does not
//! use). A failing source is switched off for the rest of the boot.

use crate::mmio::Region;
use crate::pci::Pci;

/// Start of the CCPv3 register block inside BAR 2 (Linux `ccpv3.offset`).
const REGS_OFFSET: u64 = 0x2_0000;
/// Bytes of the register block mapped (up to the queue status registers).
const REGS_LEN: usize = 0x220;
/// Queue mask (`Q_MASK_REG`): the command queues the firmware enabled.
const Q_MASK: usize = 0x000;
const TRNG_OUT: usize = 0x00c;
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
    qmask: u32,
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
    let bar = dev.bars[2].filter(|b| b.size >= REGS_OFFSET + REGS_LEN as u64)?;
    let base = bar.addr + REGS_OFFSET;
    // SAFETY: inside BAR 2 of the CCP function (size checked above),
    // assigned and mapped as device memory by pci::init; this driver (one
    // instance, probed once) is its only user, and only reads registers.
    let mut regs = unsafe { Region::new(base as usize, REGS_LEN) };
    let qmask = regs.read32(Q_MASK);
    let mut t = CcpTrng {
        regs,
        last: 0,
        words: 0,
        qmask,
        failed: None,
    };
    crate::println!(
        "  ccp             : BAR2 {:#x}+{:#x}, regs at +{REGS_OFFSET:#x}, queue mask {qmask:#010x}",
        bar.addr,
        bar.size
    );
    // Wait for the first value (busy: early boot, no tasks yet).
    let start = crate::timer::uptime();
    let mut first = 0;
    let mut zeros = 0u64;
    while first == 0 && (crate::timer::uptime() - start).as_millis() < u128::from(FIRST_VALUE_MS) {
        first = t.regs.read32(TRNG_OUT);
        zeros += u64::from(first == 0);
    }
    if first == 0 {
        t.failed = Some(alloc::format!(
            "always 0 for {FIRST_VALUE_MS} ms ({zeros} reads); queue mask {qmask:#010x}"
        ));
        return Some(t);
    }
    crate::println!("  ccp             : first TRNG value after {zeros} zero reads");
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
    // A few values on the console, to see on the hardware that they vary.
    let sample: alloc::vec::Vec<_> = seen.iter().take(4).map(|v| alloc::format!("{v:08x}")).collect();
    crate::println!("  ccp             : sample {}", sample.join(" "));
    Some(t)
}

impl CcpTrng {
    pub fn words(&self) -> u64 {
        self.words
    }

    pub fn queue_mask(&self) -> u32 {
        self.qmask
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
