//! SATA disks behind an AHCI controller (PCI class 01:06:01): the apu4's
//! mSATA and SATA ports (AMD FCH), Proxmox `sata0`–`sata5`, QEMU q35's
//! built-in ICH9 controller (00:1f.2) and `-device ahci` on aarch64
//! (docs/install.md §3.1). Serial ATA AHCI 1.3.1 and ATA8-ACS.
//!
//! - **One [`Ahci`] per port with an ATA disk:** [`open_ports`] enables
//!   AHCI mode once per controller (BIOS hand-off if the controller has
//!   it), then sets up every implemented port that has a device. ATAPI
//!   devices (CD/DVD, how Proxmox attaches an ISO) are reported, not used.
//! - **Polled, one command in flight** (slot 0): interrupts stay disabled;
//!   every wait polls a register and yields to the executor in between,
//!   so a store write never blocks the datapath; at boot the same code
//!   runs under `executor::block_on`.
//! - **No new unsafe:** the command list, FIS area, command table and a
//!   64 KiB data buffer are `mm::dma::DmaRegion`s the driver owns for good
//!   (the device may access them at any time, so they are never freed);
//!   data is copied in and out of the buffer. The only `unsafe` is the
//!   register window's constructor (`mmio::Region::new`), once for the
//!   controller and once per port, on disjoint ranges of BAR5.
//! - **Cancellation:** a caller dropped mid-command leaves it in flight;
//!   the next operation sees `in_progress` and stops and restarts the port
//!   first (AHCI 6.2.2), so a late completion never lands in a new request.
//! - Commands: IDENTIFY DEVICE, READ / WRITE DMA EXT (LBA48; READ / WRITE
//!   DMA for LBA28-only disks), FLUSH CACHE (EXT). 512-byte logical
//!   sectors only.

use crate::mm::dma::DmaRegion;
use crate::mmio::Region;
use crate::pci::PciDevice;
use crate::timer::Instant;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};
use core::time::Duration;

/// Largest single request, in sectors (64 KiB), as for virtio-blk and SD.
pub const MAX_REQUEST_SECTORS: usize = 128;
const SECTOR: usize = 512;
const BUF: usize = MAX_REQUEST_SECTORS * SECTOR;

// Controller registers (AHCI 1.3.1 §3.1).
const CAP: usize = 0x00;
const GHC: usize = 0x04;
const PI: usize = 0x0c;
const VS: usize = 0x10;
const CAP2: usize = 0x24;
const BOHC: usize = 0x28;
const CAP_S64A: u32 = 1 << 31;
const GHC_AE: u32 = 1 << 31;
const GHC_IE: u32 = 1 << 1;
const CAP2_BOH: u32 = 1 << 0;
const BOHC_BOS: u32 = 1 << 0;
const BOHC_OOS: u32 = 1 << 1;
const BOHC_BB: u32 = 1 << 4;
const PORTS: usize = 0x100;
const PORT_LEN: usize = 0x80;

// Port registers (§3.3).
const P_CLB: usize = 0x00;
const P_FB: usize = 0x08;
const P_IS: usize = 0x10;
const P_IE: usize = 0x14;
const P_CMD: usize = 0x18;
const P_TFD: usize = 0x20;
const P_SIG: usize = 0x24;
const P_SSTS: usize = 0x28;
const P_SCTL: usize = 0x2c;
const P_SERR: usize = 0x30;
const P_CI: usize = 0x38;
const CMD_ST: u32 = 1 << 0;
const CMD_SUD: u32 = 1 << 1;
const CMD_POD: u32 = 1 << 2;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
/// Task file error, host bus fatal / data error, interface fatal error.
const IS_ERRORS: u32 = 1 << 30 | 1 << 29 | 1 << 28 | 1 << 27;
const TFD_BSY: u32 = 0x80;
const TFD_DRQ: u32 = 0x08;
const TFD_ERR: u32 = 0x01;
/// SStatus.DET: device present and communication established.
const DET_PRESENT: u32 = 3;
const SIG_ATA: u32 = 0x0000_0101;
const SIG_ATAPI: u32 = 0xeb14_0101;

// ATA commands (ATA8-ACS).
const ATA_IDENTIFY: u8 = 0xec;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_READ_DMA: u8 = 0xc8;
const ATA_WRITE_DMA: u8 = 0xca;
const ATA_FLUSH_EXT: u8 = 0xea;
const ATA_FLUSH: u8 = 0xe7;
const FIS_H2D: u32 = 0x27;
const FIS_C: u32 = 0x80; // the FIS carries a command
const DEV_LBA: u32 = 0x40;

const STOP_TIMEOUT: Duration = Duration::from_millis(500);
/// How long an empty-looking port is watched for a device after spin-up.
const DETECT_TIME: Duration = Duration::from_millis(50);
const LINK_TIMEOUT: Duration = Duration::from_secs(1);
/// A spinning disk may take seconds to spin up after power-on.
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const FLUSH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No usable memory BAR5 (ABAR).
    NoRegisters,
    /// A device that is not an ATA disk (its signature): ATAPI = CD/DVD.
    NotAta(u32),
    Unsupported(&'static str),
    Timeout(&'static str),
    /// The command failed: port interrupt status, task file data.
    Device { is: u32, tfd: u32 },
    BadRequest,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Error::NoRegisters => f.write_str("no ABAR"),
            Error::NotAta(SIG_ATAPI) => f.write_str("ATAPI (CD/DVD): not used"),
            Error::NotAta(s) => write!(f, "not an ATA disk (signature {s:#010x}): not used"),
            Error::Unsupported(w) => write!(f, "unsupported: {w}"),
            Error::Timeout(w) => write!(f, "timeout ({w})"),
            Error::Device { is, tfd } => write!(f, "command failed (IS {is:#010x}, TFD {tfd:#06x})"),
            Error::BadRequest => f.write_str("bad request"),
        }
    }
}

/// Is this PCI function an AHCI controller?
pub fn supports(dev: &PciDevice) -> bool {
    (dev.info.class, dev.info.subclass, dev.info.prog_if) == (0x01, 0x06, 0x01)
}

/// Take the controller from the firmware, switch it to AHCI mode, and set
/// up every implemented port that has a device: (port, its disk or why
/// not). Ports with nothing attached are left out.
pub async fn open_ports(dev: &PciDevice) -> Result<Vec<(u32, Result<Ahci, Error>)>, Error> {
    let bar = dev.bars[5]
        .filter(|b| b.size as usize >= PORTS)
        .ok_or(Error::NoRegisters)?;
    let abar = bar.addr as usize;
    // SAFETY: the generic host control registers at the start of BAR5 of
    // an AHCI controller, mapped as device memory by pci::init; the port
    // windows below are disjoint from it, and one controller is opened
    // once (store probe or installer, at boot).
    let mut hba = unsafe { Region::new(abar, PORTS) };
    // BIOS/OS hand-off (§10.6): ask for ownership, wait for the BIOS to
    // let go (25 ms, then up to 2 s while it reports busy).
    if hba.read32(CAP2) & CAP2_BOH != 0 && hba.read32(BOHC) & BOHC_BOS != 0 {
        hba.modify32(BOHC, |v| v | BOHC_OOS);
        let t0 = Instant::now();
        while hba.read32(BOHC) & BOHC_BOS != 0 {
            let busy = hba.read32(BOHC) & BOHC_BB != 0;
            let limit = if busy { Duration::from_secs(2) } else { Duration::from_millis(25) };
            if t0.elapsed() > limit {
                break; // take it anyway, as Linux does
            }
            crate::executor::yield_now().await;
        }
    }
    hba.modify32(GHC, |v| (v | GHC_AE) & !GHC_IE);
    let cap = hba.read32(CAP);
    let s64 = cap & CAP_S64A != 0;
    let vs = hba.read32(VS);
    let implemented = hba.read32(PI);
    let ports = ((bar.size as usize - PORTS) / PORT_LEN).min(32);
    let mut out = Vec::new();
    for p in 0..ports as u32 {
        if implemented & (1 << p) == 0 {
            continue;
        }
        let base = abar + PORTS + p as usize * PORT_LEN;
        // SAFETY: port `p`'s register window inside BAR5 (bounded by the
        // BAR's size above), disjoint from the controller's and the other
        // ports' windows; this Ahci is its only user.
        let regs = unsafe { Region::new(base, PORT_LEN) };
        let mut port = Ahci::new(regs, p, s64, vs);
        match port.init().await {
            Ok(true) => out.push((p, Ok(port))),
            Ok(false) => {} // nothing attached
            Err(e) => out.push((p, Err(e))),
        }
    }
    Ok(out)
}

pub struct Ahci {
    regs: Region,
    port: u32,
    s64: bool,
    clb: DmaRegion,
    fis: DmaRegion,
    table: DmaRegion,
    buf: DmaRegion,
    sectors: u64,
    lba48: bool,
    /// A command was issued and its caller dropped before it completed.
    in_progress: bool,
    /// For the log: port, model, serial, size, AHCI version.
    pub desc: String,
}

impl Ahci {
    fn new(regs: Region, port: u32, s64: bool, vs: u32) -> Self {
        Ahci {
            regs,
            port,
            s64,
            clb: DmaRegion::new(1024, 1024),
            fis: DmaRegion::new(256, 256),
            table: DmaRegion::new(256, 128),
            buf: DmaRegion::new(BUF, 4096),
            sectors: 0,
            lba48: false,
            in_progress: false,
            desc: format!("AHCI {}.{} port {port}", vs >> 16, (vs >> 8) & 0xff),
        }
    }

    pub fn capacity(&self) -> u64 {
        self.sectors
    }

    pub fn readonly(&self) -> bool {
        false
    }

    async fn wait(&mut self, reg: usize, mask: u32, want: u32, t: Duration, what: &'static str) -> Result<(), Error> {
        let t0 = Instant::now();
        while self.regs.read32(reg) & mask != want {
            if t0.elapsed() > t {
                return Err(Error::Timeout(what));
            }
            crate::executor::yield_now().await;
        }
        Ok(())
    }

    /// Stop command processing and FIS reception (§10.1.2).
    async fn stop(&mut self) -> Result<(), Error> {
        self.regs.modify32(P_CMD, |v| v & !CMD_ST);
        self.wait(P_CMD, CMD_CR, 0, STOP_TIMEOUT, "port stop").await?;
        self.regs.modify32(P_CMD, |v| v & !CMD_FRE);
        self.wait(P_CMD, CMD_FR, 0, STOP_TIMEOUT, "FIS receive stop").await
    }

    /// COMRESET (§10.4.2): DET = 1 for at least 1 ms, then wait for the
    /// link to come back.
    async fn comreset(&mut self) -> Result<(), Error> {
        self.regs.modify32(P_SCTL, |v| (v & !0xf) | 1);
        crate::timer::sleep(Duration::from_millis(2)).await;
        self.regs.modify32(P_SCTL, |v| v & !0xf);
        self.wait(P_SSTS, 0xf, DET_PRESENT, LINK_TIMEOUT, "link after COMRESET").await
    }

    /// Set the port up: `Ok(false)` if nothing is attached.
    async fn init(&mut self) -> Result<bool, Error> {
        if !self.s64 {
            let top = [&self.clb, &self.fis, &self.table, &self.buf]
                .iter()
                .map(|r| r.bus_addr() + r.len() as u64)
                .max()
                .unwrap_or(0);
            if top > 1 << 32 {
                return Err(Error::Unsupported("32-bit controller, buffers above 4 GiB"));
            }
        }
        self.stop().await?;
        let (clb, fis) = (self.clb.bus_addr(), self.fis.bus_addr());
        // 32-bit registers: base, then upper base (zero without S64A).
        self.regs.write32(P_CLB, clb as u32);
        self.regs.write32(P_CLB + 4, (clb >> 32) as u32);
        self.regs.write32(P_FB, fis as u32);
        self.regs.write32(P_FB + 4, (fis >> 32) as u32);
        self.regs.write32(P_IE, 0);
        self.regs.write32(P_SERR, 0xffff_ffff);
        self.regs.write32(P_IS, 0xffff_ffff);
        self.regs.modify32(P_CMD, |v| v | CMD_FRE | CMD_SUD | CMD_POD);
        // SStatus.DET: 0 = no device, 1 = device but no link, 3 = ready.
        // A device's presence shows within milliseconds of spin-up; an
        // empty port stays 0 and is left at once (no COMRESET: a
        // controller with six empty ports must not cost seconds of boot).
        let t0 = Instant::now();
        while self.regs.read32(P_SSTS) & 0xf == 0 && t0.elapsed() < DETECT_TIME {
            crate::executor::yield_now().await;
        }
        let det = self.regs.read32(P_SSTS) & 0xf;
        if det == 0 {
            self.regs.modify32(P_CMD, |v| v & !CMD_FRE);
            return Ok(false);
        }
        if det != DET_PRESENT {
            // A device without a link (left asleep, or a cold link): one
            // COMRESET; still no link = treated as empty.
            if self.comreset().await.is_err() {
                self.regs.modify32(P_CMD, |v| v & !CMD_FRE);
                return Ok(false);
            }
        }
        self.wait(P_TFD, TFD_BSY | TFD_DRQ, 0, READY_TIMEOUT, "device ready").await?;
        self.regs.write32(P_SERR, 0xffff_ffff);
        let sig = self.regs.read32(P_SIG);
        if sig != SIG_ATA {
            return Err(Error::NotAta(sig));
        }
        self.regs.modify32(P_CMD, |v| v | CMD_ST);
        self.identify().await?;
        Ok(true)
    }

    async fn identify(&mut self) -> Result<(), Error> {
        self.run(ATA_IDENTIFY, 0, 0, false, SECTOR, IO_TIMEOUT, "IDENTIFY").await?;
        let mut id = vec![0u8; SECTOR];
        self.buf.copy_out(0, &mut id);
        let w = |i: usize| u16::from_le_bytes([id[2 * i], id[2 * i + 1]]);
        // ATA strings: two characters per word, the first in the high byte.
        let text = |from: usize, to: usize| {
            let s: String = (from..to)
                .flat_map(|i| [(w(i) >> 8) as u8, w(i) as u8])
                .map(|b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '?' })
                .collect();
            String::from(s.trim())
        };
        let logical = w(106);
        if logical & 0xc000 == 0x4000 && logical & (1 << 12) != 0 {
            let words = w(117) as u32 | (w(118) as u32) << 16;
            if words != 256 {
                return Err(Error::Unsupported("logical sectors other than 512 bytes"));
            }
        }
        self.lba48 = w(83) & (1 << 10) != 0;
        self.sectors = if self.lba48 {
            (0..4).fold(0u64, |acc, i| acc | (w(100 + i) as u64) << (16 * i))
        } else {
            w(60) as u64 | (w(61) as u64) << 16
        };
        if self.sectors == 0 {
            return Err(Error::Unsupported("no LBA capacity"));
        }
        self.desc = format!(
            "SATA port {}: {} (serial {}), {} MiB{}",
            self.port,
            text(27, 47),
            text(10, 20),
            self.sectors >> 11,
            if self.lba48 { "" } else { ", LBA28" }
        );
        Ok(())
    }

    /// After an error, a timeout or an abandoned command: stop the port,
    /// clear its errors, reset the link if the device stays busy, start
    /// again (§6.2.2).
    async fn recover(&mut self) -> Result<(), Error> {
        let stopped = self.stop().await;
        self.regs.write32(P_SERR, 0xffff_ffff);
        self.regs.write32(P_IS, 0xffff_ffff);
        if stopped.is_err() || self.regs.read32(P_TFD) & (TFD_BSY | TFD_DRQ) != 0 {
            self.comreset().await?;
            self.wait(P_TFD, TFD_BSY | TFD_DRQ, 0, READY_TIMEOUT, "device ready").await?;
            self.regs.write32(P_SERR, 0xffff_ffff);
        }
        self.regs.modify32(P_CMD, |v| v | CMD_FRE);
        self.wait(P_CMD, CMD_FR, CMD_FR, STOP_TIMEOUT, "FIS receive start").await?;
        self.regs.modify32(P_CMD, |v| v | CMD_ST);
        self.in_progress = false;
        Ok(())
    }

    /// Issue one command in slot 0 and wait for it: `bytes` (≤ 64 KiB)
    /// move between the device and the data buffer.
    #[allow(clippy::too_many_arguments)]
    async fn run(
        &mut self,
        cmd: u8,
        lba: u64,
        count: u16,
        write: bool,
        bytes: usize,
        timeout: Duration,
        what: &'static str,
    ) -> Result<(), Error> {
        if self.in_progress {
            self.recover().await?;
        }
        // Command header 0 (§4.2.2): FIS length 5 dwords, direction, one
        // PRD if there is data, the command table's address.
        let prdtl = u32::from(bytes > 0);
        self.clb.write32(0, 5 | u32::from(write) << 6 | prdtl << 16);
        self.clb.write32(4, 0); // bytes transferred, set by the HBA
        self.clb.write64(8, self.table.bus_addr());
        for off in (16..32).step_by(8) {
            self.clb.write64(off, 0);
        }
        // Register H2D FIS (§4.2.3, SATA 10.5.5).
        let lba28 = !matches!(cmd, ATA_READ_DMA_EXT | ATA_WRITE_DMA_EXT | ATA_FLUSH_EXT);
        let device = match cmd {
            ATA_IDENTIFY | ATA_FLUSH | ATA_FLUSH_EXT => 0,
            _ if lba28 => DEV_LBA | ((lba >> 24) as u32 & 0xf),
            _ => DEV_LBA,
        };
        for off in (0..0x80).step_by(8) {
            self.table.write64(off, 0);
        }
        self.table.write32(0, FIS_H2D | FIS_C << 8 | (cmd as u32) << 16);
        self.table.write32(4, (lba as u32 & 0xff_ffff) | device << 24);
        self.table.write32(8, (lba >> 24) as u32 & 0xff_ffff);
        self.table.write32(12, count as u32);
        if bytes > 0 {
            // PRD 0 (§4.2.3.3): data base address, byte count - 1, no
            // interrupt on completion.
            self.table.write64(0x80, self.buf.bus_addr());
            self.table.write32(0x88, 0);
            self.table.write32(0x8c, (bytes - 1) as u32);
        }
        self.regs.write32(P_IS, 0xffff_ffff);
        self.wait(P_TFD, TFD_BSY | TFD_DRQ, 0, IO_TIMEOUT, "device ready").await?;
        // The command list and table are written before the HBA reads them.
        fence(Ordering::SeqCst);
        self.in_progress = true;
        self.regs.write32(P_CI, 1);
        let t0 = Instant::now();
        loop {
            let is = self.regs.read32(P_IS);
            if is & IS_ERRORS != 0 {
                let tfd = self.regs.read32(P_TFD);
                self.recover().await?;
                return Err(Error::Device { is, tfd });
            }
            if self.regs.read32(P_CI) & 1 == 0 {
                break;
            }
            if t0.elapsed() > timeout {
                self.recover().await?;
                return Err(Error::Timeout(what));
            }
            crate::executor::yield_now().await;
        }
        fence(Ordering::SeqCst);
        self.in_progress = false;
        let tfd = self.regs.read32(P_TFD);
        if tfd & TFD_ERR != 0 {
            let is = self.regs.read32(P_IS);
            self.recover().await?;
            return Err(Error::Device { is, tfd });
        }
        Ok(())
    }

    fn check(&self, lba: u64, sectors: usize) -> Result<(), Error> {
        let end = lba.checked_add(sectors as u64).ok_or(Error::BadRequest)?;
        if sectors == 0 || sectors > MAX_REQUEST_SECTORS || end > self.sectors {
            return Err(Error::BadRequest);
        }
        Ok(())
    }

    pub async fn read(&mut self, lba: u64, sectors: usize) -> Result<Vec<u8>, Error> {
        self.check(lba, sectors)?;
        let cmd = if self.lba48 { ATA_READ_DMA_EXT } else { ATA_READ_DMA };
        let bytes = sectors * SECTOR;
        self.run(cmd, lba, sectors as u16, false, bytes, IO_TIMEOUT, "read").await?;
        let mut out = vec![0u8; bytes];
        self.buf.copy_out(0, &mut out);
        Ok(out)
    }

    pub async fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), Error> {
        if !data.len().is_multiple_of(SECTOR) {
            return Err(Error::BadRequest);
        }
        let sectors = data.len() / SECTOR;
        self.check(lba, sectors)?;
        self.buf.copy_in(0, data);
        let cmd = if self.lba48 { ATA_WRITE_DMA_EXT } else { ATA_WRITE_DMA };
        self.run(cmd, lba, sectors as u16, true, data.len(), IO_TIMEOUT, "write").await
    }

    /// Make completed writes durable: the disk's write cache to the medium.
    pub async fn flush(&mut self) -> Result<(), Error> {
        let cmd = if self.lba48 { ATA_FLUSH_EXT } else { ATA_FLUSH };
        self.run(cmd, 0, 0, false, 0, FLUSH_TIMEOUT, "flush").await
    }
}
