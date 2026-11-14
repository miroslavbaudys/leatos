//! SD card behind a standard SD host controller (SDHCI 2.0/3.0, PCI class
//! 08:05): the apu4's SD slot (AMD FCH), and QEMU's `sdhci-pci` +
//! `sd-card` for tests. The store disk (docs/config-and-storage.md §7).
//!
//! - **PIO, polled:** data moves through the buffer data port, 32 bits at
//!   a time; no DMA, no interrupts (signal enables stay 0). The only
//!   `unsafe` is the register window's constructor.
//! - **Never blocks the datapath:** every wait polls a status bit and
//!   yields to the executor in between (the store runs in the services
//!   task); at boot the same code runs under `executor::block_on`.
//! - **Cards:** SD v1 (SDSC, byte addressing) and v2 (SDSC, SDHC/SDXC
//!   with block addressing), 4-bit bus, default speed (25 MHz). Reads and
//!   writes of up to [`MAX_REQUEST_SECTORS`] go as one multi-block command
//!   with Auto CMD12.
//! - **Cancellation:** a caller dropped mid-transfer leaves the controller
//!   mid-command; the next operation sees `in_progress` and resets the
//!   command and data lines (and stops the card) first.
//!
//! All register accesses are 32-bit (SDHCI allows any width); byte and
//! half-word registers are updated by read-modify-write of their word.

use crate::mmio::Region;
use crate::pci::PciDevice;
use crate::timer::Instant;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

/// Largest single request, in sectors (64 KiB), as for virtio-blk.
pub const MAX_REQUEST_SECTORS: usize = 128;
const SECTOR: usize = 512;

// Register word offsets (SD Host Controller Simplified Specification 3.00).
const BLOCK: usize = 0x04; // block size (15:0), block count (31:16)
const ARG: usize = 0x08;
const CMD: usize = 0x0c; // transfer mode (15:0), command (31:16)
const RESP: usize = 0x10; // 4 words
const DATA: usize = 0x20;
const PRESENT: usize = 0x24;
const HOST: usize = 0x28; // host control 1 (7:0), power control (15:8)
const CLOCK: usize = 0x2c; // clock (15:0), timeout (23:16), software reset (31:24)
const INT_STATUS: usize = 0x30; // normal (15:0), error (31:16), write 1 to clear
const INT_ENABLE: usize = 0x34; // status enables, same layout
const INT_SIGNAL: usize = 0x38; // interrupt signal enables: stay 0 (polled)
const CAPS: usize = 0x40;
const VERSION: usize = 0xfc; // host controller version in bits 23:16

const PRESENT_CMD_INHIBIT: u32 = 1 << 0;
const PRESENT_DAT_INHIBIT: u32 = 1 << 1;
const PRESENT_CARD: u32 = 1 << 16;
const PRESENT_WRITE_ENABLED: u32 = 1 << 19;

const HOST_4BIT: u32 = 1 << 1;
const HOST_CD_TEST_LEVEL: u32 = 1 << 6;
const HOST_CD_TEST_SELECT: u32 = 1 << 7;
const POWER_33V_ON: u32 = (0b111 << 1 | 1) << 8;

const CLOCK_INTERNAL_ENABLE: u32 = 1 << 0;
const CLOCK_INTERNAL_STABLE: u32 = 1 << 1;
const CLOCK_SD_ENABLE: u32 = 1 << 2;
const RESET_ALL: u32 = 1 << 24;
const RESET_CMD: u32 = 1 << 25;
const RESET_DAT: u32 = 1 << 26;

const INT_CMD_COMPLETE: u32 = 1 << 0;
const INT_XFER_COMPLETE: u32 = 1 << 1;
const INT_BUF_WRITE_READY: u32 = 1 << 4;
const INT_BUF_READ_READY: u32 = 1 << 5;
const INT_ERROR: u32 = 1 << 15;
const ERR_CMD_TIMEOUT: u32 = 1 << 16;

// Transfer mode.
const TM_BLOCK_COUNT: u32 = 1 << 1;
const TM_AUTO_CMD12: u32 = 1 << 2;
const TM_READ: u32 = 1 << 4;
const TM_MULTI: u32 = 1 << 5;

// Command register: response type and checks.
const RESP_NONE: u32 = 0;
const RESP_136: u32 = 1;
const RESP_48: u32 = 2;
const RESP_48_BUSY: u32 = 3;
const CHECK_CRC: u32 = 1 << 3;
const CHECK_INDEX: u32 = 1 << 4;
const DATA_PRESENT: u32 = 1 << 5;
const R1: u32 = RESP_48 | CHECK_CRC | CHECK_INDEX;
const R1B: u32 = RESP_48_BUSY | CHECK_CRC | CHECK_INDEX;
const R2: u32 = RESP_136 | CHECK_CRC;
const R3: u32 = RESP_48;
const R6: u32 = R1;
const R7: u32 = R1;

const CMD_TIMEOUT: Duration = Duration::from_millis(500);
const READ_TIMEOUT: Duration = Duration::from_secs(1);
/// SD cards may take up to 250 ms per block to program (spec), longer
/// for erase-before-write on cheap cards.
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
const INIT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No usable memory BAR.
    NoRegisters,
    NoCard,
    /// Card initialisation failed at this step.
    Init(&'static str),
    /// The controller reported errors (error interrupt status bits).
    Controller(u16),
    Timeout(&'static str),
    BadRequest,
    ReadOnly,
}

/// Does this PCI function look like a standard SD host controller?
pub fn supports(dev: &PciDevice) -> bool {
    dev.info.class == 0x08 && dev.info.subclass == 0x05 && dev.info.prog_if <= 1
}

pub struct Sdhci {
    regs: Region,
    version: u8,
    base_hz: u64,
    rca: u32,
    /// SDHC/SDXC: block addresses; SDSC: byte addresses.
    block_addressing: bool,
    sectors: u64,
    readonly: bool,
    /// An operation started and did not finish (its caller was dropped).
    in_progress: bool,
    /// For the log: card type and size, controller version.
    pub desc: String,
}

impl Sdhci {
    /// Reset the controller and initialise the card in the slot.
    pub async fn new(dev: &PciDevice) -> Result<Self, Error> {
        let bar = dev
            .bars
            .first()
            .copied()
            .flatten()
            .filter(|b| b.size >= 0x100)
            .ok_or(Error::NoRegisters)?;
        // SAFETY: BAR0 of an SD host controller, mapped as device memory by
        // pci::init; this driver is its only user (one Sdhci per function).
        let regs = unsafe { Region::new(bar.addr as usize, 0x100) };
        let mut s = Sdhci {
            regs,
            version: 0,
            base_hz: 0,
            rca: 0,
            block_addressing: false,
            sectors: 0,
            readonly: true,
            in_progress: false,
            desc: String::new(),
        };
        s.init().await?;
        Ok(s)
    }

    pub fn capacity(&self) -> u64 {
        self.sectors
    }

    pub fn readonly(&self) -> bool {
        self.readonly
    }

    async fn init(&mut self) -> Result<(), Error> {
        self.regs.modify32(CLOCK, |v| v | RESET_ALL);
        self.wait_reg(CLOCK, RESET_ALL, 0, "reset").await?;
        self.version = (self.regs.read32(VERSION) >> 16) as u8;
        let caps = self.regs.read32(CAPS);
        // Base clock in MHz: 8 bits from version 3.00 on, 6 bits before.
        let mhz = if self.version >= 2 {
            (caps >> 8) & 0xff
        } else {
            (caps >> 8) & 0x3f
        };
        self.base_hz = if mhz == 0 { 50 } else { mhz as u64 } * 1_000_000;

        // Some boards don't wire card detect: force "inserted" and let
        // the commands tell whether a card answers.
        if self.regs.read32(PRESENT) & PRESENT_CARD == 0 {
            self.regs
                .modify32(HOST, |v| v | HOST_CD_TEST_SELECT | HOST_CD_TEST_LEVEL);
        }
        self.regs.modify32(HOST, |v| (v & !0xff00) | POWER_33V_ON);
        self.regs.write32(INT_SIGNAL, 0);
        self.regs.write32(
            INT_ENABLE,
            0xffff_0000
                | INT_CMD_COMPLETE
                | INT_XFER_COMPLETE
                | INT_BUF_WRITE_READY
                | INT_BUF_READ_READY,
        );
        self.regs.write32(INT_STATUS, 0xffff_ffff);
        self.set_clock(400_000).await?;
        // Data timeout: the largest counter value.
        self.regs
            .modify32(CLOCK, |v| (v & !0x00ff_0000) | (0x0e << 16));
        // The card needs 74 clocks (185 µs at 400 kHz) after power-up.
        spin(Duration::from_millis(2));

        self.cmd(0, 0, RESP_NONE, 0).await.map_err(|e| match e {
            Error::Controller(_) | Error::Timeout(_) => Error::NoCard,
            e => e,
        })?;
        // CMD8: only v2 cards answer; v1 cards time out.
        let v2 = match self.cmd(8, 0x1aa, R7, 0).await {
            Ok(r) if r[0] & 0xfff == 0x1aa => true,
            Ok(_) => return Err(Error::Init("CMD8 echo")),
            Err(_) => {
                self.reset_lines().await;
                false
            }
        };
        let t0 = Instant::now();
        let ocr = loop {
            self.cmd(55, 0, R1, 0).await.map_err(|_| Error::NoCard)?;
            // 3.2–3.4 V; HCS (bit 30): we handle block addressing.
            let arg = 0x0030_0000 | if v2 { 1 << 30 } else { 0 };
            let r = self.cmd(41, arg, R3, 0).await.map_err(|_| Error::NoCard)?;
            if r[0] & 1 << 31 != 0 {
                break r[0];
            }
            if t0.elapsed() > INIT_TIMEOUT {
                return Err(Error::Timeout("ACMD41 (card busy)"));
            }
            sleep_yield(Duration::from_millis(10)).await;
        };
        self.block_addressing = v2 && ocr & 1 << 30 != 0;
        self.cmd(2, 0, R2, 0)
            .await
            .map_err(|_| Error::Init("CMD2"))?;
        let r = self
            .cmd(3, 0, R6, 0)
            .await
            .map_err(|_| Error::Init("CMD3"))?;
        self.rca = r[0] >> 16;
        let csd = self
            .cmd(9, self.rca << 16, R2, 0)
            .await
            .map_err(|_| Error::Init("CMD9"))?;
        self.sectors = csd_sectors(&csd).ok_or(Error::Init("CSD"))?;
        self.cmd(7, self.rca << 16, R1B, 0)
            .await
            .map_err(|_| Error::Init("CMD7"))?;
        if !self.block_addressing {
            self.cmd(16, SECTOR as u32, R1, 0)
                .await
                .map_err(|_| Error::Init("CMD16"))?;
        }
        // 4-bit bus: ACMD6 with argument 2.
        self.cmd(55, self.rca << 16, R1, 0)
            .await
            .map_err(|_| Error::Init("CMD55"))?;
        self.cmd(6, 2, R1, 0)
            .await
            .map_err(|_| Error::Init("ACMD6"))?;
        self.regs.modify32(HOST, |v| v | HOST_4BIT);
        self.set_clock(25_000_000).await?;
        self.readonly = self.regs.read32(PRESENT) & PRESENT_WRITE_ENABLED == 0;
        let kind = match (v2, self.block_addressing) {
            (_, true) if self.sectors > 64 << 21 => "SDXC",
            (_, true) => "SDHC",
            (true, false) => "SDSC v2",
            (false, false) => "SDSC v1",
        };
        self.desc = format!(
            "{kind} {} MiB{}, SDHCI {}.00, base clock {} MHz",
            self.sectors >> 11,
            if self.readonly {
                ", write-protected"
            } else {
                ""
            },
            self.version as u32 + 1,
            self.base_hz / 1_000_000
        );
        Ok(())
    }

    /// SD clock at most `hz`: divided base clock (10-bit divider from
    /// version 3.00 on; powers of two before).
    async fn set_clock(&mut self, hz: u64) -> Result<(), Error> {
        self.regs.modify32(CLOCK, |v| v & !0xffff);
        let n = if self.base_hz <= hz {
            0
        } else if self.version >= 2 {
            self.base_hz.div_ceil(2 * hz).min(1023)
        } else {
            self.base_hz.div_ceil(2 * hz).next_power_of_two().min(128)
        } as u32;
        let field = (n & 0xff) << 8 | ((n >> 8) & 3) << 6;
        self.regs
            .modify32(CLOCK, |v| v | field | CLOCK_INTERNAL_ENABLE);
        self.wait_reg(CLOCK, CLOCK_INTERNAL_STABLE, CLOCK_INTERNAL_STABLE, "clock")
            .await?;
        self.regs.modify32(CLOCK, |v| v | CLOCK_SD_ENABLE);
        Ok(())
    }

    /// Wait until `reg & mask == want`.
    async fn wait_reg(
        &mut self,
        reg: usize,
        mask: u32,
        want: u32,
        what: &'static str,
    ) -> Result<(), Error> {
        let t0 = Instant::now();
        while self.regs.read32(reg) & mask != want {
            if t0.elapsed() > CMD_TIMEOUT {
                return Err(Error::Timeout(what));
            }
            crate::executor::yield_now().await;
        }
        Ok(())
    }

    /// Wait for one of `mask` in the normal interrupt status and clear it;
    /// an error interrupt ends the wait with the error bits.
    async fn wait_int(
        &mut self,
        mask: u32,
        timeout: Duration,
        what: &'static str,
    ) -> Result<(), Error> {
        let t0 = Instant::now();
        loop {
            let st = self.regs.read32(INT_STATUS);
            if st & INT_ERROR != 0 {
                self.regs
                    .write32(INT_STATUS, st & (0xffff_0000 | INT_ERROR));
                return Err(Error::Controller((st >> 16) as u16));
            }
            if st & mask != 0 {
                self.regs.write32(INT_STATUS, st & mask);
                return Ok(());
            }
            if t0.elapsed() > timeout {
                return Err(Error::Timeout(what));
            }
            crate::executor::yield_now().await;
        }
    }

    /// Issue one command; returns the response words. With `R1B`, also
    /// waits for the card to leave busy.
    async fn cmd(
        &mut self,
        index: u32,
        arg: u32,
        flags: u32,
        mode: u32,
    ) -> Result<[u32; 4], Error> {
        let mut inhibit = PRESENT_CMD_INHIBIT;
        if flags & DATA_PRESENT != 0 || flags & 3 == RESP_48_BUSY {
            inhibit |= PRESENT_DAT_INHIBIT;
        }
        self.wait_reg(PRESENT, inhibit, 0, "command inhibit")
            .await?;
        self.regs.write32(INT_STATUS, 0xffff_ffff);
        self.regs.write32(ARG, arg);
        self.regs.write32(CMD, (index << 8 | flags) << 16 | mode);
        let r = self
            .wait_int(INT_CMD_COMPLETE, CMD_TIMEOUT, "command")
            .await;
        if let Err(e) = r {
            if let Error::Controller(bits) = e
                && bits as u32 & (ERR_CMD_TIMEOUT >> 16) != 0
            {
                return Err(Error::Timeout("no response"));
            }
            return Err(e);
        }
        let resp = [
            self.regs.read32(RESP),
            self.regs.read32(RESP + 4),
            self.regs.read32(RESP + 8),
            self.regs.read32(RESP + 12),
        ];
        if flags & 3 == RESP_48_BUSY {
            self.wait_int(INT_XFER_COMPLETE, WRITE_TIMEOUT, "busy")
                .await?;
        }
        Ok(resp)
    }

    /// Reset the command and data lines and clear the status.
    async fn reset_lines(&mut self) {
        self.regs.modify32(CLOCK, |v| v | RESET_CMD | RESET_DAT);
        let _ = self
            .wait_reg(CLOCK, RESET_CMD | RESET_DAT, 0, "line reset")
            .await;
        self.regs.write32(INT_STATUS, 0xffff_ffff);
    }

    /// After a failed or abandoned transfer: reset the lines and stop the
    /// card (CMD12), so it is back in the transfer state.
    async fn recover(&mut self) {
        self.reset_lines().await;
        let _ = self.cmd(12, 0, R1B, 0).await;
        self.reset_lines().await;
        self.in_progress = false;
    }

    fn check(&self, lba: u64, sectors: usize) -> Result<(), Error> {
        let ok = (1..=MAX_REQUEST_SECTORS).contains(&sectors)
            && lba
                .checked_add(sectors as u64)
                .is_some_and(|end| end <= self.sectors);
        if ok { Ok(()) } else { Err(Error::BadRequest) }
    }

    fn start(&mut self, lba: u64, sectors: usize, read: bool) -> (u32, u32, u32) {
        self.regs
            .write32(BLOCK, (sectors as u32) << 16 | SECTOR as u32);
        let addr = if self.block_addressing {
            lba
        } else {
            lba * SECTOR as u64
        } as u32;
        let multi = sectors > 1;
        let mut mode = if read { TM_READ } else { 0 };
        if multi {
            mode |= TM_MULTI | TM_BLOCK_COUNT | TM_AUTO_CMD12;
        }
        let index = match (read, multi) {
            (true, false) => 17,
            (true, true) => 18,
            (false, false) => 24,
            (false, true) => 25,
        };
        (index, addr, mode)
    }

    pub async fn read(&mut self, lba: u64, sectors: usize) -> Result<Vec<u8>, Error> {
        self.check(lba, sectors)?;
        if self.in_progress {
            self.recover().await;
        }
        self.in_progress = true;
        let r = self.read_inner(lba, sectors).await;
        if r.is_err() {
            self.recover().await;
        }
        self.in_progress = false;
        r
    }

    async fn read_inner(&mut self, lba: u64, sectors: usize) -> Result<Vec<u8>, Error> {
        let (index, addr, mode) = self.start(lba, sectors, true);
        self.cmd(index, addr, R1 | DATA_PRESENT, mode).await?;
        let mut out = Vec::with_capacity(sectors * SECTOR);
        for _ in 0..sectors {
            self.wait_int(INT_BUF_READ_READY, READ_TIMEOUT, "read data")
                .await?;
            for _ in 0..SECTOR / 4 {
                out.extend_from_slice(&self.regs.read32(DATA).to_le_bytes());
            }
        }
        self.wait_int(INT_XFER_COMPLETE, READ_TIMEOUT, "read complete")
            .await?;
        Ok(out)
    }

    /// Write whole sectors. Done when the card has programmed them.
    pub async fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), Error> {
        if self.readonly {
            return Err(Error::ReadOnly);
        }
        if !data.len().is_multiple_of(SECTOR) {
            return Err(Error::BadRequest);
        }
        let sectors = data.len() / SECTOR;
        self.check(lba, sectors)?;
        if self.in_progress {
            self.recover().await;
        }
        self.in_progress = true;
        let r = self.write_inner(lba, data).await;
        if r.is_err() {
            self.recover().await;
        }
        self.in_progress = false;
        r
    }

    async fn write_inner(&mut self, lba: u64, data: &[u8]) -> Result<(), Error> {
        let (index, addr, mode) = self.start(lba, data.len() / SECTOR, false);
        self.cmd(index, addr, R1 | DATA_PRESENT, mode).await?;
        for block in data.chunks(SECTOR) {
            self.wait_int(INT_BUF_WRITE_READY, WRITE_TIMEOUT, "write buffer")
                .await?;
            for w in block.chunks(4) {
                self.regs
                    .write32(DATA, u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
            }
        }
        // Signalled once the card left busy (programmed the data).
        self.wait_int(INT_XFER_COMPLETE, WRITE_TIMEOUT, "write complete")
            .await
    }
}

/// Card size in sectors from the CSD (an R2 response: bits 127:8 of the
/// CSD, CRC stripped, so CSD bit `b` is response bit `b - 8`).
fn csd_sectors(r: &[u32; 4]) -> Option<u64> {
    let v = (r[3] as u128) << 96 | (r[2] as u128) << 64 | (r[1] as u128) << 32 | r[0] as u128;
    let bits = |hi: u32, lo: u32| ((v >> (lo - 8)) & ((1u128 << (hi - lo + 1)) - 1)) as u64;
    match bits(127, 126) {
        // CSD 1.0 (SDSC): (C_SIZE + 1) << (C_SIZE_MULT + 2) blocks of
        // 2^READ_BL_LEN bytes.
        0 => {
            let bytes = (bits(73, 62) + 1) << (bits(49, 47) + 2) << bits(83, 80);
            Some(bytes / SECTOR as u64)
        }
        // CSD 2.0 (SDHC/SDXC): (C_SIZE + 1) × 512 KiB.
        1 => Some((bits(69, 48) + 1) * 1024),
        _ => None,
    }
}

/// Busy-wait (only during init, before the card is usable).
fn spin(d: Duration) {
    let t0 = Instant::now();
    while t0.elapsed() < d {
        core::hint::spin_loop();
    }
}

/// Wait `d`, letting other tasks run.
async fn sleep_yield(d: Duration) {
    let t0 = Instant::now();
    while t0.elapsed() < d {
        crate::executor::yield_now().await;
    }
}
