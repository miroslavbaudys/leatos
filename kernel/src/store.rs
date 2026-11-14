//! The persistent store (docs/config-and-storage.md): the raw MBR
//! partition of type 0xda on a block device, holding A/B records per area.
//!
//! The format, slot choice and write plan are in `crates/config-store`;
//! this module only moves sectors between it and the disk
//! (`drivers::virtio_blk`). Reads at boot run through
//! `executor::block_on`; writes run in the services task and yield while
//! the disk works, so they never block the datapath.
//!
//! **Safety rules:** a disk is used only if its MBR has a 0xda partition
//! **and** that partition starts with a valid store header. The kernel
//! never formats (only `rrstore`, the host tool, does), and every access is
//! checked to lie inside the partition.

use crate::drivers::virtio_blk::{self, MAX_REQUEST_SECTORS, VirtioBlk};
use crate::executor::block_on;
use crate::pci::Pci;
use crate::println;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use config_store::{Area, AreaState, Layout, RecordHeader, SECTOR, Slot, SlotState, mbr};

#[derive(Debug)]
pub enum Error {
    Disk(virtio_blk::Error),
    /// The area does not exist in this store's layout.
    NoArea(&'static str),
    Plan(config_store::Error),
    /// A sector range outside the store partition (a bug: never sent).
    OutOfRange,
    /// The record read back after a write is not the one written.
    Verify,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Disk(e) => write!(f, "disk error: {e:?}"),
            Error::NoArea(a) => write!(f, "store has no area '{a}'"),
            Error::Plan(e) => write!(f, "{e:?}"),
            Error::OutOfRange => f.write_str("access outside the store partition"),
            Error::Verify => f.write_str("read-back after the write does not match"),
        }
    }
}

impl From<virtio_blk::Error> for Error {
    fn from(e: virtio_blk::Error) -> Self {
        Error::Disk(e)
    }
}

/// The current record of an area.
pub struct Record {
    pub slot: Slot,
    pub header: RecordHeader,
    pub payload: Vec<u8>,
}

pub struct Store {
    disk: VirtioBlk,
    /// First sector of the partition on the disk, and its length.
    base: u64,
    sectors: u64,
    layout: Layout,
}

/// Find the store: the first virtio-blk device with a store partition and
/// a valid store header. Logs what it finds on every block device.
pub fn open(pci: &mut Pci) -> Option<Store> {
    let devs: Vec<_> = pci
        .devices
        .iter()
        .filter(|d| d.is_virtio_blk())
        .cloned()
        .collect();
    if devs.is_empty() {
        println!("  store           : none (no block device)");
    }
    for dev in devs {
        let disk = match VirtioBlk::new(pci, &dev) {
            Ok(d) => d,
            Err(e) => {
                println!(
                    "  store           : virtio-blk {}: init failed: {e:?}",
                    dev.df
                );
                continue;
            }
        };
        match probe(disk) {
            Ok(s) => {
                let names: Vec<_> = s.layout.areas().iter().map(|a| a.name()).collect();
                println!(
                    "  store           : virtio-blk {}, partition at LBA {}, {} MiB, areas {}",
                    dev.df,
                    s.base,
                    s.sectors >> 11,
                    names.join(", ")
                );
                return Some(s);
            }
            Err(why) => println!("  store           : virtio-blk {}: {why}, not used", dev.df),
        }
    }
    None
}

fn probe(mut disk: VirtioBlk) -> Result<Store, String> {
    if disk.readonly() {
        return Err(String::from("read-only"));
    }
    let mbr = block_on(disk.read(0, 1)).map_err(|e| format!("reading the MBR: {e:?}"))?;
    let part = mbr::find_store(&mbr).ok_or_else(|| {
        format!(
            "no store partition (MBR type {:#04x})",
            mbr::STORE_PARTITION_TYPE
        )
    })?;
    let (base, sectors) = (part.first_lba as u64, part.sectors as u64);
    if base + sectors > disk.capacity() {
        return Err(String::from("store partition extends past the disk"));
    }
    let hdr =
        block_on(disk.read(base, 1)).map_err(|e| format!("reading the store header: {e:?}"))?;
    let layout = Layout::parse(&hdr, sectors)
        .map_err(|e| format!("store header invalid ({e:?}): not formatted"))?;
    Ok(Store {
        disk,
        base,
        sectors,
        layout,
    })
}

impl Store {
    fn area(&self, name: &'static str) -> Result<Area, Error> {
        self.layout.area(name).copied().ok_or(Error::NoArea(name))
    }

    fn range(&self, lba: u64, sectors: u64) -> Result<u64, Error> {
        match lba.checked_add(sectors) {
            Some(end) if end <= self.sectors => Ok(self.base + lba),
            _ => Err(Error::OutOfRange),
        }
    }

    /// Read `sectors` sectors at partition-relative `lba`.
    async fn read(&mut self, lba: u64, sectors: u64) -> Result<Vec<u8>, Error> {
        let at = self.range(lba, sectors)?;
        let mut out = Vec::with_capacity(sectors as usize * SECTOR);
        let mut done = 0;
        while done < sectors {
            let n = (sectors - done).min(MAX_REQUEST_SECTORS as u64);
            out.extend(self.disk.read(at + done, n as usize).await?);
            done += n;
        }
        Ok(out)
    }

    /// Write whole sectors at partition-relative `lba`.
    async fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), Error> {
        let at = self.range(lba, (data.len() / SECTOR) as u64)?;
        for (i, chunk) in data.chunks(MAX_REQUEST_SECTORS * SECTOR).enumerate() {
            let lba = at + (i * MAX_REQUEST_SECTORS) as u64;
            self.disk.write(lba, chunk.to_vec()).await?;
        }
        Ok(())
    }

    /// One slot from its header sector through its payload (only the
    /// header sector if it is not a valid record header).
    async fn read_slot(&mut self, area: &Area, slot: Slot) -> Result<Vec<u8>, Error> {
        let lba = area.slot_lba(slot);
        let mut buf = self.read(lba, 1).await?;
        if let Ok(h) = RecordHeader::parse(area, &buf)
            && h.payload_sectors() > 0
        {
            buf.extend(self.read(lba + 1, h.payload_sectors()).await?);
        }
        Ok(buf)
    }

    async fn state(&mut self, area: &Area) -> Result<(AreaState, [Vec<u8>; 2]), Error> {
        let a = self.read_slot(area, Slot::A).await?;
        let b = self.read_slot(area, Slot::B).await?;
        Ok((AreaState::from_slots(area, &a, &b), [a, b]))
    }

    /// The current record of `name` (newest valid one with a schema version
    /// up to `max_version`), and both slots' states for the log.
    pub async fn read_current(
        &mut self,
        name: &'static str,
        max_version: u32,
    ) -> Result<(Option<Record>, AreaState), Error> {
        let area = self.area(name)?;
        let (state, mut slots) = self.state(&area).await?;
        let rec = state.current(max_version).map(|(slot, header)| {
            let mut buf = core::mem::take(&mut slots[slot_index(slot)]);
            buf.drain(..SECTOR);
            buf.truncate(header.len as usize);
            Record {
                slot,
                header,
                payload: buf,
            }
        });
        Ok((rec, state))
    }

    /// Write a new record into the slot that is not current
    /// (docs/config-and-storage.md §4): payload, flush, header, flush, then
    /// read the slot back and check it. The slots are re-read first, so the
    /// plan never rests on stale state.
    pub async fn write_record(
        &mut self,
        name: &'static str,
        version: u32,
        max_version: u32,
        payload: &[u8],
    ) -> Result<(Slot, RecordHeader), Error> {
        let area = self.area(name)?;
        let (state, _) = self.state(&area).await?;
        let current = state.current(max_version).map(|(s, _)| s);
        let plan = state
            .plan_write(&area, current, version, payload)
            .map_err(Error::Plan)?;
        if !plan.payload.is_empty() {
            self.write(plan.payload_lba, &plan.payload).await?;
            self.disk.flush()?;
        }
        self.write(plan.header_lba, &plan.header_sector).await?;
        self.disk.flush()?;
        let back = self.read_slot(&area, plan.slot).await?;
        match config_store::check_slot(&area, &back) {
            SlotState::Valid(h) if h == plan.header => Ok((plan.slot, plan.header)),
            _ => Err(Error::Verify),
        }
    }

    /// [`Self::read_current`] outside the executor (boot).
    pub fn read_current_blocking(
        &mut self,
        name: &'static str,
        max_version: u32,
    ) -> Result<(Option<Record>, AreaState), Error> {
        block_on(self.read_current(name, max_version))
    }
}

fn slot_index(s: Slot) -> usize {
    match s {
        Slot::A => 0,
        Slot::B => 1,
    }
}

/// "A" / "B" for logs.
pub fn slot_name(s: Slot) -> &'static str {
    match s {
        Slot::A => "A",
        Slot::B => "B",
    }
}

/// A slot's state for logs.
pub fn describe(s: &SlotState) -> String {
    match s {
        SlotState::Empty => String::from("empty"),
        SlotState::Corrupt => String::from("corrupt"),
        SlotState::Valid(h) => format!("seq {} v{} {} bytes", h.seq, h.version, h.len),
    }
}
