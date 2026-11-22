//! Power-fail-safe persistent store (`docs/config-and-storage.md`).
//!
//! A raw partition (MBR type [`mbr::STORE_PARTITION_TYPE`]) starts with a
//! store header listing **areas** ([`Layout`]). Each area has two slots,
//! A and B, each holding one **record**: a header sector followed by the
//! payload ([`RecordHeader`]). The current record is the valid one with
//! the highest sequence number whose schema version the reader
//! understands ([`AreaState::current`]); a write always goes to the other
//! slot, payload first and header last ([`AreaState::plan_write`]), so a
//! power cut leaves either the old or the new record.
//!
//! - [`mbr`]: find the store partition
//! - [`Layout`]: parse, build and encode the store header
//! - [`RecordHeader`], [`check_slot`], [`AreaState`]: read side
//! - [`WritePlan`]: write side (the caller performs the sector writes)
//!
//! `#![no_std]` + `alloc`, sans-IO, no unsafe: sectors in, plans out.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod layout;
pub mod mbr;
mod record;

pub use layout::{Area, LAYOUT_VERSION, Layout, MAX_AREAS, STANDARD_MIN_SECTORS, STORE_MAGIC};
pub use record::{
    AreaState, FLAG_BOOTED, FLAG_TRIAL, RECORD_FORMAT, RECORD_MAGIC, RecordHeader, Slot, SlotState, WritePlan, check_slot,
};

/// Sector size of the store, in bytes.
pub const SECTOR: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The buffer is shorter than one sector.
    Short,
    BadMagic,
    BadChecksum,
    UnsupportedLayout(u16),
    UnsupportedSectorSize(u16),
    TooManyAreas(usize),
    BadAreaName,
    DuplicateArea,
    /// An area overlaps sector 0, another area or the partition end.
    AreaOutOfRange,
    AreasOverlap,
    /// A slot must hold at least the header sector and one payload sector.
    SlotTooSmall,
    PartitionTooSmall {
        need: u64,
        have: u64,
    },
    PayloadTooLarge {
        len: usize,
        max: usize,
    },
    /// Sequence numbers run out: a header with `u64::MAX` is never a
    /// record, and a save after `u64::MAX - 1` is refused (a correct
    /// writer never gets there; only a crafted or damaged store does).
    LastSequence,
}

fn crc32(data: &[u8]) -> u32 {
    boot_image::crc32(0, data)
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le64(b: &[u8], at: usize) -> u64 {
    let mut v = [0; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

/// The CRC over bytes 0..508 of a sector, stored in bytes 508..512.
fn sector_crc_ok(s: &[u8]) -> bool {
    le32(s, SECTOR - 4) == crc32(&s[..SECTOR - 4])
}

fn seal_sector(s: &mut [u8; SECTOR]) {
    let c = crc32(&s[..SECTOR - 4]);
    s[SECTOR - 4..].copy_from_slice(&c.to_le_bytes());
}

#[cfg(test)]
mod tests;
