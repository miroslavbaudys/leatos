//! The store header (sector 0 of the store partition): which areas exist
//! and where their slots are.

use crate::{Error, SECTOR, le16, le32, le64, seal_sector, sector_crc_ok};
use alloc::vec::Vec;

pub const STORE_MAGIC: [u8; 8] = *b"RRSTORE1";
pub const LAYOUT_VERSION: u16 = 1;
pub const MAX_AREAS: usize = 16;
const AREAS_AT: usize = 24;
const AREA_LEN: usize = 16;

/// Smallest partition [`Layout::standard`] accepts: 16 MiB.
pub const STANDARD_MIN_SECTORS: u64 = 16 << 11;

/// One area: two equal slots, A at `first`, B right after it. Sector
/// numbers are relative to the start of the store partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Area {
    name: [u8; 8],
    pub first: u32,
    pub slot_sectors: u32,
}

impl Area {
    /// `name`: 1–8 ASCII letters, digits, `-` or `_`.
    pub fn new(name: &str, first: u32, slot_sectors: u32) -> Result<Self, Error> {
        let b = name.as_bytes();
        let ok = (1..=8).contains(&b.len())
            && b.iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_');
        if !ok {
            return Err(Error::BadAreaName);
        }
        let mut n = [0; 8];
        n[..b.len()].copy_from_slice(b);
        Ok(Area {
            name: n,
            first,
            slot_sectors,
        })
    }

    pub fn name(&self) -> &str {
        let len = self.name.iter().position(|&c| c == 0).unwrap_or(8);
        // Checked to be ASCII in `new` / `from_raw`.
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub(crate) fn name_bytes(&self) -> &[u8; 8] {
        &self.name
    }

    fn from_raw(name: [u8; 8], first: u32, slot_sectors: u32) -> Result<Self, Error> {
        let len = name.iter().position(|&c| c == 0).unwrap_or(8);
        if name[len..].iter().any(|&c| c != 0) {
            return Err(Error::BadAreaName);
        }
        let s = core::str::from_utf8(&name[..len]).map_err(|_| Error::BadAreaName)?;
        Area::new(s, first, slot_sectors)
    }

    /// First sector of a slot (its record header).
    pub fn slot_lba(&self, slot: crate::Slot) -> u64 {
        self.first as u64 + slot.index() as u64 * self.slot_sectors as u64
    }

    /// One past the last sector of slot B.
    pub fn end(&self) -> u64 {
        self.first as u64 + 2 * self.slot_sectors as u64
    }

    /// Largest payload a slot holds, in bytes.
    pub fn max_payload(&self) -> usize {
        (self.slot_sectors as usize).saturating_sub(1) * SECTOR
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Partition size in sectors when the store was formatted.
    pub sectors: u64,
    areas: Vec<Area>,
}

impl Layout {
    /// A layout with these areas, checked: names unique, every area after
    /// sector 0 and inside the partition, no overlaps.
    pub fn new(sectors: u64, areas: &[Area]) -> Result<Self, Error> {
        if areas.len() > MAX_AREAS {
            return Err(Error::TooManyAreas(areas.len()));
        }
        for (i, a) in areas.iter().enumerate() {
            if a.slot_sectors < 2 {
                return Err(Error::SlotTooSmall);
            }
            if a.first == 0 || a.end() > sectors {
                return Err(Error::AreaOutOfRange);
            }
            for b in &areas[..i] {
                if a.name == b.name {
                    return Err(Error::DuplicateArea);
                }
                if (a.first as u64) < b.end() && (b.first as u64) < a.end() {
                    return Err(Error::AreasOverlap);
                }
            }
        }
        Ok(Layout {
            sectors,
            areas: areas.to_vec(),
        })
    }

    /// The layout `scripts/apu-image.sh` formats (partition ≥ 16 MiB):
    /// `config` 2 × 256 KiB at 4 KiB, `leases` 2 × 128 KiB at 1 MiB,
    /// `images` the rest from 2 MiB, split in two.
    pub fn standard(sectors: u64) -> Result<Self, Error> {
        if sectors < STANDARD_MIN_SECTORS {
            return Err(Error::PartitionTooSmall {
                need: STANDARD_MIN_SECTORS,
                have: sectors,
            });
        }
        let images_first: u32 = 4096;
        // u32 sector numbers cover 2 TiB; cap the images area at that.
        let rest = (sectors - images_first as u64).min(u32::MAX as u64 - images_first as u64);
        let image_slot = ((rest / 2) & !7) as u32; // 4 KiB aligned
        Layout::new(
            sectors,
            &[
                Area::new("config", 8, 512)?,
                Area::new("leases", 2048, 256)?,
                Area::new("images", images_first, image_slot)?,
            ],
        )
    }

    pub fn areas(&self) -> &[Area] {
        &self.areas
    }

    pub fn area(&self, name: &str) -> Option<&Area> {
        self.areas.iter().find(|a| a.name() == name)
    }

    /// Parse sector 0 of a store partition that is `partition_sectors`
    /// long. A partition smaller than when formatted is an error (areas
    /// would lie outside it); a larger one is fine.
    pub fn parse(sector: &[u8], partition_sectors: u64) -> Result<Self, Error> {
        if sector.len() < SECTOR {
            return Err(Error::Short);
        }
        let s = &sector[..SECTOR];
        if s[..8] != STORE_MAGIC {
            return Err(Error::BadMagic);
        }
        if !sector_crc_ok(s) {
            return Err(Error::BadChecksum);
        }
        let version = le16(s, 8);
        if version != LAYOUT_VERSION {
            return Err(Error::UnsupportedLayout(version));
        }
        let sector_size = le16(s, 10);
        if sector_size as usize != SECTOR {
            return Err(Error::UnsupportedSectorSize(sector_size));
        }
        let count = le16(s, 12) as usize;
        if count > MAX_AREAS {
            return Err(Error::TooManyAreas(count));
        }
        let sectors = le64(s, 16);
        if sectors > partition_sectors {
            return Err(Error::PartitionTooSmall {
                need: sectors,
                have: partition_sectors,
            });
        }
        let mut areas = Vec::with_capacity(count);
        for i in 0..count {
            let e = &s[AREAS_AT + AREA_LEN * i..AREAS_AT + AREA_LEN * (i + 1)];
            let mut name = [0; 8];
            name.copy_from_slice(&e[..8]);
            areas.push(Area::from_raw(name, le32(e, 8), le32(e, 12))?);
        }
        Layout::new(sectors, &areas)
    }

    /// Sector 0 of the store partition.
    pub fn encode(&self) -> [u8; SECTOR] {
        let mut s = [0; SECTOR];
        s[..8].copy_from_slice(&STORE_MAGIC);
        s[8..10].copy_from_slice(&LAYOUT_VERSION.to_le_bytes());
        s[10..12].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        s[12..14].copy_from_slice(&(self.areas.len() as u16).to_le_bytes());
        s[16..24].copy_from_slice(&self.sectors.to_le_bytes());
        for (i, a) in self.areas.iter().enumerate() {
            let e = &mut s[AREAS_AT + AREA_LEN * i..AREAS_AT + AREA_LEN * (i + 1)];
            e[..8].copy_from_slice(&a.name);
            e[8..12].copy_from_slice(&a.first.to_le_bytes());
            e[12..16].copy_from_slice(&a.slot_sectors.to_le_bytes());
        }
        seal_sector(&mut s);
        s
    }
}
