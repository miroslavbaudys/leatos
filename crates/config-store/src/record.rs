//! Records in A/B slots: reading, choosing the current one, planning a
//! write.

use crate::{Area, Error, SECTOR, crc32, le16, le32, le64, seal_sector, sector_crc_ok};
use alloc::vec;
use alloc::vec::Vec;

pub const RECORD_MAGIC: [u8; 4] = *b"RREC";
pub const RECORD_FORMAT: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    pub(crate) fn index(self) -> usize {
        match self {
            Slot::A => 0,
            Slot::B => 1,
        }
    }
}

/// The header sector of a record. On its own it says nothing about the
/// payload; [`check_slot`] verifies both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordHeader {
    /// Higher = newer.
    pub seq: u64,
    /// Schema version of the payload (e.g. `version` of `config.toml`).
    pub version: u32,
    /// Payload length in bytes.
    pub len: u32,
    /// CRC-32 of the payload.
    pub crc: u32,
}

impl RecordHeader {
    /// A header sector of `area`: magic, format, area name, header CRC and
    /// a payload that fits the slot.
    pub fn parse(area: &Area, sector: &[u8]) -> Result<Self, Error> {
        if sector.len() < SECTOR {
            return Err(Error::Short);
        }
        let s = &sector[..SECTOR];
        if s[..4] != RECORD_MAGIC {
            return Err(Error::BadMagic);
        }
        if !sector_crc_ok(s) {
            return Err(Error::BadChecksum);
        }
        if le16(s, 4) != RECORD_FORMAT || s[8..16] != *area.name_bytes() {
            return Err(Error::BadMagic);
        }
        let h = RecordHeader {
            seq: le64(s, 16),
            version: le32(s, 24),
            len: le32(s, 28),
            crc: le32(s, 32),
        };
        if h.len as usize > area.max_payload() {
            return Err(Error::PayloadTooLarge {
                len: h.len as usize,
                max: area.max_payload(),
            });
        }
        Ok(h)
    }

    /// Payload sectors after the header sector.
    pub fn payload_sectors(&self) -> u64 {
        (self.len as u64).div_ceil(SECTOR as u64)
    }

    pub fn encode(&self, area: &Area) -> [u8; SECTOR] {
        let mut s = [0; SECTOR];
        s[..4].copy_from_slice(&RECORD_MAGIC);
        s[4..6].copy_from_slice(&RECORD_FORMAT.to_le_bytes());
        s[8..16].copy_from_slice(area.name_bytes());
        s[16..24].copy_from_slice(&self.seq.to_le_bytes());
        s[24..28].copy_from_slice(&self.version.to_le_bytes());
        s[28..32].copy_from_slice(&self.len.to_le_bytes());
        s[32..36].copy_from_slice(&self.crc.to_le_bytes());
        seal_sector(&mut s);
        s
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    /// Never written (no record magic).
    Empty,
    /// A record that fails a check: torn or interrupted write, bit rot.
    Corrupt,
    Valid(RecordHeader),
}

impl SlotState {
    pub fn valid(&self) -> Option<&RecordHeader> {
        match self {
            SlotState::Valid(h) => Some(h),
            _ => None,
        }
    }
}

/// Check one slot. `slot` starts at the slot's header sector and holds at
/// least the payload (the caller reads the header sector, then
/// [`RecordHeader::payload_sectors`] more; reading the whole slot works
/// too).
pub fn check_slot(area: &Area, slot: &[u8]) -> SlotState {
    if slot.len() < SECTOR || slot[..4] != RECORD_MAGIC {
        return SlotState::Empty;
    }
    let Ok(h) = RecordHeader::parse(area, slot) else {
        return SlotState::Corrupt;
    };
    match slot.get(SECTOR..SECTOR + h.len as usize) {
        Some(p) if crc32(p) == h.crc => SlotState::Valid(h),
        _ => SlotState::Corrupt,
    }
}

/// Both slots of an area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AreaState {
    pub a: SlotState,
    pub b: SlotState,
}

impl AreaState {
    pub fn from_slots(area: &Area, a: &[u8], b: &[u8]) -> Self {
        AreaState {
            a: check_slot(area, a),
            b: check_slot(area, b),
        }
    }

    pub fn slot(&self, s: Slot) -> &SlotState {
        match s {
            Slot::A => &self.a,
            Slot::B => &self.b,
        }
    }

    /// The current record: valid, schema `version <= max_version`, highest
    /// `seq` (A on a tie, which a correct writer never produces).
    pub fn current(&self, max_version: u32) -> Option<(Slot, RecordHeader)> {
        [Slot::A, Slot::B]
            .into_iter()
            .filter_map(|s| Some((s, *self.slot(s).valid()?)))
            .filter(|(_, h)| h.version <= max_version)
            .fold(None, |best: Option<(Slot, RecordHeader)>, c| match best {
                Some(b) if b.1.seq >= c.1.seq => Some(b),
                _ => Some(c),
            })
    }

    /// Plan writing `payload` (schema `version`). `current` is what the
    /// reader uses ([`AreaState::current`]); it is never the target. With
    /// no current record, an invalid slot is preferred, else the older one.
    pub fn plan_write(
        &self,
        area: &Area,
        current: Option<Slot>,
        version: u32,
        payload: &[u8],
    ) -> Result<WritePlan, Error> {
        let max = area.max_payload();
        if payload.len() > max {
            return Err(Error::PayloadTooLarge {
                len: payload.len(),
                max,
            });
        }
        let seq_of = |s: Slot| self.slot(s).valid().map(|h| h.seq);
        let target = match current {
            Some(c) => c.other(),
            None => match (seq_of(Slot::A), seq_of(Slot::B)) {
                (None, _) => Slot::A,
                (_, None) => Slot::B,
                (Some(a), Some(b)) => {
                    if a <= b {
                        Slot::A
                    } else {
                        Slot::B
                    }
                }
            },
        };
        let seq = seq_of(Slot::A).max(seq_of(Slot::B)).map_or(1, |s| s + 1);
        let header = RecordHeader {
            seq,
            version,
            len: payload.len() as u32,
            crc: crc32(payload),
        };
        let mut data = vec![0; header.payload_sectors() as usize * SECTOR];
        data[..payload.len()].copy_from_slice(payload);
        let lba = area.slot_lba(target);
        Ok(WritePlan {
            slot: target,
            header,
            payload_lba: lba + 1,
            payload: data,
            header_lba: lba,
            header_sector: header.encode(area),
        })
    }
}

/// The sector writes for one record, relative to the store partition.
/// Order matters: write [`payload`](Self::payload) at `payload_lba`,
/// flush, then [`header_sector`](Self::header_sector) at `header_lba`,
/// flush, then read the slot back and check it with [`check_slot`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WritePlan {
    pub slot: Slot,
    pub header: RecordHeader,
    pub payload_lba: u64,
    /// Padded with zeros to whole sectors.
    pub payload: Vec<u8>,
    pub header_lba: u64,
    pub header_sector: [u8; SECTOR],
}
