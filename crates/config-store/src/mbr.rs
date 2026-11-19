//! Master Boot Record: find the store partition.

use crate::SECTOR;

/// MBR partition type of the leatos store ("non-FS data").
pub const STORE_PARTITION_TYPE: u8 = 0xda;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition {
    /// 0..=3, the primary partition entry.
    pub index: u8,
    pub kind: u8,
    pub first_lba: u32,
    pub sectors: u32,
}

/// The four primary partition entries (`None` for unused ones), or `None`
/// if `mbr` is not a boot sector (`55 aa` signature).
pub fn partitions(mbr: &[u8]) -> Option<[Option<Partition>; 4]> {
    if mbr.len() < SECTOR || mbr[510..512] != [0x55, 0xaa] {
        return None;
    }
    let mut out = [None; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        let e = &mbr[446 + 16 * i..446 + 16 * (i + 1)];
        let p = Partition {
            index: i as u8,
            kind: e[4],
            first_lba: crate::le32(e, 8),
            sectors: crate::le32(e, 12),
        };
        if p.kind != 0 && p.sectors != 0 && p.first_lba != 0 {
            *slot = Some(p);
        }
    }
    Some(out)
}

/// The first primary partition of type [`STORE_PARTITION_TYPE`].
pub fn find_store(mbr: &[u8]) -> Option<Partition> {
    partitions(mbr)?
        .into_iter()
        .flatten()
        .find(|p| p.kind == STORE_PARTITION_TYPE)
}
