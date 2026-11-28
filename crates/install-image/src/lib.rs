//! Install images (docs/install.md §3.3): what the installer writes to the
//! target disk, as the module Limine loads next to the kernel.
//!
//! A raw leatos disk image (`scripts/apu-image.sh`) is mostly zeros, so the
//! install image keeps only its non-zero sector runs ("extents"). Writing it
//! is not "write the extents and skip the rest": [`Image::plan`] covers
//! **every** sector of the image, the gaps as zeros, because a reused disk
//! may hold an old leatos store record with a valid CRC in a gap, which the
//! new store would otherwise take as current. It also zeroes the target's
//! last [`GPT_BACKUP_SECTORS`] (a backup GPT of a previous OS).
//!
//! Layout (little endian):
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 8 | magic `LEATINST` |
//! | 8 | 4 | version (1) |
//! | 12 | 4 | sector size (512) |
//! | 16 | 8 | image sectors |
//! | 24 | 4 | extent count |
//! | 28 | 4 | reserved (0) |
//! | 32 | 32 | SHA-256 of all other bytes: offsets 0..32, then 64 to the end |
//! | 64 | 16 × count | extents: first sector (u64), sectors (u64), ascending, disjoint |
//! | … | | the extents' data, in table order |
//!
//! `#![no_std]` + `alloc`, sans-IO, no unsafe: [`build`] on the host,
//! [`parse`] and [`Image::plan`] in the kernel.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 8] = b"LEATINST";
pub const VERSION: u32 = 1;
pub const SECTOR: usize = 512;
pub const HEADER: usize = 64;
const EXTENT: usize = 16;
/// More extents than any leatos image needs (an apu4 image has a few).
pub const MAX_EXTENTS: usize = 4096;
/// A GPT keeps its backup header and table in the last 33 sectors.
pub const GPT_BACKUP_SECTORS: u64 = 33;
/// [`build`] merges runs separated by fewer zero sectors than this, so a
/// sparse FAT does not turn into thousands of extents.
const MERGE_GAP: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Short,
    BadMagic,
    Version(u32),
    SectorSize(u32),
    Reserved,
    TooManyExtents(u32),
    /// An extent is empty, out of order, overlapping or past the image.
    BadExtent(usize),
    /// The data does not have the length the extent table gives.
    Length,
    Hash,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Short => f.write_str("too short for the header"),
            Error::BadMagic => f.write_str("not an install image (magic)"),
            Error::Version(v) => write!(f, "unknown version {v}"),
            Error::SectorSize(s) => write!(f, "sector size {s} (only 512)"),
            Error::Reserved => f.write_str("reserved header field not zero"),
            Error::TooManyExtents(n) => write!(f, "{n} extents (at most {MAX_EXTENTS})"),
            Error::BadExtent(i) => write!(f, "extent {i} empty, out of order or past the image"),
            Error::Length => f.write_str("data length does not match the extent table"),
            Error::Hash => f.write_str("SHA-256 mismatch"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub lba: u64,
    pub sectors: u64,
}

/// A checked install image, borrowing the module's bytes.
#[derive(Clone, Copy, Debug)]
pub struct Image<'a> {
    sectors: u64,
    table: &'a [u8],
    data: &'a [u8],
    sha256: [u8; 32],
}

/// One write of the plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Piece<'a> {
    /// Write `data` (whole sectors) at `lba`.
    Data { lba: u64, data: &'a [u8] },
    /// Write `sectors` zero sectors at `lba`.
    Zero { lba: u64, sectors: u64 },
}

impl Piece<'_> {
    pub fn lba(&self) -> u64 {
        match *self {
            Piece::Data { lba, .. } | Piece::Zero { lba, .. } => lba,
        }
    }
    pub fn sectors(&self) -> u64 {
        match *self {
            Piece::Data { data, .. } => (data.len() / SECTOR) as u64,
            Piece::Zero { sectors, .. } => sectors,
        }
    }
}

/// The hash a header carries: every byte but the hash field itself.
fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&bytes[..32]);
    h.update(&bytes[HEADER..]);
    h.finalize().into()
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Check an install image: header, extent table, data length and SHA-256.
pub fn parse(bytes: &[u8]) -> Result<Image<'_>, Error> {
    if bytes.len() < HEADER {
        return Err(Error::Short);
    }
    if &bytes[..8] != MAGIC {
        return Err(Error::BadMagic);
    }
    match u32_at(bytes, 8) {
        VERSION => {}
        v => return Err(Error::Version(v)),
    }
    match u32_at(bytes, 12) {
        512 => {}
        s => return Err(Error::SectorSize(s)),
    }
    if u32_at(bytes, 28) != 0 {
        return Err(Error::Reserved);
    }
    let sectors = u64_at(bytes, 16);
    let count = u32_at(bytes, 24);
    if count as usize > MAX_EXTENTS {
        return Err(Error::TooManyExtents(count));
    }
    let table_end = HEADER + count as usize * EXTENT;
    let table = bytes.get(HEADER..table_end).ok_or(Error::Length)?;
    let mut next = 0u64; // first sector the next extent may start at
    let mut data_len = 0u64;
    for (i, e) in table.as_chunks::<EXTENT>().0.iter().enumerate() {
        let (lba, n) = (u64_at(e, 0), u64_at(e, 8));
        let end = lba.checked_add(n).ok_or(Error::BadExtent(i))?;
        if n == 0 || lba < next || end > sectors {
            return Err(Error::BadExtent(i));
        }
        next = end;
        data_len = n
            .checked_mul(SECTOR as u64)
            .and_then(|l| data_len.checked_add(l))
            .ok_or(Error::Length)?;
    }
    let data = &bytes[table_end..];
    if data.len() as u64 != data_len {
        return Err(Error::Length);
    }
    let sha256: [u8; 32] = bytes[32..64].try_into().unwrap();
    if digest(bytes) != sha256 {
        return Err(Error::Hash);
    }
    Ok(Image {
        sectors,
        table,
        data,
        sha256,
    })
}

impl<'a> Image<'a> {
    /// Sectors of the disk image (the target must have at least these).
    pub fn sectors(&self) -> u64 {
        self.sectors
    }

    /// The SHA-256 the header carries (checked by [`parse`]).
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub fn extents(&self) -> impl Iterator<Item = Extent> + 'a {
        self.table.as_chunks::<EXTENT>().0.iter().map(|e| Extent {
            lba: u64_at(e, 0),
            sectors: u64_at(e, 8),
        })
    }

    /// Sector `lba` of the disk image: its bytes if an extent holds it,
    /// `None` if it lies in a gap (zeros) or past the image.
    pub fn sector(&self, lba: u64) -> Option<&'a [u8]> {
        let mut off = 0usize;
        for e in self.extents() {
            if lba < e.lba {
                return None;
            }
            if lba < e.lba + e.sectors {
                let at = off + (lba - e.lba) as usize * SECTOR;
                return self.data.get(at..at + SECTOR);
            }
            off += e.sectors as usize * SECTOR;
        }
        None
    }

    /// Bytes of data the extents hold (what is not zeros).
    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    /// Every write that puts this image on a disk of `target` sectors, in
    /// ascending order, each at most `max` sectors (`max` ≥ 1): the
    /// extents' data, zeros for every gap up to the image's end, and zeros
    /// for the target's last [`GPT_BACKUP_SECTORS`] beyond the image.
    /// Together they cover `0..sectors()` exactly once, plus that tail.
    /// `None` if the target is smaller than the image.
    pub fn plan(&self, target: u64, max: u64) -> Option<Plan<'a>> {
        (target >= self.sectors && max >= 1).then_some(Plan {
            image: *self,
            target,
            max,
            at: 0,
            extent: 0,
            data_off: 0,
            tail_done: false,
        })
    }
}

/// The iterator [`Image::plan`] returns.
#[derive(Clone, Debug)]
pub struct Plan<'a> {
    image: Image<'a>,
    target: u64,
    max: u64,
    /// The next sector to cover.
    at: u64,
    /// The next extent (index into the table) and where its data starts.
    extent: usize,
    data_off: usize,
    tail_done: bool,
}

impl<'a> Iterator for Plan<'a> {
    type Item = Piece<'a>;

    fn next(&mut self) -> Option<Piece<'a>> {
        let img = self.image;
        if self.at < img.sectors {
            let next = img.table.get(self.extent * EXTENT..(self.extent + 1) * EXTENT);
            let (lba, n) = next.map_or((img.sectors, 0), |e| (u64_at(e, 0), u64_at(e, 8)));
            if self.at < lba {
                // A gap before the next extent (or the image's end).
                let sectors = (lba - self.at).min(self.max);
                let p = Piece::Zero {
                    lba: self.at,
                    sectors,
                };
                self.at += sectors;
                return Some(p);
            }
            // Inside extent `self.extent`.
            let left = lba + n - self.at;
            let take = left.min(self.max);
            let len = take as usize * SECTOR;
            let p = Piece::Data {
                lba: self.at,
                data: &img.data[self.data_off..self.data_off + len],
            };
            self.at += take;
            self.data_off += len;
            if take == left {
                self.extent += 1;
            }
            return Some(p);
        }
        if !self.tail_done {
            // The target's GPT backup area, past what the image covered.
            let start = self.at.max(self.target.saturating_sub(GPT_BACKUP_SECTORS));
            if start < self.target {
                let sectors = (self.target - start).min(self.max);
                self.at = start + sectors;
                if self.at == self.target {
                    self.tail_done = true;
                }
                return Some(Piece::Zero { lba: start, sectors });
            }
            self.tail_done = true;
        }
        None
    }
}

/// Build an install image from a raw disk image (its length a multiple of
/// [`SECTOR`]; a partial last sector is padded with zeros).
pub fn build(raw: &[u8]) -> Vec<u8> {
    let sectors = raw.len().div_ceil(SECTOR);
    let sector = |i: usize| &raw[i * SECTOR..((i + 1) * SECTOR).min(raw.len())];
    let zero = |i: usize| sector(i).iter().all(|&b| b == 0);
    // Runs of non-zero sectors, merged across short gaps.
    let mut runs: Vec<(usize, usize)> = Vec::new(); // (first, end)
    for i in (0..sectors).filter(|&i| !zero(i)) {
        match runs.last_mut() {
            Some((_, end)) if i - *end < MERGE_GAP => *end = i + 1,
            _ => runs.push((i, i + 1)),
        }
    }
    assert!(runs.len() <= MAX_EXTENTS, "install image: too many extents");
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(SECTOR as u32).to_le_bytes());
    out.extend_from_slice(&(sectors as u64).to_le_bytes());
    out.extend_from_slice(&(runs.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[0; 32]);
    for &(first, end) in &runs {
        out.extend_from_slice(&(first as u64).to_le_bytes());
        out.extend_from_slice(&((end - first) as u64).to_le_bytes());
    }
    for &(first, end) in &runs {
        for i in first..end {
            let s = sector(i);
            out.extend_from_slice(s);
            out.resize(out.len() + SECTOR - s.len(), 0);
        }
    }
    let hash = digest(&out);
    out[32..64].copy_from_slice(&hash);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// The disk a plan writes, starting from `fill` everywhere.
    fn apply(img: &Image, target: u64, max: u64, fill: u8) -> Vec<u8> {
        let mut disk = vec![fill; target as usize * SECTOR];
        let mut covered = vec![0u8; target as usize];
        for p in img.plan(target, max).unwrap() {
            assert!(p.sectors() >= 1 && p.sectors() <= max, "{p:?}");
            let at = p.lba() as usize * SECTOR;
            let len = p.sectors() as usize * SECTOR;
            match p {
                Piece::Data { data, .. } => disk[at..at + len].copy_from_slice(data),
                Piece::Zero { .. } => disk[at..at + len].fill(0),
            }
            for c in &mut covered[p.lba() as usize..(p.lba() + p.sectors()) as usize] {
                *c += 1;
            }
        }
        let tail = target.saturating_sub(GPT_BACKUP_SECTORS).max(img.sectors());
        for (i, &c) in covered.iter().enumerate() {
            let want = (i as u64) < img.sectors() || i as u64 >= tail;
            assert_eq!(c, want as u8, "sector {i} covered {c} times");
        }
        disk
    }

    fn raw() -> Vec<u8> {
        let mut raw = vec![0u8; 1000 * SECTOR];
        raw[0] = 0x33; // MBR
        raw[510] = 0x55;
        raw[3 * SECTOR + 7] = 1; // merged into the first run (gap < 64)
        raw[500 * SECTOR..520 * SECTOR].fill(0xab);
        raw[999 * SECTOR + 511] = 9; // last sector
        raw
    }

    #[test]
    fn round_trip_restores_the_image_and_zeroes_the_rest() {
        let raw = raw();
        let bytes = build(&raw);
        let img = parse(&bytes).unwrap();
        assert_eq!(img.sectors(), 1000);
        let ex: Vec<_> = img.extents().collect();
        assert_eq!(
            ex,
            [
                Extent { lba: 0, sectors: 4 },
                Extent { lba: 500, sectors: 20 },
                Extent { lba: 999, sectors: 1 },
            ]
        );
        assert_eq!(img.data_len(), 25 * SECTOR);
        for max in [1, 3, 7, 128, 1 << 20] {
            // A disk full of 0xff (old contents) ends up exactly the image.
            let disk = apply(&img, 1000, max, 0xff);
            assert_eq!(disk, raw, "max {max}");
            // A bigger disk: image, untouched middle, zeroed GPT backup.
            let disk = apply(&img, 2000, max, 0xff);
            assert_eq!(disk[..raw.len()], raw[..]);
            assert!(disk[1000 * SECTOR..1967 * SECTOR].iter().all(|&b| b == 0xff));
            assert!(disk[1967 * SECTOR..].iter().all(|&b| b == 0));
            // Tail overlapping the image's end: zeroed only past it.
            let disk = apply(&img, 1010, max, 0xff);
            assert_eq!(disk[..raw.len()], raw[..]);
            assert!(disk[raw.len()..].iter().all(|&b| b == 0));
        }
        assert!(img.plan(999, 8).is_none(), "target smaller than the image");
        for lba in 0..1000u64 {
            let want = &raw[lba as usize * SECTOR..(lba as usize + 1) * SECTOR];
            match img.sector(lba) {
                Some(s) => assert_eq!(s, want, "sector {lba}"),
                None => assert!(want.iter().all(|&b| b == 0), "sector {lba} in a gap but not zero"),
            }
        }
        assert!(img.sector(1000).is_none());
        assert!(img.plan(1000, 0).is_none());
    }

    #[test]
    fn empty_and_partial_images() {
        let img_bytes = build(&[0u8; 4 * SECTOR]);
        let img = parse(&img_bytes).unwrap();
        assert_eq!(img.extents().count(), 0);
        assert_eq!(apply(&img, 4, 2, 0xee), vec![0u8; 4 * SECTOR]);
        // A partial last sector is padded.
        let bytes = build(&[1u8; 700]);
        let img = parse(&bytes).unwrap();
        assert_eq!(img.sectors(), 2);
        let disk = apply(&img, 2, 8, 0xee);
        assert!(disk[..700].iter().all(|&b| b == 1) && disk[700..].iter().all(|&b| b == 0));
    }

    #[test]
    fn every_corruption_is_refused() {
        let good = build(&raw());
        // Any single flipped byte anywhere is refused.
        for i in 0..good.len() {
            let mut b = good.clone();
            b[i] ^= 0x01;
            assert!(parse(&b).is_err(), "flip at {i} accepted");
        }
        // Truncated or extended.
        for n in [0, 10, HEADER, good.len() - 1] {
            assert!(parse(&good[..n]).is_err(), "truncated to {n}");
        }
        let mut longer = good.clone();
        longer.push(0);
        assert_eq!(parse(&longer).unwrap_err(), Error::Length);
    }

    /// A header with a valid hash over the given extents and data.
    fn forge(sectors: u64, extents: &[(u64, u64)], data_len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&512u32.to_le_bytes());
        out.extend_from_slice(&sectors.to_le_bytes());
        out.extend_from_slice(&(extents.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0; 36]);
        for &(l, n) in extents {
            out.extend_from_slice(&l.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
        }
        out.resize(out.len() + data_len, 7);
        let h = digest(&out);
        out[32..64].copy_from_slice(&h);
        out
    }

    #[test]
    fn bad_tables_with_valid_hashes() {
        assert!(parse(&forge(10, &[(0, 2), (5, 1)], 3 * SECTOR)).is_ok());
        assert_eq!(parse(&forge(10, &[(0, 0)], 0)).unwrap_err(), Error::BadExtent(0));
        assert_eq!(
            parse(&forge(10, &[(0, 2), (1, 1)], 3 * SECTOR)).unwrap_err(),
            Error::BadExtent(1),
            "overlap"
        );
        assert_eq!(
            parse(&forge(10, &[(5, 1), (0, 1)], 2 * SECTOR)).unwrap_err(),
            Error::BadExtent(1),
            "out of order"
        );
        assert_eq!(parse(&forge(10, &[(9, 2)], 2 * SECTOR)).unwrap_err(), Error::BadExtent(0));
        assert_eq!(
            parse(&forge(u64::MAX, &[(u64::MAX, 2)], 0)).unwrap_err(),
            Error::BadExtent(0),
            "overflow"
        );
        assert_eq!(
            parse(&forge(u64::MAX, &[(0, u64::MAX / 256)], 0)).unwrap_err(),
            Error::Length,
            "data length overflow"
        );
        assert_eq!(parse(&forge(10, &[(0, 2)], SECTOR)).unwrap_err(), Error::Length);
    }
}
