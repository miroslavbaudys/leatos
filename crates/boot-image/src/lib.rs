//! Kernel images for the in-RAM upgrade (`kernel/src/upgrade.rs`): a new
//! leatos kernel arrives as an ELF file, is checked and laid out flat
//! here, and the arch backend copies it into place and enters it the way
//! a Multiboot2 loader would.
//!
//! - [`parse`]: validate an ELF64 executable (machine, loadable segments,
//!   entry point) into a [`LoadPlan`]
//! - [`LoadPlan::flatten`]: the memory image `[lo, hi)` (file bytes +
//!   zeroed `.bss`), ready for one `memmove`
//! - [`multiboot2`]: find the header in an image; build boot information
//! - [`crc32`]: integrity check of an upload
//!
//! `#![no_std]` + `alloc`, sans-IO, no unsafe: bytes in, plans and bytes out.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod multiboot2;

use alloc::vec::Vec;

pub const EM_X86_64: u16 = 0x3e;
pub const EM_AARCH64: u16 = 0xb7;
const PT_LOAD: u32 = 1;
const ET_EXEC: u16 = 2;
const MAX_SEGMENTS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotElf64,
    WrongMachine(u16),
    NotExecutable,
    BadProgramHeaders,
    NoLoadableSegment,
    /// A segment lies outside the allowed physical range.
    SegmentOutOfRange { paddr: u64, memsz: u64 },
    SegmentOutsideFile,
    EntryOutsideImage(u64),
    TooManySegments,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Physical load address.
    pub paddr: u64,
    pub offset: usize,
    pub filesz: usize,
    pub memsz: usize,
}

/// Where the image goes: `[lo, hi)` physical, entered at `entry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadPlan {
    pub lo: u64,
    pub hi: u64,
    pub entry: u64,
    pub segments: Vec<Segment>,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

/// Validate a little-endian ELF64 executable for `machine` whose loadable
/// segments must all lie inside `[min_addr, max_addr)` (physical).
pub fn parse(elf: &[u8], machine: u16, min_addr: u64, max_addr: u64) -> Result<LoadPlan, Error> {
    // e_ident: magic, ELFCLASS64 (2), ELFDATA2LSB (1).
    if elf.len() < 64 || elf[..4] != *b"\x7fELF" || elf[4] != 2 || elf[5] != 1 {
        return Err(Error::NotElf64);
    }
    let m = u16_at(elf, 18).ok_or(Error::NotElf64)?;
    if m != machine {
        return Err(Error::WrongMachine(m));
    }
    if u16_at(elf, 16) != Some(ET_EXEC) {
        return Err(Error::NotExecutable);
    }
    let entry = u64_at(elf, 24).ok_or(Error::NotElf64)?;
    let phoff = u64_at(elf, 32).ok_or(Error::BadProgramHeaders)? as usize;
    let phentsize = u16_at(elf, 54).ok_or(Error::BadProgramHeaders)? as usize;
    let phnum = u16_at(elf, 56).ok_or(Error::BadProgramHeaders)? as usize;
    if phentsize < 56 || phnum == 0 {
        return Err(Error::BadProgramHeaders);
    }
    let end = phnum
        .checked_mul(phentsize)
        .and_then(|n| n.checked_add(phoff))
        .ok_or(Error::BadProgramHeaders)?;
    if end > elf.len() {
        return Err(Error::BadProgramHeaders);
    }
    let mut segments = Vec::new();
    for i in 0..phnum {
        let ph = &elf[phoff + i * phentsize..phoff + (i + 1) * phentsize];
        if u32_at(ph, 0) != Some(PT_LOAD) {
            continue;
        }
        let offset = u64_at(ph, 8).ok_or(Error::BadProgramHeaders)?;
        let paddr = u64_at(ph, 24).ok_or(Error::BadProgramHeaders)?;
        let filesz = u64_at(ph, 32).ok_or(Error::BadProgramHeaders)?;
        let memsz = u64_at(ph, 40).ok_or(Error::BadProgramHeaders)?;
        if memsz == 0 {
            continue;
        }
        if filesz > memsz || offset.checked_add(filesz).is_none_or(|e| e > elf.len() as u64) {
            return Err(Error::SegmentOutsideFile);
        }
        let seg_end = paddr.checked_add(memsz);
        if paddr < min_addr || seg_end.is_none_or(|e| e > max_addr) {
            return Err(Error::SegmentOutOfRange { paddr, memsz });
        }
        if segments.len() == MAX_SEGMENTS {
            return Err(Error::TooManySegments);
        }
        segments.push(Segment {
            paddr,
            offset: offset as usize,
            filesz: filesz as usize,
            memsz: memsz as usize,
        });
    }
    let lo = segments.iter().map(|s| s.paddr).min().ok_or(Error::NoLoadableSegment)?;
    let hi = segments.iter().map(|s| s.paddr + s.memsz as u64).max().unwrap_or(lo);
    // The entry must be inside a segment that has file contents.
    if !segments
        .iter()
        .any(|s| entry >= s.paddr && entry < s.paddr + s.filesz as u64)
    {
        return Err(Error::EntryOutsideImage(entry));
    }
    Ok(LoadPlan { lo, hi, entry, segments })
}

impl LoadPlan {
    pub fn len(&self) -> usize {
        (self.hi - self.lo) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.hi == self.lo
    }

    /// Write the memory image of `elf` into `out` (exactly [`Self::len`]
    /// bytes): segment contents at `paddr - lo`, everything else zero
    /// (gaps between segments and `.bss`).
    pub fn flatten(&self, elf: &[u8], out: &mut [u8]) {
        assert_eq!(out.len(), self.len(), "flatten: wrong output size");
        out.fill(0);
        for s in &self.segments {
            let at = (s.paddr - self.lo) as usize;
            out[at..at + s.filesz].copy_from_slice(&elf[s.offset..s.offset + s.filesz]);
        }
    }
}

/// CRC-32 (IEEE 802.3, as `crc32`/zlib), bitwise; incremental: pass the
/// previous result as `crc` (start with 0).
pub fn crc32(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { c >> 1 ^ 0xedb8_8320 } else { c >> 1 };
        }
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// A minimal ELF64 with the given (paddr, file bytes, memsz) segments.
    pub(crate) fn elf(machine: u16, entry: u64, segs: &[(u64, &[u8], u64)]) -> Vec<u8> {
        let phoff = 64;
        let data_start = phoff + 56 * segs.len();
        let mut f = vec![0u8; data_start];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[6] = 1;
        f[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        f[18..20].copy_from_slice(&machine.to_le_bytes());
        f[24..32].copy_from_slice(&entry.to_le_bytes());
        f[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
        f[54..56].copy_from_slice(&56u16.to_le_bytes());
        f[56..58].copy_from_slice(&(segs.len() as u16).to_le_bytes());
        for (i, (paddr, bytes, memsz)) in segs.iter().enumerate() {
            let off = f.len() as u64;
            f.extend_from_slice(bytes);
            let ph = phoff + i * 56;
            f[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            f[ph + 8..ph + 16].copy_from_slice(&off.to_le_bytes());
            f[ph + 16..ph + 24].copy_from_slice(&paddr.to_le_bytes());
            f[ph + 24..ph + 32].copy_from_slice(&paddr.to_le_bytes());
            f[ph + 32..ph + 40].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
            f[ph + 40..ph + 48].copy_from_slice(&memsz.to_le_bytes());
        }
        f
    }

    const MIB: u64 = 1 << 20;

    #[test]
    fn parses_and_flattens_with_gap_and_bss() {
        let f = elf(EM_X86_64, MIB, &[(MIB, b"code", 4), (MIB + 0x1000, b"data", 0x10)]);
        let p = parse(&f, EM_X86_64, MIB, 16 * MIB).unwrap();
        assert_eq!((p.lo, p.hi, p.entry), (MIB, MIB + 0x1010, MIB));
        let mut out = vec![0xaa; p.len()];
        p.flatten(&f, &mut out);
        assert_eq!(&out[..4], b"code");
        assert!(out[4..0x1000].iter().all(|&b| b == 0), "gap zeroed");
        assert_eq!(&out[0x1000..0x1004], b"data");
        assert!(out[0x1004..].iter().all(|&b| b == 0), "bss zeroed");
    }

    #[test]
    fn rejects_bad_images() {
        let good = elf(EM_X86_64, MIB, &[(MIB, b"code", 4)]);
        assert_eq!(parse(&good[..10], EM_X86_64, 0, u64::MAX), Err(Error::NotElf64));
        assert_eq!(parse(&good, EM_AARCH64, 0, u64::MAX), Err(Error::WrongMachine(EM_X86_64)));
        assert!(matches!(
            parse(&good, EM_X86_64, 2 * MIB, u64::MAX),
            Err(Error::SegmentOutOfRange { .. })
        ));
        assert!(matches!(
            parse(&good, EM_X86_64, 0, MIB + 2),
            Err(Error::SegmentOutOfRange { .. })
        ));
        let bad_entry = elf(EM_X86_64, 5 * MIB, &[(MIB, b"code", 4)]);
        assert_eq!(parse(&bad_entry, EM_X86_64, 0, u64::MAX), Err(Error::EntryOutsideImage(5 * MIB)));
        let mut truncated = good.clone();
        truncated.truncate(good.len() - 2);
        assert_eq!(parse(&truncated, EM_X86_64, 0, u64::MAX), Err(Error::SegmentOutsideFile));
        let mut no_exec = good.clone();
        no_exec[16] = 3; // ET_DYN
        assert_eq!(parse(&no_exec, EM_X86_64, 0, u64::MAX), Err(Error::NotExecutable));
    }

    #[test]
    fn crc32_matches_reference() {
        assert_eq!(crc32(0, b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(crc32(0, b"12345"), b"6789"), 0xcbf4_3926);
        assert_eq!(crc32(0, b""), 0);
    }
}
