//! Multiboot2 (specification 2.0): check that an image carries a header,
//! and build the boot information a loader passes in `ebx`. The kernel's
//! parser is `kernel/src/platform/multiboot2.rs`; [`build_info`] emits the
//! tags it reads (command line, memory map, ACPI RSDP).

use alloc::vec::Vec;

pub const HEADER_MAGIC: u32 = 0xe852_50d6;
/// `eax` at entry.
pub const BOOT_MAGIC: u32 = 0x36d7_6289;
/// The header must start in the first 32 KiB, 8-byte aligned.
const SEARCH: usize = 32 * 1024;

/// Offset of a valid Multiboot2 header (magic, i386, length, checksum).
pub fn find_header(image: &[u8]) -> Option<usize> {
    let n = image.len().min(SEARCH);
    (0..n.saturating_sub(16)).step_by(8).find(|&o| {
        let w = |i: usize| u32::from_le_bytes(image[o + i..o + i + 4].try_into().unwrap());
        w(0) == HEADER_MAGIC
            && w(4) == 0
            && w(8) >= 16
            && w(0).wrapping_add(w(4)).wrapping_add(w(8)).wrapping_add(w(12)) == 0
    })
}

/// A memory map entry: (base, length, type: 1 = available).
pub type MmapEntry = (u64, u64, u32);

fn tag(out: &mut Vec<u8>, kind: u32, payload: &[u8]) {
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(8 + payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
}

/// Boot information: tags 1 (command line), 6 (memory map), 15 or 14
/// (RSDP copy; v2 when `rsdp` is longer than 20 bytes), then the end tag.
pub fn build_info(cmdline: &str, mmap: &[MmapEntry], rsdp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + cmdline.len() + mmap.len() * 24 + rsdp.len());
    out.extend_from_slice(&[0; 8]); // total size, reserved
    let mut c = Vec::from(cmdline.as_bytes());
    c.push(0);
    tag(&mut out, 1, &c);
    let mut m = Vec::with_capacity(8 + mmap.len() * 24);
    m.extend_from_slice(&24u32.to_le_bytes()); // entry size
    m.extend_from_slice(&0u32.to_le_bytes()); // entry version
    for &(base, len, kind) in mmap {
        m.extend_from_slice(&base.to_le_bytes());
        m.extend_from_slice(&len.to_le_bytes());
        m.extend_from_slice(&kind.to_le_bytes());
        m.extend_from_slice(&0u32.to_le_bytes());
    }
    tag(&mut out, 6, &m);
    if !rsdp.is_empty() {
        tag(&mut out, if rsdp.len() > 20 { 15 } else { 14 }, rsdp);
    }
    tag(&mut out, 0, &[]);
    let total = out.len() as u32;
    out[..4].copy_from_slice(&total.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn header() -> Vec<u8> {
        let len = 16u32 + 8;
        let mut h = Vec::new();
        for w in [HEADER_MAGIC, 0, len, 0u32.wrapping_sub(HEADER_MAGIC + len)] {
            h.extend_from_slice(&w.to_le_bytes());
        }
        h.extend_from_slice(&[0, 0, 0, 0, 8, 0, 0, 0]); // end tag
        h
    }

    #[test]
    fn finds_header_aligned_and_checks_checksum() {
        let mut img = vec![0u8; 0x1000];
        img.extend_from_slice(&header());
        assert_eq!(find_header(&img), Some(0x1000));
        let mut bad = img.clone();
        bad[0x1000 + 12] ^= 1;
        assert_eq!(find_header(&bad), None);
        let mut late = vec![0u8; 40 * 1024];
        late.extend_from_slice(&header());
        assert_eq!(find_header(&late), None, "beyond 32 KiB");
    }

    #[test]
    fn info_layout() {
        let rsdp = [7u8; 36];
        let info = build_info("lan=10.0.0.1/24", &[(0, 0x9fc00, 1), (0x100000, 0x7f00000, 1)], &rsdp);
        let u32_at = |o: usize| u32::from_le_bytes(info[o..o + 4].try_into().unwrap());
        assert_eq!(u32_at(0) as usize, info.len());
        assert_eq!(info.len() % 8, 0);
        // Walk the tags like a kernel would.
        let mut off = 8;
        let mut kinds = vec![];
        loop {
            let (k, size) = (u32_at(off), u32_at(off + 4) as usize);
            kinds.push(k);
            if k == 1 {
                assert_eq!(&info[off + 8..off + 8 + 15], b"lan=10.0.0.1/24");
                assert_eq!(info[off + 8 + 15], 0);
            }
            if k == 6 {
                assert_eq!(u32_at(off + 8), 24);
                assert_eq!(size, 16 + 2 * 24);
                assert_eq!(u32_at(off + 16 + 24 + 16), 1); // second entry type
            }
            if k == 15 {
                assert_eq!(&info[off + 8..off + 8 + 36], &rsdp);
            }
            if k == 0 {
                break;
            }
            off += size.next_multiple_of(8);
        }
        assert_eq!(kinds, [1, 6, 15, 0]);
    }
}
