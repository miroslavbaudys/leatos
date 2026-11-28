//! Multiboot2 (specification 2.0): check that an image carries a header,
//! and build the boot information a loader passes in `ebx`. The kernel's
//! parser is `kernel/src/platform/multiboot2.rs`; [`build_info`] emits the
//! tags it reads (command line, memory map, ACPI RSDP, framebuffer).

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

/// Boot information tag 8: the screen the loader set up (§3.6.12). The
/// kernel's console screen uses it (`kernel/src/drivers/screen.rs`); a
/// kernel entered by kexec gets it passed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Framebuffer {
    pub addr: u64,
    /// Bytes per line.
    pub pitch: u32,
    /// Pixels, or characters in EGA text mode.
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    /// 0 = indexed colour, 1 = direct RGB, 2 = EGA text.
    pub kind: u8,
    /// Direct RGB: (field position, mask size) of red, green and blue.
    pub rgb: [(u8, u8); 3],
}

pub const TAG_FRAMEBUFFER: u32 = 8;
pub const FB_RGB: u8 = 1;
pub const FB_EGA_TEXT: u8 = 2;

impl Framebuffer {
    /// From a whole tag 8 (with its 8-byte type and size header).
    pub fn parse(tag: &[u8]) -> Option<Self> {
        let u32_at = |o: usize| Some(u32::from_le_bytes(tag.get(o..o + 4)?.try_into().ok()?));
        if u32_at(0)? != TAG_FRAMEBUFFER || (u32_at(4)? as usize) > tag.len() {
            return None;
        }
        let kind = *tag.get(29)?;
        let rgb = if kind == FB_RGB {
            let c = tag.get(32..38)?;
            [(c[0], c[1]), (c[2], c[3]), (c[4], c[5])]
        } else {
            [(0, 0); 3]
        };
        Some(Self {
            addr: u64::from_le_bytes(tag.get(8..16)?.try_into().ok()?),
            pitch: u32_at(16)?,
            width: u32_at(20)?,
            height: u32_at(24)?,
            bpp: tag[28],
            kind,
            rgb,
        })
    }

    /// The tag's payload (after the type and size).
    fn payload(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(32);
        p.extend_from_slice(&self.addr.to_le_bytes());
        p.extend_from_slice(&self.pitch.to_le_bytes());
        p.extend_from_slice(&self.width.to_le_bytes());
        p.extend_from_slice(&self.height.to_le_bytes());
        p.extend_from_slice(&[self.bpp, self.kind, 0, 0]);
        if self.kind == FB_RGB {
            for (pos, size) in self.rgb {
                p.extend_from_slice(&[pos, size]);
            }
        }
        p
    }
}

/// Boot information: tags 1 (command line), 6 (memory map), 15 or 14
/// (RSDP copy; v2 when `rsdp` is longer than 20 bytes), 8 (framebuffer, if
/// any), then the end tag.
pub fn build_info(
    cmdline: &str,
    mmap: &[MmapEntry],
    rsdp: &[u8],
    fb: Option<&Framebuffer>,
) -> Vec<u8> {
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
    if let Some(fb) = fb {
        tag(&mut out, TAG_FRAMEBUFFER, &fb.payload());
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
        let fb = Framebuffer {
            addr: 0xfd00_0000,
            pitch: 5120,
            width: 1280,
            height: 800,
            bpp: 32,
            kind: FB_RGB,
            rgb: [(16, 8), (8, 8), (0, 8)],
        };
        let info = build_info(
            "lan=10.0.0.1/24",
            &[(0, 0x9fc00, 1), (0x100000, 0x7f00000, 1)],
            &rsdp,
            Some(&fb),
        );
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
            if k == TAG_FRAMEBUFFER {
                assert_eq!(size, 38);
                assert_eq!(Framebuffer::parse(&info[off..off + size]), Some(fb));
            }
            if k == 0 {
                break;
            }
            off += size.next_multiple_of(8);
        }
        assert_eq!(kinds, [1, 6, 15, 8, 0]);
        let plain = build_info("", &[], &[], None);
        assert_eq!(plain.len(), 8 + 16 + 16 + 8, "no framebuffer tag without one");
    }

    #[test]
    fn framebuffer_tag_parse() {
        // EGA text, as Limine reports it: no colour fields.
        let mut t = vec![0u8; 32];
        t[..4].copy_from_slice(&TAG_FRAMEBUFFER.to_le_bytes());
        t[4..8].copy_from_slice(&32u32.to_le_bytes());
        t[8..16].copy_from_slice(&0xb8000u64.to_le_bytes());
        t[16..20].copy_from_slice(&160u32.to_le_bytes());
        t[20..24].copy_from_slice(&80u32.to_le_bytes());
        t[24..28].copy_from_slice(&25u32.to_le_bytes());
        t[28] = 16;
        t[29] = FB_EGA_TEXT;
        let fb = Framebuffer::parse(&t).unwrap();
        assert_eq!((fb.addr, fb.width, fb.height, fb.kind), (0xb8000, 80, 25, FB_EGA_TEXT));
        // RGB needs its colour fields; wrong type or a size past the end: none.
        t[29] = FB_RGB;
        assert_eq!(Framebuffer::parse(&t), None);
        t[29] = FB_EGA_TEXT;
        t[4..8].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(Framebuffer::parse(&t), None);
        t[4..8].copy_from_slice(&32u32.to_le_bytes());
        t[0] = 7;
        assert_eq!(Framebuffer::parse(&t), None);
        assert_eq!(Framebuffer::parse(&t[..20]), None);
    }
}
