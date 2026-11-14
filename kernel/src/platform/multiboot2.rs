//! Multiboot2 boot information (x86_64 on hardware): Limine, loaded by
//! SeaBIOS/coreboot on the apu4, enters `_start32` like PVH does (32-bit
//! protected mode, paging off) with `eax` = [`MAGIC`] and `ebx` = the
//! boot information. Used tags: command line (1), memory map (6), and the
//! ACPI RSDP copies (14 = v1, 15 = v2). See the Multiboot2 specification §3.6.

use super::phys::{self, u32_at, u64_at};
use super::pvh::{StartInfo, collect_mmap, copy_cmdline};

/// `eax` at entry when a Multiboot2 loader started the kernel.
pub const MAGIC: u32 = 0x36d7_6289;

const TAG_END: u32 = 0;
const TAG_CMDLINE: u32 = 1;
const TAG_MMAP: u32 = 6;
const TAG_ACPI_OLD: u32 = 14;
const TAG_ACPI_NEW: u32 = 15;
const MMAP_AVAILABLE: u32 = 1;

pub fn parse(info: usize, kernel_start: usize, kernel_end: usize) -> Result<StartInfo, &'static str> {
    let total = u32_at(phys::bytes(info as u64, 8)?, 0).ok_or("multiboot2: short info")? as usize;
    if !(16..=1 << 20).contains(&total) {
        return Err("multiboot2: implausible info size");
    }
    let mb = phys::bytes(info as u64, total)?;
    let (mut cmdline, mut rsdp_v1, mut rsdp_v2, mut mmap) = ("", 0u64, 0u64, None);
    let mut off = 8;
    while off + 8 <= total {
        let (Some(kind), Some(size)) = (u32_at(mb, off), u32_at(mb, off + 4)) else {
            break;
        };
        let size = size as usize;
        if kind == TAG_END || size < 8 || off + size > total {
            break;
        }
        let tag = &mb[off..off + size];
        match kind {
            TAG_CMDLINE => cmdline = copy_cmdline(&tag[8..]),
            TAG_MMAP => mmap = Some(tag),
            // The tags hold a *copy* of the RSDP; acpi::parse reads it in place.
            TAG_ACPI_OLD => rsdp_v1 = (info + off + 8) as u64,
            TAG_ACPI_NEW => rsdp_v2 = (info + off + 8) as u64,
            _ => {}
        }
        off += size.next_multiple_of(8);
    }
    let mmap = mmap.ok_or("multiboot2: no memory map")?;
    let entry_size = u32_at(mmap, 8).unwrap_or(0) as usize;
    if entry_size < 24 {
        return Err("multiboot2: bad memory map entry size");
    }
    let available = || {
        mmap[16..]
            .chunks_exact(entry_size)
            .filter(|e| u32_at(e, 16) == Some(MMAP_AVAILABLE))
            .filter_map(|e| Some((u64_at(e, 0)?, u64_at(e, 8)?)))
    };
    // The available RAM after the kernel: start from the entry holding
    // `kernel_end`, then merge touching entries (loaders may split RAM
    // around what they placed). The image itself is RAM too, so the region
    // is extended down to `kernel_start`.
    let k = kernel_end as u64;
    let (mut start, mut end) = available()
        .find(|&(s, l)| s <= k && k < s + l)
        .map(|(s, l)| (s, s + l))
        .ok_or("multiboot2: no available RAM after the kernel")?;
    loop {
        let grown = available().fold((start, end), |(s, e), (bs, bl)| {
            if bs <= e && bs + bl >= s { (s.min(bs), e.max(bs + bl)) } else { (s, e) }
        });
        if grown == (start, end) {
            break;
        }
        (start, end) = grown;
    }
    let start = start.min(kernel_start as u64);
    let (mmap, mmap_len) = collect_mmap(
        mmap[16..]
            .chunks_exact(entry_size)
            .filter_map(|e| Some((u64_at(e, 0)?, u64_at(e, 8)?, u32_at(e, 16)?))),
    );
    Ok(StartInfo {
        ram: (start as usize, (end - start) as usize),
        rsdp: if rsdp_v2 != 0 { rsdp_v2 } else { rsdp_v1 },
        cmdline,
        mmap,
        mmap_len,
    })
}
