//! PVH boot protocol (x86_64): the loader (QEMU `-kernel`, Xen, or a
//! bootloader) enters the kernel in 32-bit protected mode with `ebx`
//! pointing at an `hvm_start_info` structure: memory map, command line,
//! the ACPI RSDP and modules (QEMU `-initrd`). See xen/include/public/arch-x86/hvm/start_info.h.

use super::phys::{self, u32_at, u64_at};
use spin::Once;

const MAGIC: u32 = 0x336e_c578;
const E820_RAM: u32 = 1;

/// Memory map entries kept for the in-RAM upgrade (Multiboot2 info for
/// the next kernel): (base, length, type; 1 = RAM).
pub const MAX_MMAP: usize = 64;
pub type MmapEntry = (u64, u64, u32);

pub struct StartInfo {
    /// The RAM region that contains `kernel_start`: (start, size).
    pub ram: (usize, usize),
    pub rsdp: u64,
    pub cmdline: &'static str,
    pub mmap: [MmapEntry; MAX_MMAP],
    pub mmap_len: usize,
    /// The first boot module (start, length): the install image
    /// (docs/install.md §3.2).
    pub module: Option<(usize, usize)>,
}

/// Copy (base, length, type) entries into a fixed array (no heap yet).
pub(super) fn collect_mmap(
    entries: impl Iterator<Item = MmapEntry>,
) -> ([MmapEntry; MAX_MMAP], usize) {
    let mut map = [(0, 0, 0); MAX_MMAP];
    let mut n = 0;
    for e in entries.take(MAX_MMAP) {
        map[n] = e;
        n += 1;
    }
    (map, n)
}

/// The command line is copied out of firmware memory (which is unmapped
/// after `mm::mmu::init`) into kernel memory.
static CMDLINE: Once<([u8; 1024], usize)> = Once::new();

pub fn parse(start_info: usize, kernel_start: usize) -> Result<StartInfo, &'static str> {
    let si = phys::bytes(start_info as u64, 56)?;
    if u32_at(si, 0) != Some(MAGIC) {
        return Err("pvh: bad start-info magic (not booted via PVH?)");
    }
    let version = u32_at(si, 4).unwrap_or(0);
    let rsdp = u64_at(si, 32).unwrap_or(0);
    let cmdline = match u64_at(si, 24).unwrap_or(0) {
        0 => "",
        pa => copy_cmdline(phys::bytes(pa, 1024)?),
    };
    if version < 1 {
        return Err("pvh: start info v0 has no memory map");
    }
    let (map_pa, entries) = (u64_at(si, 40).unwrap_or(0), u32_at(si, 48).unwrap_or(0));
    let map = phys::bytes(map_pa, entries as usize * 24)?;
    let k = kernel_start as u64;
    let ram = map
        .as_chunks::<24>()
        .0
        .iter()
        .filter(|e| u32_at(*e, 16) == Some(E820_RAM))
        .filter_map(|e| Some((u64_at(e, 0)?, u64_at(e, 8)?)))
        .find(|&(start, size)| start <= k && k < start + size)
        .ok_or("pvh: no RAM region contains the kernel")?;
    // hvm_start_info: nr_modules at 12, modlist_paddr at 16; an entry is
    // paddr, size, cmdline_paddr, reserved (8 bytes each).
    let module = match (u32_at(si, 12).unwrap_or(0), u64_at(si, 16).unwrap_or(0)) {
        (0, _) | (_, 0) => None,
        (_, list) => {
            let e = phys::bytes(list, 32)?;
            module_range(u64_at(e, 0).unwrap_or(0), u64_at(e, 8).unwrap_or(0))?
        }
    };
    let (mmap, mmap_len) = collect_mmap(
        map.as_chunks::<24>()
            .0
            .iter()
            .filter_map(|e| Some((u64_at(e, 0)?, u64_at(e, 8)?, u32_at(e, 16)?))),
    );
    Ok(StartInfo {
        ram: (ram.0 as usize, ram.1 as usize),
        rsdp,
        cmdline,
        mmap,
        mmap_len,
        module,
    })
}

/// A module's (start, length), checked to lie in the low 4 GiB (the boot
/// map, and where `mm::mmu` maps it). Empty modules are ignored.
pub(super) fn module_range(start: u64, len: u64) -> Result<Option<(usize, usize)>, &'static str> {
    if len == 0 {
        return Ok(None);
    }
    phys::bytes(start, len as usize).map_err(|_| "boot module outside the low 4 GiB")?;
    Ok(Some((start as usize, len as usize)))
}

pub(super) fn copy_cmdline(src: &[u8]) -> &'static str {
    let (buf, len) = CMDLINE.call_once(|| {
        let n = src.iter().position(|&b| b == 0).unwrap_or(src.len());
        let mut buf = [0u8; 1024];
        buf[..n].copy_from_slice(&src[..n]);
        (buf, n)
    });
    core::str::from_utf8(&buf[..*len]).unwrap_or("")
}
