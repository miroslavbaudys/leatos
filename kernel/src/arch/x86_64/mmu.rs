//! x86_64 4-level paging encoding (4 KiB pages, 2 MiB / 1 GiB large pages).

use crate::mm::mmu::Perm;

/// PML4 (512 GiB), PDPT (1 GiB), PD (2 MiB), PT (4 KiB).
pub const LEVELS: usize = 4;
pub const TOP_LEVEL_SHIFT: usize = 39;
pub const VA_BITS: u32 = 48;

/// Legacy MMIO below 4 GiB is described by ACPI/E820 on x86 (TODO).
pub const PLATFORM_MMIO: &[(usize, usize)] = &[];

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const PWT: u64 = 1 << 3;
const PCD: u64 = 1 << 4;
const PS: u64 = 1 << 7; // large page (PDPT/PD level)
const NX: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

fn attrs(perm: Perm) -> u64 {
    match perm {
        Perm::Rx => 0,
        Perm::Ro => NX,
        Perm::Rw => WRITABLE | NX,
        Perm::Device => WRITABLE | NX | PCD | PWT,
    }
}

/// 1 GiB (PDPT, level 1) and 2 MiB (PD, level 2) pages.
pub fn block_allowed(level: usize) -> bool {
    level == 1 || level == 2
}
pub fn is_valid(desc: u64) -> bool {
    desc & PRESENT != 0
}
pub fn is_table(desc: u64, level: usize) -> bool {
    level < LEVELS - 1 && desc & PS == 0
}
pub fn desc_addr(desc: u64) -> u64 {
    desc & ADDR_MASK
}
pub fn table_desc(table_pa: u64) -> u64 {
    table_pa | PRESENT | WRITABLE
}
pub fn leaf_desc(pa: u64, perm: Perm, level: usize) -> u64 {
    let large = if level < LEVELS - 1 { PS } else { 0 };
    pa | attrs(perm) | PRESENT | large
}

/// # Safety
/// `root` must be a complete identity map of everything in use.
pub unsafe fn activate(_root: u64) {
    todo!("x86_64: write CR3 (and enable EFER.NXE, CR0.WP)")
}
