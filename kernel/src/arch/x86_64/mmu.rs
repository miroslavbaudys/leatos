//! x86_64 4-level paging encoding (4 KiB pages, 2 MiB / 1 GiB large pages).

use crate::mm::mmu::Perm;

/// PML4 (512 GiB), PDPT (1 GiB), PD (2 MiB), PT (4 KiB).
pub const LEVELS: usize = 4;
pub const TOP_LEVEL_SHIFT: usize = 39;
pub const VA_BITS: u32 = 48;

/// Interrupt controllers at their architectural addresses: IOAPIC and local
/// APIC (the ACPI MADT reports these; on PCs they never move). PCIe ECAM is
/// mapped from `BootInfo`.
pub const PLATFORM_MMIO: &[(usize, usize)] =
    &[(0xfec0_0000, 0xfec0_1000), (0xfee0_0000, 0xfee0_1000)];

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

/// New entries were written into the live tables (only previously
/// unmapped slots): x86 caches no not-present entries, nothing to flush.
pub fn sync_tables() {}

/// Switch to the page tables at `root` (EFER.NXE and CR0.WP were enabled
/// in boot.S, so NX and read-only pages are enforced, also for the kernel).
///
/// # Safety
/// `root` must be a complete identity map of everything in use.
pub unsafe fn activate(root: u64) {
    // SAFETY: forwarded from the caller; writing CR3 also flushes the TLB
    // (no global pages are used).
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags)) };
}
