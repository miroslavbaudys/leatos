//! aarch64 stage-1 descriptor encoding (4 KiB granule, 39-bit VA starting
//! at level 1, same TCR as boot.S) and TTBR0 switching.

use crate::mm::mmu::Perm;
use core::arch::asm;

/// Levels walked by the neutral builder: L1 (1 GiB), L2 (2 MiB), L3 (4 KiB).
pub const LEVELS: usize = 3;
pub const TOP_LEVEL_SHIFT: usize = 30;
pub const VA_BITS: u32 = 39;

/// Device MMIO that is not described elsewhere: on QEMU virt the whole
/// first GiB (GIC, UART, RTC, virtio-mmio, PCIe MMIO/PIO windows).
pub const PLATFORM_MMIO: &[(usize, usize)] = &[(0, 1 << 30)];

const VALID: u64 = 1 << 0;
const TABLE: u64 = 1 << 1; // table (L1/L2) or page (L3); clear = block
const ATTR_DEVICE: u64 = 0 << 2; // MAIR attr0 = Device-nGnRnE
const ATTR_NORMAL: u64 = 1 << 2; // MAIR attr1 = Normal WB
const AP_RO: u64 = 1 << 7;
const SH_INNER: u64 = 3 << 8;
const AF: u64 = 1 << 10;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

fn attrs(perm: Perm) -> u64 {
    match perm {
        Perm::Rx => ATTR_NORMAL | SH_INNER | AF | AP_RO | UXN,
        Perm::Ro => ATTR_NORMAL | SH_INNER | AF | AP_RO | PXN | UXN,
        Perm::Rw => ATTR_NORMAL | SH_INNER | AF | PXN | UXN,
        Perm::Device => ATTR_DEVICE | AF | PXN | UXN,
    }
}

/// 1 GiB (level 0 here = L1) and 2 MiB (L2) blocks are allowed with 4 KiB pages.
pub fn block_allowed(level: usize) -> bool {
    level < LEVELS - 1
}
pub fn is_valid(desc: u64) -> bool {
    desc & VALID != 0
}
pub fn is_table(desc: u64, level: usize) -> bool {
    level < LEVELS - 1 && desc & TABLE != 0
}
pub fn desc_addr(desc: u64) -> u64 {
    desc & ADDR_MASK
}
pub fn table_desc(table_pa: u64) -> u64 {
    table_pa | VALID | TABLE
}
pub fn leaf_desc(pa: u64, perm: Perm, level: usize) -> u64 {
    let kind = if level == LEVELS - 1 { TABLE } else { 0 }; // page vs block
    pa | attrs(perm) | VALID | kind
}

/// Switch TTBR0 to `root` and enable WXN.
///
/// # Safety
/// `root` must be a complete, live identity-map tree covering everything
/// the kernel uses, with attributes compatible with the current ones.
pub unsafe fn activate(root: u64) {
    // MMU off -> swap TTBR0 -> flush TLB -> MMU on (+WXN). Turning the MMU
    // off for the switch avoids TLB conflicts between the old 1 GiB blocks
    // and the new page mappings. No data memory is touched in between.
    // SAFETY: caller guarantees the tables; the sequence is self-contained.
    unsafe {
        asm!(
            "dsb ish",
            "mrs {s}, sctlr_el1",
            "bic {t}, {s}, #1",
            "msr sctlr_el1, {t}",
            "isb",
            "msr ttbr0_el1, {ttbr}",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            "orr {s}, {s}, #(1 << 19)", // WXN
            "msr sctlr_el1, {s}",
            "isb",
            s = out(reg) _,
            t = out(reg) _,
            ttbr = in(reg) root,
            options(nostack),
        );
    }
}
