//! Fine-grained kernel page tables: replaces the coarse 1 GiB boot map.
//!
//! Still an identity map (VA == PA), 4 KiB granule, 39-bit VA starting at
//! level 1 (same TCR as boot.S). The difference is per-section permissions:
//!
//! | region                 | permissions           |
//! |------------------------|-----------------------|
//! | MMIO (first GiB)       | device, RW, XN        |
//! | DTB (RAM start..kernel)| normal, RO, XN        |
//! | .text                  | normal, **RX**        |
//! | .rodata                | normal, RO, XN        |
//! | .data/.bss/page tables | normal, RW, XN        |
//! | stack guard pages      | **unmapped**          |
//! | stacks, heap           | normal, RW, XN        |
//! | PCIe ECAM              | device, RW, XN        |
//!
//! SCTLR_EL1.WXN is also set, so any writable mapping is never executable.

use crate::dtb::{BootInfo, sym};
use crate::println;
use alloc::alloc::{Layout, alloc_zeroed};
use core::arch::asm;

const PAGE: usize = 4096;
const L2_BLOCK: usize = 2 << 20;
const L1_BLOCK: usize = 1 << 30;

// Descriptor bits (stage 1, 4 KiB granule).
const VALID: u64 = 1 << 0;
const TABLE: u64 = 1 << 1; // table (L1/L2) or page (L3); clear = block
const ATTR_DEVICE: u64 = 0 << 2; // MAIR attr0 = Device-nGnRnE
const ATTR_NORMAL: u64 = 1 << 2; // MAIR attr1 = Normal WB
const AP_RO: u64 = 1 << 7; // AP[2]: read-only (EL1)
const SH_INNER: u64 = 3 << 8;
const AF: u64 = 1 << 10;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Perm {
    /// Executable code.
    Rx,
    /// Read-only data.
    Ro,
    /// Read-write data, never executable.
    Rw,
    /// MMIO.
    Device,
}

impl Perm {
    fn bits(self) -> u64 {
        match self {
            Perm::Rx => ATTR_NORMAL | SH_INNER | AF | AP_RO | UXN,
            Perm::Ro => ATTR_NORMAL | SH_INNER | AF | AP_RO | PXN | UXN,
            Perm::Rw => ATTR_NORMAL | SH_INNER | AF | PXN | UXN,
            Perm::Device => ATTR_DEVICE | AF | PXN | UXN,
        }
    }
}

#[repr(C, align(4096))]
struct Table([u64; 512]);

fn new_table() -> &'static mut Table {
    // SAFETY: the layout is non-zero-sized; an all-zero Table is valid
    // (all entries invalid). Page tables live forever, so leaking is intended.
    unsafe {
        let p = alloc_zeroed(Layout::new::<Table>()) as *mut Table;
        assert!(!p.is_null(), "out of memory for page tables");
        &mut *p
    }
}

/// Builder for an identity-mapped translation table tree.
pub struct AddressSpace {
    l1: &'static mut Table,
    tables: usize,
}

impl AddressSpace {
    fn new() -> Self {
        Self {
            l1: new_table(),
            tables: 1,
        }
    }

    /// Get the next-level table behind `entry`, creating it if needed.
    fn next_table(entry: &mut u64, tables: &mut usize) -> &'static mut Table {
        if *entry & VALID == 0 {
            let t = new_table();
            *tables += 1;
            *entry = (t as *mut Table as u64) | VALID | TABLE;
            t
        } else {
            assert!(
                *entry & TABLE != 0,
                "mmu: region overlaps an existing block mapping"
            );
            // SAFETY: table descriptors we created point at leaked `Table`s.
            unsafe { &mut *((*entry & ADDR_MASK) as *mut Table) }
        }
    }

    /// Identity-map `[start, end)` with `perm`, using the largest blocks
    /// that alignment allows. `start`/`end` must be page-aligned.
    pub fn map(&mut self, start: usize, end: usize, perm: Perm) {
        assert!(
            start.is_multiple_of(PAGE) && end.is_multiple_of(PAGE),
            "mmu: unaligned region"
        );
        let attrs = perm.bits();
        let mut addr = start;
        while addr < end {
            let left = end - addr;
            let l1i = (addr >> 30) & 0x1ff;
            assert!(addr < 1 << 39, "mmu: address beyond 39-bit VA");
            if addr.is_multiple_of(L1_BLOCK) && left >= L1_BLOCK && self.l1.0[l1i] & VALID == 0 {
                self.l1.0[l1i] = addr as u64 | attrs | VALID;
                addr += L1_BLOCK;
                continue;
            }
            let l2 = Self::next_table(&mut self.l1.0[l1i], &mut self.tables);
            let l2i = (addr >> 21) & 0x1ff;
            if addr.is_multiple_of(L2_BLOCK) && left >= L2_BLOCK && l2.0[l2i] & VALID == 0 {
                l2.0[l2i] = addr as u64 | attrs | VALID;
                addr += L2_BLOCK;
                continue;
            }
            let l3 = Self::next_table(&mut l2.0[l2i], &mut self.tables);
            let l3i = (addr >> 12) & 0x1ff;
            assert!(
                l3.0[l3i] & VALID == 0,
                "mmu: page mapped twice at {addr:#x}"
            );
            l3.0[l3i] = addr as u64 | attrs | VALID | TABLE;
            addr += PAGE;
        }
    }

    /// Switch TTBR0 to this table tree and enable WXN.
    ///
    /// # Safety
    /// The new tables must map everything the kernel touches (code, stacks,
    /// heap, MMIO) at the same addresses as before.
    unsafe fn activate(&self) {
        let ttbr = self.l1 as *const Table as u64;
        // MMU off -> swap TTBR0 -> flush TLB -> MMU on (with WXN). Turning
        // the MMU off for the switch avoids TLB conflicts between the old
        // 1 GiB blocks and the new page mappings (break-before-make). Nothing
        // in this block touches data memory while the MMU is off.
        // SAFETY: caller guarantees the new tables are a superset of what
        // is in use; the sequence is self-contained.
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
                ttbr = in(reg) ttbr,
                options(nostack),
            );
        }
    }
}

fn align_down(x: usize) -> usize {
    x & !(PAGE - 1)
}
fn align_up(x: usize) -> usize {
    (x + PAGE - 1) & !(PAGE - 1)
}

/// Build the kernel address space and switch to it. Requires the heap.
pub fn init(info: &BootInfo) {
    let mut as_ = AddressSpace::new();
    let (ram_start, ram_size) = info.ram;
    let ram_end = ram_start + ram_size;

    // MMIO: the first GiB on QEMU virt (GIC, UART, RTC, virtio-mmio, PCIe windows).
    as_.map(0, L1_BLOCK, Perm::Device);
    if let Some(p) = info.pcie {
        as_.map(
            align_down(p.ecam),
            align_up(p.ecam + p.ecam_size),
            Perm::Device,
        );
    }

    // RAM before the kernel (DTB): read-only.
    as_.map(ram_start, sym::kernel_start(), Perm::Ro);
    // Kernel image, section by section.
    as_.map(sym::text_start(), sym::text_end(), Perm::Rx);
    as_.map(sym::rodata_start(), sym::rodata_end(), Perm::Ro);
    as_.map(sym::data_start(), sym::data_end(), Perm::Rw);
    // Stacks. The guard pages below each stack are deliberately left unmapped.
    as_.map(sym::exc_stack_bottom(), sym::exc_stack_top(), Perm::Rw);
    as_.map(sym::stack_bottom(), sym::stack_top(), Perm::Rw);
    // Heap: rest of RAM.
    as_.map(sym::kernel_end(), align_down(ram_end), Perm::Rw);

    // SAFETY: everything in use is mapped above at identical addresses.
    unsafe { as_.activate() };

    println!(
        "  mmu             : 4 KiB pages, W^X + WXN, guard pages ({} tables)",
        as_.tables
    );
}

/// Is `addr` inside one of the unmapped stack guard pages?
pub fn guard_page_name(addr: usize) -> Option<&'static str> {
    let in_page = |base: usize| addr >= base && addr < base + PAGE;
    if in_page(sym::stack_guard()) {
        Some("kernel stack overflow (guard page)")
    } else if in_page(sym::exc_stack_guard()) {
        Some("exception stack overflow (guard page)")
    } else {
        None
    }
}
