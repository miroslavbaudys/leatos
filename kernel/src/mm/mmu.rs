//! Arch-neutral page-table builder (identity map, 4 KiB granule,
//! 512-entry tables). Table construction is **safe code**: tables live in an
//! owned arena and are found by index, never through raw descriptor
//! pointers. The single `unsafe` is switching the CPU to the finished tree
//! ([`AddressSpace::activate`]). The arch backend supplies the descriptor
//! encoding.
//!
//! Kernel layout applied by [`init`]:
//!
//! | region                 | permissions           |
//! |------------------------|-----------------------|
//! | platform MMIO          | device, RW, XN        |
//! | DTB/firmware (RAM start..kernel)| RO, XN       |
//! | .text                  | **RX**                |
//! | .rodata                | RO, XN                |
//! | .data/.bss/boot tables | RW, XN                |
//! | stack guard pages      | **unmapped**          |
//! | stacks, heap           | RW, XN                |
//! | PCIe ECAM              | device, RW, XN        |
//!
//! On aarch64 SCTLR_EL1.WXN is also set (writable ⇒ never executable).

use crate::arch::mmu as hw;
use crate::mm::sym;
use crate::platform::BootInfo;
use crate::println;
use alloc::boxed::Box;
use alloc::vec::Vec;

pub const PAGE: usize = 4096;
const ENTRIES: usize = 512;

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

#[repr(C, align(4096))]
pub struct Table([u64; ENTRIES]);

/// Identity-mapped translation table tree under construction.
pub struct AddressSpace {
    /// `tables[0]` is the root. Boxes never move, so their addresses are
    /// stable physical addresses (identity map).
    tables: Vec<Box<Table>>,
}

fn table_addr(t: &Table) -> u64 {
    t as *const Table as u64
}

impl AddressSpace {
    pub fn new() -> Self {
        Self {
            tables: alloc::vec![Box::new(Table([0; ENTRIES]))],
        }
    }

    fn index_of(&self, addr: u64) -> usize {
        self.tables
            .iter()
            .position(|t| table_addr(t) == addr)
            .expect("mmu: table descriptor points outside the arena")
    }

    /// Identity-map `[start, end)` with `perm`, using the largest blocks that
    /// alignment allows. `start` and `end` must be page-aligned.
    pub fn map(&mut self, start: usize, end: usize, perm: Perm) {
        assert!(
            start.is_multiple_of(PAGE) && end.is_multiple_of(PAGE),
            "mmu: unaligned region"
        );
        assert!(
            end as u64 <= 1 << hw::VA_BITS,
            "mmu: region beyond VA space"
        );
        let mut addr = start;
        while addr < end {
            let mut t = 0;
            for level in 0..hw::LEVELS {
                let shift = hw::TOP_LEVEL_SHIFT - 9 * level;
                let size = 1usize << shift;
                let slot = (addr >> shift) & (ENTRIES - 1);
                let entry = self.tables[t].0[slot];
                let last = level == hw::LEVELS - 1;
                let fits = addr.is_multiple_of(size) && end - addr >= size;
                if last || (hw::block_allowed(level) && fits && !hw::is_valid(entry)) {
                    assert!(!hw::is_valid(entry), "mmu: {addr:#x} mapped twice");
                    self.tables[t].0[slot] = hw::leaf_desc(addr as u64, perm, level);
                    addr += size;
                    break;
                }
                t = if hw::is_valid(entry) {
                    assert!(
                        hw::is_table(entry, level),
                        "mmu: {addr:#x} overlaps a block mapping"
                    );
                    self.index_of(hw::desc_addr(entry))
                } else {
                    let new = Box::new(Table([0; ENTRIES]));
                    let desc = hw::table_desc(table_addr(&new));
                    self.tables.push(new);
                    self.tables[t].0[slot] = desc;
                    self.tables.len() - 1
                };
            }
        }
    }

    /// Switch the CPU to this address space and return the table count.
    /// The tables are leaked: the MMU uses them for the rest of the kernel's life.
    ///
    /// # Safety
    /// The tree must identity-map everything the kernel touches from now on
    /// (code, stacks, heap, MMIO) with compatible attributes.
    pub unsafe fn activate(self) -> usize {
        let n = self.tables.len();
        let root = table_addr(&self.tables[0]);
        Vec::leak(self.tables);
        // SAFETY: forwarded from the caller's contract; tables are leaked (live forever).
        unsafe { hw::activate(root) };
        n
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
    let mut space = AddressSpace::new();
    let (ram_start, ram_size) = info.ram;
    let ram_end = ram_start + ram_size;

    for &(start, end) in hw::PLATFORM_MMIO {
        space.map(start, end, Perm::Device);
    }
    if let Some(p) = info.pcie {
        space.map(
            align_down(p.ecam),
            align_up(p.ecam + p.ecam_size),
            Perm::Device,
        );
    }

    // RAM before the kernel (DTB / firmware data): read-only.
    space.map(ram_start, sym::kernel_start(), Perm::Ro);
    // Kernel image, section by section.
    space.map(sym::text_start(), sym::text_end(), Perm::Rx);
    space.map(sym::rodata_start(), sym::rodata_end(), Perm::Ro);
    space.map(sym::data_start(), sym::data_end(), Perm::Rw);
    // Stacks. The guard pages below each stack are deliberately left unmapped.
    space.map(sym::exc_stack_bottom(), sym::exc_stack_top(), Perm::Rw);
    space.map(sym::stack_bottom(), sym::stack_top(), Perm::Rw);
    // Heap: rest of RAM.
    space.map(sym::kernel_end(), align_down(ram_end), Perm::Rw);

    // SAFETY: code, data, stacks, heap and all MMIO in use are mapped above.
    let tables = unsafe { space.activate() };
    println!("  mmu             : 4 KiB pages, W^X, guard pages ({tables} tables)");
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
