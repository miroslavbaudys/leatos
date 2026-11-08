//! Kernel heap: everything from the end of the kernel image to the end of
//! the RAM bank. A simple linked-list allocator is enough for bring-up;
//! packet buffers will later come from dedicated pools, not this heap.

use crate::dtb::{self, BootInfo};
use crate::println;
use linked_list_allocator::LockedHeap;

#[global_allocator]
static HEAP: LockedHeap = LockedHeap::empty();

pub fn init(info: &BootInfo) {
    let start = dtb::kernel_end();
    let end = info.ram.0 + info.ram.1;
    assert!(end > start, "no RAM left for the heap");
    let size = end - start;
    // SAFETY: [start, end) is RAM after the kernel image, mapped Normal by
    // boot.S (and later RW by mmu.rs), unused by anything else, and `init` is
    // called exactly once.
    unsafe { HEAP.lock().init(start as *mut u8, size) };
    println!(
        "  heap            : {start:#x}..{end:#x} ({} MiB)",
        size >> 20
    );
}
