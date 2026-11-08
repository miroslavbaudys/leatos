//! Kernel heap: everything from the end of the kernel image to the end of
//! the RAM bank. A simple linked-list allocator is enough for bring-up.
//! Packet buffers come from `net::packet`'s pool, not ad-hoc allocations.

use crate::mm::sym;
use crate::platform::BootInfo;
use crate::println;
use linked_list_allocator::LockedHeap;

#[global_allocator]
static HEAP: LockedHeap = LockedHeap::empty();

pub fn init(info: &BootInfo) {
    let start = sym::kernel_end();
    let end = info.ram.0 + info.ram.1;
    assert!(end > start, "no RAM left for the heap");
    let size = end - start;
    // SAFETY: [start, end) is RAM after the kernel image, mapped Normal RW
    // (boot map, later mm::mmu), used by nothing else; called exactly once.
    unsafe { HEAP.lock().init(start as *mut u8, size) };
    println!(
        "  heap            : {start:#x}..{end:#x} ({} MiB)",
        size >> 20
    );
}

/// (used, free) bytes.
pub fn usage() -> (usize, usize) {
    let h = HEAP.lock();
    (h.used(), h.free())
}
