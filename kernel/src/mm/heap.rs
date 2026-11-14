//! Kernel heap: everything from the end of the kernel image to the end of
//! the RAM bank, minus the **staging area** at the very top (where an
//! uploaded kernel waits for the in-RAM upgrade, `crate::upgrade`: the
//! copy into place must never overwrite it). A simple linked-list
//! allocator is enough for bring-up. Packet buffers come from
//! `net::packet`'s pool, not ad-hoc allocations.

use crate::mm::sym;
use crate::platform::BootInfo;
use crate::println;
use core::sync::atomic::{AtomicBool, Ordering};
use linked_list_allocator::LockedHeap;
use spin::Once;

/// Staging area size, where the arch supports the in-RAM upgrade and RAM allows.
pub const STAGING_SIZE: usize = 32 << 20;
static STAGING: Once<(usize, usize)> = Once::new();
static STAGING_TAKEN: AtomicBool = AtomicBool::new(false);

#[global_allocator]
static HEAP: LockedHeap = LockedHeap::empty();

pub fn init(info: &BootInfo) {
    let start = sym::kernel_end();
    let end = info.ram.0 + info.ram.1;
    assert!(end > start, "no RAM left for the heap");
    let mut end = end;
    if crate::arch::kexec::SUPPORTED && end - start >= 4 * STAGING_SIZE {
        let s = (end - STAGING_SIZE) & !0xfff;
        STAGING.call_once(|| (s, end - s));
        end = s;
    }
    let size = end - start;
    // SAFETY: [start, end) is RAM after the kernel image, mapped Normal RW
    // (boot map, later mm::mmu), used by nothing else; called exactly once.
    unsafe { HEAP.lock().init(start as *mut u8, size) };
    println!(
        "  heap            : {start:#x}..{end:#x} ({} MiB){}",
        size >> 20,
        STAGING
            .get()
            .map(|&(s, l)| alloc::format!(", upgrade staging {s:#x}..{:#x}", s + l))
            .unwrap_or_default()
    );
}

/// The staging area, handed out once (to the management server).
pub fn take_staging() -> Option<&'static mut [u8]> {
    let &(start, len) = STAGING.get()?;
    if STAGING_TAKEN.swap(true, Ordering::AcqRel) {
        return None;
    }
    // SAFETY: [start, start + len) is RAM excluded from the heap above,
    // mapped RW by mm::mmu (its heap mapping runs to the end of RAM),
    // and this is the only reference ever created (STAGING_TAKEN).
    Some(unsafe { core::slice::from_raw_parts_mut(start as *mut u8, len) })
}

/// (used, free) bytes.
pub fn usage() -> (usize, usize) {
    let h = HEAP.lock();
    (h.used(), h.free())
}
