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

/// How the RAM region the kernel runs in is split (bytes), for the
/// management page.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub ram: usize,
    /// Kernel image, stacks and whatever lies below it in the region.
    pub kernel: usize,
    pub staging: usize,
    pub heap: usize,
}

static LAYOUT: Once<Layout> = Once::new();

pub fn layout() -> Option<Layout> {
    LAYOUT.get().copied()
}

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
    LAYOUT.call_once(|| Layout {
        ram: info.ram.1,
        kernel: start - info.ram.0,
        staging: STAGING.get().map_or(0, |&(_, l)| l),
        heap: size,
    });
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

/// The staging area, handed out once at a time (to the boot loader in
/// `crate::upgrade`, then the management server).
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

/// Hand the staging area back (the boot loader in `crate::upgrade` did not
/// use it), so [`take_staging`] can give it out again. Taking the slice by
/// value ends the caller's only reference to it.
pub fn return_staging(staging: &'static mut [u8]) {
    let ours = STAGING
        .get()
        .is_some_and(|&(start, len)| staging.as_ptr() as usize == start && staging.len() == len);
    assert!(ours, "return_staging: not the staging area");
    STAGING_TAKEN.store(false, Ordering::Release);
}

/// (used, free) bytes.
pub fn usage() -> (usize, usize) {
    let h = HEAP.lock();
    (h.used(), h.free())
}
