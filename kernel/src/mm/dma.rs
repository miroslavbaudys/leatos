//! DMA support for `virtio-drivers`.
//!
//! The kernel identity-maps all RAM (VA == PA), and QEMU's virtio devices
//! are cache-coherent, so sharing a buffer with a device is just handing
//! over its address. Real non-coherent hardware would need cache
//! maintenance in `share` / `unshare`.

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use virtio_drivers::{BufferDirection, Hal, PAGE_SIZE, PhysAddr};

/// MMIO range that BAR addresses may fall into (set by `pci`).
static MMIO_START: AtomicUsize = AtomicUsize::new(0);
static MMIO_END: AtomicUsize = AtomicUsize::new(0);

pub fn set_mmio_window(start: usize, end: usize) {
    MMIO_START.store(start, Ordering::Relaxed);
    MMIO_END.store(end, Ordering::Relaxed);
}

fn layout(pages: usize) -> Layout {
    Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).expect("dma: bad layout")
}

pub struct DmaHal;

// SAFETY: `dma_alloc` returns zeroed, page-aligned, exclusively owned heap
// memory; addresses are identity-mapped; MMIO translation is range-checked.
unsafe impl Hal for DmaHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        // SAFETY: the layout has non-zero size (pages >= 1 by contract).
        let ptr = unsafe { alloc_zeroed(layout(pages.max(1))) };
        let ptr = NonNull::new(ptr).expect("dma: out of memory");
        (ptr.as_ptr() as PhysAddr, ptr)
    }

    unsafe fn dma_dealloc(_paddr: PhysAddr, vaddr: NonNull<u8>, pages: usize) -> i32 {
        // SAFETY: the caller passes back exactly what dma_alloc returned.
        unsafe { dealloc(vaddr.as_ptr(), layout(pages.max(1))) };
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, size: usize) -> NonNull<u8> {
        let (start, end) = (
            MMIO_START.load(Ordering::Relaxed),
            MMIO_END.load(Ordering::Relaxed),
        );
        let p = paddr as usize;
        assert!(
            p >= start && p.checked_add(size).is_some_and(|e| e <= end),
            "dma: BAR {p:#x}+{size:#x} outside MMIO window {start:#x}..{end:#x}"
        );
        NonNull::new(p as *mut u8).expect("dma: null MMIO address")
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        buffer.as_ptr() as *mut u8 as PhysAddr
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}
}
