//! DMA support for `virtio-drivers`.
//!
//! The kernel identity-maps all RAM (VA == PA), and QEMU's virtio devices
//! are cache-coherent, so sharing a buffer with a device is just handing
//! over its address. Real non-coherent hardware would need cache
//! maintenance in `share` / `unshare`.

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use alloc::vec::Vec;
use core::ptr::NonNull;
use spin::Mutex;
use virtio_drivers::{BufferDirection, Hal, PAGE_SIZE, PhysAddr};

/// MMIO ranges that BAR addresses may fall into: every memory BAR that
/// `pci` found and mapped as device memory.
static MMIO: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

pub fn add_mmio_range(start: usize, end: usize) {
    MMIO.lock().push((start, end));
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
        let p = paddr as usize;
        let end = p.checked_add(size).expect("dma: MMIO range overflows");
        assert!(
            MMIO.lock().iter().any(|&(s, e)| p >= s && end <= e),
            "dma: {p:#x}+{size:#x} is not inside a mapped PCI BAR"
        );
        NonNull::new(p as *mut u8).expect("dma: null MMIO address")
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        buffer.as_ptr() as *mut u8 as PhysAddr
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}
}
