//! DMA support: the `virtio-drivers` `Hal`, and [`DmaRegion`] for drivers
//! that own their descriptor rings (igb).
//!
//! The kernel identity-maps all RAM (VA == PA), and the devices we drive
//! (QEMU's, and PCIe on x86 hardware) are cache-coherent, so sharing a
//! buffer with a device is just handing over its address ([`bus_addr`]).
//! Non-coherent hardware would need cache maintenance in `share` /
//! `unshare` and around [`DmaRegion`] accesses.

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use alloc::vec::Vec;
use core::ptr::NonNull;
use spin::Mutex;
use virtio_drivers::{BufferDirection, Hal, PAGE_SIZE, PhysAddr};

/// MMIO ranges that BAR addresses may fall into: every memory BAR that
/// `pci` found and mapped as device memory.
static MMIO: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

/// The address a device uses for `ptr` (identity mapping, no IOMMU).
pub fn bus_addr(ptr: *const u8) -> u64 {
    ptr as u64
}

/// Memory shared with a device for its whole lifetime: zeroed, aligned,
/// accessed only with volatile 32/64-bit loads and stores at checked
/// offsets (the device may write it at any time). Never freed: a device
/// that was not reset could still write to it, so it is leaked instead.
pub struct DmaRegion {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: the region exclusively owns its allocation (like a `Box`); the
// only other party is the device, which is not a thread.
unsafe impl Send for DmaRegion {}

impl DmaRegion {
    /// `len` bytes aligned to `align` (a power of two). Panics when out of memory.
    pub fn new(len: usize, align: usize) -> Self {
        assert!(len > 0 && len.is_multiple_of(8));
        let layout = Layout::from_size_align(len, align.max(8)).expect("dma: bad region layout");
        // SAFETY: `layout` has non-zero size.
        let ptr = unsafe { alloc_zeroed(layout) };
        Self {
            ptr: NonNull::new(ptr).expect("dma: out of memory"),
            len,
        }
    }

    pub fn bus_addr(&self) -> u64 {
        bus_addr(self.ptr.as_ptr())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    fn at<T>(&self, offset: usize) -> *mut T {
        let size = core::mem::size_of::<T>();
        assert!(
            offset.is_multiple_of(size) && offset + size <= self.len,
            "dma: offset {offset:#x} out of range"
        );
        self.ptr.as_ptr().wrapping_add(offset).cast()
    }

    pub fn read32(&self, offset: usize) -> u32 {
        // SAFETY: in bounds and aligned (checked by `at`), memory owned by
        // this region for 'static; volatile because the device writes it.
        unsafe { self.at::<u32>(offset).read_volatile() }
    }

    pub fn write32(&mut self, offset: usize, value: u32) {
        // SAFETY: as in `read32`.
        unsafe { self.at::<u32>(offset).write_volatile(value) }
    }

    pub fn write64(&mut self, offset: usize, value: u64) {
        // SAFETY: as in `read32`.
        unsafe { self.at::<u64>(offset).write_volatile(value) }
    }

    /// Write a buffer's bus address into a descriptor: the DMA hand-off.
    ///
    /// # Safety
    /// Once the device sees the descriptor, it may read or write the buffer
    /// at `addr` (as large as the descriptor says). The caller must keep
    /// that memory allocated and untouched by Rust code until the device
    /// reports the descriptor done.
    pub unsafe fn write_buffer_addr(&mut self, offset: usize, addr: u64) {
        self.write64(offset, addr);
    }
}

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
