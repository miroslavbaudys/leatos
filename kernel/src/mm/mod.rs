//! Memory management: heap, page tables, DMA.

#[allow(unsafe_code)] // virtio-drivers `Hal`, `DmaRegion` (volatile access to device-shared memory)
pub mod dma;
#[allow(unsafe_code)] // global allocator initialisation
pub mod heap;
#[allow(unsafe_code)] // one call: activating the finished page tables
pub mod mmu;
#[allow(unsafe_code)] // `unsafe extern` declarations of linker symbols (addresses only)
pub mod sym;
