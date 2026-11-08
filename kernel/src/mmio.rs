//! Safe, bounds-checked MMIO register access.
//!
//! [`Region::new`] is the **only** place where an address becomes a device
//! region (one `unsafe`). After that, every access is safe and
//! bounds-checked, and goes through `safe-mmio`, which uses inline asm on
//! aarch64. This matters under hypervisors (HVF/KVM): compiler-generated
//! `ldp` or post-index forms on MMIO can't be emulated and would fault.
//!
//! Registers are addressed by **byte offset**, matching datasheets. All
//! accesses are 32-bit and must be 4-byte aligned. 64-bit registers that
//! allow 32-bit access (GICv3) are handled by [`Region::read64_split`].

use core::ptr::NonNull;
use safe_mmio::UniqueMmioPointer;
use safe_mmio::fields::ReadWrite;

pub struct Region {
    regs: UniqueMmioPointer<'static, [ReadWrite<u32>]>,
    base: usize,
}

impl Region {
    /// Take ownership of the device registers at `[base, base + len)`.
    ///
    /// # Safety
    /// The range must be device MMIO, mapped as Device memory by `mm::mmu`,
    /// valid for the kernel's lifetime, and not accessed through any other
    /// `Region` or pointer (exclusive ownership).
    pub unsafe fn new(base: usize, len: usize) -> Self {
        assert!(base.is_multiple_of(4) && len.is_multiple_of(4) && len > 0);
        let ptr = NonNull::new(base as *mut ReadWrite<u32>).expect("mmio: null base");
        // SAFETY: forwarded from the caller's contract.
        let regs = unsafe { UniqueMmioPointer::new(NonNull::slice_from_raw_parts(ptr, len / 4)) };
        Self { regs, base }
    }

    fn reg(&mut self, offset: usize) -> UniqueMmioPointer<'_, ReadWrite<u32>> {
        assert!(
            offset.is_multiple_of(4),
            "mmio: unaligned offset {offset:#x}"
        );
        self.regs
            .get(offset / 4)
            .unwrap_or_else(|| panic!("mmio: offset {offset:#x} out of range at {:#x}", self.base))
    }

    pub fn read32(&mut self, offset: usize) -> u32 {
        self.reg(offset).read()
    }

    pub fn write32(&mut self, offset: usize, value: u32) {
        self.reg(offset).write(value);
    }

    pub fn modify32(&mut self, offset: usize, f: impl FnOnce(u32) -> u32) {
        let v = self.read32(offset);
        self.write32(offset, f(v));
    }

    /// Read a 64-bit register as two 32-bit halves (low first).
    pub fn read64_split(&mut self, offset: usize) -> u64 {
        let lo = self.read32(offset) as u64;
        let hi = self.read32(offset + 4) as u64;
        hi << 32 | lo
    }

    /// Write a 64-bit register as two 32-bit halves (low first).
    pub fn write64_split(&mut self, offset: usize, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }
}
