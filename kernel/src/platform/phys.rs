//! Read-only views of firmware memory (PVH start info, ACPI tables) during
//! platform discovery, while the boot identity map covers all of the low
//! 4 GiB. Parsers work on the returned byte slices with bounds-checked
//! accessors, so the only unsafe operation is constructing the view.
//!
//! The views must not outlive discovery: `mm::mmu::init` later unmaps
//! everything that isn't kernel, heap or MMIO. Anything needed afterwards
//! is copied into `BootInfo` (plain data) or kernel statics.

/// Bytes `[pa, pa + len)` of physical memory.
///
/// Callers pass addresses taken from firmware structures. A bad address
/// reads garbage (the boot map has no holes below 4 GiB), which the parsers
/// reject through signatures, lengths and checksums.
pub fn bytes(pa: u64, len: usize) -> Result<&'static [u8], &'static str> {
    if pa == 0 || pa.checked_add(len as u64).is_none_or(|end| end > 1 << 32) {
        return Err("firmware pointer outside the low 4 GiB boot map");
    }
    // SAFETY: the boot page tables identity-map all of [0, 4 GiB) (boot.S),
    // the range was checked to lie inside it, and firmware tables are only
    // read during single-threaded discovery, before the final map is built.
    Ok(unsafe { core::slice::from_raw_parts(pa as usize as *const u8, len) })
}

pub fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

pub fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

pub fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}
