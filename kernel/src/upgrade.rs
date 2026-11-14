//! In-RAM upgrade: replace the running kernel with an uploaded one without
//! touching the boot medium (`net::mgmt` receives it, `POST /api/upgrade`).
//! A power cycle boots the SD card's kernel again, so a bad upload is
//! never fatal.
//!
//! Staging area (`mm::heap::take_staging`, top of RAM, never part of the
//! heap), split in three:
//!
//! ```text
//! [ uploaded ELF | flattened image (lo..hi) | scratch (arch::kexec) ]
//! ```
//!
//! [`prepare`] checks the ELF (`boot_image::parse`: this arch, loadable
//! segments between 1 MiB and the staging area, entry inside the image)
//! and its Multiboot2 header, then lays it out flat; [`exec`] hands over
//! to `arch::kexec`, which copies the flat image down to `lo` and enters
//! it like a Multiboot2 loader.

use crate::arch;
use alloc::format;
use alloc::string::String;
use boot_image::LoadPlan;

#[cfg(target_arch = "x86_64")]
const MACHINE: u16 = boot_image::EM_X86_64;
#[cfg(target_arch = "aarch64")]
const MACHINE: u16 = boot_image::EM_AARCH64;
/// Lowest load address accepted (below is firmware and BIOS data).
const MIN_LOAD: u64 = 1 << 20;
const PAGE: usize = 4096;

/// A validated image, laid out and ready to enter.
pub struct Prepared {
    plan: LoadPlan,
    flat_at: usize,
    scratch_at: usize,
}

impl Prepared {
    pub fn describe(&self) -> String {
        format!(
            "load {:#x}..{:#x} ({} KiB), entry {:#x}",
            self.plan.lo,
            self.plan.hi,
            self.plan.len() >> 10,
            self.plan.entry
        )
    }
}

/// The largest upload that can still be laid out (half the staging area
/// for the file, the rest for the flat image and scratch).
pub fn max_image(staging: &[u8]) -> usize {
    staging.len() / 2
}

/// Validate `staging[..len]` and lay it out after itself.
pub fn prepare(staging: &mut [u8], len: usize) -> Result<Prepared, String> {
    if !arch::kexec::SUPPORTED {
        return Err("in-RAM upgrade is not supported on this architecture".into());
    }
    let base = staging.as_ptr() as u64;
    let elf = &staging[..len];
    let plan = boot_image::parse(elf, MACHINE, MIN_LOAD, base)
        .map_err(|e| format!("not a loadable kernel: {e:?}"))?;
    if boot_image::multiboot2::find_header(elf).is_none() {
        return Err("no Multiboot2 header in the first 32 KiB".into());
    }
    let flat_at = len.next_multiple_of(PAGE);
    let scratch_at = (flat_at + plan.len()).next_multiple_of(PAGE);
    if scratch_at + arch::kexec::SCRATCH_SIZE > staging.len() {
        return Err(format!(
            "image too large: needs {} KiB of staging, have {} KiB",
            (scratch_at + arch::kexec::SCRATCH_SIZE) >> 10,
            staging.len() >> 10
        ));
    }
    let (elf, rest) = staging.split_at_mut(flat_at);
    plan.flatten(&elf[..len], &mut rest[..plan.len()]);
    Ok(Prepared {
        plan,
        flat_at,
        scratch_at,
    })
}

/// Enter the prepared image. Devices must already be quiet.
pub fn exec(staging: &'static mut [u8], p: Prepared, cmdline: &str) -> ! {
    let (head, scratch) = staging.split_at_mut(p.scratch_at);
    let flat = &head[p.flat_at..p.flat_at + p.plan.len()];
    arch::kexec::exec(flat, p.plan.lo, p.plan.entry, cmdline, scratch)
}
