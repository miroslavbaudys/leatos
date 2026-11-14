//! Kernel upgrades (docs/upgrades.md).
//!
//! **In RAM** (`POST /api/upgrade`): replace the running kernel with an
//! uploaded one without touching the boot medium. A power cycle boots the
//! boot partition's kernel again, so a bad upload is never fatal.
//!
//! **Persistent** (`POST /api/upgrade/persist`): the uploaded kernel is
//! written to the store's `images` area as a trial record, and the router
//! reboots. The kernel on the boot partition (Limine starts it; it is only
//! ever replaced by reflashing) is the loader: at every boot, [`boot`]
//! looks at the `images` area and enters the current stored kernel with
//! `arch::kexec`, adding `image=<slot>:<seq>` to the command line:
//!
//! - a confirmed record: entered;
//! - a trial not yet booted: marked booted (one sector), then entered;
//! - a trial already marked booted: that kernel never confirmed (it
//!   panicked, hung into a watchdog reset, lost power, or nobody confirmed
//!   it within `trial_secs`): erased, and the previous record (or the
//!   boot partition's kernel itself) is used;
//! - nothing valid, `image=golden`, no store: the boot partition's kernel
//!   boots itself.
//!
//! The stored kernel confirms itself only through `POST
//! /api/upgrade/confirm` (it booted, has a network and serves the web
//! interface); without it, it reboots after `trial_secs` and the loader
//! rolls back. The hardware watchdog is armed before the jump.
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
use crate::drivers::watchdog::HwWatchdog;
use crate::executor::block_on;
use crate::store::{Store, describe, slot_name};
use crate::{config, println};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use boot_image::LoadPlan;
use config_store::{FLAG_BOOTED, FLAG_TRIAL, RecordHeader, Slot};
use spin::Once;

/// The store area holding kernels.
pub const AREA: &str = "images";
/// Record schema version of a stored kernel: the payload is the ELF.
pub const IMAGE_FORMAT: u32 = 1;

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
    // The other cores must not run while the kernel is overwritten.
    crate::smp::stop_others();
    arch::smp::park_others();
    crate::watchdog::pet_now();
    arch::kexec::exec(flat, p.plan.lo, p.plan.entry, cmdline, scratch)
}

/// `cmdline` with `key=value` instead of any `key=...` it had.
pub fn with_arg(cmdline: &str, key: &str, value: &str) -> String {
    let mut out = String::new();
    for kv in cmdline.split_whitespace() {
        if kv.strip_prefix(key).is_some_and(|r| r.starts_with('=')) {
            continue;
        }
        out.push_str(kv);
        out.push(' ');
    }
    out.push_str(key);
    out.push('=');
    out.push_str(value);
    out
}

/// Where the running kernel came from (`/api/status` `image.source`).
static SOURCE: Once<String> = Once::new();
/// This boot's kernel is a trial from the store: its slot and header
/// (flags trial + booted). Confirm clears the flags.
static TRIAL: Once<(Slot, RecordHeader)> = Once::new();

pub fn source() -> &'static str {
    SOURCE.get().map_or("boot partition", |s| s.as_str())
}

/// The trial kernel this boot runs, if it is one.
pub fn trial() -> Option<(Slot, RecordHeader)> {
    TRIAL.get().copied()
}

fn set_source(s: String) {
    println!("  image           : {s}");
    SOURCE.call_once(|| s);
}

/// At boot, before `config::load`: enter the kernel stored on the disk if
/// there is one (never returns then), else note why this kernel runs.
/// `hw`: re-armed right before the jump, so the new kernel has the full
/// timeout to boot.
pub fn boot(store: Option<&mut Store>, hw: &mut Option<Box<dyn HwWatchdog>>) {
    match config::arg_of("image") {
        Some("golden") => {
            return set_source(String::from("boot partition (image=golden: stored kernels not used)"));
        }
        Some("ram") => return set_source(String::from("in-RAM upgrade")),
        Some(v) => return from_store(store, v),
        None => {}
    }
    if !arch::kexec::SUPPORTED {
        return set_source(String::from("boot partition"));
    }
    let Some(store) = store else {
        return set_source(String::from("boot partition (no store)"));
    };
    let why = chain_load(store, hw);
    set_source(format!("boot partition ({why})"));
}

/// This kernel was entered by the loader: `v` = `A:<seq>`. Find out
/// whether it is a trial (the loader marked it booted).
fn from_store(store: Option<&mut Store>, v: &str) {
    let parsed = v.split_once(':').and_then(|(s, q)| {
        let slot = match s {
            "A" => Slot::A,
            "B" => Slot::B,
            _ => return None,
        };
        Some((slot, q.parse::<u64>().ok()?))
    });
    let Some((slot, seq)) = parsed else {
        return set_source(format!("unknown (image={v})"));
    };
    let h = store.and_then(|st| block_on(st.header(AREA, slot)).ok().flatten());
    // The source stays true for the whole boot; whether it is still a
    // trial is `trial()` (cleared by a confirm), not part of this text.
    let what = match h {
        Some(h) if h.seq == seq && h.is_trial() => {
            TRIAL.call_once(|| (slot, h));
            println!(
                "  image           : trial kernel: confirm within {} s or it is rolled back",
                config::trial_secs()
            );
            ""
        }
        Some(h) if h.seq == seq => "",
        _ => ", record no longer in the store",
    };
    set_source(format!("store (slot {}, seq {seq}{what})", slot_name(slot)));
}

/// The loader. Returns why it did not jump.
fn chain_load(store: &mut Store, hw: &mut Option<Box<dyn HwWatchdog>>) -> String {
    let mut reverted: Option<u64> = None;
    let note = |r: Option<u64>| r.map(|s| format!(", trial seq {s} rolled back")).unwrap_or_default();
    loop {
        let (rec, state) = match block_on(store.read_current(AREA, IMAGE_FORMAT)) {
            Ok(r) => r,
            Err(e) => return format!("store: {e}{}", note(reverted)),
        };
        println!(
            "  store images    : slot A {}, slot B {}",
            describe(&state.a),
            describe(&state.b)
        );
        let Some(rec) = rec else {
            return format!("no kernel in the store{}", note(reverted));
        };
        let (h, slot) = (rec.header, rec.slot);
        let name = slot_name(slot);
        let erase = |why: &str, store: &mut Store| {
            println!("  image           : slot {name} seq {}: {why}: rolling back", h.seq);
            if let Err(e) = block_on(store.erase(AREA, slot)) {
                println!("  image           : erasing slot {name} failed: {e}");
            }
        };
        if h.is_trial() && h.flags & FLAG_BOOTED != 0 {
            if reverted.is_some() {
                return String::from("a failed trial kernel could not be erased");
            }
            erase("trial kernel never confirmed", store);
            reverted = Some(h.seq);
            continue;
        }
        let Some(staging) = crate::mm::heap::take_staging() else {
            return String::from("no staging area");
        };
        let len = rec.payload.len();
        let prepared = if len > max_image(staging) {
            Err(format!("{len} bytes: larger than the staging area allows"))
        } else {
            staging[..len].copy_from_slice(&rec.payload);
            prepare(staging, len)
        };
        let p = match prepared {
            Ok(p) => p,
            Err(e) => {
                crate::mm::heap::return_staging(staging);
                if !h.is_trial() || reverted.is_some() {
                    return format!("stored kernel slot {name} seq {} rejected: {e}", h.seq);
                }
                erase(&format!("rejected ({e})"), store);
                reverted = Some(h.seq);
                continue;
            }
        };
        drop(rec);
        if h.is_trial() {
            let marked = h.with_flags(FLAG_TRIAL | FLAG_BOOTED);
            if let Err(e) = block_on(store.rewrite_header(AREA, slot, marked)) {
                crate::mm::heap::return_staging(staging);
                if reverted.is_some() {
                    return format!("cannot mark the trial kernel booted ({e})");
                }
                erase(&format!("cannot mark it booted ({e})"), store);
                reverted = Some(h.seq);
                continue;
            }
        }
        let cmdline = with_arg(config::bootargs(), "image", &format!("{name}:{}", h.seq));
        println!(
            "  image           : entering the stored kernel (slot {name}, seq {}{}): {}{}",
            h.seq,
            if h.is_trial() { ", trial" } else { "" },
            p.describe(),
            note(reverted)
        );
        crate::watchdog::arm_early(hw);
        exec(staging, p, &cmdline);
    }
}
