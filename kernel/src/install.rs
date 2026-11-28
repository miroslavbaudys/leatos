//! The installer (docs/install.md): leatos booted from a USB stick or an
//! ISO writes the install image Limine (or QEMU `-initrd`) loaded as a boot
//! module to a disk it has a driver for.
//!
//! - The module is kept out of the heap (`mm::heap::region`) and checked as
//!   an install image (`crates/install-image`: header, extents, SHA-256).
//! - `install=1` runs [`run`] instead of the router: no datapath, no
//!   services, no store of its own. It lists the disks, the user types the
//!   target's PCI address (or `install_target=` names it), the target's
//!   config is read (`install_keep=0`: not), the image is written with
//!   every sector it covers (the gaps as zeros) and read back, the config
//!   is stored in the new store, and the machine reboots.
//! - **The one place the kernel formats a disk** (docs/config-and-storage.md,
//!   Safety): only with `install=1`, a module whose hash checks, and the
//!   confirmation. The install medium itself is never seen: SeaBIOS read
//!   it, leatos has no USB, CD or ISO driver.

use crate::drivers::{DISK_MAX_SECTORS, Disk};
use crate::executor::block_on;
use crate::pci::Pci;
use crate::{config, console, print, println, store, timer};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;
use install_image::{Image, Piece, SECTOR};

/// Check the boot module, if there is one, and log the result. Runs after
/// the heap and the packet pool are in use: a module the heap overlapped
/// fails its hash here.
pub fn check_module() {
    let Some(bytes) = crate::mm::heap::module() else {
        return;
    };
    match install_image::parse(bytes) {
        Ok(img) => println!("  install image   : ok, {}", summary(&img)),
        Err(e) => println!("  install image   : invalid ({e})"),
    }
}

fn summary(img: &Image) -> String {
    let h = img.sha256();
    format!(
        "{} MiB disk image, {} extents, {} KiB of data, sha256 {:02x}{:02x}{:02x}{:02x}…",
        img.sectors() >> 11,
        img.extents().count(),
        img.data_len() >> 10,
        h[0],
        h[1],
        h[2],
        h[3]
    )
}

/// Why the installer stopped.
enum Stop {
    /// Before the first write: the disks are as they were.
    Abort(String),
    /// While or after writing: the target is not a working install.
    Failed(String),
}

/// The installer (`install=1`); never returns: reboots once installed,
/// else waits for the user to power off.
pub fn run(pci: Option<&mut Pci>) -> ! {
    println!();
    println!("install: leatos installer (docs/install.md)");
    match install(pci) {
        Ok(()) => {
            println!("install: done. Remove the install medium (USB stick / ISO); rebooting in 5 s");
            block_on(timer::sleep(Duration::from_secs(5)));
            crate::arch::power::reset()
        }
        Err(Stop::Abort(why)) => println!("install: {why}: nothing written"),
        Err(Stop::Failed(why)) => println!(
            "install: FAILED: {why}. The target does not hold a working install: run the \
             installer again"
        ),
    }
    println!("install: stopped; power off or reset the machine");
    loop {
        block_on(timer::sleep(Duration::from_secs(1)));
    }
}

fn install(pci: Option<&mut Pci>) -> Result<(), Stop> {
    let abort = |s: String| Stop::Abort(s);
    let bytes = crate::mm::heap::module()
        .ok_or_else(|| abort("no install image (the boot loader loaded no module)".into()))?;
    let img = install_image::parse(bytes)
        .map_err(|e| abort(format!("install image invalid ({e})")))?;
    println!("install: image {}", summary(&img));
    let pci = pci.ok_or_else(|| abort("no PCI bus, so no disks".into()))?;

    // Every disk leatos drives, with what is on it.
    let mut disks: Vec<(String, Disk)> = Vec::new();
    println!("install: disks:");
    for dev in pci.devices.clone() {
        let Some(opened) = block_on(Disk::open(pci, &dev)) else {
            continue;
        };
        let df = format!("{}", dev.df);
        match opened {
            Err(e) => println!("  {df}  init failed: {e}"),
            Ok(mut disk) => {
                let parts = match block_on(disk.read(0, 1)) {
                    Ok(mbr) => store::partitions(&mbr),
                    Err(e) => format!("unreadable ({e})"),
                };
                let ro = if disk.readonly() { ", read-only" } else { "" };
                println!("  {df}  {}, {parts}{ro}", disk.describe());
                disks.push((df, disk));
            }
        }
    }
    if disks.is_empty() {
        return Err(abort("no disk to install to".into()));
    }

    let choice = match config::install_target() {
        Some(t) => {
            println!("install: target {t} (install_target=)");
            String::from(t)
        }
        None => {
            println!("install: everything on the target disk is replaced.");
            read_line("install: type the PCI address of the target disk (anything else cancels): ")
        }
    };
    let Some(i) = disks.iter().position(|(df, _)| *df == choice.trim()) else {
        return Err(abort(format!("'{}' is not one of the disks listed", choice.trim())));
    };
    let (df, mut disk) = disks.swap_remove(i);
    drop(disks);
    if disk.readonly() {
        return Err(abort(format!("{df} is read-only")));
    }
    let target = disk.capacity();
    let plan_of = |img: &Image<'static>| img.plan(target, DISK_MAX_SECTORS as u64);
    if plan_of(&img).is_none() {
        return Err(abort(format!(
            "{df} has {} MiB, the image needs {} MiB",
            target >> 11,
            img.sectors() >> 11
        )));
    }

    // The target's config, carried over to the new store.
    let mut kept = None;
    if config::install_keep() {
        disk = match store::probe(disk) {
            Ok((mut st, _)) => {
                kept = keep_config(&mut st)?;
                st.into_disk()
            }
            Err((why, d)) => {
                println!("install: config: none to keep ({why})");
                d
            }
        };
    } else {
        println!("install: config: not kept (install_keep=0)");
    }

    // Write every sector the image covers, then read it all back.
    let mib = |sectors: u64| sectors >> 11;
    let total: u64 = plan_of(&img).into_iter().flatten().map(|p| p.sectors()).sum();
    println!("install: writing {} MiB to {df}", mib(total));
    let zeros = vec![0u8; DISK_MAX_SECTORS * SECTOR];
    let mut done = 0u64;
    for p in plan_of(&img).into_iter().flatten() {
        let data = match p {
            Piece::Data { data, .. } => data.to_vec(),
            Piece::Zero { sectors, .. } => zeros[..sectors as usize * SECTOR].to_vec(),
        };
        block_on(disk.write(p.lba(), data))
            .map_err(|e| Stop::Failed(format!("writing sector {}: {e}", p.lba())))?;
        let before = done;
        done += p.sectors();
        if mib(done) / 16 != mib(before) / 16 {
            println!("install: written {} / {} MiB", mib(done), mib(total));
        }
    }
    disk.flush().map_err(|e| Stop::Failed(format!("flush: {e}")))?;
    println!("install: reading back");
    for p in plan_of(&img).into_iter().flatten() {
        let back = block_on(disk.read(p.lba(), p.sectors() as usize))
            .map_err(|e| Stop::Failed(format!("reading sector {} back: {e}", p.lba())))?;
        let same = match p {
            Piece::Data { data, .. } => back == data,
            Piece::Zero { .. } => back.iter().all(|&b| b == 0),
        };
        if !same {
            return Err(Stop::Failed(format!("sector {} reads back different", p.lba())));
        }
    }
    println!("install: {} MiB written and verified", mib(total));

    if let Some((version, payload)) = kept {
        let mut st = match store::probe(disk) {
            Ok((st, _)) => st,
            Err((why, _)) => {
                return Err(Stop::Failed(format!("the installed image has no store ({why})")));
            }
        };
        let r = block_on(st.write_record("config", version, config::schema::VERSION, &payload, 0));
        let (slot, h) = r.map_err(|e| Stop::Failed(format!("storing the kept config: {e}")))?;
        println!(
            "install: config carried over (slot {}, seq {}, {} bytes)",
            store::slot_name(slot),
            h.seq,
            payload.len()
        );
    }
    Ok(())
}

/// The target's current config record, if it is one to keep: `None` when
/// there is none or it does not parse (the image's config is used then).
/// An unconfirmed trial stops the install: which of the two the user wants
/// is not ours to guess.
fn keep_config(st: &mut store::Store) -> Result<Option<(u32, Vec<u8>)>, Stop> {
    let rec = match block_on(st.read_current("config", config::schema::VERSION)) {
        Ok((rec, _)) => rec,
        Err(e) => {
            println!("install: config: store unreadable ({e}): not kept");
            return Ok(None);
        }
    };
    let Some(rec) = rec else {
        println!("install: config: the target's store holds none");
        return Ok(None);
    };
    if rec.header.is_trial() {
        return Err(Stop::Abort(
            "the target's config is an unconfirmed trial: confirm or revert it first, or boot \
             with install_keep=0"
                .into(),
        ));
    }
    let parses = core::str::from_utf8(&rec.payload)
        .ok()
        .is_some_and(|t| config::schema::parse(t).is_ok());
    if !parses {
        println!("install: config: the stored one does not parse: not kept");
        return Ok(None);
    }
    println!(
        "install: config: keeping the target's (seq {}, {} bytes)",
        rec.header.seq,
        rec.payload.len()
    );
    Ok(Some((rec.header.version, rec.payload)))
}

/// A line typed on the console (echoed; Backspace edits).
fn read_line(prompt: &str) -> String {
    print!("{prompt}");
    let mut line = String::new();
    loop {
        console::poll_rx();
        while let Some(b) = console::read_byte() {
            match b {
                b'\r' | b'\n' => {
                    println!();
                    return line;
                }
                0x08 | 0x7f => {
                    if line.pop().is_some() {
                        print!("\x08 \x08");
                    }
                }
                0x20..=0x7e if line.len() < 64 => {
                    line.push(b as char);
                    print!("{}", b as char);
                }
                _ => {}
            }
        }
        block_on(timer::sleep(Duration::from_millis(20)));
    }
}
