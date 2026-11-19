//! `leatstore`: host tool for rrouter store partitions
//! (docs/config-and-storage.md). The kernel never formats a store; this
//! tool (called by the QEMU and image scripts) does.
//!
//! ```text
//! leatstore create <img> [--mib N]        new disk image: MBR + one store partition, formatted
//! leatstore format <img> [--force]        format the image's 0xda partition (standard layout)
//! leatstore show <img>                    layout and slot states
//! leatstore put <img> <area> <file> [--raw] [--version N]
//!                                       write a record (config: validated unless --raw)
//! leatstore get <img> <area>              current record's payload to stdout
//! leatstore corrupt <img> <area> [--slot A|B]
//!                                       flip a payload byte (default: of the current record)
//! ```
//!
//! Writes follow the kernel's order (payload, then header), through the
//! same `config-store` plan.

#![forbid(unsafe_code)]

use config_store::{
    AreaState, Layout, RecordHeader, SECTOR, STANDARD_MIN_SECTORS, Slot, SlotState, check_slot, mbr,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::ExitCode;

/// The store partition starts at 1 MiB (as partitioning tools align).
const FIRST_LBA: u64 = 2048;

type Result<T> = std::result::Result<T, String>;

struct Img {
    file: File,
    /// Store partition: first sector on the disk, length.
    base: u64,
    sectors: u64,
}

impl Img {
    fn open(path: &str) -> Result<Img> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("{path}: {e}"))?;
        let mut m = [0; SECTOR];
        file.read_exact(&mut m)
            .map_err(|e| format!("{path}: reading the MBR: {e}"))?;
        let p = mbr::find_store(&m).ok_or(format!(
            "{path}: no partition of type {:#04x}",
            mbr::STORE_PARTITION_TYPE
        ))?;
        let len = file.metadata().map_err(|e| e.to_string())?.len() / SECTOR as u64;
        if p.first_lba as u64 + p.sectors as u64 > len {
            return Err(format!("{path}: store partition extends past the image"));
        }
        Ok(Img {
            file,
            base: p.first_lba as u64,
            sectors: p.sectors as u64,
        })
    }

    fn seek(&mut self, lba: u64, sectors: u64) -> Result<()> {
        if lba + sectors > self.sectors {
            return Err(format!("sector {lba}+{sectors} outside the partition"));
        }
        self.file
            .seek(SeekFrom::Start((self.base + lba) * SECTOR as u64))
            .map(drop)
            .map_err(|e| e.to_string())
    }

    fn read(&mut self, lba: u64, sectors: u64) -> Result<Vec<u8>> {
        self.seek(lba, sectors)?;
        let mut v = vec![0; sectors as usize * SECTOR];
        self.file.read_exact(&mut v).map_err(|e| e.to_string())?;
        Ok(v)
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<()> {
        self.seek(lba, data.len().div_ceil(SECTOR) as u64)?;
        self.file.write_all(data).map_err(|e| e.to_string())?;
        self.file.sync_data().map_err(|e| e.to_string())
    }

    fn layout(&mut self) -> Result<Layout> {
        let s = self.read(0, 1)?;
        Layout::parse(&s, self.sectors).map_err(|e| format!("store header: {e:?} (not formatted?)"))
    }

    /// Both slots of an area, each read through its payload.
    fn slots(&mut self, area: &config_store::Area) -> Result<[Vec<u8>; 2]> {
        let mut out = [Vec::new(), Vec::new()];
        for (i, slot) in [Slot::A, Slot::B].into_iter().enumerate() {
            let lba = area.slot_lba(slot);
            let mut buf = self.read(lba, 1)?;
            if let Ok(h) = RecordHeader::parse(area, &buf) {
                buf.extend(self.read(lba + 1, h.payload_sectors())?);
            }
            out[i] = buf;
        }
        Ok(out)
    }
}

fn area_of(layout: &Layout, name: &str) -> Result<config_store::Area> {
    layout
        .area(name)
        .copied()
        .ok_or(format!("no area '{name}'"))
}

/// A fresh image: zeros, an MBR with one store partition, formatted.
fn create(path: &str, mib: u64) -> Result<()> {
    let sectors = mib << 11;
    if sectors < FIRST_LBA + STANDARD_MIN_SECTORS {
        return Err(format!(
            "--mib must be at least {}",
            (FIRST_LBA + STANDARD_MIN_SECTORS) >> 11
        ));
    }
    let f = File::create(path).map_err(|e| format!("{path}: {e}"))?;
    f.set_len(sectors * SECTOR as u64)
        .map_err(|e| e.to_string())?;
    let mut m = [0u8; SECTOR];
    let e = &mut m[446..462];
    e[4] = mbr::STORE_PARTITION_TYPE;
    // CHS fields: "use LBA" (0xfe 0xff 0xff), as for large disks.
    e[1..4].copy_from_slice(&[0xfe, 0xff, 0xff]);
    e[5..8].copy_from_slice(&[0xfe, 0xff, 0xff]);
    e[8..12].copy_from_slice(&(FIRST_LBA as u32).to_le_bytes());
    e[12..16].copy_from_slice(&((sectors - FIRST_LBA) as u32).to_le_bytes());
    m[510] = 0x55;
    m[511] = 0xaa;
    let mut f = f;
    f.write_all(&m).map_err(|e| e.to_string())?;
    drop(f);
    format(path, false)
}

/// Write the standard layout and clear every slot header, so records of
/// an earlier format cannot reappear.
fn format(path: &str, force: bool) -> Result<()> {
    let mut img = Img::open(path)?;
    if !force && img.layout().is_ok() {
        return Err(format!(
            "{path}: already formatted (use --force to erase it)"
        ));
    }
    let layout = Layout::standard(img.sectors).map_err(|e| format!("{e:?}"))?;
    for a in layout.areas() {
        for s in [Slot::A, Slot::B] {
            img.write(a.slot_lba(s), &[0; SECTOR])?;
        }
    }
    img.write(0, &layout.encode())?;
    println!(
        "{path}: store formatted, {} MiB at LBA {}",
        img.sectors >> 11,
        img.base
    );
    Ok(())
}

fn describe(s: &SlotState) -> String {
    match s {
        SlotState::Empty => "empty".into(),
        SlotState::Corrupt => "corrupt".into(),
        SlotState::Valid(h) => format!(
            "seq {} version {} {} bytes{}{}",
            h.seq,
            h.version,
            h.len,
            if h.flags & config_store::FLAG_TRIAL != 0 {
                " trial"
            } else {
                ""
            },
            if h.flags & config_store::FLAG_BOOTED != 0 {
                " booted"
            } else {
                ""
            },
        ),
    }
}

fn show(path: &str) -> Result<()> {
    let mut img = Img::open(path)?;
    let layout = img.layout()?;
    println!("store: LBA {}, {} sectors", img.base, img.sectors);
    for a in layout.areas() {
        let [sa, sb] = img.slots(a)?;
        let st = AreaState::from_slots(a, &sa, &sb);
        println!(
            "  {:8} first {:6} slot {:6} sectors   A: {}   B: {}",
            a.name(),
            a.first,
            a.slot_sectors,
            describe(&st.a),
            describe(&st.b)
        );
    }
    Ok(())
}

fn put(path: &str, area: &str, file: &str, raw: bool, version: Option<u32>) -> Result<()> {
    let payload = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let mut doc_version = 1;
    if area == "config" && !raw {
        let text = std::str::from_utf8(&payload).map_err(|_| format!("{file}: not UTF-8"))?;
        let c = config::parse(text).map_err(|e| format!("{file}: {e}"))?;
        // A password in clear would be stored as is: the router hashes it.
        if c.mgmt.password.is_some() {
            return Err(format!(
                "{file}: mgmt.password is clear text: set it on the router (CLI or web), or give mgmt.password_hash"
            ));
        }
        // The kernel refuses a stored config with settings it does not
        // implement yet: refuse it here already.
        let unsupported = c.unsupported();
        if !unsupported.is_empty() {
            let list: Vec<String> = unsupported.iter().map(|i| i.to_string()).collect();
            return Err(format!("{file}: {}", list.join("; ")));
        }
        // The header names the schema version, so older kernels skip it.
        doc_version = config::VERSION;
    }
    let version = version.unwrap_or(doc_version);
    let mut img = Img::open(path)?;
    let layout = img.layout()?;
    let a = area_of(&layout, area)?;
    let [sa, sb] = img.slots(&a)?;
    let st = AreaState::from_slots(&a, &sa, &sb);
    let current = st.current(u32::MAX).map(|(s, _)| s);
    let plan = st
        .plan_write(&a, current, version, &payload)
        .map_err(|e| format!("{e:?}"))?;
    if !plan.payload.is_empty() {
        img.write(plan.payload_lba, &plan.payload)?;
    }
    img.write(plan.header_lba, &plan.header_sector)?;
    println!(
        "{area}: wrote slot {:?}, seq {}, {} bytes",
        plan.slot, plan.header.seq, plan.header.len
    );
    Ok(())
}

fn get(path: &str, area: &str) -> Result<()> {
    let mut img = Img::open(path)?;
    let layout = img.layout()?;
    let a = area_of(&layout, area)?;
    let [sa, sb] = img.slots(&a)?;
    let st = AreaState::from_slots(&a, &sa, &sb);
    let (slot, h) = st
        .current(u32::MAX)
        .ok_or(format!("{area}: no valid record"))?;
    let buf = if slot == Slot::A { sa } else { sb };
    eprintln!(
        "{area}: slot {slot:?}, seq {}, version {}, flags {}",
        h.seq, h.version, h.flags
    );
    std::io::stdout()
        .write_all(&buf[SECTOR..SECTOR + h.len as usize])
        .map_err(|e| e.to_string())
}

fn corrupt(path: &str, area: &str, slot: Option<Slot>) -> Result<()> {
    let mut img = Img::open(path)?;
    let layout = img.layout()?;
    let a = area_of(&layout, area)?;
    let [sa, sb] = img.slots(&a)?;
    let st = AreaState::from_slots(&a, &sa, &sb);
    let slot = match slot {
        Some(s) => s,
        None => {
            st.current(u32::MAX)
                .ok_or(format!("{area}: no valid record"))?
                .0
        }
    };
    let h = st
        .slot(slot)
        .valid()
        .copied()
        .ok_or(format!("{area}: slot {slot:?} holds no valid record"))?;
    if h.len == 0 {
        return Err(format!("{area}: slot {slot:?} has an empty payload"));
    }
    let lba = a.slot_lba(slot) + 1;
    let mut s = img.read(lba, 1)?;
    s[0] ^= 0x01;
    img.write(lba, &s)?;
    let check = check_slot(&a, &img.read(a.slot_lba(slot), 1 + h.payload_sectors())?);
    println!(
        "{area}: slot {slot:?} payload byte 0 flipped, now {}",
        describe(&check)
    );
    Ok(())
}

/// `mgmt.password_hash` for a config file (salt from the OS).
fn hash(password: &str) -> Result<()> {
    if !(8..=128).contains(&password.chars().count()) {
        return Err("the password must be 8–128 characters".into());
    }
    let mut seed = [0u8; 32];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").map_err(|e| format!("/dev/urandom: {e}"))?,
        &mut seed,
    )
    .map_err(|e| format!("/dev/urandom: {e}"))?;
    let mut pool = auth::Pool::new(&seed);
    println!("{}", auth::hash_password(password, &mut pool, auth::ITERATIONS));
    Ok(())
}

fn usage() -> String {
    "usage: leatstore create <img> [--mib N] | format <img> [--force] | show <img> | \
     put <img> <area> <file> [--raw] [--version N] | get <img> <area> | \
     corrupt <img> <area> [--slot A|B] | hash <password>"
        .into()
}

fn run(args: &[String]) -> Result<()> {
    let flag = |name: &str| args.iter().any(|a| a == name);
    let opt = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let pos: Vec<&str> = {
        let mut v = Vec::new();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--mib" | "--version" | "--slot" => i += 2,
                a if a.starts_with("--") => i += 1,
                a => {
                    v.push(a);
                    i += 1
                }
            }
        }
        v
    };
    let num = |name: &str| -> Result<Option<u64>> {
        opt(name)
            .map(|v| v.parse().map_err(|_| format!("{name}: not a number")))
            .transpose()
    };
    match pos.as_slice() {
        ["create", img] => create(img, num("--mib")?.unwrap_or(17)),
        ["format", img] => format(img, flag("--force")),
        ["show", img] => show(img),
        ["put", img, area, file] => put(
            img,
            area,
            file,
            flag("--raw"),
            num("--version")?.map(|v| v as u32),
        ),
        ["get", img, area] => get(img, area),
        ["hash", password] => hash(password),
        ["corrupt", img, area] => {
            let slot = match opt("--slot") {
                None => None,
                Some("A" | "a") => Some(Slot::A),
                Some("B" | "b") => Some(Slot::B),
                Some(s) => return Err(format!("--slot {s}: A or B")),
            };
            corrupt(img, area, slot)
        }
        _ => Err(usage()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("leatstore: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let d = std::env::temp_dir().join(format!("leatstore-test-{}-{name}", std::process::id()));
        d.to_string_lossy().into_owned()
    }

    fn current(path: &str) -> Option<(Slot, RecordHeader)> {
        let mut img = Img::open(path).unwrap();
        let l = img.layout().unwrap();
        let a = area_of(&l, "config").unwrap();
        let [sa, sb] = img.slots(&a).unwrap();
        AreaState::from_slots(&a, &sa, &sb).current(u32::MAX)
    }

    #[test]
    fn create_put_corrupt_reformat() {
        let img = tmp("img");
        let toml = tmp("toml");
        std::fs::write(&toml, "version = 2\n[[network]]\nname = \"lan\"\nipv4 = \"10.20.0.1/24\"\n").unwrap();
        create(&img, 17).unwrap();
        assert!(format(&img, false).is_err(), "refuses to reformat");
        assert_eq!(current(&img), None);
        put(&img, "config", &toml, false, None).unwrap();
        put(&img, "config", &toml, false, None).unwrap();
        let (slot, h) = current(&img).unwrap();
        assert_eq!((slot, h.seq, h.version), (Slot::B, 2, config::VERSION));
        corrupt(&img, "config", None).unwrap();
        // The newer record is broken: the older one is current again.
        let (slot, h) = current(&img).unwrap();
        assert_eq!((slot, h.seq), (Slot::A, 1));
        // Invalid config is refused unless --raw.
        std::fs::write(&toml, "version = 2\nbogus = 3\n").unwrap();
        assert!(put(&img, "config", &toml, false, None).is_err());
        // So is a version 1 document.
        std::fs::write(&toml, "version = 1\n[lan]\nipv4 = \"10.20.0.1/24\"\n").unwrap();
        assert!(put(&img, "config", &toml, false, None).unwrap_err().contains("no longer supported"));
        put(&img, "config", &toml, true, None).unwrap();
        format(&img, true).unwrap();
        assert_eq!(current(&img), None, "format clears old records");
        let _ = std::fs::remove_file(&img);
        let _ = std::fs::remove_file(&toml);
    }
}
