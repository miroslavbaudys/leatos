//! Minimal ACPI table parser (x86_64): RSDP → XSDT/RSDT → MADT (local
//! APIC, IOAPIC, CPU count), MCFG (PCIe ECAM), FADT (PM1 control ports,
//! DSDT) and the DSDT's `\_S5` package (sleep type for power-off).
//!
//! Safe code over byte slices from [`super::phys`]; every table is checked
//! for its signature, length and checksum before use. No AML interpreter:
//! `\_S5` is found by the usual byte-pattern scan, which covers the
//! constant packages that firmware (QEMU, coreboot) emits.

use super::phys::{self, u16_at, u32_at, u64_at};

#[derive(Clone, Copy, Debug, Default)]
pub struct Acpi {
    pub lapic: usize,
    /// (MMIO address, first GSI) of the first IOAPIC.
    pub ioapic: Option<(usize, u32)>,
    pub cpus: usize,
    /// (ECAM base for bus 0 of segment 0, first bus, last bus).
    pub mcfg: Option<(u64, u8, u8)>,
    pub pm1a_cnt: u16,
    pub pm1b_cnt: u16,
    /// `\_S5` SLP_TYPa / SLP_TYPb.
    pub s5: Option<(u16, u16)>,
}

fn checksum_ok(b: &[u8]) -> bool {
    b.iter().fold(0u8, |a, &x| a.wrapping_add(x)) == 0
}

/// A system description table, validated.
fn table(pa: u64) -> Result<(&'static [u8; 4], &'static [u8]), &'static str> {
    let hdr = phys::bytes(pa, 36)?;
    let len = u32_at(hdr, 4).ok_or("acpi: short header")? as usize;
    if !(36..=1 << 20).contains(&len) {
        return Err("acpi: implausible table length");
    }
    let t = phys::bytes(pa, len)?;
    if !checksum_ok(t) {
        return Err("acpi: table checksum mismatch");
    }
    let sig: &[u8; 4] = t[..4].try_into().map_err(|_| "acpi: short table")?;
    Ok((sig, t))
}

/// Legacy BIOS search for the RSDP (when the boot protocol doesn't pass
/// it, e.g. QEMU's PVH loader): the first KiB of the EBDA, then
/// 0xE0000..0xFFFFF, on 16-byte boundaries.
pub fn find_rsdp() -> Option<u64> {
    let ebda = phys::bytes(0x40e, 2)
        .ok()
        .and_then(|b| u16_at(b, 0))
        .unwrap_or(0) as u64
        * 16;
    let areas = [(ebda, 1024), (0xe_0000, 0x2_0000)];
    areas
        .into_iter()
        .filter(|&(pa, _)| pa != 0)
        .find_map(|(pa, len)| {
            let area = phys::bytes(pa, len).ok()?;
            (0..len.saturating_sub(20))
                .step_by(16)
                .find(|&i| &area[i..i + 8] == b"RSD PTR " && checksum_ok(&area[i..i + 20]))
                .map(|i| pa + i as u64)
        })
}

pub fn parse(rsdp_pa: u64) -> Result<Acpi, &'static str> {
    let rsdp_pa = if rsdp_pa != 0 {
        rsdp_pa
    } else {
        find_rsdp().ok_or("acpi: no RSDP (not passed by the loader, not found in BIOS areas)")?
    };
    let rsdp = phys::bytes(rsdp_pa, 36)?;
    if &rsdp[..8] != b"RSD PTR " || !checksum_ok(&rsdp[..20]) {
        return Err("acpi: bad RSDP");
    }
    let xsdt = if rsdp[15] >= 2 {
        u64_at(rsdp, 24).unwrap_or(0)
    } else {
        0
    };
    let (root, entry_size) = if xsdt != 0 {
        (xsdt, 8)
    } else {
        (u32_at(rsdp, 16).unwrap_or(0) as u64, 4)
    };
    let (_, root) = table(root)?;
    let mut acpi = Acpi::default();
    for e in root[36..].chunks_exact(entry_size) {
        let pa = if entry_size == 8 {
            u64_at(e, 0)
        } else {
            u32_at(e, 0).map(u64::from)
        };
        let Some(pa) = pa else { continue };
        let Ok((sig, t)) = table(pa) else { continue };
        match sig {
            b"APIC" => madt(t, &mut acpi),
            b"MCFG" => acpi.mcfg = mcfg(t),
            b"FACP" => fadt(t, &mut acpi),
            _ => {}
        }
    }
    if acpi.lapic == 0 {
        return Err("acpi: no MADT (local APIC address)");
    }
    Ok(acpi)
}

fn madt(t: &[u8], acpi: &mut Acpi) {
    acpi.lapic = u32_at(t, 36).unwrap_or(0) as usize;
    let mut off = 44;
    while let (Some(&kind), Some(&len)) = (t.get(off), t.get(off + 1)) {
        let len = len as usize;
        if len < 2 || off + len > t.len() {
            break;
        }
        let e = &t[off..off + len];
        match kind {
            // Processor local APIC: flags bit 0 = enabled, bit 1 = online capable.
            0 if u32_at(e, 4).is_some_and(|f| f & 3 != 0) => acpi.cpus += 1,
            1 if acpi.ioapic.is_none() => {
                if let (Some(addr), Some(gsi)) = (u32_at(e, 4), u32_at(e, 8)) {
                    acpi.ioapic = Some((addr as usize, gsi));
                }
            }
            5 => {
                if let Some(a) = u64_at(e, 4) {
                    acpi.lapic = a as usize;
                }
            }
            _ => {}
        }
        off += len;
    }
}

fn mcfg(t: &[u8]) -> Option<(u64, u8, u8)> {
    // First allocation (segment 0), 16 bytes from offset 44.
    let e = t.get(44..60)?;
    (u16_at(e, 8)? == 0).then_some(())?;
    Some((u64_at(e, 0)?, e[10], e[11]))
}

fn fadt(t: &[u8], acpi: &mut Acpi) {
    acpi.pm1a_cnt = u32_at(t, 64).unwrap_or(0) as u16;
    acpi.pm1b_cnt = u32_at(t, 68).unwrap_or(0) as u16;
    let x_dsdt = if t.len() >= 148 {
        u64_at(t, 140).unwrap_or(0)
    } else {
        0
    };
    let dsdt = if x_dsdt != 0 {
        x_dsdt
    } else {
        u32_at(t, 40).unwrap_or(0) as u64
    };
    if let Ok((b"DSDT", d)) = table(dsdt) {
        acpi.s5 = s5(d);
    }
}

/// Find `Name(\_S5, Package() { a, b, .. })` in AML: `08 [5C] "_S5_" 12
/// PkgLength NumElements a b`, where each value is ZeroOp (00), OneOp
/// (01) or BytePrefix (0A nn).
fn s5(aml: &[u8]) -> Option<(u16, u16)> {
    let at = aml.windows(4).position(|w| w == b"_S5_")?;
    let named = at >= 1 && aml[at - 1] == 0x08 || at >= 2 && aml[at - 2..at] == [0x08, 0x5c];
    if !named {
        return None;
    }
    let mut i = at + 4;
    if *aml.get(i)? != 0x12 {
        return None;
    }
    i += 1;
    i += 1 + (*aml.get(i)? >> 6) as usize; // PkgLength: lead byte + extra bytes
    i += 1; // NumElements
    let mut value = || -> Option<u16> {
        let v = match *aml.get(i)? {
            0x0a => {
                i += 1;
                *aml.get(i)? as u16
            }
            0x00 => 0,
            0x01 => 1,
            _ => return None,
        };
        i += 1;
        Some(v)
    };
    let a = value()?;
    let b = value()?;
    Some((a, b))
}
