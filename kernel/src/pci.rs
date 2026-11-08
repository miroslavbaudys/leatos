//! PCIe enumeration over ECAM, with BAR assignment.
//!
//! With `-kernel` there is no firmware, so nobody has assigned BARs. We size
//! every memory BAR and place it in the host bridge's 32-bit MMIO window
//! (from the DTB `ranges`). I/O BARs are skipped: virtio "modern" devices
//! and real NICs work through memory BARs. Bridges are listed but not
//! configured (QEMU virt puts all devices on bus 0 by default).

use crate::dtb::{PciWindow, PcieInfo};
use crate::println;
use alloc::vec::Vec;

const VENDOR_ID: usize = 0x00;
const COMMAND: usize = 0x04;
const CLASS_REV: usize = 0x08;
const HEADER_TYPE: usize = 0x0e;
const BAR0: usize = 0x10;
const CMD_MEMORY: u16 = 1 << 1;
const CMD_BUS_MASTER: u16 = 1 << 2;

#[derive(Clone, Copy, Debug)]
pub struct Bar {
    /// CPU physical address (identity-mapped, Device).
    pub addr: u64,
    pub size: u64,
    pub is_64bit: bool,
}

#[derive(Clone, Debug)]
pub struct PciDevice {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub bars: [Option<Bar>; 6],
    /// Config-space base of this function (for capability parsing, e.g. virtio).
    #[allow(dead_code)] // used by the virtio driver in M2
    pub cfg: usize,
}

impl PciDevice {
    pub fn name(&self) -> &'static str {
        match (self.vendor, self.device) {
            (0x1af4, 0x1000 | 0x1041) => "virtio-net",
            (0x1af4, 0x1001 | 0x1042) => "virtio-blk",
            (0x1af4, 0x1005 | 0x1044) => "virtio-rng",
            (0x1af4, _) => "virtio (other)",
            (0x1b36, 0x0008) => "host bridge",
            (0x8086, _) if self.class == 0x02 => "Intel NIC",
            _ => match self.class {
                0x01 => "storage",
                0x02 => "network",
                0x06 => "bridge",
                _ => "unknown",
            },
        }
    }
}

struct Ecam {
    base: usize,
    bus_start: u8,
}

impl Ecam {
    fn cfg(&self, bus: u8, dev: u8, func: u8) -> usize {
        self.base
            + (((bus - self.bus_start) as usize) << 20)
            + ((dev as usize) << 15)
            + ((func as usize) << 12)
    }
}

fn rd32(addr: usize) -> u32 {
    // SAFETY: `addr` is inside the ECAM window, mapped as device memory.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}
fn wr32(addr: usize, v: u32) {
    // SAFETY: `addr` is inside the ECAM window, mapped as device memory.
    unsafe { core::ptr::write_volatile(addr as *mut u32, v) }
}
fn rd16(addr: usize) -> u16 {
    let word = rd32(addr & !3);
    (word >> ((addr & 2) * 8)) as u16
}
fn wr16(addr: usize, v: u16) {
    let aligned = addr & !3;
    let shift = (addr & 2) * 8;
    let word = rd32(aligned) & !(0xffff << shift) | (v as u32) << shift;
    wr32(aligned, word);
}
fn rd8(addr: usize) -> u8 {
    (rd32(addr & !3) >> ((addr & 3) * 8)) as u8
}

/// Bump allocator over the 32-bit MMIO window.
struct MmioAlloc {
    window: PciWindow,
    next: u64,
}

impl MmioAlloc {
    /// Returns (PCI bus address, CPU address).
    fn alloc(&mut self, size: u64) -> Option<(u64, u64)> {
        let pci = self.next.next_multiple_of(size.max(4096));
        let end = pci.checked_add(size)?;
        if end > self.window.pci_addr + self.window.size {
            return None;
        }
        self.next = end;
        Some((pci, self.window.cpu_addr + (pci - self.window.pci_addr)))
    }
}

/// Size and assign all memory BARs of a type-0 function.
fn assign_bars(cfg: usize, mmio: &mut Option<MmioAlloc>) -> [Option<Bar>; 6] {
    let mut bars = [None; 6];
    // Disable decoding while BARs are being probed.
    let cmd = rd16(cfg + COMMAND);
    wr16(cfg + COMMAND, cmd & !(CMD_MEMORY | 1));

    let mut i = 0;
    while i < 6 {
        let reg = cfg + BAR0 + i * 4;
        let orig = rd32(reg);
        if orig & 1 != 0 {
            i += 1; // I/O BAR: skipped
            continue;
        }
        let is_64bit = (orig >> 1) & 0b11 == 0b10;
        wr32(reg, 0xffff_ffff);
        let lo = rd32(reg) & !0xf;
        let hi = if is_64bit {
            let orig_hi = rd32(reg + 4);
            wr32(reg + 4, 0xffff_ffff);
            let h = rd32(reg + 4);
            wr32(reg + 4, orig_hi);
            h
        } else {
            0xffff_ffff
        };
        wr32(reg, orig);
        let mask = (hi as u64) << 32 | lo as u64;
        let size = (!mask).wrapping_add(1);
        if lo != 0
            && size != 0
            && let Some((pci, cpu)) = mmio.as_mut().and_then(|m| m.alloc(size))
        {
            wr32(reg, (pci as u32) | (orig & 0xf));
            if is_64bit {
                wr32(reg + 4, (pci >> 32) as u32);
            }
            bars[i] = Some(Bar {
                addr: cpu,
                size,
                is_64bit,
            });
        }
        i += if is_64bit { 2 } else { 1 };
    }

    wr16(cfg + COMMAND, cmd | CMD_MEMORY | CMD_BUS_MASTER);
    bars
}

/// Enumerate every function on every bus in the ECAM window.
pub fn enumerate(info: &PcieInfo) -> Vec<PciDevice> {
    let ecam = Ecam {
        base: info.ecam,
        bus_start: info.bus_start,
    };
    let max_bus_by_size = info.bus_start as usize + (info.ecam_size >> 20).max(1) - 1;
    let bus_end = (info.bus_end as usize).min(max_bus_by_size) as u8;
    let mut mmio = info.mem32.map(|w| MmioAlloc {
        window: w,
        next: w.pci_addr,
    });
    let mut found = Vec::new();

    for bus in info.bus_start..=bus_end {
        for dev in 0..32u8 {
            let multi = rd8(ecam.cfg(bus, dev, 0) + HEADER_TYPE) & 0x80 != 0;
            for func in 0..if multi { 8 } else { 1 } {
                let cfg = ecam.cfg(bus, dev, func);
                let id = rd32(cfg + VENDOR_ID);
                if id & 0xffff == 0xffff {
                    continue;
                }
                let class_rev = rd32(cfg + CLASS_REV);
                let header = rd8(cfg + HEADER_TYPE) & 0x7f;
                let bars = if header == 0 {
                    assign_bars(cfg, &mut mmio)
                } else {
                    [None; 6]
                };
                found.push(PciDevice {
                    bus,
                    dev,
                    func,
                    vendor: id as u16,
                    device: (id >> 16) as u16,
                    class: (class_rev >> 24) as u8,
                    subclass: (class_rev >> 16) as u8,
                    bars,
                    cfg,
                });
            }
        }
    }
    found
}

pub fn print(devices: &[PciDevice]) {
    println!("  pci             : {} function(s)", devices.len());
    for d in devices {
        println!(
            "    {:02x}:{:02x}.{} {:04x}:{:04x} class {:02x}.{:02x}  {}",
            d.bus,
            d.dev,
            d.func,
            d.vendor,
            d.device,
            d.class,
            d.subclass,
            d.name()
        );
        for (i, b) in d.bars.iter().enumerate() {
            if let Some(b) = b {
                println!(
                    "        BAR{i}: {:#x} ({} KiB{})",
                    b.addr,
                    b.size >> 10,
                    if b.is_64bit { ", 64-bit" } else { "" }
                );
            }
        }
    }
}
