//! PCIe enumeration and BAR assignment over ECAM (arch-neutral).
//!
//! Config-space access goes through `virtio-drivers`' `PciRoot`. The
//! `unsafe` here: creating the ECAM handle; two clones of it, one read-only
//! (Interrupt Pin) and one for the MSI-X capability, which `PciRoot` never
//! touches; and the MSI-X table entry region.
//!
//! Every memory BAR is mapped as device memory when found
//! (`mm::mmu::map_device`): on PCs, firmware may put BARs anywhere in the
//! PCI hole.
//!
//! **MSI-X** ([`Pci::enable_msix`]): one table entry per device, pointing
//! at a local-APIC vector (`arch::irqchip`). Used where legacy INTx routing
//! would need ACPI AML (`_PRT`): x86_64.
//!
//! With `-kernel` on QEMU aarch64 no firmware assigns BARs, so we size every
//! memory BAR and place it in the host bridge's 32-bit MMIO window. BARs that
//! firmware already assigned (x86 with SeaBIOS/OVMF) are kept. I/O BARs are
//! skipped: virtio "modern" devices and real NICs use memory BARs.

use crate::mm::{dma, mmu};
use crate::mmio::Region;
use crate::platform::{PciWindow, PcieInfo};
use crate::{arch, println};
use alloc::vec::Vec;
use virtio_drivers::transport::pci::bus::{
    BarInfo, Cam, Command, ConfigurationAccess, DeviceFunction, DeviceFunctionInfo, HeaderType,
    MemoryBarType, MmioCam, PciRoot,
};

const INTERRUPT_LINE_PIN: u8 = 0x3c;

#[derive(Clone, Copy, Debug)]
pub struct Bar {
    pub addr: u64,
    pub size: u64,
    pub is_64bit: bool,
}

#[derive(Clone, Debug)]
pub struct PciDevice {
    pub df: DeviceFunction,
    pub info: DeviceFunctionInfo,
    pub bars: [Option<Bar>; 6],
    /// Legacy INTx interrupt ID (from the platform's routing table), if any.
    pub intx: Option<u32>,
}

impl PciDevice {
    pub fn name(&self) -> &'static str {
        match (self.info.vendor_id, self.info.device_id) {
            (0x1af4, 0x1000 | 0x1041) => "virtio-net",
            (0x1af4, 0x1001 | 0x1042) => "virtio-blk",
            (0x1af4, _) => "virtio (other)",
            (0x1b36, 0x0008) => "host bridge",
            (0x8086, 0x10c9) => "Intel 82576 (igb)",
            (0x8086, 0x1533 | 0x1536 | 0x1537 | 0x1538 | 0x157b) => "Intel i210 (igb)",
            (0x8086, 0x1539) => "Intel i211 (igb)",
            (0x8086, _) if self.info.class == 0x02 => "Intel NIC",
            _ => match self.info.class {
                0x01 => "storage",
                0x02 => "network",
                0x06 => "bridge",
                _ => "unknown",
            },
        }
    }

    pub fn is_virtio_net(&self) -> bool {
        matches!(
            (self.info.vendor_id, self.info.device_id),
            (0x1af4, 0x1000 | 0x1041)
        )
    }
}

pub struct Pci {
    pub root: PciRoot<MmioCam<'static>>,
    /// Config access for registers `PciRoot` doesn't handle (capabilities).
    cfg: MmioCam<'static>,
    pub devices: Vec<PciDevice>,
}

const CAP_MSIX: u8 = 0x11;
const MSIX_ENABLE: u32 = 1 << 15;
const MSIX_FUNCTION_MASK: u32 = 1 << 14;

impl Pci {
    pub fn config_read(&self, df: DeviceFunction, offset: u8) -> u32 {
        self.cfg.read_word(df, offset)
    }

    /// Offset of the first capability with `id`.
    pub fn capability(&self, df: DeviceFunction, id: u8) -> Option<u8> {
        self.root
            .capabilities(df)
            .find(|c| c.id == id)
            .map(|c| c.offset)
    }

    /// Route the device's MSI-X entry 0 to `vector` (masked until
    /// `arch::irqchip::enable`) and switch the function from INTx to MSI-X.
    /// `None` if the device or the platform lacks MSI-X.
    /// `core`: the core the interrupt is delivered to.
    pub fn enable_msix(&mut self, dev: &PciDevice, vector: u32, core: usize) -> Option<()> {
        let (addr, data) = arch::irqchip::msi_message(vector, core)?;
        let cap = self.capability(dev.df, CAP_MSIX)?;
        let header = self.cfg.read_word(dev.df, cap);
        let table = self.cfg.read_word(dev.df, cap + 4);
        let bar = dev.bars.get((table & 7) as usize).copied().flatten()?;
        let entry_addr = bar.addr + (table & !7) as u64;
        if entry_addr + 16 > bar.addr + bar.size {
            return None;
        }
        // SAFETY: MSI-X table entry 0 inside a memory BAR that init()
        // mapped as device memory; nothing else accesses the MSI-X table.
        let mut entry = unsafe { Region::new(entry_addr as usize, 16) };
        entry.write32(12, 1); // vector control: masked
        entry.write32(0, addr as u32);
        entry.write32(4, (addr >> 32) as u32);
        entry.write32(8, data);
        arch::irqchip::attach_msix(vector, entry);
        let ctrl = (header >> 16 | MSIX_ENABLE) & !MSIX_FUNCTION_MASK;
        self.cfg
            .write_word(dev.df, cap, ctrl << 16 | (header & 0xffff));
        Some(())
    }
}

/// Bump allocator over the 32-bit MMIO window.
struct MmioAlloc {
    window: PciWindow,
    next: u64,
}

impl MmioAlloc {
    /// Returns a PCI bus address for a BAR of `size` bytes.
    fn alloc(&mut self, size: u64) -> Option<u64> {
        let pci = self.next.next_multiple_of(size.max(4096));
        let end = pci.checked_add(size)?;
        if end > self.window.pci_addr + self.window.size {
            return None;
        }
        self.next = end;
        Some(pci)
    }
}

fn assign_bars(
    root: &mut PciRoot<MmioCam<'static>>,
    df: DeviceFunction,
    mmio: &mut Option<MmioAlloc>,
) -> [Option<Bar>; 6] {
    let mut bars = [None; 6];
    let Ok(infos) = root.bars(df) else {
        return bars;
    };
    for (i, info) in infos.iter().enumerate() {
        let Some(BarInfo::Memory {
            address_type,
            address,
            size,
            ..
        }) = *info
        else {
            continue; // I/O BAR or unused
        };
        if size == 0 {
            continue;
        }
        let is_64bit = address_type == MemoryBarType::Width64;
        let addr = if address != 0 {
            address // already assigned by firmware
        } else {
            let Some(pci) = mmio.as_mut().and_then(|m| m.alloc(size)) else {
                println!("  pci: no MMIO space for {df} BAR{i} ({size} bytes)");
                continue;
            };
            if is_64bit {
                root.set_bar_64(df, i as u8, pci);
            } else {
                root.set_bar_32(df, i as u8, pci as u32);
            }
            pci
        };
        mmu::map_device(addr as usize, (addr + size) as usize);
        dma::add_mmio_range(addr as usize, (addr + size) as usize);
        bars[i] = Some(Bar {
            addr,
            size,
            is_64bit,
        });
    }
    root.set_command(df, Command::MEMORY_SPACE | Command::BUS_MASTER);
    bars
}

/// Enumerate every function on every bus in the ECAM window.
pub fn init(info: &PcieInfo) -> Pci {
    // Firmware may describe fewer than 256 buses (coreboot: often 64).
    // Only buses inside the window are ever accessed (the loop below).
    assert!(
        info.ecam_size >= ((info.bus_end as usize) + 1) << 20,
        "pci: ECAM window smaller than its bus range"
    );
    // SAFETY: the ECAM window comes from firmware, is mapped as device
    // memory by mm::mmu, and is accessed only through this PciRoot, for
    // buses bus_start..=bus_end, which lie inside the window.
    let cam = unsafe { MmioCam::new(info.ecam as *mut u8, Cam::Ecam) };
    // SAFETY: `ro` is used only to read the read-only Interrupt Pin register.
    let ro = unsafe { cam.unsafe_clone() };
    // SAFETY: `cfg` only accesses capability registers (MSI-X), which
    // PciRoot never reads or writes.
    let cfg = unsafe { cam.unsafe_clone() };
    let mut root = PciRoot::new(cam);

    let mut mmio = info.mem32.map(|w| {
        // BAR addresses are handed to drivers as CPU addresses.
        assert_eq!(
            w.pci_addr, w.cpu_addr,
            "pci: non-identity MMIO window unsupported"
        );
        MmioAlloc {
            window: w,
            next: w.pci_addr,
        }
    });

    let mut devices = Vec::new();
    for bus in info.bus_start..=info.bus_end {
        let found: Vec<_> = root.enumerate_bus(bus).collect();
        for (df, dinfo) in found {
            let bars = if dinfo.header_type == HeaderType::Standard {
                assign_bars(&mut root, df, &mut mmio)
            } else {
                [None; 6]
            };
            let pin = (ro.read_word(df, INTERRUPT_LINE_PIN) >> 8) as u8;
            let intx = (pin != 0)
                .then(|| info.intx.lookup(df.bus, df.device, df.function, pin))
                .flatten();
            devices.push(PciDevice {
                df,
                info: dinfo,
                bars,
                intx,
            });
        }
    }
    Pci { root, cfg, devices }
}

pub fn print(pci: &Pci) {
    println!("  pci             : {} function(s)", pci.devices.len());
    for d in &pci.devices {
        let irq = d
            .intx
            .map(|i| alloc::format!(", INTx -> intid {i}"))
            .unwrap_or_default();
        println!(
            "    {} {:04x}:{:04x} class {:02x}.{:02x}  {}{irq}",
            d.df,
            d.info.vendor_id,
            d.info.device_id,
            d.info.class,
            d.info.subclass,
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
