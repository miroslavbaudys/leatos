//! Arch-neutral description of the machine, filled in by a firmware
//! backend: DTB today (aarch64 QEMU virt), ACPI later (x86_64).
//!
//! Discovery runs **before the heap exists**, so these types are plain
//! `Copy` data with fixed-size arrays and no allocation.

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)] // reads the firmware DTB blob through a raw pointer
pub mod dtb;

use crate::println;

/// Interrupt controller description.
#[derive(Clone, Copy, Debug)]
pub enum IrqChipInfo {
    GicV3 {
        gicd: usize,
        gicr: usize,
        gicr_size: usize,
    },
    // x86_64 (future): Apic { lapic: usize, ioapic: usize, .. }
}

/// How to power the machine off.
#[derive(Clone, Copy, Debug)]
pub enum PowerMethod {
    PsciHvc,
    PsciSmc,
    // x86_64 (future): AcpiS5 { .. }
}

/// A CPU-visible window that the PCIe host bridge forwards to the bus.
#[derive(Clone, Copy, Debug)]
pub struct PciWindow {
    /// Address as seen on the PCI bus (what goes into BARs).
    pub pci_addr: u64,
    /// Address as seen by the CPU.
    pub cpu_addr: u64,
    pub size: u64,
}

/// One legacy-INTx routing entry: (device address bits, pin) → interrupt.
#[derive(Clone, Copy, Debug, Default)]
pub struct IntxRoute {
    /// PCI `phys.hi` bits (bus/device/function), already masked.
    pub addr_hi: u32,
    /// INTA..INTD = 1..4, already masked.
    pub pin: u8,
    pub intid: u32,
}

pub const MAX_INTX_ROUTES: usize = 32;

#[derive(Clone, Copy, Debug)]
pub struct IntxMap {
    pub mask_hi: u32,
    pub mask_pin: u8,
    pub routes: [IntxRoute; MAX_INTX_ROUTES],
    pub len: usize,
}

impl IntxMap {
    pub const EMPTY: Self = Self {
        mask_hi: 0,
        mask_pin: 0,
        routes: [IntxRoute {
            addr_hi: 0,
            pin: 0,
            intid: 0,
        }; MAX_INTX_ROUTES],
        len: 0,
    };

    /// Interrupt for a function at `bus:dev.func` using `pin` (1 = INTA).
    pub fn lookup(&self, bus: u8, dev: u8, func: u8, pin: u8) -> Option<u32> {
        let hi = (bus as u32) << 16 | (dev as u32) << 11 | (func as u32) << 8;
        let (hi, pin) = (hi & self.mask_hi, pin & self.mask_pin);
        self.routes[..self.len]
            .iter()
            .find(|r| r.addr_hi == hi && r.pin == pin)
            .map(|r| r.intid)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PcieInfo {
    pub ecam: usize,
    pub ecam_size: usize,
    pub bus_start: u8,
    pub bus_end: u8,
    /// 32-bit non-prefetchable MMIO window, used for BAR assignment.
    pub mem32: Option<PciWindow>,
    pub intx: IntxMap,
}

/// What the kernel needs to know about the machine.
#[derive(Clone, Copy, Debug)]
pub struct BootInfo {
    /// Human-readable firmware source, e.g. "dtb @ 0x40000000 (1048576 bytes)".
    pub firmware: (&'static str, usize, usize),
    pub cpus: usize,
    /// (start, size) of the RAM bank that contains the kernel.
    pub ram: (usize, usize),
    pub console_base: Option<usize>,
    pub power: PowerMethod,
    pub irqchip: Option<IrqChipInfo>,
    /// Interrupt ID of the per-CPU timer used for tickless deadlines.
    pub timer_intid: u32,
    pub pcie: Option<PcieInfo>,
}

impl BootInfo {
    pub fn print(&self) {
        let (kind, addr, size) = self.firmware;
        println!("  firmware        : {kind} @ {addr:#x} ({size} bytes)");
        println!("  cpus            : {}", self.cpus);
        println!(
            "  ram             : {:#x}..{:#x} ({} MiB)",
            self.ram.0,
            self.ram.0 + self.ram.1,
            self.ram.1 >> 20
        );
        match self.console_base {
            Some(b) => println!("  console         : {b:#x}"),
            None => println!("  console         : default address"),
        }
        println!("  power           : {:?}", self.power);
        match self.irqchip {
            Some(IrqChipInfo::GicV3 { gicd, gicr, .. }) => {
                println!("  irqchip         : GICv3, gicd {gicd:#x}, gicr {gicr:#x}")
            }
            None => println!("  irqchip         : none"),
        }
        println!("  timer intid     : {}", self.timer_intid);
        match self.pcie {
            Some(p) => {
                println!(
                    "  pcie ecam       : {:#x} ({} MiB), buses {}..={}, {} INTx routes",
                    p.ecam,
                    p.ecam_size >> 20,
                    p.bus_start,
                    p.bus_end,
                    p.intx.len
                );
                if let Some(w) = p.mem32 {
                    println!(
                        "  pcie mem32      : {:#x} ({} MiB)",
                        w.cpu_addr,
                        w.size >> 20
                    );
                }
            }
            None => println!("  pcie            : none"),
        }
    }
}
