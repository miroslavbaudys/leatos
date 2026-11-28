//! Arch-neutral description of the machine, filled in by a firmware
//! backend: DTB (aarch64 QEMU virt) or PVH start info / Multiboot2 info +
//! ACPI (x86_64).
//!
//! Discovery runs **before the heap exists**, so these types are plain
//! `Copy` data with fixed-size arrays and no allocation.

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)] // reads the firmware DTB blob through a raw pointer
pub mod dtb;

#[cfg(target_arch = "x86_64")]
pub mod acpi;
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)] // the one constructor that views firmware memory as bytes
pub mod phys;
#[cfg(target_arch = "x86_64")]
pub mod multiboot2;
#[cfg(target_arch = "x86_64")]
pub mod pvh;

use crate::println;

/// Interrupt controller description.
#[derive(Clone, Copy, Debug)]
pub enum IrqChipInfo {
    GicV3 {
        gicd: usize,
        gicr: usize,
        gicr_size: usize,
    },
    /// x86: local APIC (xAPIC MMIO) and the first IOAPIC.
    #[allow(dead_code)] // fields are read by the x86_64 backend only
    Apic {
        lapic: usize,
        ioapic: Option<(usize, u32)>,
        /// COM1's IRQ: (GSI, MPS INTI flags), see `acpi::Acpi::com1`.
        com1: (u32, u16),
    },
}

/// How to power the machine off.
#[derive(Clone, Copy, Debug)]
pub enum PowerMethod {
    PsciHvc,
    PsciSmc,
    /// ACPI S5 (soft off): write `SLP_TYP | SLP_EN` to the PM1 control
    /// register(s) (I/O ports from the FADT, `SLP_TYP` from the DSDT `\_S5`).
    #[allow(dead_code)] // fields are read by the x86_64 backend only
    AcpiS5 {
        pm1a_cnt: u16,
        pm1b_cnt: u16,
        slp_typ_a: u16,
        slp_typ_b: u16,
    },
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
    /// Hardware ID of each core (aarch64: MPIDR affinity from the DTB;
    /// x86_64: local APIC ID from the MADT), boot core first.
    pub cpu_ids: [u64; crate::smp::MAX_CORES],
    /// (start, size) of the RAM bank that contains the kernel.
    pub ram: (usize, usize),
    pub console_base: Option<usize>,
    /// The console UART's interrupt (aarch64: GIC INTID from the DTB;
    /// x86_64: `None`, COM1's comes with `IrqChipInfo::Apic`).
    pub console_irq: Option<u32>,
    pub power: PowerMethod,
    pub irqchip: Option<IrqChipInfo>,
    /// Interrupt ID of the per-CPU timer used for tickless deadlines.
    pub timer_intid: u32,
    pub pcie: Option<PcieInfo>,
    /// Running under a hypervisor (QEMU `virt`): enables hybrid idle.
    pub virtual_machine: bool,
    /// Kernel command line (DTB `/chosen/bootargs`; QEMU `-append`).
    pub bootargs: &'static str,
    /// The first boot module (start, length): the install image Limine or
    /// QEMU `-initrd` loaded (docs/install.md §3.2). Kept out of the heap
    /// (`mm::heap::region`), mapped read-only, read via `mm::heap::module`.
    pub module: Option<(usize, usize)>,
    /// The screen the boot loader set up (x86_64 Multiboot2 tag 8: a
    /// linear framebuffer, or EGA text): `drivers::screen` draws the
    /// console there.
    pub framebuffer: Option<boot_image::multiboot2::Framebuffer>,
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
        println!(
            "  machine         : {}",
            if self.virtual_machine {
                "virtual machine"
            } else {
                "physical"
            }
        );
        if let Some((s, l)) = self.module {
            println!("  boot module     : {s:#x}..{:#x} ({} KiB)", s + l, l >> 10);
        }
        if let Some(fb) = self.framebuffer {
            println!(
                "  framebuffer     : {:#x} {}x{} {} bpp, type {}",
                fb.addr, fb.width, fb.height, fb.bpp, fb.kind
            );
        }
        if !self.bootargs.is_empty() {
            println!("  bootargs        : {}", crate::config::Redacted(self.bootargs));
        }
        match self.irqchip {
            Some(IrqChipInfo::GicV3 { gicd, gicr, .. }) => {
                println!("  irqchip         : GICv3, gicd {gicd:#x}, gicr {gicr:#x}")
            }
            Some(IrqChipInfo::Apic { lapic, ioapic, .. }) => match ioapic {
                Some((io, gsi)) => println!(
                    "  irqchip         : local APIC {lapic:#x}, IOAPIC {io:#x} (GSI {gsi}..)"
                ),
                None => println!("  irqchip         : local APIC {lapic:#x}"),
            },
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
