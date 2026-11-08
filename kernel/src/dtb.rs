//! Hardware discovery from the flattened device tree QEMU provides.

use crate::println;
use crate::psci::Conduit;
use fdt::Fdt;

/// QEMU places the DTB at the start of RAM for bare-metal ELF boots.
const QEMU_VIRT_DTB: usize = 0x4000_0000;
const FDT_MAGIC: u32 = 0xd00d_feed;

/// What the kernel needs to know about the machine, copied out of the DTB.
pub struct BootInfo {
    pub dtb_addr: usize,
    pub dtb_size: usize,
    pub cpus: usize,
    /// (start, size) of the RAM bank that contains the kernel.
    pub ram: (usize, usize),
    pub uart_base: Option<usize>,
    pub psci: Conduit,
    /// (start, size) of the PCIe ECAM window, if any.
    pub pcie_ecam: Option<(usize, usize)>,
    pub virtio_mmio_slots: usize,
}

impl BootInfo {
    /// Locate and parse the DTB.
    ///
    /// # Safety
    /// `x0` must be 0 or point to readable memory; the DTB must stay mapped
    /// and unmodified for the kernel's lifetime.
    pub unsafe fn discover(x0: usize) -> Result<Self, &'static str> {
        let addr = [x0, QEMU_VIRT_DTB]
            .into_iter()
            // SAFETY: candidates are 0-filtered RAM addresses, identity-mapped.
            .find(|&a| a != 0 && unsafe { has_magic(a) })
            .ok_or("no FDT magic at x0 or 0x4000_0000")?;

        // SAFETY: magic checked above; caller guarantees lifetime.
        let fdt = unsafe { Fdt::from_ptr(addr as *const u8) }.map_err(|_| "invalid FDT")?;

        let kernel = kernel_start();
        let ram = fdt
            .memory()
            .regions()
            .filter_map(|r| Some((r.starting_address as usize, r.size?)))
            .find(|&(s, len)| kernel >= s && kernel < s + len)
            .ok_or("no memory region contains the kernel")?;

        let uart_base = fdt
            .find_compatible(&["arm,pl011"])
            .and_then(|n| n.reg()?.next())
            .map(|r| r.starting_address as usize);

        let psci = match fdt
            .find_node("/psci")
            .and_then(|n| n.property("method"))
            .and_then(|p| p.as_str())
        {
            Some("smc") => Conduit::Smc,
            _ => Conduit::Hvc,
        };

        let pcie_ecam = fdt
            .find_compatible(&["pci-host-ecam-generic"])
            .and_then(|n| n.reg()?.next())
            .map(|r| (r.starting_address as usize, r.size.unwrap_or(0)));

        let virtio_mmio_slots = fdt
            .all_nodes()
            .filter(|n| {
                n.compatible()
                    .is_some_and(|c| c.all().any(|s| s == "virtio,mmio"))
            })
            .count();

        Ok(Self {
            dtb_addr: addr,
            dtb_size: fdt.total_size(),
            cpus: fdt.cpus().count(),
            ram,
            uart_base,
            psci,
            pcie_ecam,
            virtio_mmio_slots,
        })
    }

    pub fn print(&self) {
        println!("  dtb             : {:#x} ({} bytes)", self.dtb_addr, self.dtb_size);
        println!("  cpus            : {}", self.cpus);
        println!(
            "  ram             : {:#x}..{:#x} ({} MiB)",
            self.ram.0,
            self.ram.0 + self.ram.1,
            self.ram.1 >> 20
        );
        match self.uart_base {
            Some(b) => println!("  uart (pl011)    : {b:#x}"),
            None => println!("  uart (pl011)    : not in DTB, using default"),
        }
        println!("  psci conduit    : {:?}", self.psci);
        match self.pcie_ecam {
            Some((b, s)) => println!("  pcie ecam       : {b:#x} ({} MiB)", s >> 20),
            None => println!("  pcie ecam       : none"),
        }
        println!("  virtio-mmio     : {} slots", self.virtio_mmio_slots);
    }
}

/// # Safety
/// `addr` must be readable.
unsafe fn has_magic(addr: usize) -> bool {
    // SAFETY: forwarded to the caller's contract.
    u32::from_be(unsafe { core::ptr::read_volatile(addr as *const u32) }) == FDT_MAGIC
}

pub fn kernel_start() -> usize {
    unsafe extern "C" {
        static __kernel_start: u8;
    }
    // Taking the address of an extern static is safe; it is never read.
    &raw const __kernel_start as usize
}

pub fn kernel_end() -> usize {
    unsafe extern "C" {
        static __kernel_end: u8;
    }
    // Taking the address of an extern static is safe; it is never read.
    &raw const __kernel_end as usize
}
