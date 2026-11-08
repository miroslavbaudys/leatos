//! Hardware discovery from the flattened device tree QEMU provides.

use crate::println;
use crate::psci::Conduit;
use fdt::Fdt;
use fdt::node::FdtNode;

/// QEMU places the DTB at the start of RAM for bare-metal ELF boots.
const QEMU_VIRT_DTB: usize = 0x4000_0000;
const FDT_MAGIC: u32 = 0xd00d_feed;
/// Fallback: ARM generic virtual timer PPI 11 = INTID 27.
const DEFAULT_VTIMER_INTID: u32 = 27;

/// GICv3 MMIO regions.
#[derive(Clone, Copy, Debug)]
pub struct GicInfo {
    pub gicd: usize,
    pub gicr: usize,
    pub gicr_size: usize,
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

#[derive(Clone, Copy, Debug)]
pub struct PcieInfo {
    pub ecam: usize,
    pub ecam_size: usize,
    pub bus_start: u8,
    pub bus_end: u8,
    /// 32-bit non-prefetchable MMIO window, used for BAR assignment.
    pub mem32: Option<PciWindow>,
}

/// What the kernel needs to know about the machine, copied out of the DTB.
pub struct BootInfo {
    pub dtb_addr: usize,
    pub dtb_size: usize,
    pub cpus: usize,
    /// (start, size) of the RAM bank that contains the kernel.
    pub ram: (usize, usize),
    pub uart_base: Option<usize>,
    pub psci: Conduit,
    pub gic: Option<GicInfo>,
    /// INTID of the EL1 virtual timer interrupt.
    pub vtimer_intid: u32,
    pub pcie: Option<PcieInfo>,
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

        let gic = fdt.find_compatible(&["arm,gic-v3"]).and_then(|n| {
            let mut regs = n.reg()?;
            let d = regs.next()?;
            let r = regs.next()?;
            Some(GicInfo {
                gicd: d.starting_address as usize,
                gicr: r.starting_address as usize,
                gicr_size: r.size.unwrap_or(0),
            })
        });

        let vtimer_intid = fdt
            .find_compatible(&["arm,armv8-timer"])
            .and_then(vtimer_intid)
            .unwrap_or(DEFAULT_VTIMER_INTID);

        let pcie = fdt
            .find_compatible(&["pci-host-ecam-generic"])
            .and_then(pcie_info);

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
            gic,
            vtimer_intid,
            pcie,
            virtio_mmio_slots,
        })
    }

    pub fn print(&self) {
        println!(
            "  dtb             : {:#x} ({} bytes)",
            self.dtb_addr, self.dtb_size
        );
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
        match self.gic {
            Some(g) => println!("  gicv3           : gicd {:#x}, gicr {:#x}", g.gicd, g.gicr),
            None => println!("  gicv3           : none"),
        }
        println!("  vtimer intid    : {}", self.vtimer_intid);
        match self.pcie {
            Some(p) => {
                println!(
                    "  pcie ecam       : {:#x} ({} MiB), buses {}..={}",
                    p.ecam,
                    p.ecam_size >> 20,
                    p.bus_start,
                    p.bus_end
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
        println!("  virtio-mmio     : {} slots", self.virtio_mmio_slots);
    }
}

fn be_u32s(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
}

/// The armv8-timer `interrupts` property holds four `<type num flags>`
/// triples: secure phys, non-secure phys, **virtual**, hypervisor.
fn vtimer_intid(node: FdtNode) -> Option<u32> {
    // Runs before the heap exists: no allocation.
    let mut cells = be_u32s(node.property("interrupts")?.value).skip(6);
    let (kind, num) = (cells.next()?, cells.next()?);
    // type 1 = PPI (INTID = 16 + n), type 0 = SPI (INTID = 32 + n)
    Some(if kind == 1 { 16 + num } else { 32 + num })
}

fn pcie_info(node: FdtNode) -> Option<PcieInfo> {
    let ecam = node.reg()?.next()?;
    let (bus_start, bus_end) = node
        .property("bus-range")
        .map(|p| {
            let mut it = be_u32s(p.value);
            (
                it.next().unwrap_or(0) as u8,
                it.next().unwrap_or(0xff) as u8,
            )
        })
        .unwrap_or((0, 0xff));

    // `ranges`: <pci-addr(3 cells) cpu-addr(2 cells) size(2 cells)> entries.
    // phys.hi bits 24..25 = space code: 1 = I/O, 2 = 32-bit MMIO, 3 = 64-bit MMIO.
    let mut mem32 = None;
    if let Some(ranges) = node.property("ranges") {
        // Runs before the heap exists: no allocation.
        for entry in ranges.value.chunks_exact(7 * 4) {
            let mut c = [0u32; 7];
            for (dst, src) in c.iter_mut().zip(be_u32s(entry)) {
                *dst = src;
            }
            let e = &c;
            let space = (e[0] >> 24) & 0b11;
            let pci_addr = (e[1] as u64) << 32 | e[2] as u64;
            let cpu_addr = (e[3] as u64) << 32 | e[4] as u64;
            let size = (e[5] as u64) << 32 | e[6] as u64;
            if space == 2 && mem32.is_none() {
                mem32 = Some(PciWindow {
                    pci_addr,
                    cpu_addr,
                    size,
                });
            }
        }
    }

    Some(PcieInfo {
        ecam: ecam.starting_address as usize,
        ecam_size: ecam.size.unwrap_or(0),
        bus_start,
        bus_end,
        mem32,
    })
}

/// # Safety
/// `addr` must be readable.
unsafe fn has_magic(addr: usize) -> bool {
    // SAFETY: forwarded to the caller's contract.
    u32::from_be(unsafe { core::ptr::read_volatile(addr as *const u32) }) == FDT_MAGIC
}

/// Addresses of linker-script symbols (see kernel/linker.ld).
pub mod sym {
    macro_rules! linker_symbols {
        ($($fn_name:ident => $sym:ident),* $(,)?) => {
            unsafe extern "C" { $(static $sym: u8;)* }
            $(
                #[inline]
                pub fn $fn_name() -> usize {
                    // Taking the address of an extern static is safe; it is never read.
                    &raw const $sym as usize
                }
            )*
        };
    }
    linker_symbols! {
        kernel_start => __kernel_start,
        kernel_end => __kernel_end,
        text_start => __text_start,
        text_end => __text_end,
        rodata_start => __rodata_start,
        rodata_end => __rodata_end,
        data_start => __data_start,
        data_end => __data_end,
        exc_stack_guard => __exc_stack_guard,
        exc_stack_bottom => __exc_stack_bottom,
        exc_stack_top => __exc_stack_top,
        stack_guard => __stack_guard,
        stack_bottom => __stack_bottom,
        stack_top => __stack_top,
    }
}

pub use sym::{kernel_end, kernel_start};
