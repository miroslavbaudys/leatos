//! Device-tree backend: QEMU `virt` (and other DTB platforms) → [`BootInfo`].
//!
//! Runs before the heap exists: no allocation anywhere in this file.

use super::{BootInfo, IntxMap, IntxRoute, IrqChipInfo, PciWindow, PcieInfo, PowerMethod};
use fdt::Fdt;
use fdt::node::FdtNode;

/// QEMU places the DTB at the start of RAM for bare-metal ELF boots.
const QEMU_VIRT_DTB: usize = 0x4000_0000;
const FDT_MAGIC: u32 = 0xd00d_feed;
/// Fallback: ARM generic virtual timer PPI 11 = INTID 27.
const DEFAULT_VTIMER_INTID: u32 = 27;

/// Locate and parse the DTB. `x0` is the boot register (0 or the DTB address).
///
/// # Safety
/// `x0` must be 0 or point to readable memory, and the DTB must stay mapped
/// and unmodified for the kernel's lifetime.
pub unsafe fn discover(x0: usize, kernel_start: usize) -> Result<BootInfo, &'static str> {
    let addr = [x0, QEMU_VIRT_DTB]
        .into_iter()
        // SAFETY: candidates are non-zero RAM addresses, identity-mapped.
        .find(|&a| a != 0 && unsafe { has_magic(a) })
        .ok_or("no FDT magic at x0 or 0x4000_0000")?;
    // SAFETY: magic checked above; caller guarantees lifetime.
    let fdt = unsafe { Fdt::from_ptr(addr as *const u8) }.map_err(|_| "invalid FDT")?;

    let ram = fdt
        .memory()
        .regions()
        .filter_map(|r| Some((r.starting_address as usize, r.size?)))
        .find(|&(s, len)| kernel_start >= s && kernel_start < s + len)
        .ok_or("no memory region contains the kernel")?;

    let console_base = fdt
        .find_compatible(&["arm,pl011"])
        .and_then(|n| n.reg()?.next())
        .map(|r| r.starting_address as usize);

    let power = match fdt
        .find_node("/psci")
        .and_then(|n| n.property("method"))
        .and_then(|p| p.as_str())
    {
        Some("smc") => PowerMethod::PsciSmc,
        _ => PowerMethod::PsciHvc,
    };

    let gic_node = fdt.find_compatible(&["arm,gic-v3"]);
    let irqchip = gic_node.and_then(|n| {
        let mut regs = n.reg()?;
        let d = regs.next()?;
        let r = regs.next()?;
        Some(IrqChipInfo::GicV3 {
            gicd: d.starting_address as usize,
            gicr: r.starting_address as usize,
            gicr_size: r.size.unwrap_or(0),
        })
    });

    let timer_intid = fdt
        .find_compatible(&["arm,armv8-timer"])
        .and_then(vtimer_intid)
        .unwrap_or(DEFAULT_VTIMER_INTID);

    let gic_addr_cells = gic_node
        .map(|n| cell_prop(&n, "#address-cells").unwrap_or(0))
        .unwrap_or(0);
    let pcie = fdt
        .find_compatible(&["pci-host-ecam-generic"])
        .and_then(|n| pcie_info(n, gic_addr_cells as usize));

    Ok(BootInfo {
        firmware: ("dtb", addr, fdt.total_size()),
        cpus: fdt.cpus().count(),
        ram,
        console_base,
        power,
        irqchip,
        timer_intid,
        pcie,
    })
}

fn be_u32s(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
}

fn cell_prop(node: &FdtNode, name: &str) -> Option<u32> {
    be_u32s(node.property(name)?.value).next()
}

/// GIC interrupt specifier `<type num flags>` → INTID.
fn gic_intid(kind: u32, num: u32) -> u32 {
    // type 1 = PPI (INTID = 16 + n), type 0 = SPI (INTID = 32 + n)
    if kind == 1 { 16 + num } else { 32 + num }
}

/// The armv8-timer `interrupts` property holds four `<type num flags>`
/// triples: secure phys, non-secure phys, **virtual**, hypervisor.
fn vtimer_intid(node: FdtNode) -> Option<u32> {
    let mut cells = be_u32s(node.property("interrupts")?.value).skip(6);
    Some(gic_intid(cells.next()?, cells.next()?))
}

fn pcie_info(node: FdtNode, gic_addr_cells: usize) -> Option<PcieInfo> {
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

    // `ranges`: <pci-addr(3) cpu-addr(2) size(2)>; phys.hi bits 24..25 =
    // space code: 1 = I/O, 2 = 32-bit MMIO, 3 = 64-bit MMIO.
    let mut mem32 = None;
    if let Some(ranges) = node.property("ranges") {
        for entry in ranges.value.chunks_exact(7 * 4) {
            let mut e = [0u32; 7];
            for (dst, src) in e.iter_mut().zip(be_u32s(entry)) {
                *dst = src;
            }
            let space = (e[0] >> 24) & 0b11;
            if space == 2 && mem32.is_none() {
                mem32 = Some(PciWindow {
                    pci_addr: (e[1] as u64) << 32 | e[2] as u64,
                    cpu_addr: (e[3] as u64) << 32 | e[4] as u64,
                    size: (e[5] as u64) << 32 | e[6] as u64,
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
        intx: intx_map(&node, gic_addr_cells),
    })
}

/// Parse `interrupt-map` + `interrupt-map-mask`. Entry layout:
/// child unit address (3 cells), child pin (1), parent phandle (1),
/// parent unit address (`gic_addr_cells`), parent specifier (3: type num flags).
fn intx_map(node: &FdtNode, gic_addr_cells: usize) -> IntxMap {
    let mut map = IntxMap::EMPTY;
    if let Some(mask) = node.property("interrupt-map-mask") {
        let m: [u32; 4] = {
            let mut a = [0u32; 4];
            for (d, s) in a.iter_mut().zip(be_u32s(mask.value)) {
                *d = s;
            }
            a
        };
        map.mask_hi = m[0];
        map.mask_pin = m[3] as u8;
    }
    let Some(prop) = node.property("interrupt-map") else {
        return map;
    };
    let entry_cells = 3 + 1 + 1 + gic_addr_cells + 3;
    for entry in prop.value.chunks_exact(entry_cells * 4) {
        if map.len == map.routes.len() {
            break;
        }
        let mut cells = be_u32s(entry);
        let addr_hi = cells.next().unwrap_or(0);
        let mut rest = cells.skip(2); // phys.mid, phys.lo
        let pin = rest.next().unwrap_or(0) as u8;
        let mut parent = rest.skip(1 + gic_addr_cells); // phandle, parent unit address
        let (kind, num) = (parent.next().unwrap_or(0), parent.next().unwrap_or(0));
        map.routes[map.len] = IntxRoute {
            addr_hi: addr_hi & map.mask_hi,
            pin: pin & map.mask_pin,
            intid: gic_intid(kind, num),
        };
        map.len += 1;
    }
    map
}

/// # Safety
/// `addr` must be readable.
unsafe fn has_magic(addr: usize) -> bool {
    // SAFETY: forwarded to the caller's contract.
    u32::from_be(unsafe { core::ptr::read_volatile(addr as *const u32) }) == FDT_MAGIC
}
