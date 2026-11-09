//! x86_64 backend: PVH entry, 16550 console, ACPI discovery, local APIC
//! (timer + MSI-X vectors), TSC clock, ACPI S5 power-off
//! (docs/safety-and-portability.md §3). Target: QEMU q35 now, the PC
//! Engines apu4 (M10) next.

pub mod console;
pub mod cpu;
mod exceptions;
pub mod irqchip;
pub mod mmu;
mod port;
pub mod power;
pub mod timer;

use crate::platform::{BootInfo, IntxMap, IrqChipInfo, PcieInfo, PowerMethod, acpi, pvh};

core::arch::global_asm!(include_str!("boot.S"), options(att_syntax));

/// Entry point called from `boot.S` in 64-bit mode with the boot page
/// tables and the kernel stack; `start_info` is the PVH `hvm_start_info`.
#[unsafe(no_mangle)]
extern "C" fn kernel_main(start_info: usize) -> ! {
    exceptions::init();
    crate::kmain(start_info)
}

/// Discover the machine from the PVH start info and the ACPI tables.
pub fn discover(start_info: usize) -> Result<BootInfo, &'static str> {
    let si = pvh::parse(start_info, crate::mm::sym::kernel_start())?;
    let a = acpi::parse(si.rsdp)?;
    let (pm1a_cnt, slp) = match a.s5 {
        Some(s5) => (a.pm1a_cnt, s5),
        None => (0, (0, 0)), // power::off reports the failure
    };
    let pcie = a.mcfg.map(|(base, first, last)| PcieInfo {
        ecam: base as usize + ((first as usize) << 20),
        ecam_size: (last as usize - first as usize + 1) << 20,
        bus_start: first,
        bus_end: last,
        mem32: None, // firmware (SeaBIOS/coreboot) assigned the BARs
        intx: IntxMap::EMPTY,
    });
    Ok(BootInfo {
        firmware: ("pvh start info + acpi", start_info, 56),
        cpus: a.cpus.max(1),
        ram: si.ram,
        console_base: None,
        power: PowerMethod::AcpiS5 {
            pm1a_cnt,
            pm1b_cnt: a.pm1b_cnt,
            slp_typ_a: slp.0,
            slp_typ_b: slp.1,
        },
        irqchip: Some(IrqChipInfo::Apic {
            lapic: a.lapic,
            ioapic: a.ioapic,
        }),
        timer_intid: exceptions::TIMER_VECTOR,
        pcie,
        virtual_machine: cpu::hypervisor(),
        bootargs: si.cmdline,
    })
}
