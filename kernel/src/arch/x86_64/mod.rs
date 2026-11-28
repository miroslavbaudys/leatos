//! x86_64 backend: PVH (QEMU `-kernel`) or Multiboot2 (Limine) entry, 16550 console, ACPI discovery, local APIC
//! (timer + MSI-X vectors), TSC clock, ACPI S5 power-off
//! (docs/safety-and-portability.md §3). Target: QEMU q35 now, the PC
//! Engines apu4 (M10) next.

pub mod console;
pub mod cpu;
mod exceptions;
pub mod irqchip;
pub mod kexec;
pub mod mmu;
mod port;
pub mod power;
pub mod rtc;
pub mod smp;
pub mod timer;
pub mod watchdog;

use crate::platform::{BootInfo, IntxMap, IrqChipInfo, PcieInfo, PowerMethod, acpi, multiboot2, pvh};
use core::sync::atomic::{AtomicU32, Ordering};

/// `eax` at `_start32`: [`multiboot2::MAGIC`] for Multiboot2, anything else for PVH.
static BOOT_MAGIC: AtomicU32 = AtomicU32::new(0);

core::arch::global_asm!(include_str!("boot.S"), options(att_syntax));
core::arch::global_asm!(include_str!("kexec.S"), options(att_syntax));

/// Entry point called from `boot.S` in 64-bit mode with the boot page
/// tables and the kernel stack; `start_info` is the PVH `hvm_start_info`
/// or the Multiboot2 information (then `magic` = [`multiboot2::MAGIC`]).
#[unsafe(no_mangle)]
extern "C" fn kernel_main(start_info: usize, magic: u32) -> ! {
    BOOT_MAGIC.store(magic, Ordering::Relaxed);
    exceptions::init();
    crate::kmain(start_info)
}

/// Discover the machine from the PVH start info and the ACPI tables.
pub fn discover(start_info: usize) -> Result<BootInfo, &'static str> {
    use crate::mm::sym;
    let mb2 = BOOT_MAGIC.load(Ordering::Relaxed) == multiboot2::MAGIC;
    let si = if mb2 {
        multiboot2::parse(start_info, sym::kernel_start(), sym::kernel_end())?
    } else {
        pvh::parse(start_info, sym::kernel_start())?
    };
    let a = acpi::parse(si.rsdp)?;
    let rsdp = crate::platform::phys::bytes(a.rsdp_pa, 36)
        .map(|b| if b[15] >= 2 { b } else { &b[..20] })
        .unwrap_or(&[]);
    kexec::save(&si.mmap[..si.mmap_len], rsdp, si.framebuffer);
    let (pm1a_cnt, slp) = match a.s5 {
        Some(s5) => (a.pm1a_cnt, s5),
        None => (0, (0, 0)), // power::off reports the failure
    };
    // `ecam` is the bus-0 address (MmioCam takes absolute bus numbers);
    // the window ends after `last`.
    let pcie = a.mcfg.map(|(base, first, last)| PcieInfo {
        ecam: base as usize,
        ecam_size: (last as usize + 1) << 20,
        bus_start: first,
        bus_end: last,
        mem32: None, // firmware (SeaBIOS/coreboot) assigned the BARs
        intx: IntxMap::EMPTY,
    });
    Ok(BootInfo {
        firmware: if mb2 {
            ("multiboot2 info + acpi", start_info, 0)
        } else {
            ("pvh start info + acpi", start_info, 56)
        },
        cpus: a.cpus.max(1),
        // MADT order with the boot core moved to the front.
        cpu_ids: {
            let mut ids = a.apic_ids;
            let n = a.cpus.clamp(1, ids.len());
            let me = cpu::apic_id();
            if let Some(i) = ids[..n].iter().position(|&x| x == me) {
                ids[..=i].rotate_right(1);
            }
            ids
        },
        ram: si.ram,
        console_base: None,
        console_irq: None,
        power: PowerMethod::AcpiS5 {
            pm1a_cnt,
            pm1b_cnt: a.pm1b_cnt,
            slp_typ_a: slp.0,
            slp_typ_b: slp.1,
        },
        irqchip: Some(IrqChipInfo::Apic {
            lapic: a.lapic,
            ioapic: a.ioapic,
            com1: a.com1,
        }),
        timer_intid: exceptions::TIMER_VECTOR,
        pcie,
        virtual_machine: cpu::hypervisor(),
        bootargs: si.cmdline,
        module: si.module,
        framebuffer: si.framebuffer,
    })
}
