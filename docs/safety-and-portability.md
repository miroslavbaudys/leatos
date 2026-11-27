# Minimising `unsafe`, and portability to x86_64

## 1. Where `unsafe` is unavoidable in a bare-metal router
Only a few kinds of operation fundamentally need it:

| Kind | Examples | Why it can't be safe |
|---|---|---|
| CPU control | MMU/TTBR switch, exception vectors, IRQ entry, PSCI | changes the memory model or control flow |
| System registers without a safe wrapper | GICv3 `ICC_*` | inline asm |
| Creating an MMIO handle | UART, GIC, PCIe ECAM, BARs | an address becomes "a device we own" |
| DMA ownership hand-off | virtio queue buffers, igb descriptor addresses | the device writes memory behind Rust's back |
| Global allocator init | heap region | memory becomes "ours" |
| Firmware data | DTB (later ACPI tables) | raw pointer to a blob |

Everything else (protocols, forwarding, NAT, CAKE, the executor, timers,
page-table *construction*, PCI enumeration logic, driver state machines) can be safe.

## 2. Strategy

### 2.1 The compiler enforces the boundary
- `kernel` crate root: `#![deny(unsafe_code)]`.
- Only these modules may opt out, with `#[allow(unsafe_code)]` on the `mod`
  declaration, so `grep allow(unsafe_code)` lists the whole audit surface:
  - `arch::<target>`: CPU, vectors, IRQ entry, sysregs, MMU activation, power, SMP (aarch64 `smp.rs`: PSCI `CPU_ON`, one cache-line clean; `irqchip::send_ipi`: `ICC_SGI1R_EL1`; x86_64 `smp.rs`: one copy of the trampoline to its free low page, `cpu`: `IA32_GS_BASE` write and the GS-relative core-index load, per-core `ltr`)
  - `mm::heap`: allocator init; `take_staging` (the upgrade staging area as one `&'static mut [u8]`, handed out once)
  - `mm::dma`: the `virtio_drivers::Hal` implementation; `DmaRegion`
    (descriptor rings: volatile access, and `unsafe fn write_buffer_addr`,
    the hand-off)
  - `mm::mmu`: one call, activating the finished page tables
  - `mm::sym`: `unsafe extern` declarations of linker symbols (addresses only)
  - `mmio`: one constructor that turns an address into an MMIO region, plus `Region::read64` (one 64-bit access inside a region it owns; GICv3 `GICR_TYPER` under HVF)
  - `pci`: the ECAM handle
  - `platform::dtb`: DTB blob pointer; `platform::phys` (x86_64): the one
    constructor that views firmware memory as bytes
  - `drivers::virtio_net`: the DMA buffer hand-off (begin/complete pairs)
  - `drivers::virtio_blk`: the DMA buffer hand-off (submit/complete pairs,
    driver-owned buffers)
  - `drivers::igb`: the register window (`Region::new` over BAR0) and the
    two hand-offs (RX refill, TX post)
  - `drivers::sdhci`, `drivers::i6300esb`: the register window's
    constructor (PIO, no DMA)
  - `selftest`: deliberate faults, feature-gated
  - `arch::x86_64::kexec` (inside the arch backend): the in-RAM upgrade's CR3 switch + jump into the trampoline (`kexec.S`), and the view of the trampoline bytes
- `crates/*`: `#![forbid(unsafe_code)]` (cannot be overridden).
- Lints: `unsafe_op_in_unsafe_fn = deny`, `clippy::undocumented_unsafe_blocks`
  (every block needs `// SAFETY:`), `clippy::multiple_unsafe_ops_per_block`.
- `scripts/unsafe-report.sh` counts `unsafe` per module, so the audit
  surface is visible over time and in reviews.

### 2.2 Safe abstractions built on the few unsafe primitives
| Primitive (unsafe once) | Safe API used everywhere else |
|---|---|
| `mmio::Region::new(base, len)` built on `safe-mmio` | bounds-checked `read32` / `write32` / `modify32`. **safe-mmio uses inline asm for MMIO on aarch64**, which fixes a real HVF/KVM hazard: compiler-generated `ldp` or post-index loads to MMIO can't be emulated by the hypervisor |
| `aarch64-cpu` crate (tock-registers) | typed, safe access to CNTV_*, DAIF, MPIDR, CurrentEL, …; replaces hand-written `asm!` |
| `PciRoot<MmioCam>` from `virtio-drivers` | safe config-space access, BAR info and assignment |
| `mm::dma::Hal` (identity-mapped DMA) | `virtio-drivers` queues |
| `mm::dma::DmaRegion` (leaked, zeroed, device-shared memory) | descriptor rings with bounds-checked volatile `read32` / `write32` / `write64`; only putting a *buffer address* into a ring is `unsafe` |
| `drivers::virtio_net` / `drivers::igb` slot ownership | **owned `PacketBuf`s**: a buffer lent to the device lives in a slot until completion, so the type system prevents touching it while the device owns it |
| `irq::IrqEvent` | IRQ → executor signalling with atomics only; `spin::Once` handler table, no raw pointers |
| page-table builder (`mm::mmu`) | page tables held in an owned arena (`Vec<Box<Table>>`), indices instead of raw descriptor pointers. Only `activate()` is unsafe (arch) |

### 2.3 Reuse audited crates instead of writing unsafe code
`virtio-drivers` (virtqueues, PCI transport; used by several Rust OSes),
`safe-mmio` (Google), `aarch64-cpu`, `fdt`. (smoltcp was one until 2026-11-27; the router's TCP
is now `crates/proto-tcp`, `#![forbid(unsafe_code)]`, docs/own-tcp.md.)
Every dependency is reviewed for `no_std` support and its own unsafe surface before it's added.

### 2.4 Verification
- Host tests and fuzzing cover all safe logic (most of the code, in `crates/*`).
- Miri on host-testable crates that contain unsafe (none today; keep it that way if possible).
- `fault-wx` / `fault-stack` smoke cases verify that the hardware protection (W^X, guard pages) actually holds.

## 3. x86_64 portability

**Status: x86_64 runs on QEMU and on hardware.** On QEMU q35 (TCG on
Apple Silicon), the x86_64 kernel passes the same smoke tests and the full
lab (`LEATOS_ARCH=x86_64 scripts/lab-test.sh`) since M9b (2026-11-09).
Since M10 it runs on the PC Engines apu4 (booted by Limine through
Multiboot2), the developer's home router since 2026-11-15.

### 3.1 What's the same, and what differs
| Area | aarch64 | x86_64 | Portable? |
|---|---|---|---|
| Boot | QEMU `-kernel` ELF, DTB at RAM start | **PVH** (`XEN_ELFNOTE_PHYS32_ENTRY`): QEMU `-kernel`, 32-bit entry stub in `boot.S` → long mode; **Multiboot2** for Limine on the apu4 (`platform::multiboot2`) | arch + platform backend |
| HW discovery | DTB | PVH start info (memory map, command line) + ACPI: MADT (LAPIC/IOAPIC), MCFG (ECAM), FADT + DSDT `\_S5` | neutral `BootInfo`, two backends |
| Console | PL011 MMIO | 16550 UART (port I/O `0x3f8`) | `arch::console` |
| Interrupt controller | GICv3, INTx from the DTB `interrupt-map` | local APIC, 8259 PICs remapped (224–239) and masked; devices via **MSI-X**; one IOAPIC entry for COM1's ISA IRQ 4 (from the MADT, no AML) | `arch::irqchip` API |
| Timer (tickless) | generic timer, CNTV_CVAL | TSC clock (calibrated on the 8254 PIT), **LAPIC one-shot** deadlines. TSC-deadline mode isn't used: the apu4's AMD GX-412TC lacks it | `arch::timer` API |
| Page tables | 4 KiB granule, 512-entry levels | 4-level, 4 KiB × 512; NX via EFER.NXE, W^X enforced for ring 0 by CR0.WP | **neutral builder** + per-arch descriptor bits |
| Exceptions | vector table, ESR decode | IDT, TSS with IST1 (exception stack) for #PF/#DF/NMI/#MC, error codes, CR2 | arch |
| Power off | PSCI | ACPI S5 (PM1 control ports, `\_S5` SLP_TYP) | `arch::power` |
| Memory ordering for DMA | weak (`dmb`/`dsb`) | strong (TSO) | handled inside virtio-drivers / fences |
| PCIe | ECAM, we assign BARs | ECAM via MCFG; firmware assigned the BARs; every BAR is mapped at runtime (`mm::mmu::map_device`) | **neutral** |
| virtio-net (PCI) | ✔ | ✔ | **neutral**. This is why we use virtio-**pci**, not virtio-mmio |
| Real NICs | (igb on QEMU's 82576, INTx) | Intel i211 (igb) on the apu4 | neutral driver over `mmio` + `dma` |
| SMP | PSCI `CPU_ON` | INIT-SIPI-SIPI, trampoline at 0x8000 | `arch::smp` (docs/smp.md) |
| Watchdog, RTC, kexec | none (stubs; i6300esb over PCI in QEMU) | AMD FCH watchdog, CMOS RTC, in-RAM kernel replacement | `arch::watchdog`, `arch::rtc`, `arch::kexec` |

### 3.2 Code layout that keeps the port cheap
```
kernel/src/
  main.rs            arch-neutral boot order
  arch/mod.rs        selects the backend; documents the arch API contract
  arch/aarch64/      boot.S, cpu, exceptions, irqchip (GICv3), timer, mmu bits, power (PSCI),
                     console (PL011), smp; stubs: kexec, rtc, watchdog
  arch/x86_64/       boot.S (PVH + Multiboot2 entry, AP trampoline), isr.S, cpu, exceptions
                     (IDT/TSS), irqchip (LAPIC, MSI-X, COM1's IOAPIC entry), timer (TSC + LAPIC),
                     mmu bits, power (ACPI S5), console (16550), port, smp, kexec (+ kexec.S),
                     rtc (CMOS), watchdog (AMD FCH)
  platform/          neutral BootInfo; dtb (aarch64); pvh + multiboot2 + acpi + phys (x86_64)
  mm/                heap, page-table builder, dma, stacks, sym
  irq.rs timer.rs executor.rs smp.rs console.rs pci.rs mmio.rs ...   (neutral)
  drivers/           Nic and Disk (one interface each), virtio_net, igb, virtio_blk, sdhci,
                     i6300esb, watchdog (neutral)
  net/               packet buffers, datapath, router stack glue, services (neutral)
```
**Rule:** nothing outside `arch/` may use `core::arch`, `asm!` or arch-specific
crates. Neutral code calls only the `arch::` API.

**Guards:**
- `cargo kcheck-x86`: type-checks neutral code for x86_64.
- `cargo kclippy-x86`: lints the x86 kernel, with every feature like `kclippy`.
- `LEATOS_ARCH=x86_64` on `scripts/smoke-test.sh` and `scripts/lab-test.sh`
  boots the x86 kernel.

**Unsafe on x86_64** (`scripts/unsafe-report.sh`):
- **Arch backend:** port I/O (one instruction per function), control
  registers, CPUID, `lidt`/`ltr`, the extern statics of `isr.S`/`boot.S`.
- **`platform::phys`:** one constructor that views firmware memory as a
  byte slice. The ACPI and PVH parsers are safe, bounds-checked code over
  those slices.

### 3.3 Device interrupts: the main design fork
- aarch64 QEMU virt: legacy INTx through the DTB `interrupt-map` is simple.
  MSI-X needs the GICv3 ITS (complex).
- x86: MSI-X is simple (write the LAPIC address/data), while INTx needs ACPI
  `_PRT`, which means AML interpretation (complex).
- **Decision (implemented):** drivers see an interrupt ID plus an
  `IrqEvent` either way.
  - **INTx where the platform routes it:** aarch64.
  - **Otherwise MSI-X:** `pci::Pci::enable_msix` programs table entry 0 with
    `arch::irqchip::msi_message`. `arch::irqchip::enable` and `disable`
    unmask and mask that entry. Device vectors are 48–63; a message raised
    while masked stays pending in the device, so NAPI-style masking loses
    nothing.
- **virtio caveat:** `virtio-drivers` 0.13 doesn't assign MSI-X vectors to
  the queues. `VirtioNet::route_msix` writes `msix_config` and
  `queue_msix_vector` once, after init. This is documented in
  `drivers/virtio_net.rs` as the one place where leatos touches
  registers the crate also maps. Remove it once `virtio-drivers` supports
  MSI-X.

### 3.4 Effort, as it turned out
The seams held: the port needed no changes to neutral code beyond three
small API additions:
- `mm::mmu::map_device`, because x86 firmware places BARs anywhere in the
  PCI hole;
- MSI-X in `pci` and `arch::irqchip`;
- `mmio::Region16`, for virtio's 16-bit registers.

Testing on Apple Silicon runs under TCG emulation only: functional, not
performance. Performance is measured on the apu4 (M10).
