# Minimising `unsafe`, and portability to x86_64

## 1. Where `unsafe` is unavoidable in a bare-metal router
Only a few kinds of operation fundamentally need it:

| Kind | Examples | Why it can't be safe |
|---|---|---|
| CPU control | MMU/TTBR switch, exception vectors, IRQ entry, PSCI | changes the memory model or control flow |
| System registers without a safe wrapper | GICv3 `ICC_*` | inline asm |
| Creating an MMIO handle | UART, GIC, PCIe ECAM, BARs | an address becomes "a device we own" |
| DMA ownership hand-off | virtio queue buffers | the device writes memory behind Rust's back |
| Global allocator init | heap region | memory becomes "ours" |
| Firmware data | DTB (later ACPI tables) | raw pointer to a blob |

Everything else (protocols, forwarding, NAT, CAKE, the executor, timers,
page-table *construction*, PCI enumeration logic, driver state machines) can be safe.

## 2. Strategy

### 2.1 The compiler enforces the boundary
- `kernel` crate root: `#![deny(unsafe_code)]`.
- Only these modules may opt out, with `#[allow(unsafe_code)]` on the `mod`
  declaration, so `grep allow(unsafe_code)` lists the whole audit surface:
  - `arch::<target>`: CPU, vectors, IRQ entry, sysregs, MMU activation, power
  - `mm::heap`: allocator init
  - `mm::dma`: the `virtio_drivers::Hal` implementation
  - `mmio`: one constructor that turns an address into an MMIO region
  - `platform::dtb`: DTB blob pointer
  - `drivers::virtio_net`: the DMA buffer hand-off (begin/complete pairs)
  - `selftest`: deliberate faults, feature-gated
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
| `drivers::virtio_net` slot ownership | **owned `PacketBuf`s**: a buffer lent to the device lives in a slot until completion, so the type system prevents touching it while the device owns it |
| `irq::IrqEvent` | IRQ → executor signalling with atomics only; `spin::Once` handler table, no raw pointers |
| page-table builder (`mm::mmu`) | page tables held in an owned arena (`Vec<Box<Table>>`), indices instead of raw descriptor pointers. Only `activate()` is unsafe (arch) |

### 2.3 Reuse audited crates instead of writing unsafe code
`virtio-drivers` (virtqueues, PCI transport; used by several Rust OSes),
`safe-mmio` (Google), `aarch64-cpu`, `smoltcp` (no unsafe in the stack itself), `fdt`.
Every dependency is reviewed for `no_std` support and its own unsafe surface before it's added.

### 2.4 Verification
- Host tests and fuzzing cover all safe logic (most of the code, in `crates/*`).
- Miri on host-testable crates that contain unsafe (none today; keep it that way if possible).
- `fault-wx` / `fault-stack` smoke cases verify that the hardware protection (W^X, guard pages) actually holds.

## 3. x86_64 portability

### 3.1 What's the same, and what differs
| Area | aarch64 (now) | x86_64 (future) | Portable? |
|---|---|---|---|
| Boot | QEMU `-kernel` ELF, DTB at RAM start | Limine (or PVH) boot protocol, ACPI RSDP | arch + platform backend |
| HW discovery | DTB | ACPI: MADT (APIC), MCFG (ECAM) | neutral `BootInfo`, two backends |
| Console | PL011 MMIO | 16550 UART (port I/O `0x3f8`) | `arch::console` |
| Interrupt controller | GICv3 | Local APIC + IOAPIC; **MSI/MSI-X preferred** | `arch::irqchip` API |
| Timer (tickless) | generic timer, CNTV_CVAL | **TSC-deadline** LAPIC timer (calibrate the TSC via CPUID 0x15 / HPET) | `arch::timer` API |
| Page tables | 4 KiB granule, 512-entry levels | 4-level, also 4 KiB × 512 | **neutral builder** + per-arch descriptor bits |
| Exceptions | vector table, ESR decode | IDT, error codes, CR2 | `arch::exceptions` → neutral `FaultInfo` |
| Memory ordering for DMA | weak (`dmb`/`dsb`) | strong (TSO) | handled inside virtio-drivers / fences |
| PCIe | ECAM, we assign BARs | ECAM via MCFG; firmware already assigned BARs | **neutral** (keep BARs that are already assigned) |
| virtio-net (PCI) | ✔ | ✔ | **neutral**. This is why we use virtio-**pci**, not virtio-mmio |
| Real NICs | — | Intel i225/i226 (igc), common in x86 mini-PCs | neutral driver over `mmio` + `dma` |

### 3.2 Code layout that keeps the port cheap
```
kernel/src/
  main.rs            arch-neutral boot order
  arch/mod.rs        selects the backend; documents the arch API contract
  arch/aarch64/      boot.S, cpu, exceptions, gic (irqchip), timer, mmu bits, psci, pl011
  arch/x86_64/       compile-only stubs today (`cargo kcheck-x86`)
  platform/          neutral BootInfo + dtb backend (later: acpi backend)
  mm/                heap, page-table builder, dma
  irq.rs timer.rs executor.rs console.rs pci.rs mmio.rs   (neutral)
  drivers/           virtio_net (neutral)
  net/               packet buffers, netdev, smoltcp glue (neutral)
```
**Rule:** nothing outside `arch/` may use `core::arch`, `asm!` or arch-specific
crates. Neutral code calls only the `arch::` API.

**CI guard:** `cargo kcheck-x86` type-checks the kernel for
`x86_64-unknown-none` against stub implementations. If neutral code starts
depending on aarch64, this check fails long before a real port begins.

### 3.3 Device interrupts: the main design fork
- aarch64 QEMU virt: legacy INTx through the DTB `interrupt-map` is simple.
  MSI-X needs the GICv3 ITS (complex).
- x86: MSI-X is simple (write the LAPIC address/data), while INTx needs ACPI
  `_PRT`, which means AML interpretation (complex).
- **Decision:** drivers see an abstract `IrqLine` (enable, disable, and an `IrqEvent` to
  wait on). M2 implements INTx for aarch64. The x86 port implements MSI-X
  behind the same interface. Drivers use a NAPI-style pattern either way:
  interrupt → mask → poll until empty → unmask.

### 3.4 Effort estimate for the x86_64 port (after M2)
Boot via Limine, plus a 16550 console, ACPI (MADT/MCFG, via the `acpi`
crate), LAPIC + IOAPIC, TSC-deadline timer, IDT/exceptions, x86 page-table
bits and MSI-X: **about 4–6 weeks**, if the seams above are kept clean. Testing
on Apple Silicon runs under TCG emulation only (functional, not performance).
