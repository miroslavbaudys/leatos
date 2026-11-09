# Boot flow, memory, interrupts (QEMU aarch64 `virt`)

## Physical memory map (relevant parts)

| Address | What | Mapped as |
|---|---|---|
| `0x0800_0000` | GICv3 distributor (GICD) | Device |
| `0x080a_0000` | GICv3 redistributors (GICR) | Device |
| `0x0900_0000` | PL011 UART (console) | Device |
| `0x0901_0000` | PL031 RTC | Device |
| `0x0a00_0000` | 32 × virtio-mmio slots | Device |
| `0x1000_0000` | PCIe 32-bit MMIO window (751 MiB), where we assign BARs | Device |
| `0x3eff_0000` | PCIe PIO window (unused) | Device |
| `0x4000_0000` | **RAM start**: QEMU puts the DTB here (reserves up to 1 MiB) | Normal RO |
| `0x4020_0000` | **kernel image** (`KERNEL_BASE` in `kernel/linker.ld`) | per section |
| `__kernel_end` → end of RAM | kernel heap | Normal RW |
| `0x40_1000_0000` | PCIe ECAM (256 MiB) | Device |
| `0x80_0000_0000` | PCIe 64-bit MMIO window: **not reachable** with a 39-bit VA; not used | — |

Always take addresses from the DTB (`kernel/src/platform/dtb.rs`) rather than
hard-coding them. The table above is for orientation only.

## Kernel image layout (`kernel/linker.ld`)
Every boundary is page-aligned so permissions can be applied per section:

```
.text (RX) | .rodata (RO) | .data .bss boot-L1-table (RW)
| guard | exception stack 16 KiB (SP_EL1) | guard | kernel stack 256 KiB (SP_EL0) |
__kernel_end → heap
```

## Boot sequence
`kernel/src/arch/aarch64/boot.S`:
1. QEMU jumps to `_start` on core 0 with the MMU off. Secondary cores stay
   off until PSCI `CPU_ON`.
2. If running at EL2 (TCG with `virtualization=on`), drop to EL1. Under HVF
   the core already starts at EL1.
3. Enable FP/SIMD (rustc emits NEON instructions) and set SCTLR_EL1 to a known value.
4. **Two stacks:** SP_EL1 is the exception stack. Then `msr spsel, #0`, and SP_EL0
   becomes the kernel stack. The kernel runs in "EL1t" mode, so every
   exception switches to SP_EL1. That's why a kernel stack overflow can still be reported.
5. Zero `.bss`, then build a **coarse identity map** (one L1 table, 1 GiB blocks: RAM
   Normal, everything else Device), and turn on the MMU and caches. **This is
   required before running Rust code**: with the MMU off, all memory is Device,
   so unaligned accesses and atomic exclusives can fault on real cores (HVF).
6. Install `VBAR_EL1` and call `kernel_main(x0)`.

`kernel/src/main.rs` (`kmain`, called by `arch::aarch64::kernel_main`):
7. Start the clock, discover hardware from the DTB (**no heap use before `heap::init`**), print the report.
8. `heap::init`: the rest of RAM after the kernel.
9. `mmu::init`: build **4 KiB-granular** tables from the heap and switch TTBR0
   (MMU off → swap → TLB flush → MMU on, which avoids break-before-make
   conflicts). It also sets **SCTLR.WXN**. Permissions: `.text` RX, `.rodata` and
   DTB RO, everything writable is XN, guard pages unmapped, MMIO Device+XN.
10. `gic::init`, `timer::init_irq`, unmask IRQs.
11. `pci::enumerate`: scan ECAM and assign memory BARs from the 32-bit window.
12. Self-tests, then `executor::run()`.

## Exceptions and interrupts
- **Vector table** (`boot.S`): entry 1 (IRQ, current EL, SP0) is the normal
  IRQ path. Every other entry is fatal and goes to `rust_exception`, which decodes
  ESR (exception class, data/instruction abort status, read/write) and names
  guard-page hits.
- **IRQ path** (`arch/aarch64/boot.S` → `arch/aarch64/exceptions.rs` → `irq::dispatch`): `irq_entry` saves x0–x18, x29, x30, ELR, SPSR, FPCR, FPSR and
  **all q0–q31** (720-byte frame on SP_EL1), calls `rust_irq`, and restores.
  `rust_irq` loops acknowledge (ICC_IAR1) → `irq::dispatch` (runs the
  registered action, then signals its `IrqEvent`) → EOI, until a spurious
  INTID is returned. An INTID with no handler is disabled.
- **Handler rules:** acknowledge the device and set an atomic flag. No
  allocation, no printing, no locks shared with thread context.
- **GICv3:** all interrupts are Group 1 NS at priority `0xa0`, PMR `0xff`,
  affinity routing, and SPIs routed to core 0. The redistributor is found by
  walking GICR frames and matching affinity.

## Timers
The EL1 **virtual** timer (INTID 27, read from the DTB) runs **tickless**:
`CNTV_CVAL_EL0` holds the earliest deadline from a `BTreeMap`, or the timer is
off. The IRQ only masks the timer and sets `FIRED`; `timer::process()`
(thread context) wakes expired `Sleep` futures and re-arms the comparator.
On virtual machines, **hybrid idle** arms the comparator 4 ms early and
spins out the rest of the wait (see bufferbloat-cake.md §3.2).

## Power off
`psci::system_off()` uses PSCI `SYSTEM_OFF` (`0x8400_0008`) through the
conduit named in the DTB (`hvc` on QEMU virt). The `smoke-test` feature uses
it so automated runs exit.

## Known limits
- RAM above 4 GiB and the 64-bit PCIe window are outside the 39-bit VA. Keep
  `-m` ≤ 3G. Moving to a 48-bit VA (start at L0) is a small change once it's needed.
- Single core only. SMP needs PSCI `CPU_ON`, per-core stacks and redistributors, and an SMP-safe executor.
- PCI: bus 0 only in practice (bridges are listed but not configured), no
  I/O BARs. Device interrupts use legacy INTx routed through the DTB
  `interrupt-map` (virtio-net: INTID 36/37). MSI-X arrives with the x86 port
  or the GIC ITS.
- The stack was 64 KiB until M2: NIC bring-up in debug builds overflowed it.
  The guard page caught this cleanly.
