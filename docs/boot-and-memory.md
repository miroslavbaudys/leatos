# Boot flow and memory map (QEMU aarch64 `virt`)

## Physical memory map (relevant parts)

| Address | What | Mapped as |
|---|---|---|
| `0x0800_0000` | GICv3 distributor / redistributors | Device |
| `0x0900_0000` | PL011 UART (console) | Device |
| `0x0901_0000` | PL031 RTC | Device |
| `0x0a00_0000` | 32 × virtio-mmio slots | Device |
| `0x1000_0000` | PCIe MMIO window | Device |
| `0x3eff_0000` | PCIe PIO window | Device |
| `0x4000_0000` | **RAM start**: QEMU puts the DTB here (reserves up to 1 MiB) | Normal |
| `0x4020_0000` | **kernel image** (`KERNEL_BASE` in `kernel/linker.ld`) | Normal |
| `__kernel_end` → end of RAM | kernel heap | Normal |
| `0x40_1000_0000` | PCIe ECAM (high, 256 MiB) | Device |

Always take addresses from the DTB (`kernel/src/dtb.rs`) rather than
hard-coding them. The table above is for orientation only.

## Boot sequence (`kernel/src/boot.S`)
1. QEMU loads the ELF and jumps to `_start` on core 0 with the MMU off.
   Secondary cores stay off until PSCI `CPU_ON`.
2. If running at EL2 (TCG with `virtualization=on`), drop to EL1. Under HVF
   the core already starts at EL1.
3. Enable FP/SIMD (`CPACR_EL1.FPEN`), because rustc emits NEON instructions.
4. Set SCTLR_EL1 to a known value, set up the stack (64 KiB) and zero `.bss`.
5. Build an **identity map** in a single level-1 table (4 KiB granule,
   T0SZ=25 → 39-bit VA, 512 × 1 GiB blocks):
   - entries 1..3 (`0x4000_0000`–`0xFFFF_FFFF`): Normal write-back (RAM)
   - all others: Device-nGnRnE, execute-never
6. Turn on the MMU and the I- and D-caches. **This is required before running
   Rust code**: with the MMU off, all memory is treated as Device memory, so
   unaligned accesses and atomic exclusives can fault on real cores (HVF).
7. Install `VBAR_EL1` and call `kernel_main(x0)`.

### Limits of the current mapping
- RAM above 4 GiB isn't mapped, so keep QEMU at `-m` ≤ 3G.
- There are no guard pages and no W^X yet. Splitting into 4 KiB pages with
  per-section permissions is milestone M1 work.

## Exceptions
Every vector currently reports `ESR_EL1`, `ELR_EL1` and `FAR_EL1` and halts
(`kernel/src/exceptions.rs`). IRQ handling arrives with the GIC driver.

## Power off
`psci::system_off()` uses PSCI `SYSTEM_OFF` (`0x8400_0008`) through the
conduit named in the DTB (`hvc` on QEMU virt). The `smoke-test` feature uses
it so automated runs exit.
