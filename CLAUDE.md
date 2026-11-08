# CLAUDE.md

rrouter is a SOHO router OS in Rust: a **bare-metal unikernel**, running on aarch64 QEMU `virt` today (HVF on Apple Silicon), with x86_64 planned.
Goals: PPPoE, DHCP (v4 server/client, DHCPv6-PD, RA), a DNS forwarder, NAT, a firewall, IPv4 + IPv6, and
**bufferbloat mitigation with CAKE**, which is a core design driver (`docs/bufferbloat-cake.md`).

## Layout
- `kernel/` (`rrouter-kernel`, binary `rrouter`)
  - `src/main.rs`: arch-neutral boot order (`kmain`). `#![deny(unsafe_code)]` applies crate-wide
  - `src/arch/`: **all** CPU-specific code. `aarch64/` (boot.S, cpu, exceptions + IRQ entry, irqchip = GICv3, timer, mmu descriptors, power = PSCI, console = PL011) and `x86_64/` (compile-only skeleton). `arch/mod.rs` documents the API every backend provides
  - `src/platform/`: neutral `BootInfo` (no allocation) + `dtb.rs` backend (later `acpi`)
  - `src/mm/`: `heap`, `mmu` (neutral page-table builder; arch supplies the encoding), `dma` (virtio `Hal`), `sym` (linker symbols)
  - `src/mmio.rs`: `Region` = safe, bounds-checked MMIO over `safe-mmio`
  - `src/irq.rs` (dispatch + `IrqEvent`), `timer.rs` (tickless, `sleep`), `executor.rs` (priority async), `console.rs` (`println!`, `fatal_println!`), `pci.rs` (via `virtio-drivers` `PciRoot`), `selftest.rs`
  - `src/drivers/virtio_net.rs`: slot-owned DMA buffers, pull-based TX with a byte limit
  - `src/net/`: `packet.rs` (bounded pool, headroom, `PacketMeta`), `device.rs` (smoltcp glue), `stack.rs` (WAN DHCP, LAN static, NAPI-style IRQ loop)
  - `linker.ld`: kernel at `0x4020_0000`, page-aligned sections, guard pages, 16 KiB exception stack + 256 KiB kernel stack
- `crates/proto-pppoe`, `proto-dhcp`, `proto-dns`, `fwd`, `qdisc`: sans-IO logic (skeletons for now)
- `scripts/qemu-run.sh` (cargo runner), `scripts/smoke-test.sh`, `scripts/unsafe-report.sh`
- `docs/`: architecture, boot-and-memory, qemu, soho-features, bufferbloat-cake, safety-and-portability, roadmap

## Commands
- `cargo kbuild [--release]`: build the kernel. `cargo krun` boots it (`Ctrl-A X` quits; `QEMU_NET=user` adds 2 NICs)
- `scripts/smoke-test.sh`: cases boot (DHCP + ping), fault-wx, fault-stack. Also run `QEMU_ACCEL=tcg scripts/smoke-test.sh` after boot, MMU, IRQ, timer or driver changes
- `cargo test`: host tests for `crates/*`
- `cargo kclippy [--features <f>]`: run for each of `smoke-test`, `idle-poll`, `fault-wx`, `fault-stack`
- `cargo kcheck-x86`: type-check neutral code against the x86_64 skeleton (**must stay green**)
- `scripts/unsafe-report.sh`: the unsafe audit surface

## Rules
- **Never set `build.target` in `.cargo/config.toml`.** Use the `k*` aliases.
- **Arch boundary:** outside `kernel/src/arch/`, nothing may use `asm!`, `core::arch` or arch crates (`aarch64-cpu`). Neutral code calls only the `arch::` API. Keep `cargo kcheck-x86` passing.
- **Unsafe policy** (docs/safety-and-portability.md):
  - `unsafe` is denied crate-wide. A module may opt in only via `#[allow(unsafe_code)] // reason` on its `mod` line.
  - Prefer building a safe abstraction (`mmio::Region`, slot ownership, `PciRoot`) over spreading `unsafe`.
  - Every block needs `// SAFETY:` (denied otherwise), with one unsafe op per block.
  - `crates/*` are `#![forbid(unsafe_code)]`.
- `crates/*` are `#![no_std]` + `alloc` and **sans-IO** (pass bytes and `now` in; return bytes and events). Protocol logic goes there, not in the kernel.
- Dependencies must be `no_std`. Prefer audited crates (virtio-drivers, safe-mmio, smoltcp, aarch64-cpu) over hand-written unsafe.
- Edition 2024: `#[unsafe(no_mangle)]`, `unsafe extern "C"`, `&raw const`.
- No heap use before `heap::init` (platform discovery runs before it).
- New MMIO must be mapped in `mm::mmu::init` (or `arch::mmu::PLATFORM_MMIO`). Writable memory is never executable.
- **Latency-first datapath (CAKE):** the qdisc is the only place packets may wait (no other FIFOs). TX is pull-based (`can_transmit` before `transmit`). Timers are tickless, so no periodic tick. Datapath tasks run at `Priority::Datapath`.
- **Packet buffers** come only from `net::packet` (bounded pool, no allocation per packet). On pool exhaustion, drop; never grow.
- **IRQ handlers** (`irq::register` actions) only acknowledge or mask hardware and touch atomics. No allocation, no `println!`, no locks except ones thread context takes with IRQs masked (the irqchip lock). Work runs in tasks awaiting an `IrqEvent`. Device interrupts follow NAPI: mask → poll until empty → unmask.
- Under QEMU on macOS, `wfi` wake-up adds up to ~3 ms; don't "fix" timer code for it (use the `idle-poll` feature; see docs/qemu.md).
- Update the status column in `docs/roadmap.md` when a milestone is done.
