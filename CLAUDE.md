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
  - `src/net/`: `packet.rs` (bounded pool, headroom, `PacketMeta`), `datapath.rs` (NIC RX → `fwd::Forwarder` → neighbor → qdisc → NIC TX), `device.rs` (smoltcp `Device` behind the datapath: RX from `local_rx`, TX into the qdisc), `stack.rs` (ports, WAN DHCP client, NAPI-style IRQ loop), `services.rs` (LAN DHCP server + DNS forwarder: smoltcp UDP sockets ↔ sans-IO crates)
  - `src/config.rs`: compiled-in defaults (LAN 192.168.1.1/24, DHCP range, statics, DNS) until the config store exists
  - `linker.ld`: kernel at `0x4020_0000`, page-aligned sections, guard pages, 16 KiB exception stack + 256 KiB kernel stack
- Implemented and tested: `crates/proto-dhcp` (DHCPv4 server), `crates/proto-dns` (forwarder), `crates/fwd` (`wire`, `route`, `neigh`, `conntrack` with NAPT, `forwarder` pipeline), and `crates/qdisc` (`Qdisc` trait + `BFifo` placeholder). Skeleton: `proto-pppoe`
- `lab/client/`, `lab/isp/`: overlays for the Alpine lab VMs (`/init`, configs, web/CGI); `lab/cache/` (gitignored) holds downloads
- `scripts/qemu-run.sh` (cargo runner), `scripts/smoke-test.sh`, `scripts/lab-test.sh` (+ `scripts/lab/`), `scripts/unsafe-report.sh`
- `docs/`: architecture, boot-and-memory, qemu, soho-features, bufferbloat-cake, safety-and-portability, roadmap

## Commands
- `cargo kbuild [--release]`: build the kernel. `cargo krun` boots it (`Ctrl-A X` quits; `QEMU_NET=user` adds 2 NICs)
- `scripts/smoke-test.sh`: cases boot (DHCP + ping), fault-wx, fault-stack. Also run `QEMU_ACCEL=tcg scripts/smoke-test.sh` after boot, MMU, IRQ, timer or driver changes
- `scripts/lab-test.sh`: client VM + router + ISP VM; DHCP, DNS, NAT, ICMP, traceroute, firewall end to end (`LAB_VERBOSE=1` for consoles). Run it after any network change, also with `QEMU_ACCEL=tcg`
- `cargo test`: host tests for `crates/*`; `cargo clippy --all-targets` for the crates
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
- **Ports:** NAT uses 10000–39999; router-local sockets (DNS upstream, future services) must bind ≥ 40000 so replies are never mistaken for NAT traffic.
- New lab checks need a **negative control** (show that the check fails when the feature is broken), as done for the firewall probe.
- **Packet buffers** come only from `net::packet` (bounded pool, no allocation per packet). On pool exhaustion, drop; never grow.
- **IRQ handlers** (`irq::register` actions) only acknowledge or mask hardware and touch atomics. No allocation, no `println!`, no locks except ones thread context takes with IRQs masked (the irqchip lock). Work runs in tasks awaiting an `IrqEvent`. Device interrupts follow NAPI: mask → poll until empty → unmask.
- Under QEMU on macOS, `wfi` wake-up adds up to ~3 ms; don't "fix" timer code for it (use the `idle-poll` feature; see docs/qemu.md).
- Lab downloads are pinned by SHA-256 in `scripts/lab/fetch-alpine.sh`; never unpin. Update the hashes deliberately.
- Shell scripts must run on macOS bash 3.2 (no associative arrays) and BSD tools (no `\s` in sed, no `timeout`).
- Update the status column in `docs/roadmap.md` when a milestone is done.
