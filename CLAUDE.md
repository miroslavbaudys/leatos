# CLAUDE.md

rrouter is a SOHO router OS in Rust: a **bare-metal unikernel** for aarch64 (QEMU `virt`, HVF on Apple Silicon) and x86_64 (QEMU q35 via PVH, TCG; target hardware: PC Engines apu4, M10).
Goals: PPPoE, DHCP (v4 server/client, DHCPv6-PD, RA), a DNS forwarder, NAT, a firewall, IPv4 + IPv6, and
**bufferbloat mitigation with CAKE**, which is a core design driver (`docs/bufferbloat-cake.md`).

## Layout
- `kernel/` (`rrouter-kernel`, binary `rrouter`)
  - `src/main.rs`: arch-neutral boot order (`kmain`). `#![deny(unsafe_code)]` applies crate-wide
  - `src/arch/`: **all** CPU-specific code. `aarch64/` (boot.S, cpu, exceptions + IRQ entry, irqchip = GICv3, timer, mmu descriptors, power = PSCI, console = PL011) and `x86_64/` (boot.S = PVH entry → long mode, isr.S, exceptions = IDT/TSS/IST, irqchip = local APIC + MSI-X, timer = TSC + LAPIC one-shot, power = ACPI S5, console = 16550, port I/O). `arch/mod.rs` documents the API every backend provides
  - `src/platform/`: neutral `BootInfo` (no allocation); `dtb.rs` (aarch64); `pvh.rs` / `multiboot2.rs` + `acpi.rs` over `phys.rs` (x86_64: one unsafe byte-view constructor, safe parsers)
  - `src/mm/`: `heap`, `mmu` (neutral page-table builder; arch supplies the encoding), `dma` (virtio `Hal`), `sym` (linker symbols)
  - `src/mmio.rs`: `Region` = safe, bounds-checked MMIO over `safe-mmio`
  - `src/irq.rs` (dispatch + `IrqEvent`), `timer.rs` (tickless, `sleep`), `executor.rs` (priority async; accounts idle and per-priority poll time), `cpuload.rs` (1 s CPU load samples, 5 min history, shown on the mgmt page), `console.rs` (`println!`, `fatal_println!`), `pci.rs` (via `virtio-drivers` `PciRoot`), `selftest.rs`
  - `src/drivers/`: `Nic` (the one NIC interface the stack uses), `virtio_net.rs` (slot-owned DMA buffers, pull-based TX with a byte limit), `igb.rs` (i210/i211 + QEMU's 82576: own descriptor rings in `mm::dma::DmaRegion`, INTx or MSI-X, same TX contract)
  - `src/net/`: `packet.rs` (bounded pool, headroom, `PacketMeta`), `datapath.rs` (NIC RX → `fwd::Forwarder` → neighbor → qdisc → NIC TX), `device.rs` (smoltcp `Device` behind the datapath: RX from `local_rx`, TX into the qdisc), `stack.rs` (port bring-up + the **datapath task** `net`: NAPI-style IRQ loop), `svc.rs` (the **services task** `svc`, `Priority::Service`: smoltcp, WAN DHCP client, LAN services, mgmt), `shared.rs` (the only coupling between them: per-port locked qdisc + `local_rx`, stats snapshot, `Control` messages, `dp_kick`/`svc_kick` events), `services.rs` (LAN DHCP server + DNS forwarder: smoltcp UDP sockets ↔ sans-IO crates)
  - `src/net/mgmt.rs` + `mgmt.html`: management web interface on :80 (status page, `GET /api/status`, `POST /api/upgrade` streamed into the staging area, `POST /api/reboot`; Basic auth `admin` + `mgmt_pass`)
  - `src/upgrade.rs`: in-RAM upgrade (validate + flatten an uploaded kernel in the staging area at the top of RAM, `mm::heap::take_staging`; `arch::kexec` copies it into place and enters it like a Multiboot2 loader; x86_64 only)
  - `src/config.rs`: one `config::Config` (`crates/config`) built at boot by `config::load()` (after `heap::init`): defaults ← stored `config.toml` (store not wired yet) ← boot arguments; `lan()`/`dns()`/`qos()`/`mgmt()` are views of it. Without a stored config the lab's `nas` reservation (host .10) is added
  - `linker.ld` (aarch64, kernel at `0x4020_0000`) / `linker-x86_64.ld` (at 1 MiB, keeps the PVH note): page-aligned sections, guard pages, 16 KiB exception stack + 256 KiB kernel stack
- Implemented and tested: `crates/proto-dhcp` (DHCPv4 server), `crates/proto-dns` (forwarder), `crates/fwd` (`wire`, `route`, `neigh`, `conntrack` with NAPT, `forwarder` pipeline), and `crates/qdisc` (`Qdisc` trait, `BFifo`, `codel` = RFC 8289 with ECN, `fq_codel` = RFC 8290 flow queueing (DRR, new-flows list, fattest-flow overflow drop, slab storage), `cake` = CAKE core on top (8-way set-associative hashing, host isolation from pre-NAT host hashes, COBALT = CoDel + BLUE); `testutil` = shared simulation with Reno-like, unresponsive and sparse senders). CAKE is the default egress qdisc on both ports (`net/device.rs` `Aqm`), wrapped in `shaper::Shaper` (WAN = upload rate, LAN = download rate; boot args `shape_up=`/`shape_down=` kbit/s, `shape_overhead=`). `crates/boot-image` (ELF64 validation/flattening, Multiboot2 header check + boot-info builder, CRC-32) `crates/proto-http` (incremental HTTP/1.1 parser with streaming bodies, Basic auth, JSON escaping) and `crates/config-store` (power-fail-safe store partition: MBR lookup, store header with areas, A/B record slots, write plans; `docs/config-and-storage.md`) and `crates/config` (`config.toml` schema v1 via `toml` + serde: defaults, `deny_unknown_fields`, cross-field validation with paths). Skeleton: `proto-pppoe`
- `lab/client/`, `lab/isp/`: overlays for the Alpine lab VMs (`/init`, configs, web/CGI); `lab/cache/` (gitignored) holds downloads
- `scripts/qemu-run.sh` (cargo runner), `scripts/apu-image.sh` (apu4 USB/SD image: MBR + FAT32 + Limine BIOS → Multiboot2), `scripts/smoke-test.sh`, `scripts/lab-test.sh`, `scripts/mac-lab.sh` (+ `scripts/lab/`: fetch, initrd build, `common.sh`), `scripts/unsafe-report.sh`
- `docs/`: architecture, boot-and-memory, qemu, soho-features, bufferbloat-cake, safety-and-portability, config-and-storage, roadmap

## Commands
- `cargo kbuild [--release]`: build the kernel. `cargo krun` boots it (`Ctrl-A X` quits; `QEMU_NET=user` adds 2 NICs)
- `scripts/smoke-test.sh`: cases boot (DHCP + ping), fault-wx, fault-stack. Also run `QEMU_ACCEL=tcg scripts/smoke-test.sh` after boot, MMU, IRQ, timer or driver changes
- `scripts/lab-test.sh`: client VM + router + ISP VM; DHCP, DNS, NAT, ICMP, traceroute, firewall end to end, plus router-side ECN and the per-task CPU split (`net` vs `svc`) (`LAB_VERBOSE=1` for consoles). Run it after any network change, also with `QEMU_ACCEL=tcg`
- `scripts/apu-upload.sh [--host H] [--cmdline "..."] [--debug] [--reboot]`: build + strip the x86_64 kernel and upgrade a running rrouter in RAM over HTTP (password from `target/apu4/mgmt-pass`). `scripts/upgrade-test.sh`: the same end to end in QEMU (401/422/404 negative controls, two chained upgrades, reboot); run it after changes to mgmt, upgrade, kexec, boot or the x86 NIC path
- `scripts/apu-image.sh [--debug] [--mgmt-wan] [--cmdline "..."]`: bootable image for the apu4 (`target/apu4/rrouter-apu4.img`; needs `brew install limine mtools`). `RROUTER_BOOT=limine scripts/smoke-test.sh` boots it through SeaBIOS + Limine in QEMU; run it after x86 boot or linker-script changes. `QEMU_DISK=img scripts/qemu-run.sh` boots any image
- `QEMU_NIC=igb` (any QEMU-based script): router NICs are QEMU's 82576 instead of virtio-net. Run smoke + lab with it after igb driver or datapath changes
- `scripts/mac-internet.sh [--check] [--wan-if enX] [--ipv4-only] [--release] [--shape U:D] [--kernel-args "..."] | --restore`: route the Mac's real IPv4 internet + DNS through rrouter (WAN vmnet-bridged); state saved before changes, watchdog + `--restore` undo
- `scripts/bufferbloat.sh [--label X]`: latency idle vs. under download/upload load, throughput and grade. Runs are marked INVALID if the load failed; results go to `lab/cache/bufferbloat.csv`
- `scripts/mac-lab.sh [--check]`: put the developer's Mac on rrouter's LAN (vmnet-host, needs sudo, so run it in Terminal); only 203.0.113.0/24 and `*.lan`/`*.example` DNS go via rrouter; cleans up on exit
- `cargo test`: host tests for `crates/*`; `cargo clippy --all-targets` for the crates
- `cargo kclippy [--features <f>]`: run for each of `smoke-test`, `idle-poll`, `fault-wx`, `fault-stack`
- `cargo kcheck-x86`: type-check neutral code for x86_64 (**must stay green**); `cargo kbuild-x86` / `krun-x86` / `kclippy-x86 [--features <f>]` for the x86_64 kernel (run kclippy-x86 for the same features as kclippy)
- `RROUTER_ARCH=x86_64 scripts/smoke-test.sh` / `scripts/lab-test.sh`: the same tests with the x86_64 kernel (TCG; client/ISP VMs stay aarch64). Run them after arch, boot, IRQ, timer, PCI or driver changes
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
- Kernel runtime options are **boot arguments** (DTB `/chosen/bootargs`, QEMU `-append` via `QEMU_APPEND`), parsed in `config.rs`: `shape_up`, `shape_down`, `shape_overhead`, `ecn_up` (default 0: drop on upload), `ecn_down` (default 1: mark on download), `ecn` (sets both), `qdisc` (`cake` default, `fq_codel`, `codel` = single queue), `isolation` (`triple-isolate` default, `dual-srchost`, `dual-dsthost`, `flows`), `idle_spin_us`, `lan=a.b.c.d/len` (LAN subnet; pool .100–.199), `mgmt=wan` (web interface on the WAN too: development only), `mgmt_pass=` (enables upgrade/reboot; masked in logs via `config::Redacted`). `scripts/lab-test.sh` passes extra ones via `LAB_ROUTER_ARGS` and checks per-direction ECN from the router's counters (`LAB_EXPECT_ECN=U:D` for the negative control).
- No heap use before `heap::init` (platform discovery runs before it). On x86_64, firmware memory (`platform::phys` views) is only valid during discovery: copy what you need into `BootInfo` or statics.
- New MMIO must be mapped in `mm::mmu::init` (or `arch::mmu::PLATFORM_MMIO`), or at runtime with `mm::mmu::map_device` (PCI BARs). Writable memory is never executable.
- Device interrupts: INTx where the platform routes it (aarch64), else MSI-X (`Pci::enable_msix`, vectors from `arch::irqchip::msi_vector`). Never add IOAPIC/INTx routing that needs ACPI AML.
- **Latency-first datapath (CAKE):** the qdisc is the only place packets may wait (no other FIFOs). TX is pull-based (`can_transmit` before `transmit`). Timers are tickless, so no periodic tick. Datapath tasks run at `Priority::Datapath`; router-local work (smoltcp, DHCP, DNS, mgmt, future services) runs in `Priority::Service` tasks and reaches the datapath only through `net::shared` (`spin::Mutex` + atomics, no `RefCell`, so tasks can move to other cores). Forwarded packets never leave the datapath task.
- **Ports:** NAT uses 10000–39999; router-local sockets (DNS upstream, future services) must bind ≥ 40000 so replies are never mistaken for NAT traffic.
- Never edit a script in place while it may be running (bash reads scripts incrementally): write a temp file and rename it over the original.
- Measurements must prove the load or condition actually happened (validity checks), or be reported as invalid.
- New lab checks need a **negative control** (show that the check fails when the feature is broken), as done for the firewall probe.
- **Packet buffers** come only from `net::packet` (bounded pool, no allocation per packet). On pool exhaustion, drop; never grow.
- **IRQ handlers** (`irq::register` actions) only acknowledge or mask hardware and touch atomics. No allocation, no `println!`, no locks except ones thread context takes with IRQs masked (the irqchip lock). Work runs in tasks awaiting an `IrqEvent`. Device interrupts follow NAPI: mask → poll until empty → unmask.
- Timer precision under QEMU/HVF comes from **hybrid idle** (`timer::set_spin_window`, 4 ms on virtual machines, 0 on hardware). Don't add other workarounds for `wfi` latency; `idle-poll` is only for experiments.
- Network changes on the developer's Mac: mac-lab only adds lab-scoped routes and resolvers. mac-internet may change routing and DNS, but only after confirmation, with the original state saved first, `/1` routes (never the default route), a watchdog, and `--restore`. Keep these guarantees in any new script.
- Lab downloads are pinned by SHA-256 in `scripts/lab/fetch-alpine.sh`; never unpin. Update the hashes deliberately.
- Shell scripts must run on macOS bash 3.2 (no associative arrays) and BSD tools (no `\s` in sed, no `timeout`).
- Update the status column in `docs/roadmap.md` when a milestone is done.
