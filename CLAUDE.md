# CLAUDE.md

leatos is a SOHO router OS in Rust: a **bare-metal unikernel** for aarch64 (QEMU `virt`, HVF on
Apple Silicon) and x86_64 (QEMU q35 via PVH, TCG; target hardware: PC Engines apu4, M10).
Formerly **rrouter** (renamed 2026-11-19). The old name stays where changing it would break
something deployed: the store magics `RRSTORE1`/`RREC` (crates/config-store), `/boot/rrouter` on
apu4 SD cards flashed before the rename (new images use `/boot/leatos`) and the `mac-lab.sh`
resolver marker (old one still recognised).
Goals: PPPoE, DHCP (v4 server/client, DHCPv6-PD, RA), a DNS forwarder, NAT, a firewall, IPv4 +
IPv6, and **bufferbloat mitigation with CAKE**, which is a core design driver
(`docs/bufferbloat-cake.md`).

## Where things are

Details live next to the code: `kernel/CLAUDE.md`, `kernel/src/net/CLAUDE.md`, `crates/CLAUDE.md`.
Keep them current when you change what they describe; keep this file to the map and the rules.

- `kernel/` (`leatos-kernel`, binary `leatos`): `src/main.rs` = boot order (`kmain`);
  `src/arch/{aarch64,x86_64}/` = **all** CPU-specific code (API in `arch/mod.rs`);
  `src/platform/` = DTB / PVH / Multiboot2 / ACPI discovery into `BootInfo`; `src/mm/` (stacks,
  heap = `talc`, page tables, DMA); `src/smp.rs`, `irq.rs`, `timer.rs` (tickless), `executor.rs`
  (priority async, pinned tasks); `src/drivers/` (virtio-net, igb, virtio-blk, sdhci, watchdogs,
  CCP TRNG, CPU temperature); `src/config.rs` (boot-time `Config`), `store.rs`, `upgrade.rs`,
  `cli.rs`, `console.rs`, `fatal.rs`, `watchdog.rs`, `entropy.rs`, `wallclock.rs`.
- `kernel/src/net/`: the datapath tasks `dp_down`/`dp_up` (`stack.rs`, `datapath.rs`), the services
  task `svc` (`svc.rs`: WAN, LAN services, mgmt; the router's own UDP / ICMP in `local.rs`,
  smoltcp for TCP only), `shared.rs` = the only coupling between them, `mgmt.rs` + `mgmt.html` = web
  interface and API on :80.
- Ports: `wan0` + routed LAN ports `lan0`–`lan2` (NICs in PCI order), no bridge; networks (VLANs)
  are link slots on a port.
- `crates/`: sans-IO protocol and policy crates: `fwd` (forwarder, conntrack/NAT, firewall, routes,
  fragments), `qdisc` (CoDel, fq_codel, CAKE), `proto-{dhcp,dns,dot,pppoe,sntp,mdns,http}`, `auth`,
  `cli`, `config` (`config.toml` schema v2, docs/config-v2.md), `config-store` (power-fail-safe
  store), `boot-image`.
- `fuzz/`: cargo-fuzz targets (own workspace, nightly; fuzz/README.md): `fwd`, `pppoe`, `dns`,
  `dhcp6`, `sntp`, `http`, `dhcp`, `dhcp_client`, `mdns`, `qdisc`, `ack_filter`, `boot_image`,
  `cli`, `config` (seeds in `fuzz/seeds/config`), `store`, `dns_tcp`, `auth`, `dot`; shared
  builders in `fuzz/src/lib.rs`.
- `tools/leatstore`: host tool for store images: `create`, `format`, `show`, `put` (refuses a clear
  `mgmt.password`), `get`, `corrupt`, `hash <password>`.
- `lab/client/`, `lab/isp/`: overlays for the Alpine lab VMs (`/init`, configs, web/CGI);
  `lab/cache/` (gitignored) holds downloads and results.
- `scripts/`: `qemu-run.sh` (cargo runner), tests (docs/lab-tests.md), apu4 image + upload, Mac
  network helpers, `doc-check.sh`, `unsafe-report.sh`; `scripts/lab/`: fetch (`fetch-alpine.sh`),
  initrd build, `common.sh`.
- `docs/`: design and reference. Start with architecture.md and roadmap.md;
  **boot-arguments.md** (every kernel option), **lab-tests.md** (every test and its negative
  controls), safety-and-portability, smp, config-and-storage, config-v2, upgrades, ipv6,
  security-audit, lan-neighbors (done: one neighbor table, the datapath does ARP / ND),
  local-stack (done in QEMU: smoltcp for TCP only), proxmox (plan: leatos as a KVM / Proxmox
  guest), …

## Rules

- **Never set `build.target` in `.cargo/config.toml`.** Use the `k*` aliases.
- **Arch boundary:** outside `kernel/src/arch/`, nothing may use `asm!`, `core::arch` or arch
  crates (`aarch64-cpu`). Neutral code calls only the `arch::` API. Keep `cargo kcheck-x86`
  passing.
- **Unsafe policy** (docs/safety-and-portability.md):
  - `unsafe` is denied crate-wide. A module may opt in only via `#[allow(unsafe_code)] // reason` on
    its `mod` line.
  - Prefer building a safe abstraction (`mmio::Region`, slot ownership, `PciRoot`) over spreading
    `unsafe`.
  - Every block needs `// SAFETY:` (denied otherwise), with one unsafe op per block.
  - `crates/*` are `#![forbid(unsafe_code)]`.
- `crates/*` are `#![no_std]` + `alloc` and **sans-IO** (pass bytes and `now` in; return bytes and
  events). Protocol logic goes there, not in the kernel.
- Dependencies must be `no_std`. Prefer audited crates (virtio-drivers, safe-mmio, smoltcp,
  aarch64-cpu) over hand-written unsafe.
- Edition 2024: `#[unsafe(no_mangle)]`, `unsafe extern "C"`, `&raw const`.
- Kernel runtime options are **boot arguments**, parsed in `config.rs`; those with a config field
  override it. A new one gets a row in `docs/boot-arguments.md`, a new `LAB_*` variable a line in
  the header of `scripts/lab-test.sh` (`scripts/doc-check.sh` fails otherwise).
- No heap use before `heap::init` (platform discovery runs before it). On x86_64, firmware memory
  (`platform::phys` views) is only valid during discovery: copy what you need into `BootInfo` or
  statics.
- New MMIO must be mapped in `mm::mmu::init` (or `arch::mmu::PLATFORM_MMIO`), or at runtime with
  `mm::mmu::map_device` (PCI BARs). Writable memory is never executable.
- Device interrupts: INTx where the platform routes it (aarch64), else MSI-X (`Pci::enable_msix`,
  vectors from `arch::irqchip::msi_vector`). Never add IOAPIC/INTx routing that needs ACPI AML.
- **Latency-first datapath (CAKE):** the qdisc is the only place packets may wait (no other
  FIFOs). TX is pull-based (`can_transmit` before `transmit`). Timers are tickless, so no periodic
  tick. Datapath tasks run at `Priority::Datapath`; router-local work (smoltcp, DHCP, DNS, mgmt,
  future services) runs in `Priority::Service` tasks and reaches the datapath only through
  `net::shared` (`spin::Mutex` + atomics, no `RefCell`, so tasks can move to other cores).
  Forwarded packets never leave the datapath task.
- **Ports:** NAT uses 10000–39999 (skipping forwarded ports). Router-local client sockets (SNTP
  60000–60999, DNS upstream 61000–65535 with a fresh random port per query, DoT TCP 61000–64999,
  future ones) must bind ≥ 60000 (`fwd::forwarder::ROUTER_CLIENT_PORTS`; TCP replies pass only from
  `Policy::router_tcp_peers`) so replies are never mistaken for NAT or port-forward traffic. UDP
  from outside reaches only bound client ports (`net::shared::CLIENT_PORTS` →
  `fwd::forwarder::ClientPorts`; 68 only from 67, 546 only from 547), the rest is dropped
  silently; UDP to any router port nobody bound is dropped silently by `net::local` too (smoltcp
  has no UDP and would answer protocol unreachable), so the router answers no UDP scan. Port
  forwards may use anything below 60000
  (validated).
- **Packet buffers** come only from `net::packet` (bounded pool, no allocation per packet). On
  pool exhaustion, drop; never grow.
- **IRQ handlers** (`irq::register` actions) only acknowledge or mask hardware and touch atomics.
  No allocation, no `println!`, no locks except ones thread context takes with IRQs masked (the
  irqchip lock). Work runs in tasks awaiting an `IrqEvent`. Device interrupts follow NAPI: mask →
  poll until empty → unmask. INTx lines may be shared (QEMU `virt`: slots 4 and 8 on one line with
  three igbs): `irq::register` takes up to 4 sharers with one action, signals every sharer's
  event, and the line is unmasked only when `irq::line_done` says every sharer drained its device.
- Timer precision under QEMU/HVF comes from **hybrid idle** (`timer::set_spin_window`, 4 ms on
  virtual machines, 0 on hardware). Don't add other workarounds for `wfi` latency; `idle-poll` is
  only for experiments.
- Measurements must prove the load or condition actually happened (validity checks), or be
  reported as invalid.
- New lab checks need a **negative control** (show that the check fails when the feature is
  broken), as done for the firewall probe.
- Never edit a script in place while it may be running (bash reads scripts incrementally): write a
  temp file and rename it over the original.
- Shell scripts must run on macOS bash 3.2 (no associative arrays) and BSD tools (no `\s` in sed,
  no `timeout`).
- Network changes on the developer's Mac: mac-lab only adds lab-scoped routes and resolvers.
  mac-internet may change routing and DNS, but only after confirmation, with the original state
  saved first, `/1` routes (never the default route), a watchdog, and `--restore`. Keep these
  guarantees in any new script.
- Lab downloads are pinned by SHA-256 in `scripts/lab/fetch-alpine.sh`; never unpin. Update the
  hashes deliberately.
- Update the status column in `docs/roadmap.md` when a milestone is done.
- Keep markdown lines ≤ 100 columns, so a change shows up as a small diff.

## Commands

- `cargo kbuild [--release]` builds the kernel; `cargo krun` boots it (`Ctrl-A X` quits;
  `QEMU_NET=user` adds 2 NICs). x86_64: `cargo kbuild-x86` / `krun-x86`.
- `cargo kcheck-x86`: type-check neutral code for x86_64 (**must stay green**).
- `cargo kclippy [--features <f>]` and `cargo kclippy-x86 [--features <f>]`: run for each of
  `smoke-test`, `idle-poll`, `fault-wx`, `fault-stack`, `fault-hang`, `fault-panic`.
- `cargo test` (host tests for `crates/*` and `tools/*`), `cargo clippy --all-targets`.
- `scripts/doc-check.sh`: boot arguments and `LAB_*` variables documented.
- `scripts/unsafe-report.sh`: the unsafe audit surface.
- Tests, their options and negative controls: **docs/lab-tests.md**. `scripts/smoke-test.sh`,
  `scripts/lab-test.sh` (+ `LAB_*` modes), feature tests `store-`, `lease-`, `cli-`, `pppoe-`,
  `vlan-`, `upgrade-`, `persist-test.sh`; `bufferbloat.sh`, `soak-test.sh`; fuzzing
  `cd fuzz && cargo +nightly fuzz run <target> -- -max_total_time=600`.
- apu4:
  - `scripts/apu-image.sh [--debug] [--mgmt-pass | --mgmt-wan] [--config FILE] [--cmdline "..."]`:
    bootable SD image (`target/apu4/leatos-apu4.img`: MBR + FAT32 + Limine BIOS → Multiboot2, plus
    the 16 MiB store partition p2; needs `brew install limine mtools`). `--config` seeds the store
    (validated); the apu4's config lives in `target/apu4/config.toml`, so the command line needs
    only `mgmt_pass=`.
  - `scripts/apu-upload.sh [--host H] [--tunnel CMD] [--cmdline "..."] [--debug] [--reboot]
    [--persist [--no-confirm]] [--confirm | --revert]`: build + strip the x86_64 kernel and upgrade
    a running leatos over HTTP, in RAM, or with `--persist` stored on the SD card as a trial,
    rebooted into and confirmed once that trial (its seq) has stayed up for `--stable-secs`
    (default 30; password from `target/apu4/mgmt-pass`). `--tunnel CMD` (or `LEATOS_TUNNEL`)
    re-runs CMD when nothing listens at the host (an SSH tunnel that dropped while the router
    rebooted). An upload cut off mid-way is checked (router kept running: nothing stored;
    restarted: its trial is confirmed only if it runs the uploaded build).
- Mac:
  - `scripts/mac-lab.sh [--check]`: put the Mac on leatos's LAN (vmnet-host, needs sudo, so run it
    in Terminal); only 203.0.113.0/24 and `*.home.arpa`/`*.example` DNS go via leatos; cleans up
    on exit.
  - `scripts/mac-internet.sh [--check] [--wan-if enX] [--ipv4-only] [--release] [--shape U:D]
    [--kernel-args "..."] | --restore`: route the Mac's real IPv4 internet + DNS through leatos
    (WAN vmnet-bridged); state saved before changes, watchdog + `--restore` undo.

## What to run after a change

Every QEMU test also takes `QEMU_ACCEL=tcg`, `QEMU_SMP=4`, `QEMU_NIC=igb`, `LEATOS_ARCH=x86_64`
where the table asks for them. Always: `cargo kcheck-x86`; for crates you changed, `cargo test`,
`cargo clippy` and their fuzz targets.

| Change | Run |
|---|---|
| any network code | `lab-test.sh`, also with TCG |
| boot, MMU, IRQ, timer, drivers | `smoke-test.sh`, also with TCG |
| arch, boot, IRQ, timer, PCI, drivers | smoke + lab with `LEATOS_ARCH=x86_64` |
| executor, timer, IRQ, smp, arch, datapath | smoke + lab with `QEMU_SMP=4` (HVF and TCG) |
| x86 boot, linker scripts | `LEATOS_BOOT=limine scripts/smoke-test.sh` |
| igb driver, datapath | smoke + lab with `QEMU_NIC=igb` |
| datapath, VLAN, zones, services | `LAB_GUEST=1` (also `QEMU_SMP=4`, `QEMU_NIC=igb`, x86_64, TCG) |
| datapath, ports, tasks, NICs | `LAB_PORTS=1` (also `QEMU_SMP=4`, `QEMU_NIC=igb`, x86_64) |
| neighbors, ARP, device, datapath | `LAB_NEIGH=1` (also `QEMU_SMP=4`, `QEMU_NIC=igb`, x86_64) |
| routes, DHCP, datapath | `LAB_ROUTES=1` |
| IPv6, DNS, services, device, datapath, zones | `LAB_IPV6=1` (also `QEMU_NIC=igb`, x86_64, `QEMU_SMP=4`, TCG) |
| DNS, DoT, TCP, firewall, `svc` | `LAB_DOT=1` (also x86_64, TCG) |
| DNS, zones, services | `LAB_DNS_VIEWS=1` |
| mDNS, services, multicast | `LAB_MDNS=1` |
| qdisc, classification | `LAB_ACK=1` |
| qdisc, queue limits, packet pool | `LAB_SWARM=1` |
| PPPoE, config apply, `svc` | `pppoe-test.sh` (also x86_64), `LAB_PPPOE=pap scripts/lab-test.sh` |
| VLAN, config apply, `svc` | `vlan-test.sh` (also x86_64), `LAB_VLAN=848 scripts/lab-test.sh` |
| store, virtio-blk, config loading, mgmt | `store-test.sh` (also x86_64, `QEMU_STORE_BUS=sd`) |
| SD driver | `QEMU_STORE_BUS=sd scripts/store-test.sh` (and `STORE_MIB=4096`) |
| DHCP, store, `svc` | `lease-test.sh` (also x86_64, `QEMU_STORE_BUS=sd`) |
| console, CLI, config, `svc` | `cli-test.sh` (also x86_64, `QEMU_STORE_BUS=sd`) |
| mgmt, upgrade, kexec, store, watchdog, boot, x86 NIC path | `upgrade-test.sh`, `persist-test.sh` (also `QEMU_STORE_BUS=sd`) |
| boot arguments, `LAB_*` variables, their docs | `scripts/doc-check.sh` |
