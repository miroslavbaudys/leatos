# LeatOS

A home and small-office router written in Rust as a **bare-metal unikernel**: no
Linux underneath. It is built around keeping latency low under load
(bufferbloat), with **CAKE** shaping on upload and download.

> A *leat* is an open channel that carries water to a mill wheel at a steady,
> controlled rate.

**Status:** a one-person project, under heavy development. It runs as the
author's home router (PC Engines apu4, PPPoE over VLAN). Expect breaking changes.

## Features

- **WAN:** DHCP, PPPoE (PAP/CHAP, RFC 4638 MTU), static; 802.1Q VLAN tag
- **LAN:** several networks (VLANs or their own routed ports, no bridge),
  DHCPv4 server with leases kept across reboots and pool-exhaustion defences,
  static routes (option 121)
- **Forwarding:** NAT (NAPT), zone firewall with rules, port forwards, redirects,
  hairpin, IP fragments, MSS clamping, WAN anti-spoofing
- **IPv6** (off by default: `[ipv6] enabled`; on or off per network):
  DHCPv6 prefix delegation on DHCP and PPPoE (IPv6CP) WANs, prefix kept
  across reboots, a ULA and a global /64 per network with RAs (SLAAC, RDNSS,
  DNSSL), unused parts of the prefix unreachable (no loop through the ISP),
  stateful firewall with pinholes by interface identifier, anti-spoofing,
  ICMPv6 errors incl. Packet Too Big, fragments, CAKE for both families,
  DNS/NTP/DoT over IPv6, AAAA names for DHCP clients, mDNS over `ff02::fb`
- **Queueing:** CAKE (default), FQ-CoDel or CoDel; shaped upload and a shaped
  download stage, ECN
- **DNS:** caching forwarder with prefetch and serve-stale, DNS over TCP,
  DNS over TLS upstream, a fresh random upstream port per query, local names
  under `home.arpa` with split-horizon views; mDNS reflector
- **Own network stack:** ARP / ND, UDP, ICMP echo, IGMP / MLD and the DHCP
  client are leatos's own sans-IO code; [smoltcp](https://github.com/smoltcp-rs/smoltcp)
  carries only TCP (web interface, DNS over TCP, DNS over TLS)
- **SNTP**, hardware and cross-core watchdogs, multicore datapath (download,
  upload and services on their own cores)
- **Management:** web interface (with a live WAN throughput chart), serial
  CLI, config in TOML with trial changes that revert unless confirmed, kernel
  upgrades over HTTP with rollback
- **Hardening:** silent to scans from the WAN (no RST, no port unreachable),
  DNS-rebinding and cross-site request refusals and per-source login backoff
  on the web interface, a security audit
  ([docs/security-audit.md](docs/security-audit.md)), 18 fuzz targets

IPv6 (M7) runs on the author's apu4 with its ISP (PPPoE, a delegated /60); it
goes on by default after a long soak test. Planned
([docs/roadmap.md](docs/roadmap.md)): a WireGuard server (M12) and leatos as a
KVM / Proxmox VE guest (M13).

## Platforms

| Platform | How |
|---|---|
| QEMU aarch64 `virt` (HVF on Apple Silicon) | `cargo krun` |
| QEMU x86_64 q35 | `cargo krun-x86` |
| PC Engines apu4 (4× Intel i211) | `scripts/apu-image.sh` → SD card image (Limine + Multiboot2) |

## Building

Needs Rust (edition 2024) and QEMU. Use the cargo aliases, never `build.target`:

```sh
cargo kbuild            # aarch64 kernel → target/aarch64-unknown-none/debug/leatos
cargo krun              # boot it in QEMU (Ctrl-A X quits)
cargo kbuild-x86        # x86_64 kernel
cargo test              # host tests for the sans-IO protocol crates
scripts/smoke-test.sh   # boot, faults, panic, watchdogs in QEMU
scripts/lab-test.sh     # client VM + router + ISP VM: DHCP, DNS, NAT, firewall, …
```

## Layout

- `kernel/`: the unikernel (`arch/` holds all CPU-specific code; `unsafe` is
  denied except in modules that opt in with a reason)
- `crates/`: `no_std`, sans-IO protocol and logic crates (DHCP, DNS, PPPoE,
  forwarding, CAKE and other qdiscs, config, store, …), `forbid(unsafe_code)`
- `tools/leatstore`: host tool for store images
- `fuzz/`: cargo-fuzz targets
- `docs/`: design notes ([architecture](docs/architecture.md),
  [bufferbloat and CAKE](docs/bufferbloat-cake.md),
  [safety and portability](docs/safety-and-portability.md), …)

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
