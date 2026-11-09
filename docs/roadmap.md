# Roadmap

The estimates assume one experienced developer. The whole QEMU-only feature
set is about 14–20 months; real hardware adds 3–6+ months per NIC family.

**Bufferbloat mitigation (CAKE) is a core feature.** Its constraints shape
earlier milestones (marked 🎂). See `docs/bufferbloat-cake.md`.

**Order (2026-11-09):** M6 (CAKE) is done **before** M5 (PPPoE). Milestone
numbers are kept as stable references. Reason: rrouter already routes the
developer's real internet behind the home router (`scripts/mac-internet.sh`),
so CAKE can be measured on a real line immediately (`scripts/bufferbloat.sh`:
baseline +51 ms download / +74 ms upload under load). PPPoE only matters once
rrouter replaces the home router, which also needs real hardware.

**Hardware target:** a PC Engines **apu4b4** (developer-owned; APU2-family
board with 4 ports). Path after M6: M9b (x86_64 on QEMU q35) → M10 (apu4
bare metal, igb driver) → M5 (PPPoE, with rrouter replacing the home router).

| # | Milestone | Done when | Est. | Status |
|---|---|---|---|---|
| M0 | Workspace scaffold: aarch64 boot, MMU identity map, PL011 console, DTB discovery, heap, generic timer, PSCI off, smoke test | `scripts/smoke-test.sh` passes under HVF and TCG | — | ✅ done |
| M1 | Kernel core: 4 KiB page tables with W^X + WXN and guard pages, separate exception stack, GICv3 + IRQs, **tickless high-resolution timers** 🎂, async executor with **priority classes** 🎂, PCIe enumeration + BAR assignment | self-tests pass (sleep accuracy, priorities); W^X and guard-page faults caught; 2× virtio-net found | 3–4 wk | ✅ done (HVF `wfi` wake-up latency found, see qemu.md) |
| M2 | virtio-net ×2 (INTx, NAPI-style), **pull-based TX with byte-limited rings** 🎂, bounded packet pool with **`PacketMeta`** 🎂, smoltcp, DHCPv4 client on WAN, static LAN; **arch-neutral restructure + unsafe confinement + x86_64 skeleton** | WAN gets a DHCP lease and the gateway answers ping (smoke test) | 3–4 wk | ✅ done (client-VM lab moved to M3; adaptive BQL to M6) |
| M3 | QEMU lab (Alpine client VM over `-netdev dgram`), DHCPv4 server (`crates/proto-dhcp`), DNS forwarder/cache/`.lan` zone (`crates/proto-dns`) | `scripts/lab-test.sh`: client gets a lease; `nas.lan`, `router.lan`, the client's own name and reverse lookups resolve; NXDOMAIN; upstream forwarding; ping | 4–6 wk | ✅ done (ISP VM moved to M4; DNS-over-TCP open) |
| M4 | ISP VM in the lab; forwarding plane (`crates/fwd`): LPM routes, ARP neighbor cache, conntrack, NAPT (EIM), stateful firewall, ICMP error generation and translation; **qdisc hook for all egress** + **pre-NAT flow/host hashes in `PacketMeta`** 🎂 | `scripts/lab-test.sh`: HTTP/ICMP through NAT, NATed source seen by the ISP, traceroute through NAT, 20 connections, firewall blocks WAN→LAN | 8–12 wk | ✅ done (DNAT/port forwarding, fragments, hairpin open) |
| M6 | **Bufferbloat mitigation:** hybrid idle (timer precision under QEMU/HVF) → CoDel → FQ-CoDel → **CAKE** (shaper, overhead compensation, COBALT, host isolation, ingress mode, diffserv tins, ACK filter) in `crates/qdisc` | flent RRUL in the lab: < 10 ms added latency under load, fair per-host sharing | 6–10 wk | ⏳ in progress: hybrid idle ✅, CoDel ✅, shaper ✅ (boot-arg rates, lab-verified), FQ-CoDel ✅ (flow isolation, lab-verified with negative control); next: real-line A/B, then CAKE (host isolation, COBALT, tins, ACK filter) (reordered before M5) |
| M5 | PPPoE WAN, reconnect, MSS clamp; **exposes encapsulation overhead** 🎂 | stable session against `pppoe-server`; survives a PADT | 4–6 wk | after M6 (needs real hardware to matter: rrouter sits behind the home router today) |
| M7 | IPv6: DHCPv6-PD, RA/RDNSS, v6 firewall (CAKE handles v6 the same way) | client gets a global v6 address and reaches the ISP | 5–7 wk | |
| M8 | Persistence (virtio-blk), SNTP, watchdog, panic → reboot, serial CLI, then HTTP UI | config survives a reboot | 4–6 wk | |
| M9b | **x86_64 port**: Limine boot, ACPI (MADT/MCFG), LAPIC/IOAPIC, TSC-deadline timer, MSI-X, 16550 (see safety-and-portability.md §3) | same smoke tests pass on QEMU q35 | 4–6 wk | |
| M10 | **PC Engines apu4b4 bare metal** (AMD GX-412TC, 4× Jaguar 1 GHz, 4 GB, **4× Intel GbE** (i211AT expected; confirm the PCI IDs 8086:1539 = i211 / 8086:1533 = i210), coreboot + SeaBIOS, serial console only): Limine BIOS boot from USB/SD/mSATA, **`igb` NIC driver** from the Intel datasheet (i210 and i211 share it; descriptor rings, MSI-X, **BQL-style TX limit** 🎂, unsafe confined to the driver module), hybrid idle off (spin window 0), per-packet CPU cost measured. **Several LAN ports:** shaping LAN egress no longer equals shaping the download, so this needs a **WAN ingress shaping stage** 🎂 (CAKE ingress mode) and a LAN model (software bridge or per-port subnets) | rrouter routes on the apu4 between modem and LAN: smoke and lab checks on hardware, real-line `bufferbloat.sh` with CAKE at the line rate, no hidden NIC queue (ring bytes bounded), 72 h soak | 6–9 wk | after M9b |
| — | **Mac integration** (`scripts/mac-lab.sh`: Mac on rrouter's LAN; `scripts/mac-internet.sh`: Mac's real IPv4 internet through rrouter, WAN bridged on Wi-Fi) | both `--check` runs pass on the developer's MacBook | — | ✅ done |
| M9 | Hardening: fuzzing all parsers and qdisc, conntrack stress tests, 72 h soak test; CAKE **autorate** for variable-rate links | no leaks or panics over 72 h | ongoing | |

The protocol and qdisc crates (`crates/*`) can be developed in parallel with
M1/M2 and tested on the host. In particular, `crates/qdisc` (CoDel/FQ-CoDel)
can start early using simulated time.

## Main risks
1. **Scope:** we are rebuilding netfilter *and* sch_cake. Keep NAT and the firewall minimal at first.
2. **Hidden queues:** any buffer outside the qdisc (driver rings, RX
   backlog) silently defeats CAKE. Review every new queue against
   `docs/bufferbloat-cake.md` §3.1.
3. **Timer latency:** a long task poll delays the shaper. Keep polls short
   and give the datapath priority.
4. **No std ecosystem:** DNS, TLS and SSH crates need no_std alternatives.
5. **No isolation:** one panic stops routing. Mitigate with watchdog + reboot,
   and keep `unsafe` confined to drivers and arch code.
6. **Real hardware:** NIC drivers must be written from datasheets, with BQL-style TX limits. First: Intel `igb` (i210/i211) for the apu4b4 (M10); the 1 GHz Jaguar CPU makes per-packet cost visible early.
7. **Security:** a new network stack facing the internet. Fuzzing is mandatory.
