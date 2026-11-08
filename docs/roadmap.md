# Roadmap

The estimates assume one experienced developer. The whole QEMU-only feature
set is about 14–20 months; real hardware adds 3–6+ months per NIC family.

**Bufferbloat mitigation (CAKE) is a core feature.** Its constraints shape
earlier milestones (marked 🎂), even though CAKE itself lands in M6. See
`docs/bufferbloat-cake.md`.

| # | Milestone | Done when | Est. | Status |
|---|---|---|---|---|
| M0 | Workspace scaffold: aarch64 boot, MMU identity map, PL011 console, DTB discovery, heap, generic timer, PSCI off, smoke test | `scripts/smoke-test.sh` passes under HVF and TCG | — | ✅ done |
| M1 | Kernel core: 4 KiB page tables with W^X and guard pages, separate exception stack, GICv3 + IRQs, **tickless high-resolution timers** 🎂, async executor with **priority classes** 🎂, PCIe enumeration | timer IRQ ticks; async `sleep` is accurate to the µs level; faults are reported cleanly | 3–4 wk | ⏳ in progress |
| M2 | virtio-net ×2, **pull-based TX with byte-limited rings** 🎂, packet buffer pools with **`PacketMeta`** 🎂, smoltcp, ping, DHCPv4 client on WAN | client VM can `ping` the router | 3–4 wk | |
| M3 | DHCPv4 server + DNS forwarder/cache/`.lan` zone | client gets a lease; `dig nas.lan` works | 4–6 wk | |
| M4 | Forwarding plane + conntrack + NAPT + basic firewall; **pipeline with qdisc hook points** and **pre-NAT flow/host hashes from conntrack** 🎂 | client `curl`s through to the ISP VM | 8–12 wk | |
| M5 | PPPoE WAN, reconnect, MSS clamp; **exposes encapsulation overhead** 🎂 | stable session against `pppoe-server`; survives a PADT | 4–6 wk | |
| M6 | **Bufferbloat mitigation:** CoDel → FQ-CoDel → **CAKE** (shaper, overhead compensation, COBALT, host isolation, ingress mode, diffserv tins, ACK filter) in `crates/qdisc` | flent RRUL in the lab: < 10 ms added latency under load, fair per-host sharing | 6–10 wk | |
| M7 | IPv6: DHCPv6-PD, RA/RDNSS, v6 firewall (CAKE handles v6 the same way) | client gets a global v6 address and reaches the ISP | 5–7 wk | |
| M8 | Persistence (virtio-blk), SNTP, watchdog, panic → reboot, serial CLI, then HTTP UI | config survives a reboot | 4–6 wk | |
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
6. **Real hardware:** NIC drivers (Intel igc/ixgbe) must be written from datasheets, with BQL-style TX limits.
7. **Security:** a new network stack facing the internet. Fuzzing is mandatory.
