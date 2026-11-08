# Roadmap

The estimates assume one experienced developer. The whole QEMU-only feature
set is about 12–18 months; real hardware adds 3–6+ months per NIC family.

| # | Milestone | Done when | Est. | Status |
|---|---|---|---|---|
| M0 | Workspace scaffold: aarch64 boot, MMU identity map, PL011 console, DTB discovery, heap, generic timer, PSCI off, smoke test | `scripts/smoke-test.sh` passes under HVF and TCG | — | ✅ done |
| M1 | Kernel core: 4 KiB page tables with W^X and guard pages, GICv3 + IRQs, timer interrupts, async executor, PCIe enumeration | timer IRQ ticks; an async `sleep` works | 3–4 wk | ⏳ next |
| M2 | virtio-net ×2 (via `virtio-drivers`), smoltcp, ping on LAN, DHCPv4 client on WAN | client VM can `ping` the router | 3–4 wk | |
| M3 | DHCPv4 server + DNS forwarder/cache/`.lan` zone | client gets a lease; `dig nas.lan` works | 4–6 wk | |
| M4 | Forwarding plane + conntrack + NAPT + basic firewall | client `curl`s through to the ISP VM | 8–12 wk | |
| M5 | PPPoE WAN, reconnect, MSS clamp | stable session against `pppoe-server`; survives a PADT | 4–6 wk | |
| M6 | IPv6: DHCPv6-PD, RA/RDNSS, v6 firewall | client gets a global v6 address and reaches the ISP | 5–7 wk | |
| M7 | Persistence (virtio-blk), SNTP, watchdog, panic → reboot, serial CLI, then HTTP UI | config survives a reboot | 4–6 wk | |
| M8 | Hardening: fuzzing all parsers, conntrack stress tests, 72 h soak test | no leaks or panics over 72 h | ongoing | |

The protocol crates (`crates/*`) can be developed in parallel with M1/M2 and
tested on the host.

## Main risks
1. **Scope:** we are rebuilding netfilter. Keep NAT and the firewall minimal at first.
2. **No std ecosystem:** DNS, TLS and SSH crates need no_std alternatives.
3. **No isolation:** one panic stops routing. Mitigate with watchdog + reboot,
   and keep `unsafe` confined to drivers and arch code.
4. **Real hardware:** NIC drivers (Intel igc/ixgbe) must be written from datasheets.
5. **Security:** a new network stack facing the internet. Fuzzing is mandatory.
