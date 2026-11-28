# leatos architecture

leatos is a SOHO router OS written in Rust, running **bare metal** as a
**single-address-space unikernel** on aarch64 and x86_64. Development
runs on QEMU (`virt` with HVF on Apple Silicon; q35 under TCG for x86_64);
the hardware target is a PC Engines apu4 (x86_64, 4× Intel i211), which has
been the developer's home router since 2026-11-15.

Required features: PPPoE (WAN), DHCP (WAN client, LAN server, DHCPv6-PD,
RA), DNS (forwarder, cache, local zone), NAT and a firewall, IPv4 and IPv6,
and **bufferbloat mitigation with CAKE** (a design driver; see
`docs/bufferbloat-cake.md`).

## Why a unikernel
A router appliance doesn't need processes, users, syscalls or a general
filesystem. Everything runs at EL1 in one binary, with an async executor and a
run-to-completion packet loop. That removes roughly half of the classic OS work.
The trade-off is **no isolation**: a panic anywhere takes the router down, so
panics and unhandled exceptions reboot the machine, and a cross-core software
watchdog backed by a hardware timer resets a stuck one (M8,
`docs/watchdog-and-time.md`).

## Layers

```
┌───────────────────────────────────────────────────────────────┐
│ Services (`svc` task, no_std + alloc)                          │
│  pppoe · dhcpv4 client + server · dhcpv6-pd · RA · dns + DoT   │
│  sntp · mdns · web UI (own HTTP, proto-http) · config + store  │
│  serial CLI · echo replies · IGMP / MLD (net::groups)          │
├───────────────────────────────────────────────────────────────┤
│ Local stack ← packets addressed TO the router: own UDP / ICMP  │
│  (net::local) · own TCP, proto-tcp (docs/own-tcp.md)           │
├───────────────────────────────────────────────────────────────┤
│ Forwarding plane (crates/fwd) ← packets going THROUGH          │
│  L2: eth / VLAN / PPPoE encap (kernel datapath)                │
│  L3: LPM route table · ARP neighbor cache · TTL · ICMP errors  │
│  conntrack · NAPT · DNAT · zone firewall + rules · MSS clamp   │
│ Queue management (crates/qdisc): CAKE egress on both ports     │
│  shaper · FQ · COBALT · host isolation · ACK filter · ingress  │
│  stage (later: DiffServ tins)                                  │
├───────────────────────────────────────────────────────────────┤
│ Drivers: virtio-net · igb (i211/82576) · virtio-blk · SDHCI ·  │
│ i6300esb / AMD FCH watchdog · PL011 / 16550                    │
├───────────────────────────────────────────────────────────────┤
│ Kernel core (kernel/): boot · MMU · heap · exceptions ·        │
│ GICv3 / LAPIC + MSI-X · tickless timer · PCIe · SMP ·          │
│ priority async executor (IRQ → waker)                          │
└───────────────────────────────────────────────────────────────┘
```

### Packet path (`kernel/src/net/datapath.rs` + `crates/fwd`)
1. A NIC RX interrupt wakes that port's datapath direction task (`dp_down`
   for the WAN, `dp_up` for the LAN), which drains the RX queue in batches.
2. Classification: if the packet is addressed to the router (one of its IPs,
   ARP/NDP for its IPs, PPPoE discovery or control frames), hand it to the local
   path (the datapath's ARP / ND, the PPPoE client, `net::local`, or the
   router's own TCP, `proto_tcp`). Otherwise it goes to the forwarding plane.
3. Forwarding: decapsulate (VLAN or PPPoE), conntrack lookup or create,
   firewall verdict, NAT rewrite, **classify** (fill `PacketMeta`: pre-NAT
   flow and host hashes, wire length), route lookup (LPM), neighbor
   resolution (at most 3 packets held per unresolved next hop), TTL
   decrement and incremental checksum update. Packets from the WAN then
   wait in the **WAN ingress stage** (CAKE shaped at the download rate,
   `Shared::ingress`) before the neighbor lookup, so LAN egress stays
   unshaped and traffic between networks is not held to the download
   rate (docs/bufferbloat-cake.md §3.4).
   Packets *for* the router go into a small bounded per-link queue
   (`local_rx`, 64 packets) and from there, in the services task, to the
   router's own UDP / ICMP / IGMP / MLD handling (`net::local`) or, for
   TCP, to the link's `proto_tcp`; any other protocol is dropped
   silently. The router's own transmissions go through the datapath's
   neighbor table (`send_local`) into the port's qdisc, so the qdisc sees
   all egress traffic.
4. Egress: enqueue into the egress port's qdisc (CAKE by default on both
   ports, wrapped in the shaper). The transmitting task **pulls** from the
   qdisc when the driver has ring space and the shaper allows it, then
   encapsulates and transmits. The qdisc is the only
   place packets wait (no hidden queues).

**VLAN tags (802.1Q, implemented for the WAN):** a port's tag
(`PortShared::vlan`, from `[wan] vlan`) exists only at the two ends of the
datapath. `Datapath::rx_batch` checks it first (`wire::vlan_rx`: on a
tagged port only its VID, on an untagged port only untagged or
priority-tagged frames; stacked tags never) and removes it (a 12-byte move
of the MAC addresses into the headroom gap); everything else is dropped and
counted (`VLAN_DROPS`, `vlan_drops` in `/api/status`). `flush_port` adds it
again after the qdisc, right before the NIC, so this one place covers
forwarded frames, ARP requests and the router's own frames. The forwarder,
ARP snooping, neighbor tables, the router stack and the qdiscs only see
untagged frames, and `crates/fwd` stays tag-free. Because the qdisc counts
untagged lengths, the WAN shaper adds the tag's 4 bytes to its overhead
(`config::Qos::port_rate`). LAN VLANs use the RX hook the same way (the
port and VID select the link, one router interface per network on its
LAN port), but a
frame for a VLAN network gets its tag when it is queued, so the LAN qdisc
holds tagged frames and shapes the 4 bytes too (docs/config-v2.md §6).

**PPPoE (implemented for the WAN, `wan.mode = "pppoe"`):** the same two
hooks, inside the VLAN tag. On a PPPoE port (`PortShared::pppoe_mode`)
`rx_batch` decapsulates the current session's IPv4 in place
(`proto_pppoe::wire::decap_ipv4`: an 8-byte move, the PPP protocol field
becomes EtherType 0x0800) and hands discovery and PPP control frames
(LCP, PAP/CHAP, IPCP, IPv6CP, …) to the client through
`PortShared::ctrl_rx`; anything else is dropped (`PPPOE_DROPS`).
`flush_port` encapsulates IPv4 for the session (`encap_ipv4`, from the
headroom) and passes the client's own PPPoE frames unchanged. The session
(ID + access concentrator MAC) is one atomic (`pppoe_session`), written
by svc on PADS. In between, everything sees Ethernet/IPv4: forwarded
packets to the WAN skip ARP (the AC is the only neighbor), the router
stack's WAN interface is IP-only (`Medium::Ip`, rebuilt when the mode
changes), and the WAN shaper adds 8 bytes of overhead. The forwarder
knows the WAN's MTU (1492): larger packets get ICMP "fragmentation needed"
(DF) or are split into fragments (no DF, see below), and TCP SYNs in both
directions have their MSS clamped to the smaller MTU (`wire::clamp_mss`).

IP fragments (`fwd::frag`, 2026-11-18) are forwarded without reassembly:
the first fragment (offset 0, holding the ports) goes through conntrack,
NAT and the firewall like any packet, and its decision is recorded per
datagram (source, destination, protocol, IP ID) in a table per ingress
port (so per direction task, never shared). Later fragments take the same
egress, next hop and address rewrite (`Forwarder::forward_fragment`: IP
header only; the L4 checksum in the first fragment already covers the new
addresses) and enter the qdisc in the first fragment's flow. A later
fragment that arrives before its first one is held (at most 16 per port,
250 ms), the only wait outside the qdisc besides ARP resolution. Refused:
first fragments without their whole L4 header, TCP fragments at offset 8
bytes (RFC 1858/3128), a datagram whose translated IP ID another one
already uses (`clash`).

Splitting (RFC 791, `wire::SplitPlan`, 2026-11-18): a packet without DF
that is larger than the egress MTU (a 1500 B packet or fragment into
PPPoE's 1492) is forwarded with `Verdict::Forward` `split` = the MTU, after
NAT, and the datapath cuts it: pieces of a multiple of 8 data bytes, each
with a copy of the header, its offset and MF (a fragment's pieces keep its
place; only the last keeps its MF), checksums recomputed. The first piece
stays in the packet's buffer, the others come from the pool (at most 4;
all or none, `split_drops`), and they enter the qdisc back to back in one
CAKE flow. Not split: packets with IP options (`too-big`). Counters in
`/api/status` `fragments` (`split`, `split_drops`); boot argument
`fw_split=0` drops them as `too-big` again (negative control).
Fragments to the router itself are not reassembled: UDP ones are
dropped by the router's own UDP (`net::local`), TCP ones by
`fwd::tcp::parse` (`local.other_dropped`). Boot
argument `fw_frag=0` drops all fragments (negative
control).

```text
 svc: proto_pppoe::Client ◄── ctrl_rx ──┐            ┌── qdisc ◄── Client frames
      Event::Session ─► pppoe_session ──┼────────────┤
                                        │            ▼
 NIC RX ─► VLAN ─► PPPoE decap ─► forwarder ─► qdisc ─► PPPoE encap ─► VLAN ─► NIC TX
```

### Forwarding plane
There is no host stack (smoltcp was one, and had no forwarding, NAT,
conntrack, bridging or PPPoE). The `fwd` crate provides these. It is the
largest and riskiest part of the project (it effectively replaces
netfilter), and it must be fuzzed.

## Latency rules (from the CAKE requirements)
- Timers are **tickless** and high-resolution: program the next deadline in
  `CNTV_CVAL` (aarch64) or the LAPIC one-shot counter (x86_64). There is no
  periodic tick.
- The executor has **priority classes**. Datapath work (RX → forward → qdisc → TX) runs before service tasks.

### Tasks (M11, docs/smp.md)
| Task | Priority | Core (≥ 3 online) | Owns | Does |
|---|---|---|---|---|
| `dp_down` / `dp_up` (`net::stack::run_dir`) | Datapath | 0 / 1 | one direction each: RX on one port, TX on the other; share the locked NICs and `Datapath` (16 forwarder shards, neighbor tables) | RX → forward → qdisc → TX, NAPI; `dp_down` also housekeeping and control |
| `svc` (`net::svc::run`) | Service | 2 | the router's own UDP / ICMP (`net::local`), per link its addresses and TCP (`HostIf`: `LocalLink`, `proto_tcp::Tcp`), WAN DHCP client or PPPoE, LAN DHCP servers, DNS + DoT, SNTP, mDNS, mgmt, CLI, store writes | the router's own traffic |
| `watchdog` (one per core) | Datapath | each | `LAST_SEEN` stamps | cross-core check, hardware watchdog (docs/watchdog-and-time.md) |

With one core everything runs on core 0 (a single `dp` task); with two the
datapath is on core 0 and `svc` on core 1. They share only `net::shared`:
per port a locked qdisc (plus the PPPoE `ctrl_rx` queue and session), per
link a `local_rx` queue, a stats snapshot for the status page, `Control`
messages (WAN lease, zone policy and networks → forwarder, reboot/upgrade →
the datapath quiesces the NICs) and two events (`dp_kick`, `svc_kick`). A
service poll therefore never delays forwarding on another core, and the
CPU accounting separates them (`/api/status` `cpu`, the console's per-task
`cpu` line).
- Interrupt handlers only acknowledge hardware and set flags or wake
  state. No allocation, no locks shared with thread context, no printing.
- TX is pull-based with byte-limited driver rings (BQL-style).

## Event bus
Services react to events instead of polling each other:

```
pppoe: PADI→PADO→PADR→PADS → LCP → PAP/CHAP → IPCP
        └─► Session + LeaseChange{ip, peer, dns[]}
              ├─ fwd:     WAN address + default route (Control), masquerade, MSS clamp
              ├─ dns:     upstreams = dns[] (unless dns.upstreams is set)
              └─ dhcp6pd: solicit over PPPoE → PrefixDelegated{/56, /60}
                                └─ LAN /64 + RA with RDNSS
DHCP Bound/Released{mac, ip, hostname} ─► dns local zone (`host.<domain>`)
WAN down (PADT / LCP echo timeout / lease lost) ─► address withdrawn, reconnect with backoff
config save ─► config::apply: shaping, networks, firewall policy, LAN services re-apply live
```
(Events are plain values returned by the sans-IO crates and handled in
`svc`; there is no separate bus.)

## Code-sharing strategy: sans-IO, no_std crates
Every protocol lives in a `#![no_std]` + `alloc` crate with **no I/O**: pure
state machines that take bytes and the current time as input, and return
bytes to send plus events.

```
crates/proto-pppoe   PPPoE discovery, LCP, PAP/CHAP, IPCP, IPv6CP
crates/proto-dhcp    DHCPv4 server + lease snapshots, DHCPv4 client, DHCPv6-PD, RA
crates/proto-dns     forwarder, cache, local zones
crates/proto-dot     DNS over TLS client (rustls, unbuffered)
crates/proto-sntp    SNTP client
crates/proto-mdns    mDNS reflector across networks
crates/proto-http    incremental HTTP/1.1 parser
crates/proto-tcp     the router's own TCP (sockets per link, RFC 9293 states, RTO)
crates/fwd           LPM, neighbor cache, conntrack, NAT, zone firewall;
                     the router's own ARP / ND, UDP, ICMP echo, IGMP / MLD
crates/qdisc         CoDel, FQ-CoDel, CAKE, shaper (simulation-tested with fake time)
crates/config        config.toml schema, validation, migration
crates/config-store  power-fail-safe store partition format
crates/auth          password hashes, sessions, entropy pool
crates/boot-image    ELF / Multiboot2 checks for upgrades, boot information for kexec
crates/install-image the installer's image format (extents, hash, write plan)
crates/cli           console line editor + command parser
crates/text-screen   the console on a screen: text grid, escape handling, glyphs
crates/ps2-kbd       PS/2 scan codes to console bytes (US layout)
kernel/              bare-metal platform that drives the crates
  arch/<target>/     all CPU-specific code (aarch64, x86_64)
  platform/          neutral BootInfo + firmware backends (DTB; PVH/Multiboot2 + ACPI)
  mm/ mmio.rs        memory, page tables, DMA, stacks; the safe MMIO abstraction
  drivers/ net/      NICs, block devices, watchdogs, the screen; packet pool, datapath, services
tools/leatstore        host tool for store images (std)
```

The benefits: fast iteration and unit tests on the host, fuzzing with
`cargo-fuzz`, and protocol code that doesn't depend on the kernel being finished.

Kernel code layout and the unsafe policy are described in
`docs/safety-and-portability.md`.

## Dependency constraints
Only `no_std` crates may be used (std-only crates like tokio, hickory-dns
and dhcproto are out).

| Need | Choice |
|---|---|
| DTB parsing | `fdt` |
| Heap | `talc` (`heap=list`: `linked_list_allocator`, the old one); packet buffers come from dedicated pools |
| Locks | `spin` |
| virtio drivers + PCI config access | `virtio-drivers` (rcore-os), we implement its `Hal` trait |
| MMIO | `safe-mmio` (via `mmio::Region`) |
| aarch64 system registers | `aarch64-cpu` (arch backend only) |
| TCP for the router's own services | our own (`crates/proto-tcp`, docs/own-tcp.md; smoltcp until 2026-11-27) |
| DNS wire format | our own (`crates/proto-dns`, `crates/proto-mdns`) |
| HTTP server | our own (`crates/proto-http`) over `proto_tcp` |
| TLS (DoT) | `rustls` 0.23 (no std, unbuffered API) + RustCrypto provider |
| Config | `toml` + `serde`, `serde_json` |
| SSH (later) | `sunset` |
