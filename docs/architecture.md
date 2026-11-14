# rrouter architecture

rrouter is a SOHO router OS written in Rust, running **bare metal** as a
**single-address-space unikernel** on aarch64. The development target is
QEMU's `virt` machine (HVF-accelerated on Apple Silicon); real hardware comes
later.

Required features: PPPoE (WAN), DHCP (WAN client, LAN server, DHCPv6-PD,
RA), DNS (forwarder, cache, local zone), NAT and a firewall, IPv4 and IPv6,
and **bufferbloat mitigation with CAKE** (a design driver; see
`docs/bufferbloat-cake.md`).

## Why a unikernel
A router appliance doesn't need processes, users, syscalls or a general
filesystem. Everything runs at EL1 in one binary, with an async executor and a
run-to-completion packet loop. That removes roughly half of the classic OS work.
The trade-off is **no isolation**: a panic anywhere takes the router down, so
we need a panic handler that reboots plus a watchdog (milestone M7).

## Layers

```
┌───────────────────────────────────────────────────────────────┐
│ Services (async tasks, no_std + alloc)                         │
│  pppoe-client · dhcpv4 srv/cli · dhcpv6-pd · RA · dns · ntp    │
│  config · serial CLI · (later: SSH via `sunset`, HTTP via      │
│  `picoserve`)                                                  │
├───────────────────────────────────────────────────────────────┤
│ Local stack: smoltcp  ← packets addressed TO the router        │
├───────────────────────────────────────────────────────────────┤
│ Forwarding plane (crates/fwd) ← packets going THROUGH          │
│  L2: eth / VLAN / bridge+MAC learning / PPPoE encap            │
│  L3: LPM route table · ARP/NDP neighbor cache · TTL · ICMP err │
│  conntrack · NAPT · firewall rules · MSS clamp                 │
│ Queue management (crates/qdisc): CAKE egress (WAN) + ingress   │
│  shaper · FQ · COBALT · host isolation · tins · ACK filter     │
├───────────────────────────────────────────────────────────────┤
│ Drivers: virtio-net ×2 (WAN, LAN) · virtio-blk · PL011 · PL031 │
├───────────────────────────────────────────────────────────────┤
│ Kernel core (kernel/): boot · MMU · heap · exceptions · GIC ·  │
│ generic timer · PCIe · async executor (IRQ → waker)            │
└───────────────────────────────────────────────────────────────┘
```

### Packet path (implemented in M4: `kernel/src/net/datapath.rs` + `crates/fwd`)
1. A NIC RX interrupt wakes the datapath task (`net`), which drains the RX queue in batches.
2. Classification: if the packet is addressed to the router (one of its IPs,
   ARP/NDP for its IPs, PPPoE discovery or control frames), hand it to the local
   path (smoltcp or a protocol state machine). Otherwise it goes to the forwarding plane.
3. Forwarding: decapsulate (VLAN or PPPoE), conntrack lookup or create,
   firewall verdict, NAT rewrite, **classify** (fill `PacketMeta`: pre-NAT
   flow and host hashes, tin, wire length), WAN-ingress CAKE (download
   shaping), route lookup (LPM), neighbor resolution (queue the packet if the
   neighbor is unresolved), TTL decrement and incremental checksum update.
   Packets *for* the router go into a small bounded per-port queue
   (`local_rx`) and from there into smoltcp, which runs in the services
   task. The router's own transmissions go straight into the port's qdisc,
   so the qdisc sees all egress traffic.
4. Egress: enqueue into the egress interface's qdisc (CAKE on the WAN; a bounded FIFO until M6). A TX
   task **pulls** from the qdisc when the driver has ring space and the
   shaper allows it, then encapsulates and transmits. The qdisc is the only
   place packets wait (no hidden queues).

### Forwarding plane
smoltcp is a *host* stack: it has no forwarding, NAT, conntrack, bridging or
PPPoE. The `fwd` crate provides these. It is the largest and riskiest part of
the project (it effectively replaces netfilter), and it must be fuzzed.

## Latency rules (from the CAKE requirements)
- Timers are **tickless** and high-resolution: program the next deadline in
  `CNTV_CVAL`. There is no periodic tick.
- The executor has **priority classes**. Datapath work (RX → forward → qdisc → TX) runs before service tasks.

### Tasks (M11 step 1)
| Task | Priority | Owns | Does |
|---|---|---|---|
| `dp_down` / `dp_up` (`net::stack::run_dir`) | Datapath | one direction each: RX on one port, TX on the other; share the locked NICs and `Datapath` (forwarder, neighbor table) | RX → forward → qdisc → TX, NAPI; `dp_down` also housekeeping and control |
| `svc` (`net::svc::run`) | Service | smoltcp interfaces and sockets (`HostIf`), DHCP client, LAN DHCP server, DNS, mgmt | the router's own traffic |

They share only `net::shared`: per port a locked qdisc and `local_rx`
queue, a stats snapshot for the status page, `Control` messages (WAN
lease → forwarder, reboot/upgrade → the datapath quiesces the NICs) and two
events (`dp_kick`, `svc_kick`). A service poll therefore delays forwarding
by at most one poll, and the CPU accounting separates the two (`/api/status`
`cpu`, the console's per-task `cpu` line). Next: the services and each
direction of the datapath on their own cores (roadmap M11).
- Interrupt handlers only acknowledge hardware and set flags or wake
  state. No allocation, no locks shared with thread context, no printing.
- TX is pull-based with byte-limited driver rings (BQL-style).

## Event bus
Services react to events instead of polling each other:

```
pppoe: PADI→PADO→PADR→PADS → LCP → PAP/CHAP → IPCP
        └─► WanUp{ip, peer, dns[]}
              ├─ fwd:     address + default route on ppp0, masquerade, MSS clamp
              ├─ dns:     upstreams = dns[] (unless overridden)
              └─ dhcp6pd: solicit over PPPoE → PrefixDelegated{/56}
                                └─ LAN /64 + RA with RDNSS
LeaseAdded{mac, ip, hostname} ─► dns local zone (`host.lan`)
WanDown (PADT / LCP echo timeout) ─► routes withdrawn, reconnect with backoff
ConfigChanged ─► only the affected services re-apply
```

## Code-sharing strategy: sans-IO, no_std crates
Every protocol lives in a `#![no_std]` + `alloc` crate with **no I/O**: pure
state machines that take bytes and the current time as input, and return
bytes to send plus events.

```
crates/proto-pppoe   PPPoE discovery, LCP, PAP/CHAP, IPCP, IPv6CP
crates/proto-dhcp    DHCPv4 server/client, DHCPv6-PD, RA
crates/proto-dns     forwarder, cache, local zone
crates/fwd           LPM, neighbor cache, conntrack, NAT, firewall
crates/qdisc         CoDel, FQ-CoDel, CAKE (simulation-tested with fake time)
kernel/              bare-metal platform that drives the crates
  arch/<target>/     all CPU-specific code (aarch64 today, x86_64 skeleton)
  platform/          neutral BootInfo + firmware backends (DTB; ACPI later)
  mm/ mmio.rs        memory, page tables, DMA; the safe MMIO abstraction
  drivers/ net/      virtio-net, packet pool, smoltcp glue, network task
(platform-host)      planned: TAP/pcap harness to run the crates on a dev machine
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
| Heap | `linked_list_allocator` (bring-up); packet buffers come from dedicated pools |
| Locks | `spin` |
| virtio drivers + PCI config access | `virtio-drivers` (rcore-os), we implement its `Hal` trait |
| MMIO | `safe-mmio` (via `mmio::Region`) |
| aarch64 system registers | `aarch64-cpu` (arch backend only) |
| TCP/IP for the router's own services | `smoltcp` |
| DNS wire format | `simple-dns` or `domain` (check no_std support), or our own |
| SSH / HTTP (later) | `sunset` / `picoserve` |
