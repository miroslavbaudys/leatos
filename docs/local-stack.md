# Router-local stack: smoltcp for TCP only (plan)

Status (2026-11-26): steps 1 and 2 done in QEMU (the WAN IP-only on DHCP and static, `net::wan4`
over the router's own UDP: `net::local` + `fwd::udp`, IPv4 and IPv6); the fallbacks
(`wan_medium=eth`, `lan_medium=eth`), the neighbor hints and `medium-ethernet` removed on
2026-11-26 (user decision: the whole migration goes to the apu4 at once after the soak, no
per-step day there). Step 0 (docs/lan-neighbors.md) done with it. Step 3 done the same day
(every UDP service on `net::local`, `socket-udp` gone), steps 4 and 5 too (ICMP echo, the
pinger, IGMP / MLD ours; smoltcp for TCP only). Unbound UDP dropped silently (2026-11-27, step 3
below). Left: the apu4 (§6). Roadmap M14.

## 1. Goal

smoltcp is a host stack. As the router's own stack it needed workarounds against its internals on
every link (docs/lan-neighbors.md §1: neighbor hints, the NA Router flag, cache size, address
updates emptying the cache), and its DHCPv4 socket panics without an Ethernet address. The
protocol logic already lives in sans-IO crates (`proto-dhcp`, `proto-dns`, `proto-sntp`,
`proto-mdns`, `fwd::nd`); smoltcp only carries their bytes.

**Target:** smoltcp keeps **TCP only** (the web interface on :80, DNS over TCP on :53, the DoT
client), on `Medium::Ip` on every link, with features `medium-ip`, `proto-ipv4`, `proto-ipv6`,
`socket-tcp`. Everything else the router sends or answers is leatos's own code: link layer in the
datapath, UDP and ICMP in a small router-local path in `svc`, packet building in `crates/fwd`.

Not a goal (then; reversed 2026-11-27, docs/own-tcp.md, roadmap M15): our own TCP.
Retransmission, windows and the state machine are where a stack is hard to get right; the
router's TCP is low-volume, and smoltcp's TCP needs no workarounds.

## 2. What smoltcp does today, and what replaces it

- **TCP** (:80, DNS over TCP :53, the DoT client; `mgmt.rs`, `dns_tcp.rs`, `dot.rs`): stays.
- **ARP / ND on LAN links**: done (`fwd::nd`, lan-neighbors step 3).
- **ARP / ND on the WAN**, with hints (workarounds 1, 3, 7 on link 0, `device.rs`): `fwd::nd` and
  `send_local` (step 2).
- **DHCPv4 client** on a DHCP WAN (`Socket::Dhcpv4`, `svc.rs`): `proto_dhcp::v4::client` (step 1).
- **UDP sockets**: DNS :53 and 64 upstream slots (61000–65535, `services.rs`), DHCP server :67,
  DHCPv6 client :546 (`wan6.rs`), SNTP 60000–60999 (`ntp.rs`), mDNS :5353 (`mdns.rs`): the
  router-local UDP path (step 3).
- **ICMP**: echo replies (`auto-icmp-echo-reply`), the gateway pinger's socket (`svc.rs`
  `Pinger`): `fwd` builders (step 4).
- **IGMP / MLD** reports for its groups (224.0.0.251, ff02::fb, solicited-node; `mdns.rs` joins):
  `fwd` builders (step 4).
- **Source address and routes** for its own packets (the interfaces): the per-link addresses
  (`fwd::local::LocalLink`) and the datapath's routes.
- **`socket-dns`**: in the feature list but unused (nothing uses smoltcp's DNS socket): can go now.

The PPPoE WAN and the LAN links already run smoltcp on `Medium::Ip`; a static WAN does not yet
(`stack::new_iface`: IP-only only for PPPoE and LAN links), though it needs no DHCP client.

## 3. Design

### 3.1 Receive

The datapath already decides which packets are for the router (`local_rx`, a small bounded queue
per link, docs/bufferbloat-cake.md §3.1). It keeps doing that; `svc` then dispatches by protocol:

- **TCP** → smoltcp (`PortDevice::receive`, as today, IP packets only).
- **UDP** → a port table in `svc` (`local::Udp`): destination port (and for client ports the
  remote address and port the query went to) → the owning service, which gets
  `(link, src, dst, payload)` as a slice of the packet buffer, no copy into a socket ring.
  Unknown ports: dropped silently, as `net::shared::CLIENT_PORTS` already does in the datapath.
- **ICMP / ICMPv6** echo → answered in `svc` (or the datapath: decided in step 4); errors about
  the router's own packets → the service that sent the packet (e.g. DNS upstream unreachable).

Checksums are verified once on receive (`fwd::wire`), so services see only valid payloads.

### 3.2 Send

A service returns `(link, dst, src port, dst port, payload)`; `svc` builds the IP + UDP header
into a `net::packet` buffer (`fwd::wire` builders, checksums) and hands it to
`Datapath::send_local`, which already maps broadcast / multicast and resolves unicast next hops
through `fwd::neigh` (lan-neighbors step 2). No UDP packet waits anywhere but the neighbor
table's bounded pending queue and the qdisc.

- **Source address:** IPv4 = the link's address; IPv6 = link-local for link-local destinations
  and multicast on the link (mDNS, RAs), else the link's ULA or GUA matching the destination's
  scope (an RFC 6724 subset: scope, then longest matching prefix). `LocalLink` holds the
  addresses already.
- **Size:** no router UDP payload exceeds the link MTU (DNS ≤ 1472 with TC set past it, DHCP and
  mDNS bounded by `MAX_OUTPUT`), so the router never fragments its own packets; a larger one is a
  bug, dropped and counted.
- **Port choice for client queries** stays a fresh random port per DNS query
  (`ROUTER_CLIENT_PORTS`), now without smoltcp's bind / unbind slots: the port table is the
  registry, `CLIENT_PORTS` is fed from it as today.

### 3.3 Link layer on the WAN

Same as the LANs: smoltcp on `Medium::Ip`, ARP / ND answered by `fwd::nd`, the gateway resolved by
`fwd::neigh`. That needs our own DHCPv4 client first (smoltcp's panics on `Medium::Ip`). With
it, the last hints go, and with them `medium-ethernet` and `neigh-cache-256`.

### 3.4 What `svc` still owns

The tasks and their timing stay: `svc` runs every service's `poll(now)` and timers, builds and
parses headers, and calls into the datapath only through `send_local` and `net::shared`
(CLAUDE.md: router-local work in `Priority::Service`, forwarded packets never leave the datapath).

## 4. Steps

Each step deploys on its own and passes the CLAUDE.md test table for what it touches.

### Step 0: lan-neighbors to the end

docs/lan-neighbors.md: the apu4 day (§5), `--persist`, a week, step 4 (LAN workarounds removed).

### Step 1: DHCPv4 client in `crates/proto-dhcp`

- `v4::client`: sans-IO RFC 2131 client (DISCOVER / OFFER / REQUEST / ACK, renew at T1 unicast to
  the server, rebind at T2 broadcast, NAK and lease loss, INIT-REBOOT with the stored address),
  options as the smoltcp socket gives them today (router, DNS, subnet, lease times, MTU).
- Host tests against the server in the same crate and against recorded ISP packets; a fuzz target
  `dhcp_client` (replies to what it sent).
- Not used yet: kernel unchanged.

Done (2026-11-26): `proto_dhcp::v4::client` and option 26 in `v4::packet`. 19 host tests: DORA,
renewal, rebinding to another server, lease end, NAK while renewing, INIT-REBOOT (ACK, NAK,
unanswered), backoff, NAK spacing, what is ignored, lease checks, infinite and tiny leases, reset,
broadcast flag, T1 = T2. No ISP capture exists (the home line is PPPoE), so other servers' replies
are hand-built byte by byte the way busybox udhcpd writes them (the lab ISP), plus T1 / T2 / MTU;
step 2b checks against the real udhcpd in the lab. Fuzz target `dhcp_client`: 5.6 M runs in 5 min
clean, after a fix it found (T1 = T2 sent a RENEW and a REBIND at the same instant). Not done:
ARP probe + DECLINE, RELEASE, option overload (52).

### Step 2: WAN on `Medium::Ip`

- 2a, static WAN first (no DHCP client needed): `new_iface` IP-only for every role; ARP / ND for
  the WAN answered by `fwd::nd`, the gateway through `fwd::neigh`. `LAB_WAN_STATIC=1` with the
  hints off.
- 2b, DHCP WAN: `svc` drives `v4::client` over the router-local UDP path for ports 68 / 67 (that
  part of step 3 comes first, for broadcast to and from 0.0.0.0).
- The hints (`NdHints`, `ipv6_ns_to_solicited`, `ipv6_na_set_router`), `arp_hints=`,
  `neigh-cache-256` and `medium-ethernet` removed, `wan_medium=eth` too (done 2026-11-26, without
  the planned deployment cycle).

### Step 3: router-local UDP

The port table, receive dispatch and send path (§3.1, §3.2), then the services one at a time,
each with its lab suite passing before the next: DNS (server :53 and upstream ports; the
highest volume, and the random-port slots go away), DHCP server :67, DHCPv6 client :546, SNTP,
mDNS :5353 (multicast send and receive without smoltcp groups). `socket-udp` removed at the
end.

- DNS (2026-11-26, QEMU): :53 per network and the upstream ports on `net::local`, which also got
  its PPPoE send path (into the WAN qdisc) and `source` (the datapath's view of the link:
  `LocalLink::source4` / `source6`). DNS over TCP and DoT stay on smoltcp's TCP.
- DHCP server :67, DHCPv6 client :546, SNTP and mDNS :5353 (TTL 255: `fwd::udp::build4` takes the
  TTL now) followed the same day; `socket-udp` removed. Step 3 done in QEMU; the IGMP / MLD reports
  for mDNS's groups still come from smoltcp (step 4).
- Unbound ports (2026-11-27): without `socket-udp`, smoltcp answered UDP to a router port nobody
  bound with ICMP protocol unreachable (IPv6: parameter problem), from zones without an input
  policy. `net::local` now takes all UDP and drops unbound datagrams silently
  (`local.udp_unbound`); the lab's client-port check counts every ICMP unreachable, and a LAN
  probe checks the drop (negative control `udp_unbound_drop=0`).

### Step 4: ICMP and group membership (done in QEMU 2026-11-26)

Done: `fwd::echo` (echo parse / reply / request) and `fwd::mcast` (IGMPv2 report / leave, MLDv2
report, IGMP v1–v3 / MLD v1–v2 query parse); `net::local` answers echo requests to the router's
unicast addresses (`/api/status` `local.echo_replies`) and queues pinger replies and membership
queries; `net::groups` keeps the memberships per link (solicited-node, ff02::2, mDNS) with
reports on change (twice) and to queries; the forwarder passes IGMP queries from networks up (MLD
queries it did already). `groups=0`: the lab's control for the mDNS IGMP / MLD checks. ICMP
errors about the router's own packets are not delivered to its senders (smoltcp did not either).

- Echo replies for the router's addresses, ICMP errors to the router's own senders, the gateway
  pinger without an ICMP socket; `auto-icmp-echo-reply` and `socket-icmp` removed.
- IGMPv2 / MLDv2 reports and query answers for the groups the router listens to (switches with
  snooping); `multicast` removed if smoltcp no longer needs it for TCP.

### Step 5: smoltcp trimmed (done 2026-11-26)

Reached with step 4: smoltcp is built with `alloc`, `medium-ip`, `proto-ipv4`, `proto-ipv6`,
`socket-tcp` and its route / address limits; `socket-udp`, `socket-icmp`, `socket-dhcpv4`,
`socket-dns`, `medium-ethernet`, `auto-icmp-echo-reply`, `multicast` and the neighbor cache size
are gone.

Features down to `medium-ip`, `proto-ipv4`, `proto-ipv6`, `socket-tcp` (+ limits); its interfaces
hold the addresses and routes TCP needs. Docs: kernel/src/net/CLAUDE.md, docs/architecture.md,
docs/ipv6.md, docs/safety-and-portability.md (dependency surface).

## 5. Tests and negative controls

- Every step: the CLAUDE.md table for network, services, DHCP, DNS, IPv6, mDNS changes (lab
  default, `LAB_GUEST`, `LAB_PORTS`, `LAB_IPV6`, `LAB_ROUTES`, `LAB_MDNS`, `LAB_DNS_VIEWS`,
  `LAB_DOT`, `LAB_PPPOE=pap`, `LAB_VLAN`, lease / cli / store tests; `QEMU_SMP=4`,
  `QEMU_NIC=igb`, x86_64, TCG), `cargo test`, clippy, the fuzz targets of changed crates.
- New: **DHCP WAN client** in the lab (the ISP's Kea): lease, renew, rebind after the server
  stops answering renews, NAK on a moved subnet. Negative controls per case (no renew answer →
  rebind seen; NAK ignored → FAIL).
- New: **UDP checksums and ports**: the client sends DNS queries with a bad UDP checksum (dropped,
  counted) and to a closed port (silence, no port unreachable, as today's scan check).
- New: **source address**: the router answers a query to its ULA from the ULA and one to its
  link-local address from that (negative control: a build that always picks the GUA fails).
- **Measurements** (CLAUDE.md: proven load): `svc` CPU per DNS query before / after step 3 under
  the lab's DNS load (`cpu.tasks`), and heap per open service socket (the soak's `heap_live`).

## 6. On the apu4

Each step in RAM first, a day against the previous build's `/api/status` (as lan-neighbors §5),
then `--persist`, a soak for the steps that change the WAN (2) or the DNS path (3). The fallback
boot argument of a step is used only in RAM (docs/upgrades.md: a stored kernel boots with the SD
card's command line).

## 7. Risks and open questions

- **More code on the wire is ours.** Headers, checksums and demultiplexing are small but exposed:
  builders and parsers in `crates/fwd` with host tests and fuzz targets, like `fwd::nd`.
- **The DHCP client is the WAN's lifeline.** A bug leaves the home without internet. No fallback
  any more (removed 2026-11-26); the lab covers bind and renewal (`LAB_WAN_LEASE`), host tests
  rebind / NAK. The home line is PPPoE, so the apu4 does not exercise it.
- **smoltcp's TCP on `Medium::Ip` with addresses we manage**: its interface must still know the
  addresses and routes TCP uses (source address for the DoT client). Checked with `LAB_DOT=1` and
  `LAB_IPV6=1` at step 5.
- **Where ICMP echo is answered** (datapath or `svc`): the datapath is cheaper and needs no
  `local_rx` slot, `svc` keeps rate limiting next to other services. Decided in step 4.
