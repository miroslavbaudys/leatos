# IPv6 (M7, plan)

Status (2026-11-17): not started. This is the plan; the analysis in §1 was
checked against the code at 2712911 (line numbers dropped since: search
for the names).

Goal (roadmap M7): a LAN client gets a global IPv6 address (SLAAC from the
delegated prefix) and reaches the ISP over IPv6, through DHCP or PPPoE on
the WAN, with a stateful IPv6 firewall (inbound blocked by default) and
CAKE handling IPv6 like IPv4.

## 1. Today (verified in the code)
- `crates/fwd` `Forwarder::process`: anything that is not IPv4 goes to
  `local()` ("ARP, IPv6 (until M7)"); `shard_of` puts every non-IPv4
  frame in shard 0. IPv6 is never
  forwarded, so nothing bypasses the firewall.
- smoltcp 0.14 is built with `proto-ipv6` and `multicast`, but no IPv6
  address is ever configured (not even link-local): `net/stack.rs`,
  `net/svc.rs`, `net/pppoe.rs` only push `IpCidr::Ipv4`. IPv6 frames are
  parsed and dropped.
- Side effect: LAN clients' ND, MLD and mDNS multicast all go through each
  link's `local_rx` into `svc` and are discarded there; they compete with
  ARP for `local_rx` space (`local_rx_drops`).
- PPPoE: IPv6CP gets an LCP Protocol-Reject (`proto-pppoe` `protocol_reject`);
  `classify_session` / `decap_ipv4` / `encap_ipv4` handle PPP protocol
  0x0021 only; `datapath.rs` `pppoe_rx`/`pppoe_tx` drop anything else. The
  lab ISP offers `+ipv6` to exercise the reject.
- WAN DHCP mode: the ISP's RAs reach smoltcp and are ignored. LAN clients
  get no RA, so link-local only.
- All `crates/fwd` types are IPv4-only: `conntrack::Tuple` (`src`/`dst:
  Ipv4Addr`), mappings, `host_hash`, `neigh::NeighTable` keyed by
  `(IfIndex, Ipv4Addr)`, `route` (IPv4 LPM), `wire` (no IPv6 view).
- `PacketBuf::mark_ce` is IPv4-only (`net/packet.rs`).
- Already usable: `PPP_IPV6`/`PPP_IPV6CP` constants
  (`proto-pppoe/src/wire.rs`); igb accepts all multicast, virtio-net
  delivers everything; the qdiscs only see `flow_hash` / `host_hashes`
  (`qdisc/src/lib.rs`), so CAKE needs nothing version-specific.
- `crates/proto-dhcp` has only the DHCPv4 server (`v4`) so far; the WAN
  DHCPv4 client is smoltcp's. DHCPv6-PD and RA are new code.
- Requirements already written down: `docs/soho-features.md` (DHCPv6-PD
  with a /56 hint, prefix changes with deprecating RAs, a /64 per network,
  RA + RDNSS + M/O flags, SLAAC mandatory: Android has no DHCPv6),
  `docs/config-v2.md` §9 item 12 (`[wan.ipv6]`, inbound blocked by default),
  `docs/mdns.md` (`ff02::fb` waits for M7).

## 2. Design decisions
- **Separate IPv6 path in the forwarder.** `Forwarder::process` branches on
  the EtherType first; the IPv4 fast path stays untouched (no enum
  dispatch in its hot loop). IPv6 gets its own `Conntrack6`: no NAT, no
  port mappings, no DNAT, only a stateful filter, so it is much smaller
  than making NAPT generic. Shared pieces (zone `Policy`, `Rule` matching,
  `DropReason`, hints) are reused.
- **No NAT66, no NPTv6.** Global addresses from the delegated prefix only.
- **Hashes:** IPv6 flows get `flow_hash` and host hashes from `Conntrack6`.
  **Decided (2026-11-15): same as Linux CAKE** (`sch_cake.c` `cake_hash`:
  the host hash covers the full address from the flow dissector). A host
  is one full IPv6 address (/128), not its /64; a host's IPv4 and IPv6
  addresses count as separate hosts, and nothing ties them together (e.g.
  by MAC). Accepted consequence: a device using SLAAC privacy addresses
  (several temporary /128s) can get more than one host's share.
- **Neighbor discovery** for forwarding lives in `crates/fwd` (sans-IO,
  `Neigh6` or a generic `NeighTable<A>`); NS for the router's own addresses
  and DAD go to smoltcp through the local path, the same way ARP does.
- **No fragmentation:** IPv6 routers never fragment; oversized packets get
  ICMPv6 Packet Too Big (PPPoE MTU 1492 matters). MSS clamp for IPv6 SYNs
  (MTU − 60).
- **Router-local IPv6 client sockets** follow the same port rule (≥ 60000,
  `ROUTER_CLIENT_PORTS`); DHCPv6 client is UDP 546 (like UDP 68 for v4,
  always passes as a reply to the router).
- Protocol logic stays in sans-IO crates: DHCPv6 client and RA sender in
  `crates/proto-dhcp` (or a new `crates/proto-ra` if it grows), IPv6CP in
  `crates/proto-pppoe`. The kernel only glues sockets.
- ICMPv6 that must pass the firewall (RFC 4890): Packet Too Big, Time
  Exceeded, Parameter Problem, Destination Unreachable (related to a
  connection), echo (configurable per zone), ND/RA/RS link-local only
  (hop limit 255 check).

## 3. Steps (each one testable on its own)

### Step 1: router IPv6 on the LAN, no forwarding
- smoltcp: link-local addresses (EUI-64 from the port MAC) on every link;
  a ULA per network (`fdxx::/64`, from a stable random /48 stored in the
  config on first boot, or a boot argument for tests).
- RA sender (sans-IO): periodic unsolicited RAs (tickless: next deadline
  from the crate) + replies to RS; prefix information (A flag), RDNSS,
  DNSSL (`[dns] domain`), MTU, router lifetime 0 while there is no IPv6
  default route (so clients do not send internet traffic to us).
- DNS: listener on the router's IPv6 addresses, AAAA for `router.lan`.
- Web interface reachable over IPv6 (link-local + ULA).
- Lab: client gets a SLAAC ULA, `ping6` router, resolves over IPv6;
  negative control `LAB_ROUTER_ARGS=ipv6=0` (no address, checks fail).

### Step 2: IPv6 forwarding with a static WAN prefix
- `crates/fwd`: `wire::Ipv6View` (extension-header walk to the L4 header,
  bounded), routes for IPv6 (LPM), neighbor table for IPv6 with NS/NA,
  `Conntrack6` (stateful, inbound blocked), hop limit, ICMPv6 errors (Time
  Exceeded, Unreachable, Packet Too Big) with rate limiting, MSS clamp,
  `shard_of` for IPv6, zone `Policy` and rules for IPv6.
- Datapath: `PacketMeta` hashes for IPv6, `mark_ce` for IPv6 (traffic
  class, no checksum), drop reasons.
- Boot arguments for a static WAN address + gateway + delegated prefix
  (development, replaced by step 3).
- Lab: ISP VM with a static IPv6 prefix and route; client ping6 + HTTP to
  the ISP, traceroute6, inbound from the ISP refused (negative control:
  firewall `forward` from wan allowed), Packet Too Big with
  `LAB_BIG_PING` over IPv6 (negative control: the oversized ping).
- Host tests: header parsing fuzzed, conntrack6, ICMPv6 errors, PTB.
  CPU cost of the IPv4 path measured before/after (must not regress).

### Step 3: DHCPv6-PD on a DHCP WAN
- WAN: RS, default route from the ISP's RA (router lifetime, M/O flags),
  SLAAC or IA_NA for a WAN address (optional: many ISPs only route the
  prefix to the link-local).
- DHCPv6 client (sans-IO): Solicit/Advertise/Request/Reply, IA_PD with
  the `prefix_hint`, Renew/Rebind/expiry, Reconfigure ignored, DUID from the
  WAN MAC (DUID-LL), stable across reboots, DNS servers from the reply.
- Prefix split: `/64` per network slot (slot index = subnet id), the ULA
  stays alongside; RA lifetimes follow the lease.
- Prefix change / loss: deprecating RAs (preferred 0, valid ≤ 2 h) for the
  old prefix, conntrack6 entries of the old prefix flushed.
- Config: `[wan.ipv6]` (`enabled`, `dhcpv6_pd`, `prefix_hint`), per network
  `ipv6 = true` / `subnet_id`; in `unsupported()` until it works; API and
  UI status (prefix, lease, per-network /64), CLI `status`.
- Lab: ISP VM runs radvd + a DHCPv6 server with prefix delegation (dnsmasq
  or Kea from Alpine, pinned in `fetch-alpine.sh`); client gets a global
  address; prefix change on the ISP side; negative control: ISP without
  PD (no global address, LAN keeps the ULA only).

### Step 4: IPv6 over PPPoE
- `proto-pppoe`: IPv6CP (interface identifier negotiation, link-local),
  no more Protocol-Reject for it; `Session` carries the IPv6 state.
- `wire`/datapath: classify/decap/encap for PPP 0x0057 ↔ EtherType 0x86DD.
- DHCPv6-PD over the session (WAN interface is `Medium::Ip`).
- Lab: `LAB_PPPOE=pap` with `+ipv6` on the ISP and a PD server behind it;
  negative control `pppoe-server` without `+ipv6`.

### Step 5: the rest
- Firewall: IPv6 rules in `[[firewall.rule]]` (address family, IPv6
  prefixes), "port forward" for IPv6 = allow rule to a host; web page.
- mDNS over `ff02::fb` (reflector on IPv6 too), SNTP over IPv6, DNS
  upstreams over IPv6.
- Optional: stateful DHCPv6 server on the LAN (M flag), DHCPv6 for
  hostnames in the `.lan` zone.
- apu4: real ISP PD (PPPoE), bufferbloat run with IPv6 traffic,
  `mac-internet.sh` without `--ipv4-only`.

## 4. Risks and open questions
- IPv4 hot path: the early EtherType branch must keep the per-packet cost;
  measure in step 2 (`cpuload`, lab per-task split).
- Neighbor cache exhaustion from scans of a /64: bounded table, incomplete
  entries limited per interface, oldest dropped (RFC 6583).
- Packet pool and `local_rx` pressure from IPv6 multicast (ND, MLD, mDNS)
  on busy LANs: count it, drop non-solicited multicast early in the
  forwarder if it shows up.
- QEMU slirp only offers an RA prefix (no PD), so most checks need the ISP
  VM; the Mac lab needs an IPv6 path for the ISP VM.
- ISP specifics (prefix size, PD over PPPoE vs. DHCP, WAN address or not)
  need checking against the developer's ISP on the apu4.
