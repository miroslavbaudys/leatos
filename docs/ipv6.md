# IPv6 (M7, plan)

Status (2026-11-20): step 0 started (AAAA rebind protection done). First plan 2026-11-15 (checked at
2712911); **revised 2026-11-20 against 74cb3d1**, after 135 commits that
added routed LAN ports and live link slots, the WAN ingress stage, IPv4
fragments, anti-spoofing, redirects, static routes, DNS views, DoT, the
mDNS reflector, conntrack hardening and fuzzing. Each of those has an IPv6
side that the first plan did not cover; §1 lists them, §2 decides them.
Names, not line numbers: search for them.

Goal (roadmap M7): a LAN client gets a global IPv6 address (SLAAC from the
delegated prefix) and reaches the ISP over IPv6, through DHCP or PPPoE on
the WAN, with a stateful IPv6 firewall (inbound blocked by default) and
CAKE handling IPv6 like IPv4.

## 1. Today (verified in the code at 74cb3d1)

### Forwarding plane (`crates/fwd`, IPv4-only throughout)
- `Forwarder::process`: anything not IPv4 goes to `local()` ("ARP, IPv6
  (until M7)"); `shard_of` puts every non-IPv4 frame in shard 0. IPv6 is
  never forwarded, so nothing bypasses the firewall today.
- IPv4-typed: `conntrack::Tuple`, mappings, `Budget` (per-host buckets
  keyed by `Ipv4Addr`), `neigh::NeighTable` (`(IfIndex, Ipv4Addr)`),
  `route::RouteTable` (IPv4 LPM, static routes), `Interface::addr`,
  `Rule::src`/`dst` (`(Ipv4Addr, u8)`), `PortForward`/`Redirect` targets,
  `frag` (IPv4 fragment table, 16-bit IDs), anti-spoofing
  (`spoofed_from_wan`), `wire` (no IPv6 view), ICMP error builders.
- The conntrack machinery that M9 hardened (slab, hashing, `EVICT_SCAN`
  early drop, `expire_some` bounded passes, `lookup_live`, the shared
  `Budget`, the per-host limit) lives inside the IPv4 `Conntrack`
  together with NAPT.

### Kernel datapath
- `PacketMeta::next_hop` is a `u32` (IPv4): the WAN ingress stage stores
  the next hop there until the shaper releases the packet.
- `PacketBuf::mark_ce` is IPv4-only (`net/packet.rs`).
- The datapath snoops ARP (`snoop_arp`) for its neighbor tables and passes
  the frame on to smoltcp. NS/NA will need the same.
- `crates/qdisc` `ack_filter` handles IPv4 without options only. The
  qdiscs otherwise see only `flow_hash`/host hashes, so CAKE itself needs
  nothing version-specific.
- igb accepts all multicast, virtio-net delivers everything.

### Router stack (smoltcp 0.14, `svc`)
- Built with `proto-ipv6` + `multicast`, but no IPv6 address is ever
  configured, not even a link-local one: `net/stack.rs`, `net/svc.rs`,
  `net/pppoe.rs` push only `IpCidr::Ipv4`. IPv6 frames are parsed and
  dropped.
- One smoltcp interface per **link** (link 0 = WAN, then `MAX_LINKS - 1`
  network slots, switched on and readdressed live by `assign_slots`).
  IPv6 addresses have to follow the same live path.
- Default limits that IPv6 outgrows: `IFACE_MAX_ADDR_COUNT` = 2 (IPv6
  needs IPv4 + link-local + ULA + global = 4 per link),
  `IFACE_MAX_MULTICAST_GROUP_COUNT` = 4 (needs ff02::2, the
  solicited-node groups, ff02::fb, 224.0.0.251), `IFACE_MAX_PREFIX_COUNT`
  = 1.
- smoltcp has `proto-ipv6-slaac` (an RS/RA client), but it reads only the
  prefixes and the router lifetime: no M/O flags, RDNSS, or MTU. It is not
  enough for the WAN and cannot send RAs.
- LAN clients' ND, MLD and IPv6 mDNS multicast go through each link's
  `local_rx` into `svc` and are discarded there. They compete with ARP for
  `local_rx` space (`local_rx_drops`).

### PPPoE
- An IPv6CP request from the peer gets an LCP Protocol-Reject
  (`proto-pppoe` `protocol_reject`). `classify_session`, `decap_ipv4` and
  `encap_ipv4` handle PPP 0x0021 only, and `datapath.rs`
  `pppoe_rx`/`pppoe_tx` drop anything else. `PPP_IPV6`/`PPP_IPV6CP`
  constants exist. The lab ISP offers `+ipv6` to exercise the reject.
- The developer's ISP (PPPoE, VLAN 848, no auth) **does offer IPv6 over
  PPPoE** (confirmed by the developer 2026-11-20), so step 4 can be tested
  on the real line. Still unknown: the delegated prefix size and whether
  the WAN gets an address of its own. We reject IPv6CP without logging
  it, so leatos has never seen what the AC offers.

### Services and config
- `crates/proto-dns` zone: A records and in-addr.arpa PTR only
  (`zone.rs` is `Ipv4Addr` throughout); overrides answer AAAA with NoData
  by design (docs/dns-views.md §6).
- ~~Gap:~~ rebind protection (`resolver.rs` `is_private`) checked A
  records only, so an upstream AAAA of `::1`, `fe80::/10` or `fc00::/7`
  for a public name passed. Fixed in step 0 (`is_private6`).
- `crates/proto-dhcp` has the DHCPv4 server only (the WAN DHCPv4 client is
  smoltcp's). DHCPv6-PD client and RA sender are new code.
- `crates/proto-mdns` already rebuilds messages with raw records. Only the
  transport (`ff02::fb`) and link-local filtering for AAAA would need work.
- `crates/config` `Network` has `ipv4: Cidr` and no IPv6 field. `Wan` has
  no `ipv6`. docs/config-v2.md §9 item 12 reserves `[wan.ipv6]`.
- Redirects (`[[firewall.redirect]]`, e.g. the home NTP redirect) are
  DNAT. A dual-stack client that reaches an outside server over IPv6
  will bypass them.

### Lab
- The ISP VM (Alpine aarch64) has dnsmasq 2.92, which can send RAs and
  run a DHCPv6 server, but **cannot delegate prefixes** (no IA_PD server).
  None of the pinned packages can serve PD. Candidates: Kea
  (`kea-dhcp6`, heavy dependency chain), wide-dhcpv6, ISC dhcpd
  (`dhcpd -6`, end-of-life). They need checking against Alpine's
  repositories before step 3.
- The ISP needs a route for the delegated prefix to the router. The
  router's link-local address comes from its MAC (EUI-64), which is fixed
  in the lab, so a static `ip -6 route` works without server hooks.
- QEMU slirp offers an RA prefix (no PD), enough for WAN-side RA/SLAAC
  smoke checks.
- `fuzz/` has a `fwd` target that generates valid IPv4 operations. IPv6
  extends it.

## 2. Design decisions

Kept from the first plan:
- **Separate IPv6 path in the forwarder.** `Forwarder::process` branches
  on the EtherType first. The IPv4 fast path stays as it is: no enum
  dispatch and no generic address type in its hot loop.
- **No NAT66, no NPTv6.** Global addresses come from the delegated prefix
  only.
- **CAKE hashes like Linux** (decided 2026-11-15, `sch_cake.c`
  `cake_hash`): a host is one full /128, and IPv4 and IPv6 addresses
  count as separate hosts. Privacy addresses can earn a device more than
  one host's share. This is accepted.
- **No fragmentation by the router:** oversized packets get ICMPv6
  Packet Too Big (PPPoE MTU 1492 matters). SYNs get an MSS clamp (MTU −
  60).
- **Router-local client sockets** follow the port rule (≥ 60000,
  `ROUTER_CLIENT_PORTS`). The DHCPv6 client is UDP 546, which always passes
  as a reply to the router, like UDP 68.
- **Protocol logic in sans-IO crates:** the DHCPv6 client and the RA
  sender/parser go in a new `crates/proto-dhcp` `v6` module (`ra.rs`,
  `pd.rs`), IPv6CP in `crates/proto-pppoe`. The kernel only glues.
- **ICMPv6 through the firewall (RFC 4890):** Packet Too Big, Time
  Exceeded, Parameter Problem, Destination Unreachable (when related to a
  connection), echo (per zone), ND/RA/RS link-local only with a hop limit
  255 check.

New or changed (2026-11-20):
- **One conntrack core, two front ends.** Duplicating the M9 work (early
  drop, bounded expiry, budget, per-host limit, `lookup_live`) in a
  `Conntrack6` would mean two copies to keep correct and to fuzz. Instead
  step 2a moves the table machinery into a generic core (`ct::Table<T>`
  over a tuple type with its own hash), monomorphised, with no dynamic
  dispatch. IPv4 `Conntrack` = core + NAPT mappings. `Conntrack6` = core
  only: no mappings, DNAT or port search. The IPv4 tests, the fuzz target
  and `ct_bench` must show no change in behaviour or cost before IPv6
  uses it. Both families share one `Budget`: the table limit is a memory
  limit.
- **Per-host connection limit keys on the /64**, unlike CAKE's /128. With
  privacy addresses a /128 limit can be multiplied by rotating addresses.
  The limit is for protection; fairness is CAKE's job.
- **Anti-spoofing both ways.** WAN ingress: sources in our delegated
  prefix, our ULA, `::1`, `::`, `ff00::/8` or `fe80::/10` (in forwarded
  packets) are dropped as `spoofed`, the IPv4 rule extended. **LAN ingress
  (new, BCP 38):** a forwarded packet whose source is not in its network's
  /64s is dropped as `spoofed`. IPv4 NAT hides a forged source; IPv6
  routes it to the ISP.
- **Forward IPv6 fragments, don't reassemble.** IPv6 fragments are
  common (large EDNS answers, some VPNs). The first fragment must carry
  the whole header chain through the L4 header (RFC 7112), otherwise drop.
  It is decided like a whole packet. Later fragments follow that decision
  through the `frag` table, generalised to a 32-bit ID plus the IPv6
  address pair, with the same limits (≤ 16 held, 250 ms). Atomic
  fragments (offset 0, M = 0) are treated as whole packets.
- **Extension headers:** a bounded walk (at most 8 headers or 256 bytes)
  over Hop-by-Hop (first only), Destination Options, Routing (type 0 is
  dropped, RFC 5095) and Fragment. Any other non-L4 header is dropped as
  `unsupported`. Hop-by-Hop is not processed, only skipped (RFC 9098).
- **Next hop in `PacketMeta`:** `next_hop` becomes `[u8; 16]` (IPv4 in the
  first 4 bytes, the family from the EtherType). 12 more bytes per packet
  meta, no indirection.
- **Router addresses in the forwarder:** `Interface` gets a fixed array of
  IPv6 addresses (link-local, ULA, global: no `Vec` on the hot path). These
  addresses and their solicited-node groups decide `to_us`.
- **Router ND outside smoltcp.** The datapath snoops NA/NS for its
  neighbor table (like `snoop_arp`) and sends its own NS for forwarded
  packets. smoltcp keeps answering NS for its own addresses. RS and RA
  (ICMPv6 133/134) are taken out in `svc` before smoltcp, handled by the
  sans-IO RA code and sent as frames into the link's qdisc, the way PPPoE
  control frames are. smoltcp's `proto-ipv6-slaac` stays off: we need M/O,
  RDNSS and MTU from the ISP's RA, and that RA also sets the forwarder's
  default route.
- **Neighbor table bounded against /64 scans (RFC 6583):** per interface
  a cap on incomplete entries, with the oldest dropped. Counter
  `neigh_incomplete_drops`.
- **ULA** per network from a stable random /48 (RFC 4193, made from
  `entropy` on the first boot that has IPv6, stored as
  `ipv6.ula_prefix` in the config). Kept alongside the global prefix, so
  local names and the web interface survive a prefix change or WAN loss.
- **Firewall rules and address families:** a rule without addresses
  matches both families. A rule with IPv4 prefixes matches IPv4 only, one
  with IPv6 prefixes IPv6 only (OpenWrt semantics). An IPv6 "port
  forward" is an accept rule to a host. The host is named by its
  **interface identifier** (`dst = "::1:238/-64"` = any prefix, this
  suffix), so the rule survives a prefix change.
- **Redirects stay IPv4.** No DNAT66. Docs and the firewall page say that
  dual-stack clients can bypass a redirect over IPv6, and a rule can block
  outbound IPv6 for that port.
- **DNS:** AAAA for the router's names (ULA, plus the global address once
  there is one), `ip6.arpa` PTR for the ULA and the delegated /64s,
  `[[dns.host]] ipv6`. Rebind protection covers AAAA (see §1). Our own
  delegated prefix counts as private for it. Clients' AAAA records
  (SLAAC hostnames) are out of scope until step 5.
- **RA MTU option = the LAN link MTU (1500)**, not the WAN's. Clients
  learn 1492 over PPPoE from Packet Too Big and the MSS clamp, like
  OpenWrt.
- **Off by default** (`[ipv6] enabled = false`, boot argument `ipv6=0|1`)
  until step 4 runs on the apu4. Then on, with `ipv6=0` as the lab's
  negative control throughout.

## 3. Steps (each one testable on its own)

### Step 0: before code (can start now)
- ✅ **AAAA rebind protection** (2026-11-20, `crates/proto-dns`
  `is_private6`, `wire::answer_ipv6s`, `Rdata::Aaaa`): `::1`, `::`,
  `fe80::/10`, `fc00::/7` and IPv4-mapped private addresses are refused
  (REFUSED + EDE 15, not cached). Host test with a negative control (the
  test fails with the IPv6 check off); the `dns` fuzz target builds AAAA
  answers (5 min clean). The delegated prefix joins the list in step 3.
- **Ask the real ISP:** IPv6 over PPPoE is confirmed. Still useful:
  `proto-pppoe` counts IPv6CP Configure-Requests from the peer and logs the
  first one (options seen), still rejecting it (`/api/status`
  `pppoe.ipv6cp_offered`). **Deploy on the apu4 only after the soak run
  ends (2026-11-22).** The prefix size is only learned in step 4 (PD over
  the session).
- **Lab PD server:** pick and pin one (Kea or wide-dhcpv6 from Alpine
  aarch64), check that it delegates a /56 to a Linux `dhcpcd` test client
  inside the ISP VM image, and pin its hashes in `fetch-alpine.sh`.
- smoltcp features: `iface-max-addr-count-4`,
  `iface-max-multicast-group-count-8`. Measure heap and binary size.

### Step 1: router IPv6 on the LAN, no forwarding
- Link-local addresses (EUI-64 from the port MAC) on every link, the WAN
  included, and a ULA /64 per network slot (subnet id = slot), applied live
  through `assign_slots` like IPv4.
- RA sender (`proto-dhcp` `v6::ra`, tickless: the crate returns the next
  deadline): unsolicited RAs (RFC 4861 timers), replies to RS. Prefix
  information (A flag), RDNSS (RFC 8106, the router's ULA), DNSSL (the
  network's `domain`), MTU. Router lifetime 0 while there is no IPv6
  default route, so clients do not send internet traffic to us. A
  network that goes away sends a final RA with lifetime 0.
- svc: RS/RA taken out before smoltcp (§2). Joins ff02::2 and the
  solicited-node groups. Counters `ra_sent`, `rs_received`.
- DNS on `[::]:53` UDP + TCP per network, AAAA/PTR for the router's names.
  Views apply as for IPv4 (by the socket's network).
- Web interface on IPv6 (link-local + ULA). Input policy per zone applies
  to IPv6 too: a guest zone without the `mgmt` service cannot reach it.
- Lab: the client gets a SLAAC ULA, `ping6` to the router, resolves
  `router.lan` AAAA over IPv6, fetches the web page over the ULA. With
  `LAB_GUEST=1` the guest gets its own ULA /64 and cannot open the web
  interface over IPv6. Negative control `LAB_ROUTER_ARGS=ipv6=0` (no
  address, checks fail). Also `LEATOS_ARCH=x86_64`, `QEMU_NIC=igb`.

### Step 2a: conntrack core refactor (no IPv6 yet)
- `ct::Table<T>` as in §2; IPv4 `Conntrack` on top, no behaviour change.
- Proof: all `crates/fwd` tests unchanged, `fwd` fuzz target 10 min clean,
  `ct_bench=1` numbers within noise of before (release, HVF), lab
  per-task CPU split unchanged.

### Step 2b: IPv6 forwarding with a static WAN prefix
- `crates/fwd`: `wire::Ipv6View` (extension-header walk, §2), IPv6 LPM
  routes, `Neigh6` with NS/NA and the RFC 6583 bound, `Conntrack6`
  (stateful, inbound blocked), hop limit, ICMPv6 errors (Time Exceeded,
  Unreachable, Packet Too Big, rate-limited by the existing token bucket),
  MSS clamp, `shard_of` for IPv6, zone `Policy` and rules for IPv6 (address
  families as in §2), anti-spoofing both ways, fragments via `frag`,
  `Classification` for IPv6.
- Datapath: `next_hop` widened, NS/NA snooping and NS sending,
  `mark_ce` for IPv6 (traffic class, no checksum), `ack_filter` for IPv6
  TCP, drop reasons (reuse `spoofed`, `fragment`, `unsupported`;
  `too-big` for PTB).
- Boot arguments for development (replaced by step 3): `wan6_ip=`,
  `wan6_gw=`, `lan6_prefix=` (the delegated prefix).
- Lab (`LAB_IPV6=1`, ISP VM with a static prefix, a route to the router's
  link-local and an IPv6 web/CGI): client ping6 + HTTP to the ISP over a
  global address, traceroute6, inbound from the ISP refused (negative
  control: a rule accepting wan → lan), Packet Too Big
  (`LAB_BIG_PING` over IPv6 with a smaller ISP-side MTU; negative control
  the oversized ping), a forged LAN source dropped as `spoofed` (negative
  control `LAB_ROUTER_ARGS=lan_antispoof=0`), a fragmented `ping6 -s 3000`
  both ways (negative control `fw_frag=0`), ECN marks on IPv6 from the
  router's counters.
- Host tests and fuzzing: header walk (`fwd` fuzz target with IPv6
  operations), conntrack6, ICMPv6 errors, PTB, fragments, spoofing. CPU
  cost of the IPv4 path measured before and after: it must not regress.

### Step 3: DHCPv6-PD on a DHCP WAN
- WAN RA (sans-IO parser in `v6::ra`): default route from the ISP's RA
  (router lifetime), M/O flags, MTU, RDNSS. WAN address by SLAAC or IA_NA
  is optional: many ISPs route the prefix to the link-local only.
- DHCPv6 client (`v6::pd`): Solicit/Advertise/Request/Reply, IA_PD with
  `prefix_hint`, Renew/Rebind/expiry, Reconfigure ignored. DUID-LL from
  the WAN MAC, stable across reboots. DNS servers from the reply feed the
  forwarder's upstreams (when `dns.upstreams` is empty).
- Prefix split: a /64 per network slot (subnet id = slot index, or
  `subnet_id` from the config). Networks beyond the delegated size get
  the ULA only, with a warning. RA lifetimes follow the lease.
- Prefix change or loss: RAs deprecating the old prefix (preferred 0,
  valid ≤ 2 h), conntrack6 entries of the old prefix flushed,
  pinhole rules re-resolved (interface identifiers, §2). The last prefix
  is kept in the store's lease area and asked for again after a reboot.
- Config: `[ipv6]` (`enabled`, `ula_prefix`), `[wan.ipv6]` (`dhcpv6_pd`,
  `prefix_hint`, default /56), per network `ipv6` (default true when
  `[ipv6] enabled`) and `subnet_id`. API and UI status (prefix, lease,
  per-network /64), CLI `status`.
- Lab: the ISP VM runs RA (dnsmasq `enable-ra` or the PD server's) + the
  PD server from step 0. The client gets a global address. Prefix change
  on the ISP side, after which the old address is deprecated on the
  client. Negative control: ISP without PD (no global address, LAN keeps
  the ULA only).

### Step 4: IPv6 over PPPoE
- `proto-pppoe`: IPv6CP (interface identifier negotiation, link-local),
  no more Protocol-Reject for it. `Session` carries the IPv6 state.
- `wire`/datapath: classify/decap/encap for PPP 0x0057 ↔ EtherType 0x86DD.
- RA and DHCPv6-PD over the session (the WAN interface is `Medium::Ip`: RS
  to ff02::2, RA from the AC's link-local).
- Lab: `LAB_PPPOE=pap` with `+ipv6` on the ISP and the PD server behind
  `pppd`. Negative control: `pppoe-server` without `+ipv6`.
- apu4 (after step 0's answer): real ISP, PD, a client on each home
  network, IoT zone without internet over IPv6 too.

### Step 5: the rest
- Firewall page: IPv6 rules, pinholes by interface identifier, the
  redirect caveat.
- mDNS reflector on `ff02::fb` (link-local AAAA removed as for IPv4
  today), SNTP and DNS upstreams/DoT over IPv6, `[[route]]` for IPv6.
- AAAA for DHCP hostnames: neighbor table (MAC ↔ IPv6) joined with
  DHCPv4 leases (MAC ↔ hostname), global and ULA addresses only.
- Optional: stateful DHCPv6 server on the LAN (M flag).
- apu4: bufferbloat run with IPv6 traffic, `mac-internet.sh` without
  `--ipv4-only`, 72 h soak with IPv6 on.

## 4. Risks and open questions
- **Home ISP:** IPv6 over PPPoE (confirmed 2026-11-20), so step 4 is the
  one that matters at home. Steps 1–3 stay first because the lab can check
  them. Prefix size and WAN address are unknown until step 4 meets the
  real AC.
- IPv4 hot path: the early EtherType branch and the conntrack refactor
  must keep the per-packet cost (2a and 2b measure it).
- `local_rx` and packet pool pressure from IPv6 multicast (ND, MLD, mDNS)
  on busy LANs: counted, and if it shows up, unsolicited multicast is
  dropped early in the forwarder (MLD reports from clients are not needed:
  no multicast routing).
- smoltcp IPv6 maturity (ND for its own addresses, MLD with several
  groups): step 1 shakes it out. Fixes go upstream or in a small wrapper,
  never in a fork.
- Lab PD server availability on Alpine aarch64 (step 0).
- Privacy addresses and pinholes: a pinhole by interface identifier hits
  the stable (EUI-64 or RFC 7217) address only. Documented.
