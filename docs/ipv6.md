# IPv6 (M7, plan)

Status (2026-11-20): steps 0 and 1 done in QEMU (step 0: AAAA rebind protection, Kea for the lab, smoltcp limits, IPv6CP offer logged; step 1: IPv6 on the router's networks, below). Step 2a (conntrack generic over the address family) done too. The apu4 check of the IPv6CP offer waits for the soak run to end. Next: step 2b. First plan 2026-11-15 (checked at
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
  Alpine v3.24 has no wide-dhcpv6 and no ISC dhcpd: **Kea 3.0.3**
  (`kea-dhcp6`) is the only PD server. It is pinned in `fetch-alpine.sh
  kea` (kea-common, kea-dhcp6, log4cplus, libstdc++, libgcc: about 6.5 MB
  more in the ISP initrd, so only when an IPv6 lab asks for it).
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
  step 2a made the table generic over the address family (as built,
  2026-11-20: `Conntrack<A: Addr = Ipv4Addr>`, `Tuple<A>`, `Conn<A>`; the
  `Addr` trait gives the flow hash, the CAKE host hash and the per-host
  key), monomorphised, with no dynamic dispatch. NAPT and DNAT live in
  `impl Conntrack<Ipv4Addr>`; IPv6 uses the core only
  (`Conntrack<Ipv6Addr>::create_routed`). The IPv4 tests, the fuzz target
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
- **Router addresses in the forwarder** (step 1): the link-local address
  comes from the interface's MAC (`wire::link_local`), the ULA from
  `Forwarder::set_ula6` (a list beside `Interface`, which stays as it is);
  the global address joins it in step 3. These, ff02::1, ff02::2,
  ff02::fb and solicited-node groups decide what is for the router.
- **The IPv6 input filter comes first** (step 1): before 2026-11-20
  every non-IPv4 frame went to the router stack without the zone input
  policy (`Forwarder::input`). That was harmless only because smoltcp had
  no IPv6 address. `Forwarder::process6`/`input6` apply it to IPv6: ND
  (hop limit 255), MLD queries, ICMPv6 errors, echo replies and replies
  to the router's UDP clients pass; then rules without addresses, then
  the zone's services; refused input is dropped (`reject` answers for
  IPv6 come with step 2). With `ipv6` off every IPv6 frame is dropped
  (`unsupported`), which also keeps clients' ND/MLD out of `local_rx`.
- **Router ND outside smoltcp.** The datapath snoops NA/NS for its
  neighbor table (like `snoop_arp`) and sends its own NS for forwarded
  packets (step 2). smoltcp keeps answering NS for its own addresses.
  RAs come from the sans-IO `proto_dhcp::v6::ra` and go as whole frames
  into the link's qdisc. An RS is noticed as the router stack reads it
  (`net::device` sets `LinkShared::rs_seen`; smoltcp ignores it, being a
  host). smoltcp's `proto-ipv6-slaac` stays off: we need M/O, RDNSS and
  MTU from the ISP's RA, and that RA also sets the forwarder's default
  route.
- **smoltcp 0.14's neighbor discovery needs help** (found in the step 1
  lab, 2026-11-20). It learns IPv6 neighbors only from ND and drops the
  packet that makes it resolve one; clients know our MAC from the RA and
  never solicit us, so the first answer after a quiet minute (its 60 s
  entry lifetime) was lost (the first ping of six, the first DNS query).
  And it answers only solicitations to a solicited-node group, not the
  unicast reachability probes of RFC 4861 §7.3.3. `net::device` fixes
  both at its input, with two pure functions in `fwd::wire`: before a
  client's frame smoltcp gets a solicitation from that client to our
  unicast address (`ipv6_neighbor_hint`: recorded, not answered), at most
  every 20 s per neighbor (`NdHints`); unicast solicitations are
  readdressed to the target's group (`ipv6_ns_to_solicited`). Worth
  taking upstream; until then this stays the only place that knows.
- **Neighbor table bounded against /64 scans (RFC 6583):** per interface
  a cap on incomplete entries, with the oldest dropped. Counter
  `neigh_incomplete_drops`.
- **ULA** per network (decided 2026-11-20): the /48 is `fd` + 40 bits of
  SHA-256 over a label and the WAN MAC (`config::ula_prefix`; RFC 4193
  §3.2 allows any good source), so it stays the same across reboots
  without a store write at boot; `ipv6.ula_prefix` sets it instead.
  Network `i` (config order) gets `<ula>:<i>::/64`, the router `::1`. Kept
  alongside the global prefix, so local names and the web interface
  survive a prefix change or WAN loss.
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
- ✅ **IPv6CP offer logged** (2026-11-20, QEMU): `proto-pppoe` counts the
  peer's IPv6CP Configure-Requests (`Client::ipv6cp_requests`) and reports
  the first of a session as `Event::PeerOffersIpv6` (raw options), still
  answering with a Protocol-Reject. The kernel logs `the access
  concentrator offers IPv6 (IPv6CP, interface id …); rejected until M7`;
  `/api/status` `pppoe.ipv6cp_offered`, a WAN page row. Lab: `LAB_PPPOE=pap`
  checks the log line; negative control `LAB_PPPOE_IPV6=0` (the ISP's pppd
  gets `noipv6`: pppd 2.5 runs IPv6CP even without `+ipv6`). **On the apu4
  after the soak run ends (2026-11-22)**: it shows the real AC's interface
  identifier. The prefix size is only learned in step 4 (PD over the
  session).
- ✅ **Lab PD server** (2026-11-20): Kea 3.0.3, pinned
  (`fetch-alpine.sh kea`). Checked in a throwaway VM (Alpine virt kernel,
  veth pair across two network namespaces, dhcpcd 10.5.2 as the client):
  Solicit → Advertise → Request → Reply, `2001:db8:100::/56` delegated
  from a `/48` pool, DUID-LL. Lab notes: busybox `ip link add … type veth
  peer name X` ignores the peer name (it becomes `veth0`, so rename it);
  Kea needs `service-sockets-max-retries` when it starts before the link
  is up; `memfile` with `persist: false`. libssl3/libcrypto3 moved to
  3.5.9-r1 at the same time (r0 left the mirror; PPPoE and DoT labs pass).
- ✅ smoltcp features `iface-max-addr-count-4`,
  `iface-max-multicast-group-count-8` (2026-11-20): `.text` +556 B
  (aarch64) / +1392 B (x86_64), heap in use after boot unchanged
  (5 246 696 B, release, aarch64); smoke (both arches) and lab pass.

### Step 1: router IPv6 on the LAN, no forwarding
✅ in QEMU (2026-11-20). What was built differs from the plan below in
places: the WAN gets no link-local address yet (step 3 needs it, PPPoE
gets one from IPv6CP in step 4); the subnet id is the network's place in
the config, not its slot; RS frames are not taken out of the router
stack's input but noticed there; the IPv6 input filter and the smoltcp
ND help (§2) were added. Known gaps: a client asking DNS from a
link-local source gets no UDP answer (the reply's network is found from
the client's ULA /64); a client's first query in its first second can
fail while its SLAAC address is still tentative (the lab waits for DAD).

- Link-local addresses (EUI-64 from the port MAC) on every network's
  link and a ULA /64 per network, applied live like IPv4
  (`stack::set_host_addrs`, `Datapath::apply`).
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
- Done (2026-11-20): `LAB_IPV6=1 [LAB_GUEST=1] scripts/lab-test.sh`, 66
  checks pass on aarch64 (HVF), with `QEMU_NIC=igb`, `LEATOS_ARCH=x86_64`,
  `QEMU_SMP=4` and `QEMU_ACCEL=tcg`; `LAB_PORTS=1` too (71). Negative
  controls: `LAB_ROUTER_ARGS=ipv6=0` (the router reports no IPv6, the
  IPv6 checks fail), `LAB_GUEST_ZONE=lan` (the guest reaches the web
  interface over IPv6). The default lab (IPv6 off) passes unchanged and
  the IPv4 datapath's CPU over the load phase stays within run-to-run
  spread (dp_down 230–238 ms vs. 231 ms before). Host tests: the input
  filter (with a mutation check: accepting everything fails 4 of 6
  tests), the extension-header walk, `v6::ra` against smoltcp's parser,
  router AAAA / `ip6.arpa`, `[ipv6]` validation; the `fwd` fuzz target
  sends IPv6 to the router (never forwarded) and runs the ND helpers.
  On the way the `fwd` target found an old IPv4 NAT bug: an echo reply
  turned all-zero by the identifier rewrite got checksum 0x0000 instead
  of 0xffff (`Ipv4View::set_port` now recounts; regression test in
  `wire.rs`).

### Step 2a: conntrack core refactor (no IPv6 yet)
✅ (2026-11-20). `Conntrack<A: Addr = Ipv4Addr>` as in §2; IPv4 code
paths and hash values unchanged (a test pins the IPv4 formulas). New
host tests for IPv6 on the same table: routed connection both ways, TCP
states, clash, `lookup_live`; early drop when full; one `Budget` for
both families; the per-host limit by /64; hashes over the whole address.
- Proof:
  - all 102 `crates/fwd` tests pass unchanged; `fwd` fuzz target 10 min clean
  - `ct_bench=1` (release, HVF), 6 interleaved pairs of the kernels
    before and after, medians before → after: fill 684 → 691 ns/conn,
    scan 15 → 13 µs, 256-entry pass 73 → 75 µs, refuse 54 → 56 ns, early
    drop 909 → 904 ns; all within the pairs' spread (±10 %), except
    removing all 16 128 at once: 4599 → 4748 µs, higher in all six pairs
    (+0.3–6 %). That bulk removal never runs on the datapath (passes are
    bounded to 256), so it is recorded, not chased.
  - lab per-task CPU split, 3 interleaved pairs (debug kernel, as the lab
    builds it): dp_down 231–238 → 231–233 ms, dp_up 211–216 → 212–214 ms:
    unchanged.

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
