# IPv6 (M7, plan)

Status (2026-11-20): steps 0–5b done in QEMU (§3). On the apu4 against
the home ISP (IPv6 over PPPoE): IPv6CP up at once, a /60 delegated, the
ISP's RA seen, clients online over IPv6 and AAAA names for them; b3079ef
persisted there with `[ipv6] enabled` in the stored config. IPv6 bufferbloat run there: A+/A+, like IPv4. Left: the soak, whether IPv6 becomes
the default, optional stateful DHCPv6. First plan 2026-11-15 (checked at
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
✅ in QEMU (2026-11-20). As built:
- **Forwarder:** `Verdict::Forward6`; `ct6`, `routes6`, `addrs6` per shard.
- **Generic tables:** `NeighTable<P, A>` (a cap of 64 entries being
  resolved per link for IPv6) and `RouteTable<A>`.
- **Datapath:** `neigh6`, NS sending, ND snooping. `PacketMeta::next_hop`
  is a `u128`.
- **CAKE:** `mark_ce` and the ACK filter for IPv6; RAs carry the global
  /64 and a router lifetime of 1800 s once the WAN has an IPv6 default
  route.
- **Development boot arguments:** `wan6_ip=`, `wan6_gw=`, `lan6_prefix=`,
  `wan_mtu=` and `lan_antispoof=0`.
- **Status:** `/api/status` `wan_ipv6`, `networks[].ipv6_global`,
  `icmp_errors`.

Fragments moved to step 2c: later fragments are dropped as `fragment`.

Two things the lab found that host tests could not:
- **The NA Router flag.** smoltcp, a host stack, sends Neighbor
  Advertisements without the Router flag. A client that sees its default
  router's NA without it removes the router (RFC 4861 §7.2.5), so the
  client's default route vanished seconds after the RA installed it.
  `net::device` sets the flag on the router stack's NAs
  (`fwd::wire::ipv6_na_set_router`).
- **ICMPv6 errors about errors.** An ICMPv6 error is never answered with
  one (RFC 4443 §2.4 e), also when its quote is not understood. The first
  version keyed this on "related to a tracked flow".

The plan as written before:
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

### Step 2c: IPv6 fragments
✅ in QEMU (2026-11-20). `fwd::frag` keys and decisions are enums (IPv4,
IPv6). `classify` looks at an IPv6 frame only when an extension header
follows the fixed one. A first fragment needs TCP/UDP/ICMPv6 and its
whole header behind the chain, and a TCP fragment at offset 8 bytes is
refused. `forward6` records a first fragment's decision
(`Decision6`: connection, egress, next hop, class);
`Forwarder::forward_fragment` takes later ones the same way, with no
rewrite. IPv6 decisions never clash (no NAT). The datapath's park and
release flow is shared with IPv4 unchanged. `fw_frag=0` drops IPv6
fragments too. The `fwd` fuzz target sends later IPv6 fragments through
`forward_fragment`.
- Forward fragments, don't reassemble: the first fragment must carry the
  header chain through L4 (RFC 7112) and is decided like a whole packet;
  later fragments follow it via `frag`, generalised to IPv6 (32-bit ID +
  the address pair), with the same limits.
- Lab: a fragmented `ping6 -s 3000` both ways; negative control
  `LAB_ROUTER_ARGS=fw_frag=0`.

### Step 3: DHCPv6-PD on a DHCP WAN
✅ in QEMU (2026-11-20). As built:
- **`net::wan6`** runs in `svc` while IPv6 and `ipv6.dhcpv6_pd` are on and
  the WAN is Ethernet without the development boot arguments. It:
  - takes the ISP's RA (the last one the WAN received, `NdHints::take_ra`,
    parsed by `proto_dhcp::v6::ra::parse_frame`: its link-local source
    is the default router while the lifetime lasts)
  - sends up to three Router Solicitations
  - runs `proto_dhcp::v6::pd::Client` on the WAN's UDP :546
- **Applying it:** the result (`wan6::state`) feeds `config::wan6` (the
  datapath's default route) and `config::gua_router` (network `i` gets
  `<delegated>:<i>::/64`). On a change `svc` reapplies the networks the
  way a saved config does (`reapply_networks`). A saved config that
  changes the WAN mode or `[ipv6]` restarts the client.
- **When the prefix changes:** the RAs keep the old prefix deprecated for
  2 h, and the forwarder drops IPv6 connections of the old /64.
- **Default router:** a network advertises one only with an IPv6 default
  route *and* a global /64 (RFC 7084 G-4).
- **Config:** `[ipv6] dhcpv6_pd` (default on), `prefix_hint` (56).
- **Status:** `/api/status` `wan_ipv6` (`source`, `state`, `gateway`,
  `prefix`, lifetimes) and a WAN page row.
- **Not yet:** a WAN global address (IA_NA or SLAAC), keeping the last
  prefix across reboots, using the reply's DNS servers (the resolver's
  upstreams are IPv4; step 5).
- **Lab:** the ISP VM runs dnsmasq (RAs only) and Kea (prefix delegation,
  `lab-kea`, renew 10 s). `LAB_IPV6=1` checks the delegation, every
  step 2 WAN check through it, and a prefix change (`cgi-bin/pd?change`):
  new addresses, the old one deprecated, traffic through the new one.
  Negative control `LAB_IPV6_PD=0`; `LAB_IPV6=static` keeps step 2b's
  boot arguments.

The plan as written before:
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
✅ in QEMU (2026-11-20). As built:
- **`proto-pppoe`:** with `Config::ipv6` (= `ipv6.enabled`), IPv6CP
  (RFC 5072) starts with IPCP.
  - Our interface identifier is the MAC's modified EUI-64. A peer
    identifier that is zero or ours is NAKed with a suggestion; a NAK's
    suggestion is taken.
  - A rejected, Protocol-Rejected, unanswered or nak-looping IPv6CP means
    no IPv6; IPv4 stays up.
  - `Event::Ipv6Up { local, remote }` comes after `Up`; `Ipv6Down` also
    comes before `Down`. A peer's Terminate-Request is acknowledged, and
    its next request starts IPv6CP again.
  - With IPv6 off, IPv6CP is Protocol-Rejected and logged as before.
  - Fuzz target `pppoe`: IPv6CP and IPv6 frames, the event order
    checked.
- **Wire and datapath:** `SessionRx::Ipv6`, `decap_ipv6`/`encap_ipv6`. IPv6
  to the WAN goes to the access concentrator like IPv4 (no neighbor
  discovery on the session).
- **Router stack:** the IP-only interface writes 0x86DD for IPv6, and the
  WAN keeps the last RA on PPPoE too.
- **Addresses:** the WAN's link-local address is IPv6CP's (`net::wan6`
  `set_ppp_link`/`ppp_link`): smoltcp's WAN interface and
  `Forwarder::set_ll6` (`is_mine6`, ICMPv6 error source).
- **Default router:** the RA's router, else the IPv6CP peer. Many ISPs
  send RAs; pppd does not.
- **Prefix delegation:** `net::wan6` runs while IPv6CP is up (started and
  stopped by `svc`, the networks reapplied). Router Solicitations carry
  no link-layer option on PPP.
- **Status:** `/api/status` `pppoe.ipv6` (`local`, `peer`).
- **Lab:** `LAB_PPPOE=pap|chap|none LAB_IPV6=1`.
  - The ISP's pppd `ipv6-up` routes 2001:db8:100::/48 and
    2001:db8:200::/48 over `ppp0` and starts Kea there. It first gives
    pppd's link-local address no peer: musl's `getifaddrs` would report
    the peer's address as ours, and Kea would bind to the router's.
  - Checks: the router's IPv6CP line, the delegation and every WAN check
    over the session (Packet Too Big at the session's 1492), the prefix
    change, and IPv6 back after the ISP ends the session.
  - Negative controls: `LAB_PPPOE_IPV6=0` (pppd `noipv6`),
    `LAB_IPV6_PD=0`.

The plan as written before:
- `proto-pppoe`: IPv6CP (interface identifier negotiation, link-local),
  no more Protocol-Reject for it. `Session` carries the IPv6 state.
- `wire`/datapath: classify/decap/encap for PPP 0x0057 ↔ EtherType 0x86DD.
- RA and DHCPv6-PD over the session (the WAN interface is `Medium::Ip`: RS
  to ff02::2, RA from the AC's link-local).
- Lab: `LAB_PPPOE=pap` with `+ipv6` on the ISP and the PD server behind
  `pppd`. Negative control: `pppoe-server` without `+ipv6`.
- apu4 (after step 0's answer): real ISP, PD, a client on each home
  network, IoT zone without internet over IPv6 too.

### Step 5a: the home line's needs (done in QEMU 2026-11-20)
After step 4 ran on the apu4 against the home ISP (2026-11-20: IPv6CP up
at once, a /60 delegated, no RA seen yet), these were added:
- **The WAN's own global address:** `::1` in the delegated prefix's last
  /64 (`config::wan_address6`; no network gets that /64, so a /60 leaves
  15 for networks). It is a /128 in the forwarder and smoltcp, with a
  default IPv6 route in smoltcp, so the router can send its own IPv6
  traffic. Many ISPs give no IA_NA.
- **The ISP's IPv6 DNS servers** (from the delegation's reply) come after
  the lease's IPv4 ones while the WAN has that address. The resolver's
  upstreams are `IpAddr`; queries start with the first server and rotate
  on timeouts, so IPv6 is the fallback. `dns.upstreams` and DoT stay
  IPv4.
- **The prefix across reboots:** the lease record (version 2,
  `persist::encode_v2`) keeps the last delegated prefix; the Solicit asks
  for it again (`PdConfig::last`). A kernel that reads only version 1
  takes the other slot's older record. Boot argument `pd_keep=0`: not
  asked for (the lab's negative control).
- **Status:** `wan_ipv6` `router_from` (`ra` or `ipv6cp`), `addr`, `dns`;
  WAN page row, CLI `status` line `wan ipv6`.
- The boot line "under QEMU" only on virtual machines.
- **Lab (`LAB_IPV6=1`):**
  - WAN address and router source checked in status.
  - `v6dns.isp.example` resolved through the ISP's IPv6-only resolver
    (2001:db8:ffff::53, handed out by Kea) with its IPv4 DNS stopped;
    negative control `LAB_IPV6_DNS6=0`.
  - With a store (`LAB_GUEST=1`): the router reboots while Kea forgets
    every lease and allocates at random (`cgi-bin/pd?fresh`), and the
    same prefix comes back; negative control
    `LAB_ROUTER_ARGS=pd_keep=0`.
  - The router-side checks read its log up to that reboot.

### Step 5b: IPv6 in the rest of the config (done in QEMU 2026-11-20)
- **Firewall rules:** `src`/`dst` take IPv6 prefixes; `dst_iid` matches an
  interface identifier under any prefix (a pinhole that survives
  renumbering). A rule with IPv4 addresses is IPv4-only, one with IPv6
  ones IPv6-only, one with neither for both (`fwd::Rule6`). The web
  firewall page has an "IPv6 host ID" column. Lab: `v6-pinhole` (ISP →
  the client's :8087 open, another identifier closed, open again under
  the new prefix); negative control `LAB_IPV6_PINHOLE=0`.
- **AAAA names:** the datapath notes global/ULA neighbors from neighbor
  discovery per link (`LinkShared::neigh6`, 128, no allocation per
  packet). The services join them by MAC with leases and reservations
  (`Zone::add_host6_in`, AAAA + ip6.arpa PTR, the A record's view;
  forgotten after 30 min unseen). Lab: `labclient.lan` AAAA global + ULA,
  PTR; hidden from the guest with views. Negative control
  `dns_aaaa=0`.
- **Config addresses:** `dns.upstreams` take IPv6 servers (UDP and DoT;
  `Policy::router_tcp_peers6`); `time.ntp_servers` IPv6 literals;
  `[[route]]` with an IPv6 `dst` via a host in a network's ULA /64
  (`Forwarder::set_static_routes6`; forwarded back out to that router,
  no option 121 in IPv6; `/api/status` `routes6`). Lab: DoT to
  `[2001:db8:ffff::1]:853` (control `LAB_DOT_V6=0`), NTP from
  `2001:db8:ffff::1`, `lab-behind6` (control `LAB_ROUTES=0`).
- **mDNS:** the reflector takes IPv6 sources (link-local or the network's
  /64s) and reflects each message in its own family (`Output::v6`, to
  ff02::fb from the router's link-local address). Lab: `LAB_MDNS=1
  LAB_IPV6=1` (the copy on the LAN capture; control `LAB_MDNS_RULES=0`).

### Step 5: what is left
The rest of the step 5 plan (firewall page, mDNS on `ff02::fb`, IPv6
SNTP/DNS/DoT/routes, AAAA names) was built in 5a and 5b. Still open:
- ✅ apu4 bufferbloat run with IPv6 traffic (2026-11-20, b3079ef, PPPoE,
  CAKE at 98/18 Mbit/s, `scripts/bufferbloat.sh --ipv6` from a Mac on the
  LAN, interleaved with IPv4 runs): IPv6 A+/A+ in all 3 runs, added
  latency 0.4–0.5 ms down and 0.3–0.4 ms up, 88.2–88.4 / 15.2–16.3
  Mbit/s; IPv4 0.5 / 0.5–0.7 ms, 88.7–89.7 / 15.6–16.6 Mbit/s (one
  earlier IPv4 run: 15.2 ms down, A). The ~1 % less IPv6 throughput is the
  20 B larger header. Download max 37–43 ms in both families (slow
  start). Valid: shaper drops in both directions (WAN egress ~500,
  ingress 1300–2200 per run), no pool failures.
- apu4: `mac-internet.sh` without `--ipv4-only`, 72 h soak with IPv6 on
  (also shows whether IPv6 multicast puts pressure on `local_rx` and the
  packet pool, §4).
- IPv6 on by default (`[ipv6] enabled`): §2 says on once step 4 runs on
  the apu4, which it has; not switched yet.
- Optional: stateful DHCPv6 server on the LAN (M flag).

## 4. Risks and open questions
- **Home ISP:** IPv6 over PPPoE (confirmed 2026-11-20), so step 4 is the
  one that matters at home. Steps 1–3 stay first because the lab can check
  them. The real AC (2026-11-20): IPv6CP at once, a /60 by DHCPv6-PD over
  the session, an RA, no IA_NA (the WAN address comes from the prefix,
  step 5a).
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
