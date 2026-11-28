# crates/ in detail

All `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`, sans-IO (bytes and `now` in, bytes and
events out), host-tested with `cargo test`. Fuzz targets in `fuzz/` (fuzz/README.md).

## Forwarding: `fwd`

- `wire`: packet views; `Ipv6View` (bounded extension-header walk); `SplitPlan` (RFC 791
  fragmentation of non-DF packets above the egress MTU: `Verdict::Forward` `split`, cut by the
  datapath).
- IPv6: `process6`/`input6` (the zone input policy, ND hop limit 255, rules without addresses);
  `forward6`: untranslated, `ct6`, zones and rules without addresses for new flows, anti-spoofing
  both ways, ICMPv6 Time Exceeded / Packet Too Big, MSS clamp, `Verdict::Forward6`; fragments via
  `frag` like IPv4 (`Decision6`, no rewrite); `ipv6` off = dropped.
- `route`: connected, default and static routes (`Forwarder::set_static_routes`), active while a
  connected subnet holds the router; routed subnets count as inside.
- `nd`: the router's link layer for its own addresses (docs/lan-neighbors.md; the datapath's
  `Datapath::link_layer` on every link but PPPoE): `nd::answer` gives the ARP reply / NA (R, S, O
  flags; DAD defended to all nodes;
  unicast NS answered) and conflicts (another MAC claiming or probing for our address); RFC 4861
  §7.1.1 checks; `Config` switches for the lab's negative controls (`nd_unicast=0`,
  `na_router=0`). Tests parse every reply with smoltcp.
- `udp`: the router's own UDP datagrams, `build4` (with a TTL) / `parse4`, `build6` / `parse6`
  (all lengths and the checksums, extension headers skipped, fragments refused; the kernel's
  `net::local`, docs/local-stack.md steps 2b–3); tested against smoltcp's parser.
  `port_unreachable` only for the lab control `udp_unbound_drop=0`.
- `tcp`: the IP layer of the router's own TCP (docs/own-tcp.md): `frame` puts the IPv4 / IPv6
  header around a `proto_tcp` segment, `parse` checks a frame for the router down to its segment
  (header checksum, no fragments, unicast ends); tested against smoltcp's parsers.
- `local::LocalLink::source4` / `source6`: the router's source address (an RFC 6724 subset).
- `echo`: ICMP / ICMPv6 echo for the router (parse, `reply`, `build`); `mcast`: IGMPv2 report /
  leave, MLDv2 report, IGMP / MLD query parse (docs/local-stack.md step 4). Both against
  smoltcp's parsers where it has them; the `fwd` fuzz target runs them on every frame.
- The forwarder passes IGMP membership queries from networks (not the WAN) to the router.
- `local`: the next hop of the router's own packets on a link without a link layer
  (docs/lan-neighbors.md step 2): `LocalLink::next_hop` = a fixed MAC (broadcast, directed
  broadcast, IPv4 / IPv6 multicast mapping) or a neighbor (on the link, or a `[[route]]`'s
  gateway), else `NoRoute` (no default route on a LAN).
- `neigh`: entries in use are probed at the end of their 300 s lifetime and kept meanwhile (RFC 4861
  PROBE); unused ones age out. Drops are drop reason `neighbor`, probes `/api/status`
  `neigh_probes`.
- `conntrack` with NAPT, generic over the address family: `Conntrack<A: Addr = Ipv4Addr>`.
  - NAPT/DNAT in `impl Conntrack<Ipv4Addr>`; IPv6 routed only, via `create_routed`.
  - One `Budget` shared by the shards and families; per-host limit `Budget::with_host_limit` (drop
    reason `host-limit`), by /64 for IPv6.
  - A full table or a shard's NAT ports taken early-drops a sampled not-assured connection
    (`EVICT_SCAN`, `early_drops`).
  - TCP established only after the handshake's last ACK.
  - `expire_some` bounded per pass; expired entries invisible via `lookup_live`.
- `frag`: IP fragments without reassembly, IPv4 and IPv6 (`Key`/`Decision` enums): the first
  fragment's decision per datagram in a `Table` per ingress port, later fragments via
  `Forwarder::forward_fragment`, early ones held ≤ 16 / 250 ms; tiny and offset-1 TCP fragments
  refused.
- `forwarder` pipeline, shardable (`shard_of`, `Forwarder::new_shard`):
  - Zone firewall `Policy`: forward bitmask + input service mask per zone + ordered `Rule`s (first
    match, `rule_hits`; `Action::Reject` answers with a RST / ICMP port unreachable,
    rate-limited).
  - `Forwarder::recheck` after a new policy: tracked connections it refuses are removed
    (`revoked`).
  - WAN ingress anti-spoofing: sources in our networks or loopback are `DropReason::Spoofed`.
  - Replies to the router's own clients (ports ≥ 60000, UDP 68, ICMP non-echo) always pass
    (`ROUTER_CLIENT_PORTS`, `ClientPorts`).
  - Port forwards (`PortForward`, DNAT via `Conntrack::create_dnat`, hairpin, `forward_hits`,
    `ShardHints`); the target's own connections out keep the forwarded WAN port
    (`Conntrack::create_from`); tuple collisions are drop reason `clash`.
  - Redirects (`Redirect`): the networks' connections to outside servers or to router ports it does
    not serve (`router_serves`) DNAT'd to a device inside, SNAT on the target's own network,
    `redirect_hits`, target-endpoint shard.
  - `Role::Wan` = masquerade only. Per-interface MTU: ICMP frag-needed for DF, else dropped. MSS
    clamp on SYNs.

## Queues: `qdisc`

`Qdisc` trait, `BFifo`; `codel` = RFC 8289 with ECN; `fq_codel` = RFC 8290 flow queueing (DRR,
new-flows list, fattest-flow overflow drop, slab storage); `cake` = the CAKE core on top (8-way
set-associative hashing, host isolation from pre-NAT host hashes, COBALT = CoDel + BLUE,
conservative ACK filter `ack_filter`); `testutil` = shared simulation with Reno-like, unresponsive
and sparse senders. How the kernel uses it: kernel/src/net/CLAUDE.md.

## Protocols

- `proto-dhcp`:
  - DHCPv4 server. Against pool exhaustion: DECLINE only for the client's own address, a full
    pool's oldest unrequested offer taken over, leases indexed by address. `Stats` → `/api/status`
    `networks[].dhcp_stats`. `persist` lease snapshots + `Server::restore`. Option 121/249
    classless routes when asked.
  - `v6::ra` Router Advertisements: SLAAC prefixes, RDNSS, DNSSL, MTU, router lifetime, RFC 4861
    timers, solicited ≥ 3 s apart, prefixes that leave deprecated for 2 h, `retire`, `parse_frame`
    for upstream RAs; tested against smoltcp's parser.
  - `v4::client` DHCPv4 client (RFC 2131: DISCOVER/REQUEST, INIT-REBOOT with `Config::last`,
    renew unicast at T1, rebind at T2, NAK backoff, lease checks, option 26 MTU); returns
    `Transmit` with source and destination; fuzz target `dhcp_client`. The WAN's client
    (`net::wan4`, docs/local-stack.md step 2b).
  - `v6::pd` DHCPv6 prefix delegation client (RFC 8415: Solicit/Advertise/Request/Reply,
    Renew/Rebind, DUID-LL, retransmission with jitter); fuzz target `dhcp6`.
- `proto-dns`: the forwarder: zone → cache (TTL aging, prefetch, serve-stale) → upstream.
  - The zone also answers `router.<domain>` AAAA (`add_router6`) and `ip6.arpa` of the networks'
    /64s.
  - Per-network answers (`View`): records carry the networks that see them; `handle_query_in` takes
    the asking network (the DNS socket a query came in on). Hidden names NXDOMAIN (counter
    `hidden`); overrides of public names.
  - Extended DNS Errors, RFC 8914: stale 3/19, unreachable 22, rebind 15. Rebind protection on A
    and AAAA.
  - Answers cut to the client's UDP size with TC, whole over TCP (`handle_query_tcp`,
    `Action::Reply` `tcp`). Upstream queries always EDNS 1232; OPT stripped for clients without
    EDNS.
  - Hits per `[[dns.host]]` entry (`host_hits`, records tagged by `Zone::add_host_in` /
    `add_host_override`; `/api/status` `dns.hosts`, the Hits column on the DNS page, kept across
    config saves by name + address). Counters in `/api/status` `dns`.
- `proto-dot`: DNS over TLS client: rustls 0.23 without std (unbuffered API), own RustCrypto
  provider (TLS 1.3 + 1.2 ECDHE/AEAD, X25519/P-256/P-384, ECDSA/Ed25519/RSA), Mozilla roots
  (`webpki-roots`) + `dns.tls_ca`; dates checked at the leaf's notBefore (≥ build time) until the
  clock is known. Tested against a rustls/ring server.
- `proto-pppoe`: PPPoE client: discovery, LCP + echo keepalive, PAP, CHAP-MD5 (`md-5`), IPCP + DNS,
  backoff.
  - IPv6CP with `Config::ipv6` (RFC 5072: EUI-64 interface identifiers, `Event::Ipv6Up`/
    `Ipv6Down`, failure keeps IPv4); else offers counted and rejected (`Event::PeerOffersIpv6`).
  - RFC 4638 MTU 1500 with a full-size echo check and fallback to 1492.
  - `wire` encap/decap (IPv4 and IPv6) for the datapath. Tested against a simulated AC.
- `proto-sntp`: SNTP client: packet checks, burst + backoff state machine.
- `proto-mdns`: mDNS across networks: whole-message parse/rebuild with raw labels and compression,
  filtered `Reflector` with rules from → to per service type, hosts learned from SRV, link-local
  addresses removed, QU cleared, echo/rate/source checks; docs/mdns.md.
- `proto-tcp`: the router's own TCP (docs/own-tcp.md; the kernel has no host stack): `Socket`
  with smoltcp's API shape (listen / connect, one socket per connection, no backlog), `Tcp` = the
  sockets of one link (demultiplexing, RST for segments nobody takes, `next_deadline`), `wire`
  (header, MSS option, checksum). RFC 9293 states, RFC 6298 RTO, fast retransmit, user timeout,
  bounded out-of-order ranges, zero-window probes, RFC 5961 (exact-sequence RST / SYN, challenge
  ACKs ≤ 10/s), RFC 6528 ISNs (SipHash). No window scaling, SACK, Nagle, congestion control.
  Tests on a lossy simulated link and against smoltcp's TCP (dev-dependency); fuzz target `tcp`.
- `proto-http`: incremental HTTP/1.1 parser with streaming bodies, Basic auth, JSON escaping,
  `check_browser_origin`.

## System

- `auth`: PBKDF2-SHA256 password hashes (stored ones ≤ `MAX_ITERATIONS` = 100000), SHA-256 entropy
  `Pool`, login `Sessions`, verify `Cache`, login `Throttle` per source + PBKDF2 budget.
- `boot-image`: ELF64 validation/flattening, Multiboot2 header check + boot-info builder, CRC-32.
- `install-image`: the installer's image (docs/install.md §3.3): `build` (non-zero sector runs,
  merged across short gaps) / `parse` (header, ascending disjoint extents, SHA-256 over all but
  the hash field) / `Image::plan` (every sector of the image once, gaps as zeros, then the
  target's last 33 sectors); fuzz target `install_image`.
- `cli`: line editor + command parser.
- `config-store`: the power-fail-safe store partition: MBR lookup, store header with areas and a
  store ID (`Layout::id`, bytes 280..288, 0 = none; no layout version bump), A/B
  record slots, write plans, trial flags (docs/config-and-storage.md). Magics `RRSTORE1`/`RREC` keep
  the old name.
- `config`: the `config.toml` schema v2 (docs/config-v2.md) via `toml` + serde; JSON via
  `serde_json` for the web form; defaults, `deny_unknown_fields`, cross-field validation with paths,
  `needs_trial`.
  - Sections: `[[network]]`, `[[zone]]`, `[[firewall.rule]]`, `[[firewall.forward]]`,
    `[[firewall.redirect]]`, `[[mdns.reflect]]` (from/to networks, service types; zone service
    `mdns`).
  - `dhcp.range` at most 4096 addresses (`MAX_DHCP_POOL`).
  - `[[route]]`: static routes via a router on a network or the WAN subnet (DHCP option 121); IPv6
    routes via a host in a network's ULA /64. `Route::v4/v6`, `Config::route_via`,
    `network_routes`.
  - `[dns]`: `domain` (default) + per-network `domain`/`[[dns.host]]`; `upstreams`
    (`ip[:port][#name]`, else the WAN lease's) + `tls` (strict DoT) + `tls_ca`. `views` +
    `[[dns.host]] networks` = split horizon (docs/dns-views.md): `names.rs`
    `Config::name_visibility` = who resolves which address's names from zones, `forward_to` and
    accept rules; `local_hosts` = records as domain + label or overrides of public names; refused on
    save, `leatstore put` and load.
  - `[ipv6]`: `enabled` (default on; the section is always written, so an older kernel after a
    rollback does not read it as off), `ula_prefix`, `dhcpv6_pd`, `prefix_hint`. The kernel's
    `config::ula_prefix` derives the /48 from the WAN MAC; network `i` gets `<ula>:<i>::/64` and
    `<delegated>:<i>::/64`.
  - `[wan]`: VLAN, `mode` = dhcp/pppoe/static, `[wan.pppoe]`, `[wan.static]` (kernel
    `config::wan_link`, `net/svc.rs` `configure_static`, applied live); written only when set. The
    PPPoE password is a secret (`without_secrets`/`keep_secrets`: never shown by API/CLI, kept when
    a save leaves it out).
  - Version 1 (`[lan]`) is refused with a hint (`Error::OldVersion`); record header version =
    `VERSION`.
  - `unsupported()` lists what the kernel does not implement yet (today: a network on several ports
    (bridge), port names other than lan0–lan2).
  - CLI paths by name: `network.guest.vlan`; `lan.` = the first network.
