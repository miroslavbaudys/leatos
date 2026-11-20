# mDNS across networks (design)

Status (2026-11-15): steps 1–3 done in QEMU: `crates/proto-mdns` (wire
format + the filtered reflector, host tests incl. mutation fuzzing), the
config (`[[mdns.reflect]]`, zone service `mdns`, validation) and the
kernel (`net/mdns.rs`, counters on `/api/status` and the CLI), with a
first lab check (`LAB_MDNS=1`, §7), and the web page section (§5).
Open: a browse test with real mDNS software, the apu4 (§8).

mDNS (RFC 6762) and DNS-SD (RFC 6763) are link-local: queries and
announcements go to `224.0.0.251:5353` (IPv6 `ff02::fb`) with TTL 255, and
receivers ignore packets whose source is not on their own link. With more
than one network (`docs/config-v2.md`: main, guest, IoT on VLANs) a phone on
the main LAN no longer finds the printer, AirPlay speaker or Chromecast on
the IoT network. Forwarding the packets cannot fix that; the router must
receive them on one link and **send them again from its own address** on
another.

## 1. Before the reflector (verified in the code, 2026-11-15)
The starting point; §3–§5 describe what changed (smoltcp `multicast`,
`svc::MDNS`, the reflector).
- `crates/fwd` `Forwarder::process`: a multicast destination counts as "to
  us" and goes to `input()`; multicast is never forwarded. Stays so.
- `input()` service mask: UDP 5353 maps to no service, so a zone with
  `input = drop` (guest) drops it (`DropReason::Input`); the main zone
  (accept) passes it to smoltcp.
- smoltcp is built without its `multicast` feature: `has_multicast_group`
  accepts only 224.0.0.1, so 224.0.0.251 is dropped there. Nothing leaks
  and nothing works.
- NICs: igb accepts all multicast (`drivers/igb.rs`); virtio-net never
  negotiates `CTRL_RX`, so QEMU delivers everything. No driver work.
- One smoltcp `Interface` + `SocketSet` per link (`net/svc.rs` `HostIf`),
  per-network service state in `net/services.rs` (`Net`): an mDNS socket
  per network fits the existing pattern.
- IPv6 (since 2026-11-20, docs/ipv6.md step 5b): with `ipv6` on the router
  also joins `ff02::fb`; a message reflects in the family it came in on, from
  the router's link-local address; IPv6 sources must be link-local or in the
  network's /64s.
- `crates/proto-dns::wire` cannot be reused for names: its `read_name`
  rejects non-ASCII bytes and dots inside labels, and DNS-SD instance
  names (`Living Room._airplay._tcp.local`) need both. `proto-mdns` keeps
  names as raw labels.

## 2. Reflector first, proxy later
| | Filtered reflector | Caching proxy (gateway) |
|---|---|---|
| Mechanism | parse, filter by service type, send again on the allowed networks from the router's address there | cache records per network, answer queries from the cache, announce selected services |
| State | short duplicate cache | records with TTLs, goodbyes (TTL 0), cache-flush bit |
| Multicast on Wi-Fi | grows with the number of networks | lower |
| Effort | 1–2 weeks | 4–6 weeks |
| Risk | name conflicts across networks (`MacBook (2)`) | conflict probing is subtle |

Build the reflector; keep the crate's interface so a cache can be added
behind it without changing the kernel side.

## 3. `crates/proto-mdns` (sans-IO, `no_std`, `forbid(unsafe_code)`)
- `wire::Message`: a whole message parsed into owned parts (names as raw
  labels, names inside PTR/CNAME/NS/MX/SRV/NSEC rdata decompressed) and
  written back with compression (never inside NSEC). Pointers must point
  strictly backwards (no loops); counts are checked against the length
  before allocating.
- `Reflector::handle(now_ms, from, src, &[u8]) -> Vec<Output>`, configured
  with `Config { nets: [Option<Net { addr, prefix_len }>], rules }`;
  `stats(net)`, `takes_part(net)`, `reconfigure` (keeps counters, forgets
  learned hosts).
- Accept only source port 5353, a valid header, opcode 0. Legacy unicast
  queries (source port ≠ 5353, RFC 6762 §6.7) are dropped in the first
  version (they would need ID mapping and a unicast reply path).
- **Filter and rebuild**: a rule allows `from` → `to` for listed service
  types (`_airplay._tcp`, `_ipp._tcp`, …). Devices announce many services
  in one message, so each copy is **rebuilt** with only what is allowed
  for its target network: names under an allowed type (instances,
  subtypes, the browse name), and names of hosts learned from allowed SRV
  records (per source network and type, for the SRV's TTL, at most 75 min,
  128 entries; a goodbye (TTL 0) teaches nothing). A/AAAA records with
  link-local addresses (169.254/16, fe80::/10) are always removed. A
  response with no allowed answer, or a query with no allowed question,
  is not sent. `_services._dns-sd._udp` (list everything) never passes.
- **QU bit cleared** on reflected questions: otherwise the responder
  unicasts to the router's address and that answer would need relaying.
  Queries lose their authority section (probes become plain questions, so
  a name in use on the other network is still defended) and additional
  records; known answers are filtered like records.
- **Loops and duplicates**: packets from the router's own addresses are
  ignored; a hash of recently sent messages (about 1 s) catches a second
  reflector on a segment.
- **Rate limit**: a token bucket per source network (50 messages/s, burst
  100), so a storm is not multiplied onto every other network.
- Copies over 1472 bytes (one unfragmented datagram at MTU 1500) are
  dropped and counted.
- Counters per network: received, sent, filtered, duplicate,
  rate-limited, malformed, foreign (wrong port, off-subnet, the router),
  oversize.
- Host tests for each point above, plus a fuzz target (M9).

## 4. Kernel (`kernel/src/net/mdns.rs`)
- `kernel/Cargo.toml`: smoltcp feature `multicast` (the default group
  count, 4 per interface, is enough: one group).
- `Mdns`, owned by `LanServices` like `Ntp`: for each network a rule
  involves (`Reflector::takes_part`), `join_multicast_group(224.0.0.251)`
  on that link's interface and a UDP socket on 5353 (16 datagrams, 24 KiB
  each way, `set_hop_limit(Some(255))`); never on the WAN. Network `k` of
  `config::networks` is reflector network `k`; `config::mdns_rules()`
  maps the enabled entries to those indices.
- `reconfigure` (boot and every live config apply): memberships that
  stay (same interface, same VID) are kept; the others are left at once
  (the leave goes out on the tag still in effect); new or retagged ones
  are joined only once the datapath shows the link active with the
  network's VID (`step`, rechecked every 20 ms while one waits). The
  services task runs ahead of the datapath after a live change: a report
  queued before `Datapath::apply` would carry the link's old tag (none,
  for a network just added) and never reach the network. This was caught
  by `LAB_MDNS=1 LAB_GUEST_LIVE=1` (no IGMP join on the live-added guest
  VLAN). Sockets are closed and reopened. Counters stay while the network
  names stay the same.
- `step` (end of `LanServices::step`): each received datagram goes to
  `Reflector::handle`; its copies are sent to `224.0.0.251:5353` on the
  target networks' sockets (smoltcp picks the source address and the
  multicast MAC). A full socket buffer drops (bounded). `Priority::Service`;
  the datapath is untouched (the forwarder passes 5353 up when the zone
  allows `mdns`); reflected packets reach the LAN qdisc like any local
  traffic.
- smoltcp sends the IGMP v2 report when the group is joined on an
  interface that has its address; it answers IGMP queries. The guest
  zone's input policy drops IGMP queries (no service bit for IGMP); this
  matters only for snooping switches that do not flood 224.0.0.0/24
  (RFC 4541 says they must).
- Status: `GET /api/status` `"mdns":[{network, received, sent, filtered,
  duplicate, rate_limited, malformed, foreign, oversize}]` (networks taking
  part), the CLI `status` an `mdns :` line per network.
- Ports: 5353 is a server socket like 53; the ≥ 60000 rule for router
  client sockets does not apply.

## 5. Config (`crates/config`) and firewall (`crates/fwd`)
```toml
[[mdns.reflect]]
name = "iot-to-lan"
from = "iot"
to = ["lan"]
services = ["_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_ipp._tcp"]
```
- `from` and `to` are **network** names (reflection is per link), not
  zones. Answers flow back along the same rule; a rule is needed only per
  direction of discovery. `enabled = false` keeps an entry without it
  taking effect. CLI paths by name (`mdns.reflect.iot-to-lan.services`).
- `fwd` maps UDP 5353 to `svc::MDNS` for the zone input policy.
- `Service::Mdns` (`allow = ["mdns"]`) and `svc::MDNS` = UDP 5353: a
  zone with a restrictive input policy must allow it for its network to
  take part. Validation (paths like `mdns.reflect.iot-to-lan.to[1]`):
  names are keys and unique, at most 32 entries; `from` and every `to`
  are existing networks whose zone accepts input or allows `mdns`; `to`
  is non-empty, without `from` or repeats; `services` non-empty, each
  parsed by `proto_mdns::ServiceType::parse`, no repeats (any case); at
  most 128 distinct types over the enabled entries. A config with
  `[mdns]` needs schema version 2. Applied live, no trial.
- Default: no rules, nothing reflected.
- Web page (Firewall, "mDNS across networks"): a row per entry (on, name,
  "Services on" = `from`, "Discoverable on" = `to` as checkboxes of the
  networks, service types with presets: AirPlay, Chromecast, printers,
  scanners, HomeKit, Spotify Connect, file shares), the counters per
  network from `/api/status`. Before saving it warns about a zone that
  does not allow `mdns` (the router would refuse) and about clients that
  could not open connections to the devices found (no `forward_to`, no
  accept rule); network renames update the menus.

## 6. Pitfalls
1. **Discovery is not reachability.** Answers carry the device's real
   (routed, not NATed) address; the connection still needs `forward_to`
   or a `[[firewall.rule]]` (main → IoT). AirPlay 2 and some printers also
   connect back to the client. The web page warns when a reflect rule has
   no matching forward path.
2. **Privacy**: reflecting guest → main exposes main's host names. Off by
   default; only what a rule names.
3. **Size**: mDNS allows up to 9000 B; without IPv4 reassembly in smoltcp
   fragmented messages are lost. Accepted (≤ MTU), counted as malformed.
4. **Link-local addresses** in answers are useless on another link; the
   rebuild removes them (IPv6 transport: `ff02::fb`, docs/ipv6.md step 5b).
5. **Name conflicts**: probes reflected across networks make names unique
   across them, so a host may rename itself (`Name (2)`) once. Known
   reflector behaviour.

## 7. Tests
- Host tests and fuzzing in `crates/proto-mdns` (§3); config validation
  in `crates/config`; the zone input bit in `crates/fwd`.
- ✅ `LAB_MDNS=1 scripts/lab-test.sh` (implies `LAB_GUEST=1`): the guest
  zone allows `mdns`, rule `guest-printers` reflects `_ipp._tcp` guest →
  lan. The client sends a crafted announcement (`_ipp._tcp` + `_ssh._tcp`)
  from 5353 on VLAN 20 (busybox `nc -u`); checks: the router's counters
  (guest received +1, lan sent +1), and on the LAN capture (QEMU
  `filter-dump`, decoded by the host's tcpdump): the copy from
  192.168.1.1 to 224.0.0.251 with TTL 255 carrying `_ipp` and not `_ssh`,
  and the router's IGMP reports for 224.0.0.251 on both networks.
  Negative control `LAB_MDNS_RULES=0` (the rule disabled: all three
  fail). Combines with `LAB_GUEST_LIVE=1` (added live) and
  `LEATOS_ARCH=x86_64`.
- Open: a browse test with real mDNS software (`avahi-publish` on one
  network, `avahi-browse` on the other, in **separate network
  namespaces**: a host on both links finds the service directly and
  proves nothing; avahi in the pinned Alpine packages).

## 8. Order
1. ✅ `crates/proto-mdns` reflector + tests.
2. ✅ Config schema, `Service::Mdns`, validation.
3. ✅ Kernel: smoltcp multicast, sockets, wiring, counters on
   `/api/status` and the CLI; first lab check (§7).
4. ✅ Web page section (reflect entries, warnings, counters). Open: a
   browse test with avahi (§7).
5. On the apu4 with a real IoT VLAN.
6. Later: caching proxy, legacy unicast (IPv6 `ff02::fb` done with M7 step 5b).
