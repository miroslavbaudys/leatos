# mDNS across networks (design)

Status: design only (2026-11-15). Nothing below is implemented.

mDNS (RFC 6762) and DNS-SD (RFC 6763) are link-local: queries and
announcements go to `224.0.0.251:5353` (IPv6 `ff02::fb`) with TTL 255, and
receivers ignore packets whose source is not on their own link. With more
than one network (`docs/config-v2.md`: main, guest, IoT on VLANs) a phone on
the main LAN no longer finds the printer, AirPlay speaker or Chromecast on
the IoT network. Forwarding the packets cannot fix that; the router must
receive them on one link and **send them again from its own address** on
another.

## 1. Today (verified in the code)
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
- No IPv6 in the kernel yet (M7): `ff02::fb` waits for it.
- `crates/proto-dns::wire` already reads and writes names (with
  compression) and walks records.

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
- `Reflector::on_packet(now, from_net, &[u8]) -> Vec<(to_net, Vec<u8>)>`,
  configured with the reflect rules (§5) and the router's own addresses.
- Accept only source port 5353, a valid header, opcode 0. Legacy unicast
  queries (source port ≠ 5353, RFC 6762 §6.7) are dropped in the first
  version (they would need ID mapping and a unicast reply path).
- **Filter**: a rule allows `from` → `to` for listed service types
  (`_airplay._tcp`, `_ipp._tcp`, …). A query passes if a question is
  for an allowed type (or a name below one); a response passes if it
  carries a PTR/SRV/TXT for an allowed type. Mixed messages are dropped
  whole in the first version (no rewriting).
- **QU bit cleared** on reflected questions: otherwise the responder
  unicasts to the router's address and that answer would need relaying.
- **Loops and duplicates**: packets from the router's own addresses are
  ignored; a hash of recently sent messages (about 1 s) catches a second
  reflector on a segment.
- **Rate limit**: a token bucket per source network, so a storm is not
  multiplied onto every other network.
- Counters per network: in, reflected, filtered, duplicate, rate-limited,
  malformed.
- Host tests for each point above, plus a fuzz target (M9).

## 4. Kernel
- `kernel/Cargo.toml`: smoltcp feature `multicast` (default group count
  is enough).
- `net/svc.rs`: on each LAN link that takes part, `join_multicast_group
  (224.0.0.251)` once its address is set, leave on reconfigure; never on
  the WAN. The IGMP reports smoltcp then sends keep IGMP-snooping switches
  and APs delivering the group.
- `net/services.rs`: a 5353 UDP socket per participating `Net`,
  `set_hop_limit(Some(255))`, fixed buffers from `udp_socket(..)`; `step()`
  feeds received datagrams to the `Reflector` and sends its output on the
  target networks' sockets. `Priority::Service`; the datapath is untouched.
  Reflected packets reach the LAN qdisc like any local traffic.
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
- Answers flow back along the same rule (to → from); a rule is needed
  only per direction of discovery.
- `Service::Mdns` (`allow = ["mdns"]`) and `svc::MDNS` = UDP 5353 to
  224.0.0.251: a zone with a restrictive input policy must allow it for
  its network to take part. Validation: networks exist, are not the WAN,
  and the `from`/`to` zones allow `mdns`; service names look like
  `_x._tcp` / `_x._udp`. Applied live, no trial.
- Default: no rules, nothing reflected.

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
4. **Link-local AAAA** (`fe80::`) in answers is useless on another link;
   removing it needs rewriting (with M7).
5. **Name conflicts**: probes reflected across networks make names unique
   across them, so a host may rename itself (`Name (2)`) once. Known
   reflector behaviour.

## 7. Tests
- Host tests and fuzzing in `crates/proto-mdns` (§3).
- `LAB_MDNS=1 scripts/lab-test.sh` (on top of `LAB_GUEST=1`):
  `avahi-publish` on the main LAN, `avahi-browse` on VLAN 20, in
  **separate network namespaces** (a host on both links finds the service
  directly and proves nothing). Needs avahi added to the pinned Alpine
  packages in `scripts/lab/fetch-alpine.sh`.
- Negative controls: `LAB_MDNS_RULES=0` (nothing found); a service type
  not in the rule (not found); zone without `allow = ["mdns"]` (not found,
  input drop counter rises).

## 8. Order
1. `crates/proto-mdns` reflector + tests.
2. Config schema, `Service::Mdns`, validation.
3. Kernel: smoltcp multicast, sockets, wiring, counters on `/api/status`.
4. Lab test with negative controls; web page section and CLI status.
5. On the apu4 with a real IoT VLAN.
6. Later: IPv6 (`ff02::fb`, with M7), caching proxy, legacy unicast.
