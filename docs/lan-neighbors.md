# LAN neighbors: one table per link (plan)

Status (2026-11-22): step 0 done except the upstream report (lab check `LAB_ND_FLOOD=1` for its
WAN fix); step 1 done (`fwd::nd`, host tests, `fwd` fuzz target); step 2 done (`fwd::local`,
`Datapath::send_local` / `set_local_link`, not called yet). Nothing is deployed before the apu4 soak ends (2026-11-25).

## 1. The problem

On every link the router has **two neighbor tables**:

- `fwd::neigh` in the datapath (`Datapath::neigh` / `neigh6`, per link): RFC 4861-style entries,
  300 s lifetime, entries in use probed instead of dropped, sized for the whole LAN, a tiny bounded
  pending queue (`MAX_PENDING` = 3 per neighbor, docs/bufferbloat-cake.md §3.1). Forwarded
  packets use it.
- smoltcp's cache in each `HostIf` interface (`svc`): what the router's own packets use (DNS and
  DHCP answers, pings, the web interface, mDNS, TCP to clients).

smoltcp 0.14 is a host stack, and as the router's stack on a busy LAN its cache needs these
workarounds (all checked in its source):

| # | smoltcp 0.14 | Workaround today |
|---|---|---|
| 1 | Learns IPv4 neighbors only from ARP aimed at it; traffic refreshes only entries it still has (upstream removed learning from traffic on purpose: a broadcast had poisoned its cache) | ARP replies synthesised from clients' frames (`fwd::wire::ipv4_neighbor_hint`, `NdHints`, `arp_hints=`) |
| 2 | The same for IPv6 (ND only) | NS synthesised from clients' frames (`ipv6_neighbor_hint`) |
| 3 | Answers an NS only when it went to the solicited-node group (`iface/interface/ipv6.rs:490`); unicast reachability probes go unanswered (RFC 4861 §7.2.4) | unicast NS readdressed to the group (`ipv6_ns_to_solicited`) |
| 4 | One request rate limit for the whole cache (`silent_until`, 1 s); the packet that needed the lookup is dropped | 1 and 2 avoid lookups |
| 5 | 8 entries by default | feature `neigh-cache-256` |
| 6 | `update_ip_addrs` empties the cache (`iface/interface/mod.rs:400`) | 1 and 2 refill it |
| 7 | NAs say "not a router": clients drop it as their default router | R flag patched into outgoing NAs (`ipv6_na_set_router`) |

They work (`LAB_NEIGH=1` with negative controls), but every neighbor change has to think about
both tables, and the synthesised frames rely on smoltcp internals that are not its API.

## 2. The change

**LAN links run smoltcp on `Medium::Ip`; the datapath does their link layer.** That is what the
PPPoE WAN already does (`device.rs`: strip the Ethernet header on RX, put one in front on TX).

- **RX** (svc's `PortDevice::receive` on a LAN link): smoltcp gets the IP packet (`skip` = 14;
  the VLAN tag is already gone). ARP never reaches smoltcp on a LAN link; neither do NS / NA.
  RS are still noted (`LinkShared::rs_seen`) before the frame is dropped.
- **TX** (`TxToken::consume` on a LAN link): smoltcp writes an IP packet after 14 bytes of room;
  the device sets the EtherType by the IP version and hands it to a new
  `Datapath::send_local(link, pkt, now, touched)`, instead of enqueueing a finished frame. svc
  already holds the `SharedDatapath` (`&'static`) through `stack`.
- **`send_local`** picks the destination MAC:
  - IPv4 limited or directed broadcast → `ff:ff:ff:ff:ff:ff` (DHCP server replies are always
    broadcast: `services.rs:936`);
  - IPv4 multicast → `01:00:5e` + low 23 bits; IPv6 multicast → `33:33` + low 32 bits (mDNS,
    IGMP / MLD reports smoltcp sends for its groups);
  - unicast: the next hop, i.e. the destination if it is on the link, else the gateway of a
    `[[route]]` on that link (from a per-link route snapshot the datapath keeps, so the svc core
    does not take forwarder shard locks), then `to_next_hop` / `to_next_hop6`, the same calls
    forwarded packets use: `Ready` → `send_resolved` into the qdisc; `Queued` → it waits in
    `fwd::neigh`'s pending queue (the existing, bounded exception to "only the qdisc holds
    packets"; no new FIFO) and the ARP request / NS goes out; released by `snoop_arp` /
    `snoop_nd` in the direction task that receives the answer.
  - No route: dropped and counted (`local_no_route`).
  - Lock order stays NIC → forwarder shard → neighbor table → qdisc (send_local takes only the last
    two). svc wakes the datapath as today (`queued` → `dp_kick`).
- **ARP / ND responder in the datapath** (`rx_batch`, LAN links only, where `snoop_arp` /
  `snoop_nd` already run): sans-IO builders in `crates/fwd` (`wire::build_arp_reply`,
  `wire::build_na`) and a `fwd::nd` decision function, host-tested and fuzzed.
  - ARP request for a router address on that link from an in-subnet sender → ARP reply. An ARP
    probe (sender 0.0.0.0, RFC 5227) for the router's address is answered too (defends it).
  - NS (hop limit 255, valid options) whose target is one of the router's addresses on the link
    (link-local, ULA, GUA), to the solicited-node group **or unicast** → NA with R = 1, S = 1,
    O = 1 to the solicitor; a DAD NS (source `::`) → NA to `ff02::1`, S = 0.
  - The router's IPv6 addresses per link: a `Datapath::addrs6` next to `addrs`, written where
    `stack.rs` sets the interfaces' addresses.
  - A conflict (an ARP or NA claiming a router address from another MAC) is logged and counted.
- **Readdressing** no longer forgets neighbors (6 is gone): `fwd::neigh` is kept when a link only
  changes addresses, as today.
- **The WAN stays as it is.** smoltcp's DHCPv4 socket panics without an Ethernet address
  (`socket/dhcpv4.rs:569`), so a DHCP WAN keeps `Medium::Ethernet` with its workarounds (1, 3, 7
  on link 0 only). It has one neighbor, the gateway, so 4–6 do not arise. A PPPoE WAN is already
  `Medium::Ip`. A later option: WAN on `Medium::Ip` too, with a sans-IO DHCPv4 client in
  `crates/proto-dhcp`; out of scope here.

What goes away on the LANs: workarounds 1–7, `neigh-cache-256` (the WAN needs the default 8), and
smoltcp's multicast-group slots for solicited-node groups (headroom for `iface-max-addr-count`).

## 3. Steps

Each step is testable on its own; the full matrix (§4) runs before a step is done.

### Step 0: small fixes first (independent)

- An interface address that does not fit (`iface-max-addr-count-4`) is logged, not dropped with
  `let _ =` (`stack.rs`, LAN and WAN).
- docs/security-audit.md: why the WAN's remaining hints do not reintroduce the cache poisoning
  upstream removed (only frames to the router, no broadcast / multicast, smoltcp's own subnet
  check `iface/interface/ipv4.rs:288`, no worse than ARP spoofing).
- Report workaround 3 (unicast NS) upstream with a test; it is an RFC bug for hosts too.

### Step 1: responder and builders in `crates/fwd` (no kernel change)

- `wire::build_arp_reply`, `wire::build_na` (flags, target link-layer option, checksum),
  `nd::answer(frame, my_addrs) -> Option<Reply>` covering the cases in §2.
- Host tests: request / probe / gratuitous / foreign target / off-subnet sender; NS multicast,
  unicast, DAD, hop limit ≠ 255, bad checksum, NA flags. Checked against smoltcp's parsers as the RA
  code is.
- Fuzz target `fwd` gets the responder (replies only to valid NS / ARP for our addresses).

### Step 2: `Datapath::send_local` and the MAC mapping

- `send_local`, the multicast / broadcast mapping, the per-link route snapshot, `addrs6`; unit
  tests for the mapping and next hop in `crates/fwd` where the logic is pure.
- Not used yet; kernel builds, smoke + lab unchanged.

### Step 3: LAN links on `Medium::Ip`

- `new_iface` and `capabilities()` by link role, not by port: a LAN link is `Medium::Ip`
  (`HardwareAddress::Ip`, MTU 1500), the WAN as today.
- Nothing calls `set_hardware_addr` on a LAN interface (it asserts `Medium::Ethernet`:
  `stack.rs:614` would panic); the MAC comes from the port for `ra_config` (`services.rs:115`) and
  the mDNS link-local address (`mdns.rs:87`).
- Device RX strips, TX goes through `send_local`; the datapath answers ARP / NS on LAN links and
  keeps them from `local_rx`.
- Boot argument `lan_medium=eth`: the old path, unchanged (smoltcp Ethernet + hints), as a fallback
  and A/B for one deployment cycle on the apu4; a row in docs/boot-arguments.md.
- Counters in `/api/status` (`neighbor`): `arp_replies`, `na_sent`, `nd_conflicts`,
  `local_no_route`, local packets queued / dropped in `fwd::neigh`.

### Step 4: remove the LAN workarounds

After the apu4 has run step 3 without the fallback (at least a week, the clients' usual mix: phones
sleeping and waking, IPv6 privacy addresses):

- `NdHints` hints and `ipv6_ns_to_solicited` / `ipv6_na_set_router` only on link 0 (or removed if
  the WAN moved to `Medium::Ip`), `neigh-cache-256` removed, `lan_medium=` removed.
- `LAB_NEIGH_CACHE=8` and `arp_hints=0` stop being LAN negative controls (§4); docs updated:
  kernel/src/net/CLAUDE.md, docs/ipv6.md §2, docs/architecture.md, docs/boot-arguments.md,
  docs/lab-tests.md, docs/bufferbloat-cake.md §3.1 (the pending queue now also holds router
  packets).

## 4. Tests and negative controls

- **`LAB_NEIGH=1`** stays the main check (40 addresses, 3 rounds, a download across several
  neighbor lifetimes). It must pass with no hints at all.
  - Negative controls: `LAB_ROUTER_ARGS=lan_medium=eth arp_hints=0` (round 1 fails, the old
    path's failure), `LAB_ROUTER_ARGS=neigh_probe=0` (now local answers fail at the end of a
    lifetime too, not only forwarded traffic).
- **New: unicast NS probe.** The client sets its entry for the router to STALE
  (`ip -6 neigh change … nud stale`) and sends traffic; Linux probes with a unicast NS; the entry
  must become REACHABLE (`ip -6 neigh show`). Negative control: `nd_unicast=0` (the responder
  ignores unicast NS, as smoltcp did) → FAILED.
- **New: router flag.** After NS / NA exchanges the client keeps its IPv6 default route via the
  router (`LAB_IPV6=1`). Negative control: `na_router=0` (NAs without R) → the route disappears.
- **New: readdress keeps neighbors.** A live `/api/config` change to a network (`LAB_GUEST_LIVE=1`)
  and a prefix change (`LAB_IPV6=1`, `cgi-bin/pd?change`): pings to the router from the
  `LAB_NEIGH` addresses lose nothing afterwards. Negative control: `lan_medium=eth arp_hints=0`.
- **New: local traffic over a `[[route]]`.** `LAB_ROUTES=1`: the router answers 10.30.0.5 (ping,
  DNS) through the client as next hop. Negative control: `LAB_ROUTES=0`.
- **ARP / ND conflict:** the client claims the router's address with `arping -U` from a second
  MAC: `nd_conflicts` rises, the router keeps answering. Negative control: the claim from the
  router's own MAC does not count.
- Everything else unchanged and run as the CLAUDE.md table says for device, datapath, services,
  IPv6 and DHCP changes: lab default, `LAB_GUEST` (+ `LAB_GUEST_LIVE`), `LAB_PORTS`, `LAB_IPV6`,
  `LAB_ROUTES`, `LAB_MDNS` (multicast mapping), `LAB_DNS_VIEWS`, `LAB_DOT`, `LAB_PPPOE=pap`
  (the WAN unchanged), lease / cli / store tests; with `QEMU_SMP=4`, `QEMU_NIC=igb`,
  `LEATOS_ARCH=x86_64`, TCG. `cargo test`, clippy, the `fwd` fuzz target ≥ 10 min.
- The new boot arguments (`lan_medium=`, `nd_unicast=`, `na_router=`) get rows in
  docs/boot-arguments.md; `scripts/doc-check.sh` enforces it.

## 5. On the apu4

After the soak (2026-11-25), in RAM first (`apu-upload.sh`), then `--persist`:

- `/api/status` neighbor counters, `neighbor` drop reason, local queued / dropped over a day.
- The symptoms that started this (2026-11-22, the Twitch pauses): none.
- iPhone / Mac: IPv6 default route stays (R flag); a sleeping phone gets DNS answers at once after
  waking.
- A/B for a day with `lan_medium=eth` if anything looks off; the fallback goes in step 4.

## 6. Risks and open questions

- **Local packets share the pending queue with forwarded ones** (3 per neighbor): a burst of
  answers to a neighbor not yet resolved loses the oldest. Today smoltcp drops the packet and
  stops all lookups for 1 s, so this is no worse; measured by the local queued / dropped counters.
- **svc calls into the datapath:** `send_local` must stay short (two locks, no allocation beyond
  what the datapath already does) and never wait. Its cost on the svc core is measured with
  `cpu.tasks` in the lab's load phase.
- **smoltcp on `Medium::Ip` for LANs is new to us:** IPv4 broadcast reception (DHCP server), IGMP /
  MLD reports, IPv6 source selection for link-local multicast (mDNS on ff02::fb). Covered by the
  lab, but checked first in step 3.
- **A responder bug cuts every client off from the router.** Fuzzing and host tests in step 1, the
  `lan_medium=eth` fallback in step 3, the trial / rollback on the apu4 (`--persist`).
- **The WAN keeps the old workarounds** until a sans-IO DHCPv4 client exists. Acceptable: one
  neighbor, and its workarounds are already tested (`LAB_PPPOE`, `LAB_WAN_STATIC`, `LAB_IPV6`).
