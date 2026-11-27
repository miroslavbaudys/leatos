# Configuration schema v2: networks, zones, firewall

Status (2026-11-17): **the schema is implemented** in `crates/config`
(types, validation, CLI editing by name; version 1 is no longer read
since 2026-11-18, §5). The kernel implements networks on the LAN ports
`lan0`–`lan2` (routed ports, one port per network, since 2026-11-19; untagged or VLANs, a
DHCP server and DNS domain each, changed live), zones (forwarding between
them, input policy), rules (incl. `reject`), port forwards with hairpin,
redirects, WAN anti-spoofing, mDNS reflect rules (docs/mdns.md), and the
web interface's Networks and Firewall pages (§9), DNS hosts and
split-horizon DNS views (docs/dns-views.md; in QEMU, 2026-11-18). All of
it but the DNS views runs on the apu4 as the developer's home router.
A network on several ports (a bridge) and port names other than
`lan0`–`lan2` are refused as unsupported (`Config::unsupported`). Schema v1 is
in `docs/config-and-storage.md` §5. v2 is the data model the multipage
web interface is built against (Networks and Firewall pages). It also covers
the kernel work listed for M10 in `docs/roadmap.md`: one router interface
per VLAN, firewall zones, port forwarding, and later the LAN bridge.

## 1. Goals and borrowed ideas
- **Network = one object** (from UniFi). A network bundles a VLAN ID, a
  subnet, a DHCP pool and a zone. A guest network is one
  entry, not four sections that have to agree.
- **Zone firewall** (from OpenWrt). Each network belongs to a zone. A
  zone has a policy for traffic to the router (`input`) and a list of
  zones it may forward to. Rules and port forwards are exceptions on top
  of that. The firewall decides only when conntrack sees a new flow, so
  established traffic costs nothing extra in the datapath.
- **Safe changes** (from MikroTik's safe mode, implemented here as trials).
  A change that could cut off the management session boots as a trial and
  reverts unless it is confirmed (§7).
- **Not adopted:** MikroTik-style raw chains, address lists and
  mangle/raw tables. They are too low-level for a SOHO router and cost
  per packet.

## 2. Example
```toml
version = 2

[wan]                       # one WAN; zone "wan" is implied
port = "wan0"
vlan = 848                  # as in v1
mode = "pppoe"              # "dhcp" | "pppoe" | "static"
[wan.pppoe]                 # as in v1
username = "user@isp.cz"
[wan.static]                # mode = "static" only
ipv4 = "203.0.113.2/30"
gateway = "203.0.113.1"
dns = ["203.0.113.53"]

[[network]]
name = "lan"                # key: [a-z][a-z0-9-]{0,14}; also the interface name
ports = ["lan0"]            # physical ports; more than one = bridged (M10)
vlan = 0                    # 0 / absent = untagged on its ports
ipv4 = "10.10.0.1/24"
zone = "lan"
[network.dhcp]              # v1's [lan.dhcp], per network
enabled = true
range = ["10.10.0.100", "10.10.0.199"]
lease_secs = 43200
[[network.dhcp.static]]
mac = "52:54:00:00:00:05"
ip = "10.10.0.10"
hostname = "nas"

[[network]]
name = "guest"
ports = ["lan0"]
vlan = 20                   # tagged on lan0 (trunk to the AP)
ipv4 = "10.20.0.1/24"
zone = "guest"

[[zone]]
name = "lan"
input = "accept"
forward_to = ["wan", "guest"]

[[zone]]
name = "guest"
input = "drop"              # nothing to the router ...
allow = ["dhcp", "dns", "ping"]   # ... except these services
forward_to = ["wan"]        # internet only

[[firewall.rule]]           # exceptions, first match wins
name = "printer-from-guest"
from = "guest"
to = "lan"                  # a zone, or "router" for input
proto = "tcp"
dst = "10.10.0.20"
dst_port = "9100"
action = "accept"           # accept | drop | reject

[[firewall.forward]]        # DNAT from the WAN address
name = "nas-https"
proto = "tcp"               # tcp | udp | tcp+udp
wan_port = "8443"           # a port or a range "8000-8010"
to = "10.10.0.10:443"       # with a range: a base port, or no port = same ports
src = "0.0.0.0/0"           # optional: limit who may connect
hairpin = true              # also from inside, via the WAN address

[dns]
cache_entries = 4096
rebind_protection = true
prefetch = true             # default; false needs version 2
stale_secs = 86400          # serve-stale window (RFC 8767), 0 = off, max a week
views = "firewall"          # "all" (default): who resolves which local names
[[dns.host]]                # local records beside DHCP names
name = "nas"
ip = "10.10.0.10"
networks = ["lan"]          # optional: who gets this answer (docs/dns-views.md)

[shaping]                   # unchanged from v1
[mgmt]                      # on_wan, password_hash (PBKDF2-SHA256, crates/auth)
[time]                      # unchanged
```

## 3. Sections
### `[wan]`
Unchanged from v1, with two additions:
- `port` (default `"wan0"`): which physical port. The datapath keeps one
  WAN, and the per-direction core layout (`docs/smp.md`) assumes that.
- `mode = "static"` with `[wan.static]` (`ipv4`, `gateway`, `dns`).
  Implemented 2026-11-18 (`config::wan_link`, `net/svc.rs`
  `configure_static`): the address and default route on the WAN's
  router-stack interface, reported like a lease that never expires
  (`via = "static"`), `dns` used as the WAN's servers unless
  `dns.upstreams` names its own. Applied live like the other modes
  (DHCP ⇄ PPPoE ⇄ static); `[wan.static]` stays when another mode is
  chosen. Boot arguments `wan_mode=static wan_ip=a.b.c.d/len
  wan_gw=a.b.c.d wan_dns=a,b`. CLI: `config set wan.static = { ipv4 =
  "…", gateway = "…" }` (both are required, so the table first), then
  `config set wan.mode = "static"`.

The WAN is always zone `wan`, a built-in zone: input drop, masquerade on,
`forward_to` empty. Input drop is silent: no RST, no ICMP port
unreachable, no ping reply, so a scan from the internet sees nothing but
the forwarded ports (`kernel/src/config.rs` `firewall`). Replies to the
router's own clients (DHCP, DNS upstream, SNTP, ICMP errors) pass before
the policy. Its policy can be changed only through rules (`from = "wan"`,
`to = "router"`) and forwards. `[mgmt] on_wan` stays the only way to open
management on the WAN, and it remains for development only. Lab check:
"wan input" in `scripts/lab-test.sh` (the ISP probes TCP 22, 80, 61000 and ping;
negative controls `LAB_ROUTER_ARGS=mgmt=wan`, `LAB_WAN_OPEN=1`).

### `[[network]]`
| Field | Default | Notes |
|---|---|---|
| `name` | required | key; unique; not `wan`, `router` or `any` |
| `ports` | `["lan0"]` | one of `lan0`, `lan1`, `lan2` (the LAN NICs in PCI order after `wan0`; more than one = a bridge, not supported yet). A network on a port the machine lacks is left out there with a boot-log line, not refused (the same file boots on QEMU and on the apu4) |
| `vlan` | `0` | 0 = untagged, 1–4094 = tagged |
| `ipv4` | required | router address/prefix, prefix 8–29 as in v1 |
| `ipv6` | `true` | with `[ipv6] enabled`: its ULA and global /64s (`<prefix>:<index>::/64`), RAs, DNS and the web interface over IPv6. `false` = IPv4 only: no addresses or RAs there, the forwarder drops the network's IPv6 (`unsupported`), its /64s stay unused so the other networks keep theirs (and are unreachable: ICMPv6 no route, never sent to the ISP); an IPv6 `[[route]]` via it is refused. CLI `network.<name>.ipv6 = false`, web UI: Networks / LAN pages |
| `zone` | `"lan"` | an existing `[[zone]]` or a built-in one |
| `domain` | `dns.domain` | the network's own DNS domain (DHCP option 15, `<hostname>.<domain>`); version 2 only |
| `dhcp` | enabled, pool derived as in v1 | v1's `[lan.dhcp]` fields plus `enabled` |

Port membership comes from the networks, as with UniFi port profiles. On
each port, at most one network is untagged (the port's native VLAN), and
the others are tagged (a trunk). A frame with a VID that no network claims
on that port is dropped (`vlan_drops`, as on the WAN today). A per-port
`[[port]]` section (disable, speed, a default for unknown VIDs) can come
later without changing networks.

### `[[zone]]`
| Field | Default | Notes |
|---|---|---|
| `name` | required | key; `wan` is built in and can't be redefined |
| `input` | `"accept"` | traffic to the router: `accept`, `drop`, `reject` (TCP RST / ICMP port unreachable, rate-limited) |
| `allow` | `[]` | with `input = "drop"/"reject"`: router services still reachable: `dhcp`, `dns`, `ntp`, `ping`, `mgmt` |
| `forward_to` | `["wan"]` | zones this zone may open new flows to. Replies are always allowed (conntrack) |

Networks in the same zone may always forward to each other: the same zone
means the same trust. Built-in zone `lan` (input accept, forward to `wan`)
exists if the file defines none, so a config with one LAN needs no zones.

Management (`:80`) is reachable from a zone with `input = "accept"`, or
from one that lists `mgmt` in `allow`. Today's rule, "LAN only unless
`mgmt=wan`", is the default case.

### `[[firewall.rule]]`
Checked in order before the zone policy. The first match decides. Only
new flows are checked.

| Field | Default | Notes |
|---|---|---|
| `name` | required | key; unique |
| `enabled` | `true` | the UI can disable a rule without deleting it |
| `from` | required | zone name or `any` |
| `to` | required | zone name, `router` (input) or `any` |
| `proto` | `"any"` | `tcp`, `udp`, `tcp+udp`, `icmp`, `any` |
| `src`, `dst` | any | IPv4 or IPv6 address or prefix (`10.10.0.20`, `2001:db8::/48`; a bare IPv6 address is /128); one family per rule |
| `dst_iid` | any | IPv6 only: the destination's interface identifier (`::5054:ff:fe00:10`, the low 64 bits) under any prefix, so a pinhole survives the ISP renumbering; not for `to = "router"` |
| `dst_port` | any | `"443"` or `"8000-8100"`; only with tcp/udp |
| `action` | required | `accept`, `drop`, `reject` |

A rule with IPv4 addresses applies to IPv4 only, one with IPv6 addresses or
`dst_iid` to IPv6 only, one with neither to both. An IPv6 pinhole for a
device (docs/ipv6.md step 5b):

```toml
[[firewall.rule]]
name = "qbittorrent6"
from = "wan"
to = "lan"
proto = "tcp+udp"
dst_iid = "::5054:ff:fe00:10"
dst_port = 9524
action = "accept"
```

### `[[firewall.forward]]`
Port forwarding (DNAT) from the WAN address.

| Field | Default | Notes |
|---|---|---|
| `name` | required | key; unique |
| `enabled` | `true` | |
| `proto` | `"tcp"` | `tcp`, `udp`, `tcp+udp` |
| `wan_port` | required | port or range |
| `to` | required | `ip` or `ip:port`; `ip` must be inside a network's subnet (not the router itself) |
| `src` | any | CIDR allowed to connect |
| `hairpin` | `true` | LAN clients reach the forward through the WAN address (DNAT plus SNAT to the router's address on that network) |

A forward also lets the flow through the firewall: no separate rule is
needed (like OpenWrt redirects). Port interactions with the router's own
ports:
- **NAPT ports (10000–39999):** forwarded ports in this range are skipped
  when NAPT allocates a source port, so a mapping never shadows a forward
  (`Conntrack::set_reserved`).
- **The target going out:** connections from a forward's target endpoint
  (`to`, e.g. a torrent client's listen port) leave from the forward's
  WAN port (`Conntrack::create_from`), any range, as Linux's NAT keeps
  the source port. A peer it contacts that then connects to the forward
  meets the same connection; before, the two collided and the peer's
  packets were dropped (now counted as drop reason `clash`, not
  `table-full`). A new policy (any config change) keeps these
  connections (`Forwarder::recheck`) while the forward still points at
  that endpoint.
- **One endpoint, one shard:** all of a target endpoint's connections
  (inbound to the forward, its own out, uTP and DHT on one UDP port) live
  in one conntrack shard, so the shards share one connection budget
  (`conntrack::Budget`, 16384 in all) instead of a fixed 1/16 each.
- **Router-local ports (60000–65535):** the router's own client sockets
  (SNTP UDP 60000–60999, DNS upstream UDP 61000–65535 (a random port per query), DoT TCP
  61000–64999) live here, and forwards
  may not use them (validation), so a reply to the router is never taken
  for a forwarded connection. Forwards may use everything below,
  WireGuard's 51820 for example.
- **Fixed router ports:** a forward may not use a port the router itself
  listens on from the WAN (`:80` with `mgmt.on_wan`). Validation rejects
  it.
- **Forged sources:** packets from the WAN whose source is loopback or
  inside one of the networks are dropped before anything else looks at
  them (drop reason `spoofed`, RFC 2827 / RFC 3704 ingress filtering).
  Without it, a forward would take a SYN "from" an internal host and its
  target would answer that host directly on its own network. Addresses in
  the WAN's own subnet stay allowed (an ISP's private gateway, such as
  10.x over PPPoE, is not affected). Boot argument `wan_antispoof=0` turns
  it off (the lab's negative control).

### `[[firewall.redirect]]`
Redirects (DNAT inside, the UniFi/OpenWrt "NTP/DNS redirect"): new
connections from the networks to an outside server go to a device inside
instead. For devices with hard-coded servers, e.g. every NTP query to the
LAN's own time server. The clients keep thinking they talk to the server
they chose (the answers carry its address).

| Field | Default | Notes |
|---|---|---|
| `name` | required | key; unique |
| `enabled` | `true` | |
| `from` | required | zone name or `any` (every network; not `wan`) |
| `proto` | `"udp"` | `tcp`, `udp`, `tcp+udp` |
| `dst_port` | required | port or range |
| `to` | required | `ip` or `ip:port`; `ip` must be inside a network's subnet (not the router itself) |

```toml
[[firewall.redirect]]
name = "ntp"
from = "any"
dst_port = 123
to = "192.168.1.200"
```

What is redirected (`fwd::forwarder::Redirect`):
- New TCP/UDP connections arriving from a network of zone `from`, to
  `dst_port` of an address outside every network (the internet), or of a
  router address for a port the router does not serve itself: DHCP (67),
  DNS (53), mDNS (5353) and the web interface (TCP 80) stay the router's
  (`router_serves`), so NTP to the router (it serves none) is redirected.
- Never: the target's own connections (its upstream queries go out as
  addressed), connections to the target or to any other address inside
  the networks (a client that picked a local server keeps it),
  broadcast and multicast.
- A port forward wins over a redirect for the same connection.

How: the forwarder translates the destination (`Conntrack::create_dnat`)
and lets the connection through the firewall, like a port forward (no
rule needed, also when the zones would refuse it). A client on the
target's own network is also translated to the router's address there
(as hairpin forwards are), because the target would otherwise answer it
directly, from its own address, and the client would drop the answer.
Clients on other networks keep their address (the target sees who asks;
its answers go back through the router, their gateway). Counted per
redirect (`redirects` in `/api/status`, the Firewall page).

Sharding: `shard_of` cannot see zones, so every connection a redirect
may take (its ports, outside or at a router address, not from the
target), every connection to the target's ports and the target's packets
from them to inside live in the target endpoint's shard
(`ShardHints::redirects`). ICMP errors from inside follow the connection
they are about. A zone-limited redirect thus also puts the other zones'
connections to those ports in that shard (their NAT ports come from it,
so the WAN side finds them); keep redirects to small services.

### `[[route]]`
Static routes to subnets behind other routers (a lab router, a VPN box):

```toml
[[route]]
name = "lab"            # key
dst = "10.30.0.0/24"    # subnet (host bits zero) or one address
via = "192.168.1.2"     # the next router
# enabled = true
```

| Field | Default | Notes |
|---|---|---|
| `name` | required | key; unique |
| `enabled` | `true` | |
| `dst` | required | not `0.0.0.0/0` (the WAN's), not inside a network's subnet (around one is fine: the subnet is the longer match), not loopback, link-local or multicast; unique. IPv6: a global or unique local prefix, not `::/0` |
| `via` | required | a host on one of the networks (not the router), or else on the WAN's subnet (not with PPPoE; with a DHCP WAN the route is used while the lease's subnet holds it); not inside `dst` for a WAN route. IPv6: a host in a network's unique local /64 (`<ula>:<i>::/64` = network `i`, stable when the ISP renumbers; in `ipv6.ula_prefix` if set) |

IPv6 routes (docs/ipv6.md step 5b) are in use while IPv6 is on and `via`
is in this boot's ULA /48; DHCP option 121 is IPv4 only, so the router
forwards a network's packets for an IPv6 route back out to its router
(the IPv4 rule against that, `hairpin`, does not apply); `/api/status`
`routes6` lists them.

At most 16. The route leaves through the network whose subnet holds `via`
(`Config::route_via`):
- **Forwarding** (`fwd::Forwarder::set_static_routes`): in the table
  (`RouteKind::Static`) while a connected subnet holds `via`; a connected
  route or the default with the same destination wins. Hosts behind a
  network's router count as inside for WAN anti-spoofing, redirects,
  `recheck` (their connections came in on that network, in its zone) and
  shard selection (`ShardHints::routed`); they are NATed to the internet
  like the network's own.
- **DHCP option 121** (RFC 3442; 249 for clients asking for that one
  instead): each network's DHCP clients that ask for it get the routes
  through routers on their network, plus the default route via the router
  (such clients ignore option 3). They send to the other router directly;
  the router never sends a packet back out the link it came in on
  (drop reason `hairpin`), so devices with a fixed address need the route
  themselves.
- **The router's own stack** (per link `HostIf::link`, a
  `fwd::local::LocalLink`; smoltcp's interfaces until 2026-11-27): each
  link's view holds the routes through its routers, so the router answers hosts
  behind them (DNS, web interface, ping); the WAN's holds WAN routes.
- **DNS views:** a routed subnet belongs to `via`'s network.
- **Status:** `/api/status` `routes` (the table in use, then configured
  routes not in use, `active: false`), CLI `routes`, web page Routes.

Lab: `LAB_ROUTES=1 scripts/lab-test.sh` (negative control `LAB_ROUTES=0`).

### `[[dns.host]]` and `[dns] views`
Static A records in the local zone (`name` + `ip`), beside the DHCP-derived
names. A name without a dot is in `dns.domain`; a dotted one in the
longest local domain it ends in; any other name overrides a public name
(needs `networks`). `networks` lists who gets the answer (the same name may
have another address for other networks); without it `dns.views`
decides. `views = "firewall"` lets a network resolve only the names of
addresses its zone can reach (same zone, `forward_to`, accept rules); the
default `all` lets every network resolve every local name. Design, rules
and lab check (`LAB_DNS_VIEWS=1`): docs/dns-views.md.

### `[dns] domain`
The default local domain (version 1's `lan.domain`, default `home.arpa`, the
special-use domain for home networks, RFC 8375; before 2026-11-23 `lan`): DHCP
clients of a network without its own `domain` are `<hostname>.<domain>`.
A network with `domain` set (`iot.home.arpa`) serves that domain to its
DHCP clients, and its reservations and leases resolve there only. Every
domain in use is local (never forwarded, exempt from rebind protection)
and has `router.<domain>` = the address of the first network using it.
Domains may nest (`home.arpa`, `iot.home.arpa`): a name belongs to the
longest local domain it ends in (`crates/proto-dns` `Zone`). Lab check:
`LAB_GUEST=1 scripts/lab-test.sh` (guest network `guest.home.arpa`; negative
control `LAB_GUEST_DOMAIN=0`).

### `[ipv6]` (M7 step 1, docs/ipv6.md)
```toml
[ipv6]
enabled = true                       # default false; boot argument ipv6=0|1
ula_prefix = "fd12:3456:789a::/48"   # optional: else derived from the WAN MAC
dhcpv6_pd = true                     # default: ask the ISP for a prefix (Ethernet WAN)
prefix_hint = 56                     # 48–64: the length asked for
```
With `dhcpv6_pd`, network `i` also gets `<delegated prefix>:<i>::/64`
(the router `::1`), renumbered live when the ISP changes the prefix
(docs/ipv6.md step 3).
With `enabled`, network `i` (config order) gets `<ula_prefix>:<i>::/64`:
the router `::1` and its link-local address on the network, Router
Advertisements (SLAAC, RDNSS = the router, DNSSL = the network's domain,
router lifetime 0), DNS and the web interface over IPv6 under the zone's
input policy. Nothing is forwarded over IPv6 yet. `ula_prefix` must be a
/48 in `fc00::/7`. Applied live. `[wan.ipv6]` (prefix delegation) comes
with step 3.

## 4. Validation (`crates/config`, one pass, paths for the UI)
- Every key (`network.name`, `zone.name`, `rule.name`, `forward.name`) is
  unique. References (`network.zone`, `forward_to`, rule `from`/`to`)
  exist. An issue path names an entry by its key, e.g.
  `network.guest.dhcp.range[0]`, `firewall.rule.printer.dst_port`, so the
  UI finds the row after it is reordered. An entry whose name is not a
  valid unique key is named by its index (`network[2].name`).
  Reservations and DNS hosts by index (`network.lan.dhcp.static[3].ip`).
- Subnets of networks don't overlap with each other or with a static WAN.
- Per port: (port, vlan) is unique, and at most one network is untagged.
- DHCP pools and reservations lie inside their own network. Reservation
  MACs are unique across all networks.
- Forward targets lie inside a network. Forward port ranges don't overlap
  for the same protocol. A range maps onto a range of the same length.
- Bounds: ≤ 16 networks (more makes no sense before hardware tag offload),
  ≤ 16 zones, ≤ 256 rules, ≤ 128 forwards, ≤ 1024 reservations in total,
  ≤ 256 DNS hosts.
- Settings the running kernel does not implement yet are rejected as
  unsupported (`Config::unsupported`, separate from validation so the
  crate accepts the whole schema): by a save (web, CLI), by `leatstore
  put`, and a stored config with them is not used (defaults, as for any
  rejected record). Today that is a network on several ports (a bridge),
  port names other than `lan0`–`lan2`, and a WAN port other than `wan0`.

## 5. Migration and rollback
- **Version 1 is no longer read** (dropped 2026-11-18). It had one
  `[lan]` instead of `[[network]]` and the local domain in `lan.domain`.
  Until then it was migrated on load, and a config that fit it was written
  as version 1 so kernels that read only version 1 kept their LAN after a
  rollback. No such kernel is deployed any more (the apu4's config has
  been version 2 since 2026-11-15), and every new feature had to be
  listed as "beyond v1", so both directions were removed. A version 1
  document (`version = 1`, or `[lan]` without a `version` line) is refused
  with `Error::OldVersion` and a hint: write `[lan]` as `[[network]]` with
  `name = "lan"`, and `lan.domain` as `dns.domain`. A stored version 1
  record is rejected at boot (defaults, as for any rejected record).
- **The record header names the schema version** (always `VERSION` now).
  The store picks the newest record whose version the reader understands,
  so a kernel skips a record of a newer schema and boots the one before it.
- No config is saved while a trial kernel runs, so a record is only
  written by a confirmed kernel.
- **JSON** (`/api/config.json`, the web form) has the same schema.
- **Boot arguments** keep overriding: `lan=` sets the first network's
  `ipv4`. `wan_*`/`pppoe_*` are unchanged.
- **CLI** (`config set/unset`): entries by name, `network.guest.vlan = 20`,
  `network.guest = { ipv4 = "10.20.0.1/24", vlan = 20 }` (new entries go
  last), `config unset network.guest`; `lan.…` is the first network and
  `lan.domain` is `dns.domain` (shorthands from version 1).

## 6. Datapath and services mapping (kernel work)
- **Interfaces** ✅. A *port* is a NIC with its egress qdisc; a *link*
  (`net::shared::LinkShared`) is a router interface on a port: link 0 is
  the WAN on `wan0`, links 1.. the networks, each on its LAN port
  (`LinkShared::port`, set live with the VID: routed ports, 2026-11-19).
  Forwarder interfaces (with the port's MAC), ARP tables, the router
  stack's `HostIf`s and `local_rx` queues are per link. On RX the
  datapath maps the frame's (port, VID) to a link (none:
  dropped, `vlan_drops`); a frame for a network on a VLAN gets its tag
  when it is queued (forwarded, ARP, the router's own), so the qdisc holds tagged
  frames and shapes the 4 bytes too. `fwd::Interface` gained `zone: u8`;
  `Role` stays and now only means "masquerade towards it" (`Wan`), so
  traffic between networks is not NATed. `shard_of` hashes a flow
  between two networks by the endpoint pair, so both directions meet in
  one conntrack shard.
  - The two-port, two-direction core layout stays: all LAN networks share
    `lan0`, so they share one LAN qdisc. The download shaper is the WAN
    ingress stage (2026-11-19, docs/bufferbloat-cake.md §3.4): one CAKE
    for everything from the WAN, so its host isolation spans every
    network, while traffic between the networks only passes `lan0`'s
    unshaped CAKE and is not held to the download rate.
- **Firewall** (zones ✅, rules ✅).
  - `fwd::forwarder::Policy`: per zone a bitmask of zones it may forward
    to, and its input (`None` = all, or a mask of `svc::*` services),
    compiled from the config by `config::firewall` (zone 0 = wan, 1 = lan,
    then the defined zones), set on every shard, replaced live on a save
    (`Control::policy`).
  - Rules: `Policy::rules` (`fwd::forwarder::Rule`: from zone or any, to
    a zone / the router / any, protocol bits, source and destination
    prefix, destination port range, `Action` accept / drop / reject), compiled from the
    enabled `[[firewall.rule]]`s. On a new flow (conntrack miss) and for
    traffic to the router the first matching rule decides, else the
    zones. Each shard counts packets per rule (`rule_hits`); the datapath
    sums them once a second into `Shared::rule_hits`, shown as `rules[]`
    in `/api/status` and on the Firewall page. A new policy restarts the
    counters. A new policy (or a network moved to another zone) also
    applies to tracked connections: `Forwarder::recheck` runs the
    new-flow decision again for each one in every shard and removes those
    it refuses (zones, rules, a port forward or redirect gone or pointing
    elsewhere, a redirect that now takes it, a masquerade on a port now
    forwarded). Their next packet is a new flow: refused (TCP without SYN
    is invalid, so it ends), or for UDP/ICMP started under the new
    policy. Connections without a route are left to expire. Counted in
    `/api/status` `revoked`; boot argument `fw_recheck=0` skips it (the
    lab's negative control).
  - `reject` (rule action, zone `input`) answers in place of the packet,
    back out of its ingress, sharing the ICMP errors' token bucket (50/s,
    burst 20; beyond it, silent drops): TCP gets a RST from the address
    and port it went to (RFC 9293: seq = its ACK, or ACK of what it
    occupies), everything else ICMP port unreachable from the router.
    Never for RSTs, ICMP errors, fragments, or from or to broadcast and
    multicast addresses (those, and ones over the rate, are dropped and
    counted as drops). Answered ones count as `Stats::rejected`, not as
    drops: `/api/status` `rejected`, not in `drop_reasons`. The WAN zone's input is never rejected,
    only an explicit `reject` rule from `wan` answers there.
  - Checked only on a conntrack miss, so per-packet cost is unchanged for
    tracked flows.
  - Input policy: packets for the router from a zone with `input = drop`
    are dropped in the forwarder (`drop_reasons.input`) unless they are
    an `allow`ed service (DHCP UDP 67, DNS 53, NTP UDP 123, ping, web TCP
    80). The router stack never sees them. With `input = reject` they are answered
    (above). Replies to the router's own clients always pass,
    before rules and zones: TCP/UDP to ports ≥ 60000 (router-local
    sockets), UDP 68 (the DHCP client), ICMP other than echo requests. So
    a rule "from any to router: drop" cannot break its DHCP, DNS
    upstream or SNTP. The WAN zone's input stays open otherwise (the
    router answers only on ports it listens on, TCP elsewhere with a RST);
    rules can close it.
- **DNAT** ✅. `Policy::forwards` (`fwd::forwarder::PortForward`). On a
  conntrack miss for a TCP/UDP packet to the WAN address, a matching
  forward (from the WAN if `src` allows; from inside only with hairpin)
  routes it to the target and creates the connection with
  `Conntrack::create_dnat`: the reply tuple is the target's, so packets
  are rewritten both ways by the same code as masquerade (whatever
  differs between the tuple seen and `Conn::translated`; ICMP errors
  alike). Hairpin also translates the source to the router's address on
  the target's network (an endpoint-independent mapping), so the target
  answers through the router. A forward lets its connections through the
  firewall; zones and rules are not consulted. `shard_of` puts DNAT and
  hairpin connections in the shard of their target endpoint
  (`ShardHints`: WAN address, forwards), so both directions meet; NAPT
  never allocates a forwarded port. Hit counters per forward
  (`forward_hits`, `/api/status` `forwards[]`).
- **On apply:** rule and forward changes apply to new flows. Tracked
  connections that the new policy would refuse are removed. This is a
  pass over each shard, at most 16384 entries in total, run in the
  datapath's housekeeping.
- **Services** ✅. One DHCP server (`proto-dhcp`) per network with DHCP
  on, and a DNS socket on every network's address (the input policy
  decides who reaches it); one resolver and one local zone
  (`dns.domain`), with reverse lookups for every network's subnet,
  answered per network (`dns.views`, docs/dns-views.md). The
  web interface listens on the networks whose zone reaches it.
- **Status API** ✅. `/api/status` has `networks[]` (name, vlan, ipv4,
  zone, dhcp, mgmt, bound leases), leases name their network,
  `drop_reasons` has `firewall`, `input`, `spoofed` and `clash`, and
  `rules[]`, `forwards[]`, `redirects[]`, `rejected`, `revoked` count the
  firewall's decisions.

## 7. Live apply and trials
- **Live:** shaping, DNS, DHCP pools and reservations, zone policies
  (`input`, `allow`, `forward_to`), rules, forwards, redirects (tracked
  connections the new policy refuses are removed: `Forwarder::recheck`),
  mDNS rules, the WAN mode and VLAN.
- **Networks live** ✅ (2026-11-15): the kernel has a link slot per
  possible network from boot (`net::shared::MAX_LINKS`: a forwarder
  interface, ARP table and router-stack `HostIf` each, inactive until used).
  A save places the networks in slots (`shared::assign_slots`: a network
  keeps its slot while its name stays), gives the router stack its
  addresses (`stack::set_host_addrs`), sends the datapath the slots with
  VID, address and zone plus the firewall (`Control::networks` →
  `Datapath::apply`: one snapshot of VID → link, prefixes and forwards,
  read per RX batch; a changed slot forgets its neighbors), opens or
  closes DHCP and DNS per network (`LanServices::reconfigure`; a network
  that keeps name and slot keeps its leases), and listens for the web
  interface on networks that newly reach it (`Mgmt::add_sockets`; sockets
  are never taken away, the input policy guards them). Connections
  through a removed network find no route and expire.
- **Reboot** (`Config::needs_reboot`): only a bridge (a network on
  several ports; not supported yet). Moving a network to another LAN
  port is live: every NIC is up from boot, the slot changes port, forgets
  its neighbors and takes the port's MAC.
- **Trial** (`Config::needs_trial`): any change to the network or zone
  that serves management, i.e. its address, VLAN, ports or zone. Also
  `input`/`allow` of a zone that can reach management, rules with
  `to = "router"` or `"any"`, `mgmt.on_wan`, and WAN changes while
  management is on the WAN. The UI can't always tell which network
  the browser came from, so the kernel decides (it knows the ingress
  interface of the request) and says so in the save response.

## 8. Web interface mapping
| Page | Sections |
|---|---|
| Networks | `[[network]]` list + editor (VLAN, subnet, zone, domain), a DHCP panel per network (pool, lease time, reservations) |
| Routes | the routing table in use; `[[route]]` list (enable toggle, destination, router, state) |
| WAN | `[wan]` (mode, VLAN, PPPoE) |
| LAN & DHCP | the first network's address and DHCP |
| Clients | leases of all networks, "Reserve" |
| DNS | `[dns]` (upstreams, DoT, cache, prefetch, stale), DoT state per server |
| Firewall | zone matrix (rows from, columns to), zone input/allow, rules (ordered, enable toggle, hit counters), port forwards, redirects, mDNS reflect rules |
| Traffic shaping | `[shaping]` |
| System | `[time]`, `[mgmt]` (password), backup/restore, upgrade, reboot |

Lists are edited by key, never by index, so a validation issue keeps
pointing at the right row while the user edits.

## 9. Order of work
1. ✅ (2026-11-15) Multipage UI on schema v1 (pages, pending changes
   with a diff, login, logs, per-reason drop counters).
2. ✅ (2026-11-15) `crates/config` v2 types + validation + migration +
   v1-compatible writer + CLI editing by name (33 host tests); the kernel,
   web form, `leatstore` and the test scripts on it; unsupported settings
   refused.
3. ✅ (2026-11-15) Networks on `lan0` (untagged + VLANs), zones with
   forwarding and input policy, per-network DHCP, Networks and Firewall
   pages. `LAB_GUEST=1 scripts/lab-test.sh`: the client adds VLAN 20 and
   gets a guest lease, reaches the ISP, DNS and ping to the router work,
   the router's web interface is blocked and new connections to the main
   LAN are refused (router firewall drop counter); negative control
   `LAB_GUEST_ZONE=lan` (both isolation checks fail). `store-test`: a
   network added through the web API is saved and rebooted into.
4. ✅ (2026-11-15) Rules (`[[firewall.rule]]`): forwarder rules with hit
   counters, live apply, Firewall page editor (ordered, enable, hits).
   `LAB_GUEST=1 scripts/lab-test.sh` adds an accept rule (guest ICMP to
   192.168.1.10, which the zones refuse: rule hit, no firewall drop) and
   a reject rule (guest TCP 80 to the WAN: refused, rule hit); negative
   control `LAB_GUEST_RULES=0` (both fail). `store-test`: a rule saved
   through the API applies live.
5. ✅ (2026-11-15) Port forwards + hairpin (DNAT, live apply, Firewall
   page editor with hit counters; router-local ports moved to ≥ 60000).
   `LAB_GUEST=1 scripts/lab-test.sh`: the ISP VM fetches the client's
   web server through the router's WAN address (`cgi-bin/fetch`), and the
   client reaches itself through the WAN address (hairpin); negative
   control `LAB_FORWARD=0` (both fail). `store-test`: a forward saved
   through the API applies live.
   On the apu4 (2026-11-15): build 16bf581 persisted and confirmed; the
   v1 config from the SD store runs as one network `lan`. VLAN networks,
   zones, rules and forwards are not yet tried on hardware.

### What is left (as of 2026-11-17)
In rough order of value:

6. ✅ (2026-11-16) **Hardware check on the apu4.** The apu4 has been the
   developer's home router since 2026-11-15: three networks on `lan0`
   (untagged main LAN, VLAN 2 and VLAN 3 through a managed switch) all
   serve leases and resolve names in their own domains; the port forward
   (9524 tcp+udp) answers from outside, and it is the only open WAN port
   (nmap from an outside host); the NTP redirect counts hits; PPPoE on
   VLAN 848; hairpin: a LAN client reaches the forward through the WAN
   address (TCP 9524 connects; 9525 and 22 on the WAN address time out:
   negative control); isolation: a phone on the iot network (zone with
   `forward_to = []`) gets its lease but no internet, while the router's
   `firewall` drop counter rises (~15/s).
7. ✅ (2026-11-16) **Firewall polish.**
   - `reject` sends a TCP RST / ICMP port unreachable (rate-limited)
     instead of dropping. Lab: the guest's refused HTTP fails at once
     ("Connection refused") and `rejected` rises; negative control
     `LAB_GUEST_REJECT=drop`.
   - When rules or zones change, tracked connections the new policy
     refuses are removed (`Forwarder::recheck`). Lab: a guest ping to
     the ISP stops when a live config takes the guest zone's internet
     away, `revoked` rises; negative control
     `LAB_ROUTER_ARGS=fw_recheck=0`.
   - ICMP errors about forwarded and hairpin connections reach their
     connection's shard (`shard_of`: the inner packet from a forwarded
     port of the WAN address, or from a router address to a forward's
     target), e.g. "fragmentation needed" from the internet about a
     forwarded server's answers. Host tests with a control (the old
     mapping misses each kind).
8. ✅ (QEMU, 2026-11-18) **Small schema items the kernel refused:** a
   static WAN (`mode = "static"`, `[wan.static]`, §3): web WAN page,
   CLI, boot arguments; `LAB_WAN_STATIC=1 scripts/lab-test.sh` (the ISP
   runs no DHCP server; negative control `LAB_ROUTER_ARGS=wan_mode=dhcp`)
   and `scripts/vlan-test.sh` (DHCP → static → DHCP live). Open: the
   apu4 (no static line at home). `[[dns.host]]` ✅ (QEMU, 2026-11-18)
   with split-horizon views, docs/dns-views.md.
9. ✅ (2026-11-15) **Web interface gaps.** Every network's DHCP pool,
   lease time and reservations (a DHCP panel per network on the Networks
   page; "Reserve" on the Clients page for any network); the management
   password in the config as a PBKDF2 hash (`mgmt.password_hash`, set as
   `mgmt.password`, `crates/auth`); login sessions (Bearer tokens).
   `store-test`: password from the config, 401/429/200, token saves, hash
   never shown and kept, password change ends sessions, logout, negative
   control without any password (403).
10. ✅ (2026-11-15) **Live network changes** (§7 "Networks live").
   `store-test`: a network added, re-tagged and removed through the API
   in one boot; `LAB_GUEST_LIVE=1 scripts/lab-test.sh`: the router boots
   with the main LAN only, the client adds the guest network, zone, rules
   and forward live, then every guest, rule and forward check runs.
11. **Multi-port LAN (M10).** The apu4's other two i211 ports.
   **Step A, routed ports ✅ (QEMU, 2026-11-19):** `lan1`, `lan2` (NICs
   3 and 4 in PCI order), each network on one port (untagged or tagged
   there), moved live; `dp_up` receives on every LAN port, `dp_down`
   sends on them; `/api/status` `networks[].port`, a Port column on the
   Networks page. `LAB_PORTS=1 scripts/lab-test.sh` (third NIC, network
   wired on lan1; negative control `LAB_PORTS_NET=lan0`). Open: which
   physical socket is which name on the apu4.
   **Step B, bridge (not started):** a network on several ports, MAC
   learning, flooding, loop protection, igb unicast promiscuous mode,
   per-port tagged/untagged membership (one `vlan` per network can't say
   "tagged on lan0, untagged on lan2" yet); software switching on the
   Jaguar stays well below a hardware switch. **WAN ingress shaping** (CAKE ingress mode), which
   this needs because LAN egress no longer equals the download once
   traffic can stay between LAN ports, is done ✅ (2026-11-19,
   docs/bufferbloat-cake.md §3.4): it already lifted the download cap off
   traffic between the networks on `lan0`.
12. **IPv6 (M7).** DHCPv6-PD over DHCP and PPPoE (IPv6CP), a /64 per
   network with RA/RDNSS, the zone firewall for IPv6 (inbound blocked by
   default), `[wan.ipv6]`. Step 1 ✅ (QEMU, 2026-11-20): `[ipv6]` with a
   ULA /64 per network, RAs, DNS and the web interface over IPv6, the zone
   input policy for IPv6.
13. **mDNS across networks** (`docs/mdns.md`; reflector, config and
   kernel and web page done in QEMU, `LAB_MDNS=1 scripts/lab-test.sh`;
   open: avahi browse test, apu4). A filtered reflector: `[[mdns.reflect]]` rules (from, to,
   service types), `allow = ["mdns"]` for zones; caching proxy and
   `ff02::fb` later.

Outside this document (`docs/roadmap.md`): PPPoE long-run stability and a
bufferbloat run on the PPPoE line with the right shaper overhead (M5),
CAKE tuning on hardware (M6: DiffServ tins, ACK filter, rate-aware target),
per-packet cost on the apu4 and a 72 h soak (M10).
