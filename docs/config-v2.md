# Configuration schema v2: networks, zones, firewall

Status: **design** (2026-11-15). Nothing in this document is implemented
yet. Schema v1 (`docs/config-and-storage.md` §5, `crates/config`) is what
the kernel reads and writes today. v2 is the data model the multipage web
interface is built against (Networks and Firewall pages). It also covers
the kernel work listed for M10 in `docs/roadmap.md`: one router interface
per VLAN, firewall zones, port forwarding, and later the LAN bridge.

## 1. Goals and borrowed ideas
- **Network = one object** (from UniFi). A network bundles a VLAN ID, a
  subnet, a DHCP pool, a DNS domain and a zone. A guest network is one
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
domain = "lan"
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
domain = "guest.lan"

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
[[dns.host]]                # local records beside DHCP names
name = "router"
ip = "10.10.0.1"

[shaping]                   # unchanged from v1
[mgmt]                      # unchanged; later: password_hash (PBKDF2-SHA256)
[time]                      # unchanged
```

## 3. Sections
### `[wan]`
Unchanged from v1, with two additions:
- `port` (default `"wan0"`): which physical port. The datapath keeps one
  WAN, and the per-direction core layout (`docs/smp.md`) assumes that.
- `mode = "static"` with `[wan.static]` (`ipv4`, `gateway`, `dns`).

The WAN is always zone `wan`, a built-in zone: input drop, masquerade on,
`forward_to` empty. Its policy can be changed only through rules and
forwards. `[mgmt] on_wan` stays the only way to open management on the
WAN, and it remains for development only.

### `[[network]]`
| Field | Default | Notes |
|---|---|---|
| `name` | required | key; unique; not `wan`, `router` or `any` |
| `ports` | `["lan0"]` | ports must exist at runtime; unknown ones are an apply-time warning, not a parse error (the same file boots on QEMU and on the apu4) |
| `vlan` | `0` | 0 = untagged, 1–4094 = tagged |
| `ipv4` | required | router address/prefix, prefix 8–29 as in v1 |
| `zone` | `"lan"` | an existing `[[zone]]` or a built-in one |
| `domain` | `"lan"` for the first network, `"<name>.lan"` for others | unique |
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
exists if the file defines none, so a v1 config needs no zones.

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
| `src`, `dst` | any | address or CIDR |
| `dst_port` | any | `"443"` or `"8000-8100"`; only with tcp/udp |
| `action` | required | `accept`, `drop`, `reject` |

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
  when NAPT allocates a source port, so a mapping never shadows a forward.
- **Router-local ports (≥ 40000):** the ephemeral allocator skips
  forwarded ports.
- **Fixed router ports:** a forward may not use a port the router itself
  listens on from the WAN (`:80` with `mgmt.on_wan`). Validation rejects
  it.

### `[[dns.host]]`
Static A records in the local zone (`name` + `ip`), beside the DHCP-derived
names. A name is relative to the first network's domain unless it contains
a dot.

## 4. Validation (`crates/config`, one pass, paths for the UI)
- Every key (`network.name`, `zone.name`, `rule.name`, `forward.name`) is
  unique. References (`network.zone`, `forward_to`, rule `from`/`to`)
  exist. An issue path uses the key, e.g. `network[guest].dhcp.range`,
  so the UI can find the row after it is reordered.
- Subnets of networks don't overlap with each other or with a static WAN.
- Per port: (port, vlan) is unique, and at most one network is untagged.
- DHCP pools and reservations lie inside their own network. Reservation
  MACs are unique across all networks.
- Forward targets lie inside a network. Forward port ranges don't overlap
  for the same protocol. A range maps onto a range of the same length.
- Bounds: ≤ 16 networks (more makes no sense before hardware tag offload),
  ≤ 16 zones, ≤ 256 rules, ≤ 128 forwards, ≤ 1024 reservations in total,
  ≤ 256 DNS hosts.
- Settings the running kernel does not implement yet (bridged `ports`
  with more than one entry, before M10) are rejected as unsupported.

## 5. Migration and rollback
- **v1 → v2 on load:**
  - `[lan]` becomes `network "lan"` (ports `["lan0"]`, untagged, zone `lan`).
  - `[lan.dhcp]` moves into it.
  - Zones are the built-in `lan` and `wan`.
  - Everything else carries over unchanged.
- **Writing: v1 form while the config fits it.** An older kernel rejects
  `version = 2` (`NewerVersion`) and falls back to the defaults. That
  could happen after a persistent-upgrade rollback or with `image=golden`,
  and it would lose the LAN address. So the canonical writer emits a v1
  document whenever the config is expressible in v1: exactly one network,
  untagged on `lan0`, no zones, rules, forwards or DNS hosts, and WAN
  mode `dhcp` or `pppoe`. This is how `[wan]` is already handled: it is
  written only when set.
- The first save that needs v2 is refused while a trial kernel runs (it
  already is today: no config saves during a kernel trial). The UI warns:
  "this configuration needs kernel ≥ X; rolling back to an older kernel
  starts with the defaults".
- **Boot arguments** keep overriding: `lan=` sets the first network's
  `ipv4`. `wan_*`/`pppoe_*` are unchanged.

## 6. Datapath and services mapping (kernel work)
- **Interfaces.** The forwarder gets one interface per network plus the
  WAN (`fwd::Interface` gains `zone: u8`, and `Role` goes away). On RX the
  datapath maps (port, VID) to an interface; on TX it pushes the
  network's tag. This reuses the WAN's `push_vlan`/`pop_vlan` in packet
  headroom.
  - The two-port, two-direction core layout stays: all LAN networks share
    `lan0`, so they share one LAN qdisc. CAKE's host isolation then spans
    every network, and the download shaper covers them all (the roadmap
    requires this).
- **Firewall.**
  - A zone-pair matrix (`[[bool; Z]; Z]`) plus the compiled rule list
    (ranges as integers, CIDRs as mask/value), held by each forwarder
    shard and swapped on apply.
  - Checked only on a conntrack miss, so per-packet cost is unchanged for
    tracked flows.
  - Input policy: `to_us` packets from a zone with `input = drop` are
    dropped in the forwarder unless their port matches an `allow`ed
    service. smoltcp never sees them.
- **DNAT.** A conntrack entry gets a destination translation next to the
  source one. A forward is a static lookup (proto, WAN port) → target, done
  before routing on a conntrack miss from the WAN. Hairpin: the same
  lookup for LAN-side packets to the WAN address, plus a source
  translation to the router's address on the target's network.
- **On apply:** rule and forward changes apply to new flows. Tracked
  connections that the new policy would refuse are removed. This is a
  pass over each shard, at most 16384 entries in total, run in the
  datapath's housekeeping.
- **Services.** One DHCP server instance (`proto-dhcp`) and one DNS zone
  per network, each with its own smoltcp interface address. The DNS
  forwarder listens on every network whose zone allows `dns`.
- **Status API.** `/api/status` grows `networks[]` (name, vlan, address,
  counters, lease count), per-reason drop counters (`drop_reasons`, already
  there from the UI work) and per-rule hit counters.

## 7. Live apply and trials
- **Live:** shaping, DNS, DHCP pools and reservations, rules, forwards,
  new networks, and the removal of networks not used to reach management.
- **Trial** (`Config::needs_trial`): any change to the network or zone
  that serves management, i.e. its address, VLAN, ports or zone. Also
  `input`/`allow` of a zone that can reach management, rules with
  `to = "router"`, and `[mgmt]`. The UI can't always tell which network
  the browser came from, so the kernel decides (it knows the ingress
  interface of the request) and says so in the save response.

## 8. Web interface mapping
| Page | Sections |
|---|---|
| Networks | `[[network]]` list + editor (VLAN, subnet, DHCP, zone), port membership view |
| WAN | `[wan]` |
| Firewall | zone matrix (rows from, columns to), zone input/allow, rules (ordered, enable toggle, hit counters), port forwards |
| DHCP & DNS | leases (all networks), reservations, `[[dns.host]]`, `[dns]` |
| SQM | `[shaping]` |
| System | `[time]`, `[mgmt]`, backup/restore, upgrade, reboot |

Lists are edited by key, never by index, so a validation issue keeps
pointing at the right row while the user edits.

## 9. Order of work
1. ✅ (2026-11-15) Multipage UI on schema v1 (pages, pending changes
   with a diff, login, logs, per-reason drop counters).
2. `crates/config` v2 types + validation + migration + v1-compatible
   writer; host tests.
3. LAN VLAN networks on `lan0` and per-network DHCP/DNS. Lab: a guest
   client on VLAN 20 gets a lease, reaches the ISP, and can't reach the
   main LAN (negative control: put both in one zone and it can).
4. Zones, input policy, rules. Lab: a rule opens one port, with a
   negative control.
5. Port forwards + hairpin. Lab: the ISP VM reaches a client's HTTP
   server through a forward, and doesn't without it.
6. Multi-port bridge (M10), static WAN, IPv6 (M7, `[wan.ipv6]` and
   per-network RA).
