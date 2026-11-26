# kernel/src/net/ in detail

The protocol logic lives in `crates/*` (crates/CLAUDE.md); this directory is the glue.
Docs: architecture, bufferbloat-cake, ipv6, dns-over-tls, dns-views, mdns, security-audit.

## Datapath

- `packet.rs`: bounded pool, headroom, `PacketMeta`, `pop_vlan`/`push_vlan`.
- `datapath.rs`: NIC RX → VLAN check/untag → PPPoE decap → `fwd::Forwarder` → (from the WAN: the
  ingress qdisc, `drain_ingress`) → neighbor (PPPoE: the AC) → qdisc → PPPoE encap → VLAN tag → NIC
  TX. PPPoE control frames → `ctrl_rx`.
- `Datapath::send_local` / `set_local_link` (docs/lan-neighbors.md step 2, not called yet): the
  router stack's own packets on a link without a link layer, next hop by `fwd::local`, then the
  same neighbor table and qdisc as forwarded packets; `LOCAL_NO_ROUTE` counts the rest.
- `stack.rs`: port bring-up + the **datapath direction tasks** `dp_down`/`dp_up` (`run_dir`):
  NAPI-style IRQ loop. Lock order NIC → forwarder shard → neighbor table → qdisc.
- Queues: CAKE is the default qdisc on both ports' egress and in the WAN ingress stage
  (`device.rs` `Aqm`), wrapped in `shaper::Shaper`.
  - WAN egress = upload rate.
  - The ingress stage (`Shared::ingress`, `Shaper::ingress`: drops and bypassing WAN traffic charged
    to the rate) = download rate. Forwarded WAN packets wait there before the neighbor lookup,
    drained by `dp_down`.
  - LAN egress unshaped, so traffic between networks runs at line rate.
  - Boot arguments `shape_up=`/`shape_down=` kbit/s, `shape_overhead=`.

## Coupling: `shared.rs`

The only coupling between the datapath and the services:

- Per port: locked qdisc + PPPoE `ctrl_rx`/`pppoe_session`, stats snapshot, `RateRing` (lock-free
  throughput history, 1 s × 5 min, written by `poll_links`; the WAN's is `/api/status`
  `interfaces[0].rate_history_kbit`, the overview chart).
- Per **link** `local_rx` (`LinkShared`): link 0 = WAN on port 0, links 1..`MAX_LINKS` = network
  slots on `lan0`, created at boot, switched on/retagged/readdressed live (`assign_slots`,
  `Networks` → `Datapath::apply`). Forwarder interfaces, ARP tables and smoltcp interfaces are per
  link; a VLAN network's tag is pushed when a frame is queued on the port.
- `Control` messages (WAN lease, zone `Policy`, reboot/exec), `dp_kick`/`svc_kick` events.

## smoltcp side: `device.rs`

smoltcp `Device` behind the datapath: RX from `local_rx`, TX into the qdisc.

- **smoltcp is IP-only on every link** (`Medium::Ip`, built without `medium-ethernet`;
  docs/lan-neighbors.md, docs/local-stack.md step 2). On a LAN link and a DHCP / static WAN
  (`HostIf::ip_only` = `LinkShared::ip_only`; the MAC is `HostIf::mac`) RX passes the IP packet
  only; TX goes through `Datapath::send_local` (next hop by `fwd::local`, the datapath's neighbor
  table). The datapath answers ARP / NS for the router's addresses (`Datapath::link_layer`,
  `fwd::nd`; counters `/api/status` `lan_nd`, switches `nd_unicast=0`, `na_router=0`) and keeps
  those frames from smoltcp. The per-link addresses and routes come from `stack::local_links`, the
  one source for both smoltcp's interfaces and the datapath (`set_local_links` after every
  `set_host_addrs`).
- The WAN's view (`stack::set_wan_local_link`) is read back from smoltcp's WAN interface at start
  and after every lease or address change (`svc::publish_wan`, `reapply_networks`); `restart_wan`
  switches DHCP / static ⇄ PPPoE live. Counters `/api/status` `wan_nd` (`medium` ip / ppp). On
  PPPoE the frame goes into the qdisc for the session's headers.
- Neighbor table limits: `neigh_secs=`, `neigh_probe=0`, `neigh_pending=0` (nothing held while
  resolving: the lab's first-contact control).
- `local.rs`: the router's own UDP without smoltcp (docs/local-stack.md steps 2b, 3): one port
  table per link owned by the module (`bind` / `recv`; the device offers every frame to `take`
  before smoltcp; bounded queue per port, `/api/status` `local_udp.dropped`), IPv4 and IPv6
  (`Ends`), `send` through `Datapath::send_local` or, on PPPoE, into the WAN qdisc; `source` =
  the datapath's view of the link (`Datapath::local_source`); headers by `fwd::udp`.
- `wan4.rs`: the WAN's DHCPv4 client (`proto_dhcp::v4::client`) on port 68 over `local`, events
  into `svc::lease_bound` / `lease_lost`; `/api/status` `wan_dhcp`.
- `RxTap` (`HostIf::tap`): the last RA a link received (the WAN's for `net::wan6`) and RS seen
  (`LinkShared::rs_seen`, the network's advertiser answers). No neighbor hints any more (removed
  with the fallbacks, 2026-11-26).
- Per-queue `Delay`: time waited summed, pings apart (`/api/status` per queue `delay`, the lab's
  latency-under-load check).

## Services task: `svc.rs`

`svc`, `Priority::Service`: smoltcp, the WAN DHCP client (`net::wan4`) or PPPoE, LAN
services, mgmt. A saved WAN change restarts the WAN live, DHCP ⇄ PPPoE included; static WAN via
`configure_static`. `LeaseStore`: see kernel/CLAUDE.md (store).

- `pppoe.rs`: svc side of `proto_pppoe::Client`: `ctrl_rx` in, frames into the WAN qdisc, `Session`
  → `PortShared::pppoe_session`, up/down → router-stack address + `LeaseChange`. The WAN interface
  is `Medium::Ip` in PPPoE mode. PADT at reboot/upgrade from the datapath.
- `services.rs`: per network a DHCP server + DNS, one resolver/zone, all UDP on `net::local`
  (step 3; smoltcp is built without `socket-udp`): DNS :53 per network's link (answers from the
  network's address), `services::Upstream` a fresh random upstream port per query on the WAN
  (bound in `local` and `CLIENT_PORTS`), DHCP :67 (replies broadcast from the network's address).
  With IPv6 an RA `Advertiser` per network, frames straight into the port qdisc; retired ones send
  a last RA.
- `dns_tcp.rs`: DNS over TCP from clients (RFC 7766): 4 TCP :53 sockets per network, framing in
  `proto_dns::tcp`, length-prefixed queries → `Resolver::handle_query_tcp`, answers by client
  endpoint, pipelining, bounded buffers, 10 s idle close; `/api/status` `dns.tcp`.
- `ntp.rs`: SNTP client on the WAN (a port in 60000–60999 on `net::local`, from the WAN's source
  address); names resolved through the forwarder as client `127.0.0.1:1`.
- `dot.rs`: DNS over TLS (docs/dns-over-tls.md): one `proto_dot::Conn` per `dns.upstreams` server
  over a smoltcp TCP socket on the WAN (local ports 61000–64999), opened on demand, 30 s idle close,
  backoff on failure, reconnect once SNTP sets the clock. Strict: with `dns.tls` no UDP upstream
  query and UDP answers ignored. Entropy from `entropy`, clock `wallclock`, build time floor
  `LEATOS_BUILD_TIME`.
- `wan6.rs`: the WAN's IPv6 (docs/ipv6.md steps 3–5a).
  - The WAN's own address `config::wan_address6` (::1 in the prefix's last /64); the ISP's IPv6 DNS
    servers after the lease's (`LanServices::set_dns6`).
  - The last prefix asked for again after a restart (lease record v2, `pd_keep=0` off).
  - The ISP's RA (default router; `RxTap::take_ra`), router solicitations,
    `proto_dhcp::v6::pd::Client` on UDP :546 (`net::local`, from the link-local address).
  - `wan6::state` feeds `config::wan6`/`gua_router`; changes reapply the networks
    (`svc::reapply_networks`).
  - On PPPoE while IPv6CP is up (`set_ppp_link` from `net::pppoe`): the WAN link-local address,
    `Forwarder::set_ll6`, default router = the RA's or the IPv6CP peer.
  - Not with the `wan6_*`/`lan6_prefix` boot arguments.
- `mdns.rs`: mDNS reflector glue inside `LanServices`: joins 224.0.0.251 (smoltcp `multicast`, its
  IGMP / MLD reports until step 4) and port 5353 on `net::local` per network a `[[mdns.reflect]]`
  entry involves (copies to the group with TTL 255, from the network's address / link-local),
  `proto_mdns::Reflector`, counters in `/api/status` `mdns` and CLI `status`.

## Management: `mgmt.rs` + `mgmt.html`

The web interface on :80.

- **Page:** one hash-routed page: overview, interfaces, clients, WAN, networks (VLANs, zone, DHCP
  per network), routes (table in use + `[[route]]` list), LAN & DHCP, DNS (upstreams, local names:
  `dns.views` + `[[dns.host]]` table), firewall (zones, rules, port forwards, redirects, mDNS
  reflect rules with warnings and counters), shaping, system, logs. Pending changes with a diff; a
  config form with import/export.
- **Login:** a screen covering the page (LuCI-style) via `POST /api/login` (Basic `admin` +
  `mgmt_pass=` boot argument, else the config's `mgmt.password_hash` via `crates/auth` PBKDF2,
  cached) returns a session token used as `Authorization: Bearer`, kept in `localStorage`;
  `POST /api/logout`. A 401 brings the screen back and the request is retried. `X-Leatos-UI: 1`
  suppresses `WWW-Authenticate`.
- **Who may do what:** with a password everything but `/` and `GET /api/info` (`{auth}`) needs auth,
  reads included (scripts: `curl -u admin:…`); without one reads are public and changes refused.
- **Origin checks** (before routing, `proto_http::check_browser_origin`): a `Host` that is not an
  address, single label or name in the router's DNS domains gets 421 (DNS rebinding); a non-GET from
  another `Origin` / `Sec-Fetch-Site: cross-site` 403 (CSRF). Counters `/api/status`
  `mgmt.refused`; docs/security-audit.md.
- **Lockout:** wrong passwords back off their source only (IPv4 address / IPv6 /64, 1 s doubling to
  30 s, `auth::Throttle`); PBKDF2 checks ≤ 4/s in all. 8 connection slots per network, one kept
  listening by cutting the oldest head-less connection of the source holding most
  (`mgmt_evict=0` off); request head within 5 s. `/api/status` `mgmt.throttle`.
- **Passwords:** a saved clear `mgmt.password` is hashed first (`Config::hash_new_password`, salt
  from `kernel/src/entropy.rs`) and ends all sessions.
- **API:**
  - `GET /api/status` (incl. `drop_reasons`, `mgmt.auth`, `routes`, per queue `delay`),
    `GET /api/log` (RAM log, auth).
  - `POST /api/upgrade` streamed into the staging area; `POST /api/upgrade/persist` (stored as a
    trial, reboot) + `/api/upgrade/confirm|revert`; `POST /api/reboot`.
  - `GET /api/config[.json]`, `GET /api/config/effective[.json]` (boot arguments applied: for moving
    them into the config).
  - `POST /api/config` (TOML or JSON): validate, save to the store, then apply live
    (`config::apply`, `stack::apply_qos`, `LanServices::reconfigure`); trials reboot.
    `POST /api/config/confirm|revert`: LAN/management changes boot as a trial that reverts without
    confirm (docs/config-and-storage.md §6).
