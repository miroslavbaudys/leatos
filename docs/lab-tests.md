# Tests

Which test covers what, how to run it, and its negative controls. Every check needs a negative
control (a setting under which it must fail), and a measurement without proof that the load
happened is INVALID. The per-variable reference of the lab is the header of `scripts/lab-test.sh`;
`scripts/doc-check.sh` (CI) fails when a `LAB_*` variable the lab scripts read is missing there.
Which test to run after which change: the table in CLAUDE.md.

Variables that work with any QEMU-based script:

- `QEMU_ACCEL=tcg`: run without hardware acceleration.
- `QEMU_SMP=4`: four cores. The smoke boot case then requires all cores online and the SMP self-test
  (negative control: `QEMU_APPEND=cores=1`).
- `QEMU_NIC=igb`: router NICs are QEMU's 82576 instead of virtio-net.
- `LEATOS_ARCH=x86_64`: the x86_64 kernel (TCG; the client and ISP VMs stay aarch64).
- `QEMU_STORE=img`: attach a store image as virtio-blk, or as an SD card with `QEMU_STORE_BUS=sd`
  (written in place).
- `QEMU_DISK=img scripts/qemu-run.sh`: boot any disk image.
- `QEMU_APPEND`: boot arguments (docs/boot-arguments.md).

## Smoke test: `scripts/smoke-test.sh`

- Cases: boot (DHCP + ping), fault-wx, fault-stack, panic (reboots), wdt-task (cross-core watchdog,
  2+ cores), wdt-hw (i6300esb with `cores=1`).
- Negative controls: `QEMU_APPEND=panic=halt`, `QEMU_APPEND=watchdog=0`, `QEMU_WDT=0`. QEMU gets
  `-device i6300esb` unless `QEMU_WDT=0`.
- `LEATOS_BOOT=limine scripts/smoke-test.sh` boots the apu4 image through SeaBIOS + Limine.

## Lab: `scripts/lab-test.sh`

A client VM, the router and an ISP VM (Alpine; overlays in `lab/client/`, `lab/isp/`, downloads in
`lab/cache/`, pinned by SHA-256 in `scripts/lab/fetch-alpine.sh`). The router always gets
`mgmt_pass=lab-pass`; `LAB_ROUTER_ARGS` adds boot arguments, `LAB_VERBOSE=1` prints the consoles.

### Default checks

- DHCP, DNS, NAT, ICMP, traceroute.
- DNS cache prefetch: ISP TTL 12 s; negative control `LAB_ROUTER_ARGS=dns_prefetch=0`.
- Serve-stale with the ISP's DNS stopped (via `cgi-bin/dns` / `lab-dns`), plus EDE 3 on a crafted
  EDNS query; negative control `LAB_ROUTER_ARGS=dns_stale=0`.
- DNS over TCP: big.isp.example (850 B TXT from the ISP's cacheless dnsmasq in front of dnsd)
  truncated over UDP, whole over TCP; negative control `LAB_ROUTER_ARGS=dns_tcp=0`.
- Full-size ICMP: `LAB_BIG_PING=1473 LAB_ROUTER_ARGS=fw_frag=0` is its negative control.
  Fragmented `ping -s 3000` both ways; negative control `LAB_ROUTER_ARGS=fw_frag=0`.
- Web interface origin checks, raw requests from the client: a rebound `Host` gets 421, a cross-site
  POST with Basic 403; address, `router.home.arpa`, same-origin and script requests pass.
  Negative control `LAB_ROUTER_ARGS=mgmt_origin=0`.
- Web interface lockout: a second client address guesses wrong passwords while the client's own
  logs in (always answered); 8 idle connections from it, the client is still answered and
  `mgmt.throttle.evicted` rises. Negative controls `LAB_MGMT_SAME_SOURCE=1`,
  `LAB_ROUTER_ARGS=mgmt_evict=0`.
- Firewall end to end.
- Client ports, from the router's WAN capture: the ISP's UDP probes to unbound client ports and 68
  draw no ICMP unreachable (any code), and they never reach the router's own UDP (the client's
  `local.udp_unbound` before and after); upstream DNS queries use many ports. Negative controls
  `LAB_ROUTER_ARGS=fw_client_ports=0` (the client's check), `"fw_client_ports=0
  udp_unbound_drop=0"` (the capture check), `dns_port_random=0`.
- Unbound UDP from the LAN: the client's UDP to router ports nobody bound is dropped by the
  router's own UDP (`local.udp_unbound` rises) and draws no ICMP unreachable (LAN capture).
  Negative control `LAB_ROUTER_ARGS=udp_unbound_drop=0`.
- The router's own TCP (docs/own-tcp.md): the web page byte-exact (SHA-256 against
  `kernel/src/net/mgmt.html`); a closed router port refused at once with a RST (negative control
  `LAB_ROUTER_ARGS=tcp_rst=0`: silent, the client's `nc` times out).
- Other protocols: the host injects 4 frames with IP protocol 253 (`LAB_OTHER_PROTO`) from the
  client to the router (`scripts/lab/inject.py`); the router drops them (`local.other_dropped`
  rises) and the LAN capture shows no ICMP unreachable back. Negative control `LAB_OTHER_PROTO=17
  LAB_ROUTER_ARGS=udp_unbound_drop=0` (UDP to port 9: a port unreachable comes back).
- WAN input silent to the ISP's probes (TCP 22, 80, 61000, ping). Negative controls
  `LAB_ROUTER_ARGS=mgmt=wan`, `LAB_WAN_OPEN=1` (a rule accepting wan → router).
- Router-side ECN per direction, from the router's counters (`LAB_EXPECT_ECN=U:D` for the negative
  control).
- SNTP from the ISP's ntpd, ±5 s of the host; negative control `LAB_ROUTER_ARGS=ntp=203.0.113.99`.
- Per-task CPU split (`dp_down`, `dp_up` vs `svc`, over the client's load phase, from `/api/status`
  `cpu.tasks`) and core placement.

### WAN variants

- `LAB_WAN_STATIC=1`: the ISP runs no DHCP server; the router gets
  `wan_mode=static wan_ip=203.0.113.60/24 …`: static line + NATed source 203.0.113.60, all checks
  through it. The client's `wan arp` (ISP `cgi-bin/arp` forgets and re-ARPs the WAN address) must
  be answered by the datapath (`wan_nd` medium `ip`, `arp_replies` rising; docs/local-stack.md
  step 2). Negative control `LAB_ROUTER_ARGS=wan_mode=dhcp`. (`wan_medium=eth`, smoltcp
  answering, was the control of the datapath part until the fallback went, 2026-11-26.)
- Every IPv4 run without PPPoE: `wan arp`, the ISP's ARP for the router's WAN address answered.
  On a DHCP WAN also `dhcp wan ip-only` (docs/local-stack.md step 2b): medium `ip` and the
  router's own DHCP client bound at the end (`wan_dhcp`); negative control
  `LAB_WAN_LEASE=60 LAB_WAN_LEASE_STOP=1` (the lease lost: not bound).
- `LAB_WAN_LEASE=N`: the ISP's leases last N s; the router must renew during the run (a third
  reply taken) and never lose the lease. Negative control `LAB_WAN_LEASE_STOP=1` (the ISP's DHCP
  server stopped first: lease lost).
- `LAB_PPPOE=pap|chap|none`: the ISP is rp-pppoe `pppoe-server` only (user mode). `none` = no
  authentication and no router user name (negative control `LAB_PPPOE=pap LAB_PPPOE_ANON=1`).
  - All checks run through the session, plus a reconnect after the ISP ends it.
  - IPv6CP comes up (IPv6 is on by default); with `LAB_ROUTER_ARGS=ipv6=0` the ISP's offer is
    logged and rejected instead (negative control for both `LAB_PPPOE_IPV6=0`).
  - With `LAB_IPV6=1`, IPv6 over the session instead (docs/ipv6.md step 4: pppd `ipv6-up` routes
    the prefixes over ppp0 and starts Kea there): IPv6CP line, PD, all IPv6 WAN checks, prefix
    change, IPv6 back after the reconnect. Negative controls `LAB_PPPOE_IPV6=0`, `LAB_IPV6_PD=0`.
  - The router splits the 1500 B fragments, checked by `fragments.split`; negative control
    `fw_split=0`.
  - Negative controls `LAB_ROUTER_ARGS=pppoe_pass=wrong` / `wan_mode=dhcp`, `LAB_PPPOE_KICK=stop`,
    `LAB_BIG_PING=1465 LAB_ROUTER_ARGS=fw_frag=0` (1465 alone passes: the client's DF ping learns
    MTU 1492 and fragments itself).
  - Combines with `LAB_VLAN=848`.
- `LAB_VLAN=N`: the ISP VM on VLAN N only (8021q from `modloop-virt`, `fetch-alpine.sh modloop`),
  the router on `wan_vlan=N`. Negative controls `LAB_ROUTER_ARGS=wan_vlan=0` / another VID.

### `LAB_TCP_LOSS=N`: loss on the path to the router's TCP

A relay (`scripts/lab/relay.py`) between the router's LAN NIC and the client drops N % of the TCP
frames in both directions (nothing else). The default checks run through it; the web page must
still arrive byte-exact. Valid only if the relay dropped frames and the router retransmitted
(`local.tcp.retransmits` over the page), else INVALID. Negative control `LAB_TCP_LOSS=100`
(nothing gets through: the page and the other TCP checks fail).

### `LAB_TCP_RST=blind`: blind RSTs into the router's TCP (RFC 5961)

The same relay (0 % loss unless `LAB_TCP_LOSS` is set) knows the router's next expected sequence
number from the client's last segment. The client leaves a request to the web interface
half-sent for 4 s; meanwhile the relay injects RSTs with the client's addresses and ports, four
in the window but off the exact number and one far outside it. The request must still be
answered and `local.tcp.challenge_acks` rise (else INVALID: the RSTs missed the window); INVALID
too if the relay injected nothing. Negative control `LAB_TCP_RST=exact` (one RST at the exact
number: the connection ends, the check fails). No shaping phase, ECN or queue checks.

### `LAB_DOT=1`: DNS over TLS (docs/dns-over-tls.md)

- The router boots from a store with `dns.tls`, upstream the ISP's stunnel + dnsmasq on :853 (a CA
  made per run, in `dns.tls_ca`).
- The client resolves `dot.isp.example` (DoT server only), not `plain.isp.example` (plain dnsd
  only); the router's connection and the ISP's query log are checked.
- Negative controls `LAB_DOT_NAME=wrong.example`, `LAB_DOT_CA=0`, `LAB_ROUTER_ARGS=dns_tls=0`.
- Certificate dates before SNTP: the RTC on x86_64, the issue time on aarch64 (`LAB_EXPECT_DATES`).
  RTC control: `LEATOS_ARCH=x86_64 QEMU_EXTRA="-rtc base=2040-01-01" LAB_EXPECT_DATES=expired`
  (DNS keeps working, the RTC is corrected after SNTP).

### `LAB_GUEST=1`: networks, zones, rules, forwards

The router boots from a store with a second network (VLAN 20, zone guest) and two rules; the client
adds eth0.20.

- Guest lease, ISP, allowed DNS and ping, blocked web interface, refused main LAN (router firewall
  drop counter).
- Rule guest-ping-nas (accept, hit counter) and guest-no-isp-web (reject guest TCP 80 to the WAN).
- Port forward lab-web (WAN :8080 → the client): the ISP fetches through it
  (`lab/isp/www/cgi-bin/fetch`), the client through the WAN address (hairpin).
- The guest network's own DNS domain `guest.home.arpa`: lease domain, `labguest.guest.home.arpa`,
  `router.guest.home.arpa`, `labclient.guest.home.arpa` NXDOMAIN.
- Redirect lab-ntp (UDP 123 → 192.168.1.101, a second client address running `busybox ntpd -l`):
  NTP to 203.0.113.99 answered from the main LAN and from the guest, hit counter.
- Forward target out: forward lab-src (WAN :8090 → client :8090); a connection from the client's
  :8090 reaches the ISP (`cgi-bin/srcport`) from the WAN's :8090 and survives a live rule change
  (`cgi-bin/slow`; negative control `LAB_FWD_CUT=1`).
- Anti-spoofing: the ISP connects to the forward from the forged source 192.168.1.77
  (`cgi-bin/spoof`): dropped as `spoofed`, forward hits unchanged.
- Reject: the refused guest HTTP fails at once with a RST (`rejected` counter).
- Recheck: a running guest ping stops when a live config takes the guest zone's internet away
  (`revoked`).
- LAN to guest (WAN ingress shaping): eth0.20 moves into its own network namespace and serves 5 MB
  to the main LAN through rule lab-lan-to-guest (TCP 8081), faster than twice the download rate.
- Negative controls:
  - `LAB_ROUTER_ARGS=shape_ingress=0`: LAN to guest fails (held to the download rate).
  - `LAB_GUEST_ZONE=lan`: isolation fails.
  - `LAB_GUEST_RULES=0`: both rule checks fail.
  - `LAB_GUEST_REJECT=drop`: the reject check fails.
  - `LAB_ROUTER_ARGS=fw_recheck=0`: the recheck check fails.
  - `LAB_ROUTER_ARGS=wan_antispoof=0`: the anti-spoofing check fails.
  - `LAB_FORWARD=0`: forward, hairpin and forward-target-out fail.
  - `LAB_REDIRECT=0`: both redirect checks fail.
  - `LAB_GUEST_DOMAIN=0`: lease domain, labguest and router checks fail.
- `LAB_GUEST_LIVE=1`: the router boots with the main LAN only and the client adds the rest live
  through `/api/config` (combines with the controls).

Modes that imply `LAB_GUEST=1`:

- `LAB_DNS_VIEWS=1` (docs/dns-views.md): `dns.views = "firewall"` + `[[dns.host]]`
  split.home.arpa per network (its entries' hits rise) + files.isp.example overridden for the
  LAN. From the guest, labclient.home.arpa and its PTR are NXDOMAIN (`hidden` counter);
  nas.home.arpa still resolves (rule guest-ping-nas). Negative controls `LAB_DNS_VIEWS=0`,
  `LAB_DNS_HOSTS=0`, `LAB_GUEST_RULES=0`.
- `LAB_MDNS=1` (docs/mdns.md): rule guest-printers reflects `_ipp._tcp` guest → lan. The client
  announces on VLAN 20 (crafted, `nc -u`), checked by the router's counters and on the LAN capture
  (copy from 192.168.1.1, TTL 255, `_ipp` only; IGMP joins on both networks, with `LAB_IPV6=1`
  also the MLDv2 report with ff02::fb from the router's link-local address: `net::groups`).
  Negative controls `LAB_MDNS_RULES=0`, `LAB_ROUTER_ARGS=groups=0` (no reports: both join checks
  fail).
- `LAB_ROUTES=1`: `[[route]]` lab-behind 10.30.0.0/24 via the client, 10.30.0.5 on its loopback:
  option 121 (route + default), NAT to the ISP and ping to the router from 10.30.0.5, `/api/status`
  `routes`, the ISP forging 10.30.0.5 dropped as `spoofed` (`cgi-bin/spoof?8080&src=`); the
  router's own answers to 10.30.0.5 over UDP (DNS `router.home.arpa`) and TCP (`GET /api/info`) with
  `lan_nd.local_no_route` unchanged. Negative control `LAB_ROUTES=0` (route disabled).
- `LAB_PORTS=1`: the router gets a third NIC (`lan1`, `LAB_LAN1_PORT`), network wired 10.40.0.1/24
  untagged on it; the client's second NIC (`VM_NIC2` in `scripts/lab/common.sh`) moves into a
  network namespace: lease, ping router and ISP, `/api/status` wired on lan1, lan0 → lan1 above
  twice the download rate. Negative control `LAB_PORTS_NET=lan0` (VLAN 40 on lan0: no lease on the
  lan1 wire). With `LAB_GUEST_LIVE=1` the network is added live.

### `LAB_IPV6=1`: IPv6 (docs/ipv6.md)

- Prefix delegation (step 3): the ISP VM runs dnsmasq RAs + Kea (`lab-kea`, `fetch-alpine.sh kea`,
  `LAB_INITRD_KEA`); the router gets `ipv6=1 wan_mtu=1400` only. Checks the delegated
  2001:db8:100::/56 and a prefix change to 2001:db8:200::/56 (`cgi-bin/pd?change`: new address, old
  deprecated, ping through it). Negative control `LAB_IPV6_PD=0`.
- Step 5a: WAN address + router source in status; the router's DNS over IPv6 via the ISP's
  IPv6-only resolver with its IPv4 DNS stopped (negative control `LAB_IPV6_DNS6=0`). With a store
  (`LAB_GUEST=1`) the prefix is kept across a reboot while Kea forgot it (`cgi-bin/pd?fresh`;
  negative control `LAB_ROUTER_ARGS=pd_keep=0`; router-side checks read the log up to that
  reboot).
- Step 1 (router `ipv6=1`): SLAAC address from the main LAN's ULA /64, no default route (router
  lifetime 0), ping the router's ULA and link-local, `router.home.arpa` AAAA over IPv6, web
  interface on the ULA, RA counters. With `LAB_GUEST=1`: the guest's ULA, DNS over IPv6 allowed,
  web refused, RS answered. Negative controls `LAB_ROUTER_ARGS=ipv6=0` (every IPv6 check fails),
  `LAB_GUEST_ZONE=lan` (guest web-refused fails).
- The WAN side (step 2b): the ISP VM gets 2001:db8:ffff::1/64 and routes 2001:db8:100::/56 to the
  router (`wan6_ip=… wan6_gw=… lan6_prefix=… wan_mtu=1400`, IPv4 big ping 1372).
  - Global SLAAC + default route, ping6/HTTP to the ISP, the ISP sees the client's own address,
    traceroute6.
  - Inbound refused (`cgi-bin/fetch` back to `[::]:8086`), Packet Too Big (`icmp_errors` rises), a
    forged source `spoofed`, the guest's global address out, fragmented `ping6 -s 3000` both ways
    (negative control `LAB_ROUTER_ARGS=fw_frag=0`).
  - Negative controls `LAB_IPV6_OPEN=1` (a wan → lan accept rule: inbound reaches the client),
    `LAB_ROUTER_ARGS=wan_mtu=1500` (no PTB), `LAB_ROUTER_ARGS=lan_antispoof=0`.
  - An unused /64 of the prefix is unreachable at the router (`/api/status` `unreachable6`);
    negative control `LAB_ROUTER_ARGS=v6_unreachable=0`.
- `LAB_ND_FLOOD=1` (implies `LAB_GUEST=1` and `LAB_IPV6=1`): the WAN's IPv6 neighbor cache under a
  flood (docs/security-audit.md §4.2). Rule lab-wan-ping6 lets the ISP ping the router's WAN
  address from 2001:db8::/32; the ISP (`cgi-bin/ndflood`) pings it once from each of 1500
  addresses of 2001:db8:eeee::/64, whose replies all go via the router's default router: at most
  2 lost. INVALID unless 100+ were answered. Its negative control was `wan_hints6=all` (every
  source into smoltcp's cache: 10 of 1500 lost in the first run), gone with the hints
  (2026-11-26): the datapath's table holds on-link neighbors only.
- Neighbor discovery as a client sees it (pd mode, docs/lan-neighbors.md §4): with a 2 s reachable
  time and a 1 s probe delay the client keeps probing the router (its default router) with unicast
  NS while it pings the ISP through it for 15 s: no resolution fails (`res_failed` in
  `/proc/net/stat/ndisc_cache`) and the default route stays. INVALID unless the router sent NAs
  (`lan_nd.na_sent`). Negative controls `LAB_ROUTER_ARGS=nd_unicast=0` (resolutions fail) and
  `na_router=0` (the default route goes).
- `LAB_IPV6=static`: step 2b's boot arguments.
- `LAB_GUEST_IPV6=0` (with `LAB_GUEST=1`): the guest network has `ipv6 = false`: no IPv6 reported
  there, no SLAAC address, its IPv6 dropped as `unsupported`. Negative control
  `LAB_GUEST_IPV6_CONTROL=1`.

### `LAB_NEIGH=1`: neighbor tables

Unshaped unless `LAB_SHAPE_KBIT` is set; router `neigh_secs=10`. The client pins the router's MAC
(never ARPs) and pings the router from `LAB_NEIGH_HOSTS` (40) addresses of its own, 3 rounds,
without loss (round 1 = first contact: each answer waits in the datapath's neighbor table while it
ARPs; rounds 2–3 find them resolved), then downloads for `LAB_NEIGH_SECS` (35) across several
neighbor lifetimes with no `neighbor` drops and some probes. Negative controls
`LAB_ROUTER_ARGS=neigh_pending=0` (nothing waits: round 1 fails), `LAB_ROUTER_ARGS=neigh_probe=0`
(forwarded). The old controls (`lan_medium=eth arp_hints=0`, `LAB_NEIGH_CACHE=8`) went with the
smoltcp path on 2026-11-26; rounds 2–3 guarded smoltcp's 8-entry cache, the datapath's table has
no such limit.

Two more parts (docs/lan-neighbors.md §4):

- **Readdress** (with `LAB_GUEST=1` or `LAB_GUEST_LIVE=1` for the store, and `LAB_IPV6=1`): the
  LAN's ULA prefix moved to fd99:1:2::/48 and back by two live `/api/config` saves (as a new
  delegated prefix would), then a fourth IPv4 round loses nothing; INVALID unless the router showed
  the new ULA. It guarded smoltcp emptying its cache on every address update (40 of 40 lost on
  the old path, its negative control until 2026-11-26); no control now.
- **Conflicts** (`lan_nd.conflicts`): an RFC 5227 probe for 192.168.1.1 is answered and counted, a
  gratuitous claim from the client's MAC counted, the router still answers ARP after; a claim
  for another address and one from the router's own MAC (eth0 set to it for a moment) are the
  controls that must not count.
- **Local queue** (`lan_nd.local_queued` / `local_dropped`): in round 1 the router's first answer to
  each new address waits for ARP, so `local_queued` rises by at least one per address and
  `local_dropped` stays; rounds 2–3 are INFO. Negative control
  (2026-11-25, a one-off build without the `LOCAL_QUEUED` increment): FAIL "not counted".

### `LAB_ACK=1`: ACK filter

CAKE's ACK filter on an asymmetric line (upload `LAB_ACK_UP_KBIT`, default 150 kbit/s, with
`ack_filter=1`; download 10 Mbit/s): the client runs only the download, whose ACKs queue on the
upload; checks the router's wan0 `ack drops` and the download arriving whole. Negative control
`LAB_ACK_FILTER=0`.

### `LAB_SWARM=1`: many flows

256 flows (`LAB_SWARM=N` for N; 64 are too few to fill the queue at the lab's ~1 ms RTT): a
torrent-like download, shaped at `LAB_SWARM_KBIT` (98000), N parallel loops of 256 KB HTTP
downloads with MTU `LAB_SWARM_MTU` (680) for `LAB_SWARM_SECS` (15), HVF only (TCG cannot reach the
rate: INVALID). The ingress queue's `overflow_drops` must stay ≤ `LAB_SWARM_OVF` (10) % of its drops
(`/api/status` `ingress`); invalid unless the queue was pushed and half the rate moved. The usual
shaping phase is skipped. Negative control `LAB_ROUTER_ARGS=queue_pkts=384`.

### `LAB_UPLOAD=N`: parallel uploads (info only)

N parallel TCP uploads from the client to the ISP's byte sink (port 5001) for `LAB_UPLOAD_SECS`
(30), upload shaped at `LAB_UPLOAD_KBIT` (18000, the home line), download 98000; the usual shaping
phase is skipped. No check: prints the router's `qdisc wan0` lines (max sojourn, overflow drops,
backlog, flows) and the client's `/api/status` deltas, to compare with the apu4
(docs/bufferbloat-cake.md, 2026-11-23: 16 macOS uploads ~500 ms there, Linux ~45 ms here).

### `LAB_BIDIR=N`: both directions at once (info only)

N downloads from the ISP's zero source (port 5002) and N uploads to its sink (5001) at the same
time for `LAB_BIDIR_SECS` (20), unshaped, so both datapath cores use the same NICs at once (each
port's NIC lock: RX by one direction, TX by the other, docs/smp.md). The usual shaping phase is
skipped. No check: the client prints the rates (lan0 / wan0 `tx_bytes`), packets forwarded,
the `/api/status` `nic_lock_waits` deltas and the datapath tasks' CPU time; INVALID if a
direction moved under 1 Mbit/s.

## Feature tests

- `scripts/store-test.sh` (also `LEATOS_ARCH=x86_64`): store read at boot, config save via the web
  interface + reboot, trials (confirm, timeout, revert, kill during the trial), corruption negative
  controls. Also with `QEMU_STORE_BUS=sd` (and `STORE_MIB=4096` for SDHC).
- `scripts/lease-test.sh` (also `LEATOS_ARCH=x86_64`, `QEMU_STORE_BUS=sd`): router + lab client:
  leases listed and resolvable after a power cut (router killed after its periodic save) and after
  `POST /api/reboot`; each one `"restored":true` in `/api/status` (expiry an upper bound) until the
  client asks for it again, then `false`. Negative control `LEASE_TEST_NO_STORE=1`; a restore that
  leaves the flag clear fails the "marked restored" checks.
- `scripts/cli-test.sh` (also `LEATOS_ARCH=x86_64`, `QEMU_STORE_BUS=sd`): types into the UART via a
  FIFO on QEMU's stdin. Runs with the RAM log (the other scripts get `log=console` from
  `qemu-run.sh`). Negative controls `CLI_TEST_SKIP_SAVE=1`, `CLI_TEST_LOG=console`.
- `scripts/pppoe-test.sh` (also `LEATOS_ARCH=x86_64`): the ISP VM as a PPPoE-only AC, the router
  driven over the CLI: DHCP → PPPoE live (password never printed), PADT at reboot + PPPoE from the
  store, back to DHCP. Negative control `PPPOE_TEST_SKIP_SAVE=1`.
- `scripts/vlan-test.sh` (also `LEATOS_ARCH=x86_64`): WAN VLAN changed live through the CLI (lease
  lost when tagged against slirp, regained when untagged; shaper overhead +4 B and back), then a
  static WAN live (10.0.2.50 on slirp, the gateway pings answer) and back to DHCP. Negative control
  `VLAN_TEST_SKIP_SAVE=1`.
- `scripts/upgrade-test.sh`: the in-RAM upgrade end to end in QEMU (401/422/404 negative controls,
  two chained upgrades, reboot).
- `scripts/install-test.sh` (also `QEMU_STORE_BUS=sd`; x86_64, TCG): the installer ISO as a
  CD, prompt answered on the console: fresh install (gaps zero, past the image untouched, GPT
  backup zero, the disk boots with its config), config kept, `install_target=` +
  `install_keep=0`, the ISO as a disk offers no disk. Negative controls: an unlisted address,
  an unconfirmed trial, a flipped module byte: nothing written, target hash unchanged
  (docs/install.md §4).
- `scripts/persist-test.sh` (also `QEMU_STORE_BUS=sd`): persistent upgrades, confirm, rollbacks
  (panic, hang, no confirm, revert, kill), `image=golden`, corrupt record. Negative control
  `PERSIST_TEST_CONTROL=no-confirm`.

## Measurements

- `scripts/bufferbloat.sh [--label X]`: latency idle vs. under download/upload load, throughput and
  grade. Runs are INVALID if the load failed; results go to `lab/cache/bufferbloat.csv`.
- `scripts/soak-test.sh [--host H] [--hours 72] [--interval 60] [--label X]` (M9): polls
  `/api/status` into `lab/cache/soak-LABEL.csv`. FAIL on a reboot, a rising heap minimum or a
  falling free-pool maximum (first vs. last window after warm-up and once the DNS cache is full:
  it grows once to `dns.cache_entries`), INVALID without enough forwarded packets, coverage or room
  for both windows; `--report CSV` judges a run so far. It only observes: the load comes from real
  use (the apu4) or another driver. Negative controls (on the 457cb97 apu4 CSV with a synthetic
  `dns_cached`): a 50 KiB/h heap leak and a cache full from the start FAIL, a cache filling until
  the last window is INVALID.

## Fuzzing

`cd fuzz && cargo +nightly fuzz run <target> -- -max_total_time=600` (own workspace, nightly;
fuzz/README.md). Run the targets of crates you changed, and `cargo +nightly fuzz build` after
changing a fuzzed crate's API. A crash becomes a host regression test in its crate before the fix.
