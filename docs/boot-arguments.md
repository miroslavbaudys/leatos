# Boot arguments

Kernel runtime options come from the kernel command line: DTB `/chosen/bootargs` on aarch64, the
PVH / Multiboot2 command line on x86_64, QEMU `-append` via `QEMU_APPEND`. They are parsed in
`kernel/src/config.rs` (`arg`, `arg_u64`, `arg_of`), always as `key=value` (`lan=` does not match
`lan_x=`).

- **Precedence:** compiled-in defaults ← stored `config.toml` ← boot arguments
  (docs/config-and-storage.md). An argument with a config field overrides it and is listed by
  `config::overrides()` (shown on the web form); `GET /api/config/effective` shows the config with
  them applied, for moving them into the store. The others are boot-argument only: platform knobs,
  tests and the lab's negative controls.
- **Secrets:** `mgmt_pass=` and `pppoe_pass=` are masked in logs (`config::Redacted`).
- **Scripts:** `scripts/qemu-run.sh` adds `log=console` unless `QEMU_APPEND` sets `log=`;
  `scripts/lab-test.sh` passes extra ones via `LAB_ROUTER_ARGS` (docs/lab-tests.md).
- **Completeness:** `scripts/doc-check.sh` (CI) fails when an argument the kernel parses has no row
  here. Each row starts with `` | `name= ``.

## WAN

| Argument | Config field | Meaning |
|---|---|---|
| `wan_mode=pppoe\|dhcp\|static` | `wan.mode` | how the WAN gets its address |
| `wan_vlan=N` | `wan.vlan` | 802.1Q tag on the WAN, `0` = untagged |
| `wan_pcp=0..7` | `wan.vlan_pcp` | priority bits of that tag |
| `wan_ip=a.b.c.d/len` | `wan.static.ipv4` | static WAN address; without a stored `[wan.static]` both `wan_ip=` and `wan_gw=` are needed |
| `wan_gw=a.b.c.d` | `wan.static.gateway` | static WAN gateway |
| `wan_dns=a,b` | `wan.static.dns` | static WAN DNS servers |
| `wan_mtu=N` | – | Ethernet WAN MTU, both families |
| `pppoe_user=` | `wan.pppoe.username` | optional: empty = no authentication |
| `pppoe_pass=` | `wan.pppoe.password` | masked like `mgmt_pass=` |
| `pppoe_service=` | `wan.pppoe.service` | service name in discovery |
| `pppoe_ac=` | `wan.pppoe.ac_name` | access concentrator to pick |
| `pppoe_mtu=N` | `wan.pppoe.mtu` | 1280–1500; above 1492 = RFC 4638: PPP-Max-Payload in discovery, MRU 1500 only if the AC echoes it, a full-size LCP echo must pass, else back to 1492 |

## LAN

| Argument | Config field | Meaning |
|---|---|---|
| `lan=a.b.c.d/len` | `network.*.ipv4` | the LAN subnet; pool .100–.199 |

## Shaping and queues (docs/bufferbloat-cake.md)

| Argument | Config field | Meaning |
|---|---|---|
| `shape_up=N` | `shaping.up_kbit` | upload rate in kbit/s (WAN egress) |
| `shape_down=N` | `shaping.down_kbit` | download rate in kbit/s (the WAN ingress stage) |
| `shape_overhead=N` | `shaping.overhead` | bytes added per packet, default 0 |
| `shape_ingress=0` | – | download shaped on LAN egress instead of the ingress stage (the pre-M10 design), which also caps traffic between networks: the lab's negative control for its LAN-to-guest check |
| `ecn_up=0\|1` | `shaping.ecn_up` | ECN marking on upload, default 0 = drop |
| `ecn_down=0\|1` | `shaping.ecn_down` | ECN marking on download, default 1 = mark |
| `ecn=0\|1` | `shaping.ecn_up`, `shaping.ecn_down` | sets both; `ecn_up=` / `ecn_down=` win |
| `qdisc=cake\|fq_codel\|codel` | `shaping.qdisc` | `cake` default; `codel` = a single queue |
| `isolation=triple-isolate\|dual-srchost\|dual-dsthost\|flows` | `shaping.isolation` | CAKE host isolation, `triple-isolate` default |
| `queue_ms=N` | `shaping.queue_ms` | a shaped queue's byte limit as time at its rate, default 100; `0` = the fixed 384 × 1514 B (`config::Qos::queue_limit`) |
| `ack_filter=0\|1` | `shaping.ack_filter` | CAKE's ACK filter on WAN egress, default off (`crates/qdisc/src/ack_filter.rs`) |
| `queue_pkts=N` | – | every queue's packet limit, default `config::QUEUE_PACKETS` = 2048, byte ceiling N × 1514; `384` is the swarm check's negative control |
| `igb_itr_us=N` | – | igb RX interrupt moderation (`EITR0`): at most one RX interrupt per N µs under load, immediate after a quiet interval; default `config::IGB_ITR_US` = 0 = none until measured on the apu4 (docs/bufferbloat-cake.md §7); max 8191; TX always unmoderated |

## DNS and time

| Argument | Config field | Meaning |
|---|---|---|
| `dns=ip#name,…` | `dns.upstreams` | upstream servers; `dns=` = the WAN lease's |
| `dns_tls=0\|1` | `dns.tls` | strict DNS over TLS: fails closed, unnamed servers dropped |
| `dns_prefetch=0\|1` | `dns.prefetch` | default on: cache hits in the last tenth of the TTL renew the entry |
| `dns_stale=SECS` | `dns.stale_secs` | serve-stale (RFC 8767), default 86400, `0` = off |
| `dns_tcp=0` | – | no DNS over TCP from clients: the lab's negative control |
| `dns_aaaa=0` | – | no AAAA names for DHCP clients from neighbor discovery: the lab's negative control |
| `client6_probe=N` | – | every N s (default 300) the router solicits each lease's EUI-64 address and the clients' known IPv6 addresses not seen since the last round (`net::services`); `0` = never: the lab's negative control (the lab uses 2) |
| `client6_dad=0` | – | the targets of DAD probes not noted as the clients' addresses: the lab's negative control |
| `dns_port_random=0` | – | one upstream DNS port per boot: the lab's negative control for its port check |
| `ntp=a,b` | `time.ntp_servers` | SNTP servers; `ntp=` = off |

## IPv6 (docs/ipv6.md)

| Argument | Config field | Meaning |
|---|---|---|
| `ipv6=0\|1` | `ipv6.enabled` | IPv6 (default 1): link-local + ULA and global /64 per network, RAs, DNS, web, forwarding |
| `wan6_ip=addr/len` | – | development IPv6 WAN (step 2b; DHCPv6-PD replaces it): the WAN's address |
| `wan6_gw=addr` | – | development IPv6 WAN: its gateway |
| `lan6_prefix=prefix` | – | development IPv6 WAN: network `i` gets `<prefix>:<i>::/64` |
| `lan_antispoof=0` | – | IPv6 from a network with a source outside its /64s not dropped: the lab's negative control |
| `v6_unreachable=0` | – | the delegated prefix's unused /64s go out the default route instead of ICMPv6 no-route (RFC 7084 WPD-5): the lab's negative control |
| `pd_keep=0` | – | don't ask for the last delegated prefix again after a restart: the lab's negative control |

## Firewall, forwarding, neighbors

| Argument | Config field | Meaning |
|---|---|---|
| `conn_per_host=N` | – | connections one initiating host may hold, default a quarter of the 16384-entry table, `0` = no limit |
| `fw_client_ports=0` | – | UDP to the whole router client range from anyone (the old behaviour): the lab's negative control for its client-port check |
| `udp_unbound_drop=0` | – | UDP to a router port nobody bound gets an ICMP port unreachable (`net::local::other`) instead of being dropped silently: the lab's negative control for its unbound-UDP checks |
| `tcp_rst=0` | – | TCP to a router port nobody listens on is dropped silently instead of answered with a RST (`proto_tcp`): the lab's negative control for its closed-port check |
| `fw_recheck=0` | – | a new firewall policy leaves tracked connections alone: the lab's negative control |
| `fw_frag=0` | – | IP fragments dropped instead of forwarded: the lab's negative control |
| `fw_split=0` | – | non-DF packets above the egress MTU dropped as `too-big` instead of split: the lab's negative control |
| `wan_antispoof=0` | – | WAN packets from our own networks' or loopback sources not dropped as `spoofed`: the lab's negative control |
| `nd_unicast=0` | – | the datapath ignores unicast NS for the router's addresses (as smoltcp did): the lab's negative control |
| `na_router=0` | – | the datapath's NAs without the Router flag: the lab's negative control |
| `neigh_secs=N` | – | the forwarder's neighbor lifetime, default 300 (tests) |
| `neigh_probe=0` | – | entries in use dropped at the end of their lifetime instead of probed: the lab's negative control |
| `groups=0` | – | no IGMP / MLD reports for the router's groups (`net::groups`: mDNS, solicited-node, all-routers): the lab's negative control for the mDNS join checks (`LAB_MDNS=1`) |
| `neigh_pending=0` | – | the neighbor table holds no packet while it resolves a neighbor (default `fwd::neigh::MAX_PENDING` = 3): the first packet to an unknown neighbor is dropped; the lab's negative control for first contact (`LAB_NEIGH=1`) |

## Management and configuration

| Argument | Config field | Meaning |
|---|---|---|
| `mgmt_pass=` | – | the web interface password (enables upgrade, reboot, config save); masked in logs; else `mgmt.password_hash` |
| `mgmt=wan` | – | web interface on the WAN too: development only |
| `mgmt_evict=0` | – | no idle connection cut to keep a web interface slot free: the lab's negative control |
| `mgmt_origin=0` | – | no `Host` / `Origin` check on the web interface: the lab's negative control for its DNS-rebinding and CSRF refusals |
| `config=defaults` | – | ignore the stored config (recovery) |
| `trial_secs=N` | – | confirm window of a trial config or kernel, default 120 (tests) |
| `image=golden` | – | ignore stored kernels (recovery); `image=` is otherwise set by the loader / an in-RAM upgrade (docs/upgrades.md) |

## System

| Argument | Config field | Meaning |
|---|---|---|
| `cores=N` | – | use at most N cores (docs/smp.md) |
| `idle_spin_us=N` | – | hybrid idle spin window, default 4000 on virtual machines, 0 on hardware (`timer::set_spin_window`) |
| `watchdog=0` | – | no watchdog (gdb) |
| `watchdog_secs=N` | – | hardware watchdog timeout, default 30 |
| `panic=halt` | – | halt instead of rebooting on panics and exceptions |
| `log=console` | – | log messages stay on the serial console after boot instead of the RAM log |
| `store_id=<16 hex digits>` | – | use only the store with this ID (store header, `leatstore id`); none if no disk has it. `scripts/apu-image.sh` passes its store's: a machine with two leatos disks uses the one it booted from (docs/install.md §3.5). Without it: the first store found, with a warning when there are several |
| `install=1` | – | run the installer instead of the router (docs/install.md): write the boot module (install image) to a disk after a confirmation, keeping its config; set by the ISO's Limine entry |
| `install_target=<PCI address>` | – | with `install=1`: write this disk without asking (e.g. `00:04.0`, as the installer lists it) |
| `install_keep=0` | – | with `install=1`: do not carry the target's stored config over |
| `module_carve=0` | – | lab only: the heap does not leave the boot module (install image) out, so it overwrites it and the image's hash fails (docs/install.md §3.2: the negative control) |
| `heap=list` | – | the old first-fit linked-list allocator: the heap bench's control, fallback |
| `ct_bench=1` | – | time conntrack operations on a full synthetic table at boot (`selftest::conntrack_bench`) |
| `heap_bench=N` | – | time alloc/free and a conntrack fill + expiry pass on the fresh heap, then with N 64-byte holes in front of the free space (`selftest::heap_bench`); `heap_bench=1` and `heap=list` are its controls |
