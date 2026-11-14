# SOHO feature specification: PPPoE, DHCP, DNS

These are the requirements and the known pitfalls, gathered during the initial
analysis. Each protocol is implemented as a sans-IO `no_std` crate (see
architecture.md).

## PPPoE
Crate: `crates/proto-pppoe`. Status: not started.

| Stage | Details |
|---|---|
| Discovery (EtherType `0x8863`) | PADI (broadcast) → PADO → PADR → PADS (session ID); PADT terminates. Handle multiple concentrators, Service-Name and AC-Name filtering, Host-Uniq |
| Session (`0x8864`) | PPP frames inside the PPPoE header. On bare metal the forwarding plane does the encapsulation (no kernel PPP driver) |
| LCP | MRU 1492, magic number, auth protocol; **echo request/reply keepalive** (for example a 10 s interval, 5 failures → reconnect) |
| Auth | PAP (most common at ISPs), CHAP-MD5 |
| IPCP | IPv4 address + DNS servers (RFC 1877 options 129/131) |
| IPv6CP | interface identifier → link-local address; then DHCPv6-PD over the session |

Pitfalls:
- **MTU and MSS:** the WAN MTU is 1492, so **clamp TCP MSS** (1452 for IPv4)
  on SYNs crossing the WAN. Without clamping, some websites hang.
- **ISP VLAN:** many ISPs require PPPoE on a VLAN tag (some Czech ISPs, for
  example O2 with VLAN 848; verify per ISP). Make `wan.vlan` configurable.
- RFC 4638 (MTU 1500 over PPPoE) is optional and only works if the ISP supports it.
- Reconnect with exponential backoff. Send PADT on shutdown so the ISP
  doesn't keep a stale session. Handle forced daily disconnects.
- On multi-core hardware, NIC RSS can't hash inside PPPoE, so all traffic
  lands on one core. This doesn't matter for single-core QEMU.

## DHCP
Crate: `crates/proto-dhcp`. Status: v4 server done (M3); clients and v6 pending.

### DHCPv4 server (LAN), required
**Status (M3): implemented** in `crates/proto-dhcp/src/v4/` (17 tests,
including fuzzing) and wired up in `kernel/src/net/services.rs`. Done:
DORA, static reservations, offer hold, returning client gets the same IP,
renew/rebind, INIT-REBOOT, NAK, RELEASE, DECLINE (10 min hold), INFORM,
expiry, hostname sanitising, and `Bound`/`Released` events to DNS. Replies
are always broadcast. Open: lease persistence (M8), conflict probe, option
121, multiple pools/VLANs, relay.

- Pools, static reservations by MAC, lease time, T1/T2, DECLINE, RELEASE, INFORM.
- Options: 1 subnet mask, 3 router, 6 DNS (= router IP), 15/119 domain, 42 NTP,
  12 hostname (from the client), optionally 121 classless routes.
- Lease persistence: in memory, flushed periodically and on shutdown. Batch
  writes to limit flash wear.
- Optional ARP or ICMP probe before handing out an address.
- Emit `LeaseAdded{mac, ip, hostname}` so the DNS zone resolves `host.lan`.
- One pool per LAN or VLAN (guest network later).

### DHCPv4 client (WAN, non-PPPoE ISPs)
- DISCOVER, OFFER, REQUEST, ACK, then renew, rebind and expire. Must work
  before the interface has an IP address (raw L2 frames).
- Some ISPs need option 60/61 or MAC cloning.
- smoltcp has a DHCPv4 client socket that may cover this.

### DHCPv6-PD client (WAN), required
- SOLICIT, ADVERTISE, REQUEST, REPLY with an IA_PD prefix-size hint (/56).
- Renewals, and **prefix changes** (some ISPs rotate prefixes): re-address
  the LAN and send deprecating RAs.
- Split the delegated prefix into /64s, one per LAN or VLAN.

### IPv6 on the LAN
- Router Advertisements with the prefix (SLAAC), **RDNSS** (RFC 8106) and the M/O flags.
- **Android doesn't support DHCPv6**, so SLAAC with RA is mandatory. A
  stateful DHCPv6 server is optional.

## DNS
Crate: `crates/proto-dns`. **Status (M3): forwarder implemented** (15
tests, including fuzzing): local `.lan` zone (router, static hosts, DHCP
hostnames, PTR for the LAN subnet; never forwarded), bounded cache with
TTL aging and negative caching, upstreams from the WAN lease, random
transaction IDs, response validation (server + question), merging of
identical in-flight queries, retries across upstreams, SERVFAIL on
timeout, rebind protection, bounded pending queries.
**Open:** TCP port 53 and TC-bit retry, randomised upstream source port
per query (Kaminsky hardening; one fixed random port today), DoT/DoH,
blocklists, DNSSEC.

| Function | Priority |
|---|---|
| Forwarder + cache on LAN IPs, UDP **and** TCP port 53; TTLs, negative caching (RFC 2308), deduplicate in-flight queries | required |
| Upstreams from IPCP/DHCP or config; failover and health tracking | required |
| Local zone `.lan`: DHCP hostnames, static hosts, `router.lan`, PTR records for LAN subnets | required |
| **Never resolve for the WAN side** (bind to LAN only, plus a firewall rule) | required |
| DNS rebind protection (drop public answers that contain private IPs) | recommended |
| Bounded LRU cache (memory cap) | recommended |
| DoT/DoH upstream | later (TLS on no_std is hard) |
| Blocklists (Pi-hole style) | later |
| DNSSEC validation (needs correct time, so NTP) | optional |

Resolution order in the request handler: local zone → blocklist → cache →
forward to the current upstream (the upstream list is swapped atomically on `WanUp`).

## NAT and firewall
**Status (M4): implemented** in `crates/fwd` (27 tests, including fuzzing) and
`kernel/src/net/datapath.rs`, verified end to end in the lab:
- NAPT/masquerade on the WAN with **endpoint-independent mapping**
  (RFC 4787) and endpoint-dependent filtering. NAT ports 10000–39999
  (router-local sockets use ≥ 40000). Port preservation when free.
- Conntrack: TCP state (SYN → established → closing/closed) with
  timeouts, UDP unreplied/assured, ICMP echo; bounded at 16384 entries;
  all NAT state flushed when the WAN address changes.
- ICMP errors: TTL-exceeded generated (rate-limited, 50/s), and errors
  about NATed flows translated, including the embedded header.
- Firewall: new flows only LAN→WAN; TCP must start with SYN; WAN→LAN only
  for tracked connections; hairpin, fragments and unknown protocols dropped.
- Open: **port forwarding (DNAT)**, hairpin NAT, IP fragment reassembly
  (fragments are dropped today), ICMP unreachable for no-route, MSS
  clamping + PMTU (M5, with PPPoE), UPnP/NAT-PMP, faster conntrack
  structures (hash table + timer wheel instead of BTreeMap + O(n) expiry).

## Supporting pieces needed by all of the above
- NAT (masquerade on the WAN) and a stateful firewall: LAN→WAN allowed,
  WAN→LAN only established or related, input protection, an IPv6 firewall
  that blocks inbound by default, and port forwarding.
- An SNTP client (QEMU provides a PL031 RTC; real boards often have none).
- Persistent config storage: raw store partition with A/B record slots (`docs/config-and-storage.md`); virtio-blk in QEMU, SD on the apu4.

## Target configuration UX
```toml
[wan]
interface = "wan0"
vlan = 848                 # optional, ISP-specific
mode = "pppoe"             # "pppoe" | "dhcp" | "static"

[wan.pppoe]
username = "user@isp.cz"
password = "secret"
mtu = 1492
lcp_echo_interval = 10
lcp_echo_failure = 5

[wan.ipv6]
dhcpv6_pd = true
prefix_hint = 56

[lan]
ipv4 = "192.168.1.1/24"
domain = "lan"

[lan.dhcp]
range = ["192.168.1.100", "192.168.1.250"]
lease_time = "12h"
[[lan.dhcp.static]]
mac = "aa:bb:cc:dd:ee:ff"
ip = "192.168.1.10"
hostname = "nas"

[dns]
upstream = "auto"          # from PPPoE/DHCP, or a list
cache_size = 10000
rebind_protection = true
```
