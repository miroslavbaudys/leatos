# SOHO feature specification: PPPoE, DHCP, DNS

These are the requirements and the known pitfalls, gathered during the initial
analysis. Each protocol is implemented as a sans-IO `no_std` crate (see
architecture.md).

## PPPoE
Crate: `crates/proto-pppoe`. Status: **implemented (M5, QEMU lab)**:
discovery with Service-Name/AC-Name filtering, Host-Uniq, AC-Cookie and
Relay-Session-Id echo, PADS errors, PADT both ways (sent at shutdown and
when a session is torn down); LCP (RFC 1661 automaton shared with IPCP:
MRU 1492, magic numbers with loopback check, auth protocol: PAP or
CHAP-MD5, other methods naked to CHAP; PFC/ACFC and unknown options
rejected; Protocol-Reject for unsupported protocols (IPv6CP too while
`ipv6` is off);
echo keepalive, `lcp_echo_interval` / `lcp_echo_failure`); PAP and CHAP-MD5
(`md-5`, RustCrypto); IPCP with DNS (RFC 1877), DNS servers feed the
forwarder. With `ipv6` on: IPv6CP (interface identifiers, link-local
addresses; failure leaves IPv4 up), IPv6 in the session, DHCPv6 prefix
delegation over it (docs/ipv6.md step 4). Reconnect with exponential backoff (1 s doubling to 64 s, at
least 10 s after an authentication failure, reset once a session is up).
Kernel: `net::pppoe` (svc) + the datapath hooks (architecture.md). MSS
clamping and ICMP "fragmentation needed" in `crates/fwd`. Lab:
`LAB_PPPOE=pap|chap scripts/lab-test.sh` (rp-pppoe's `pppoe-server` in the
ISP VM, also with `LAB_VLAN=848`), `scripts/pppoe-test.sh` (live switch
between DHCP and PPPoE). PPPoE runs on the apu4 against the developer's ISP (VLAN 848, no
authentication, since 2026-11-15). Open: IPv6 on the real line (done in
QEMU), RFC 4638 on hardware (implemented, see below; not usable on
the developer's line), long-run stability (forced daily disconnects).
Non-DF packets above the session's MTU are split (2026-11-18).

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
  example O2 with VLAN 848; verify per ISP). `wan.vlan` (+ `wan.vlan_pcp`)
  is implemented (software tag in `net::datapath`; boot argument
  `wan_vlan=`); PPPoE runs inside it (lab: `LAB_PPPOE=pap LAB_VLAN=848`).
- RFC 4638 (MTU 1500 over PPPoE) is optional and only works if the ISP supports it.
  Implemented 2026-11-18 (`crates/proto-pppoe`): `wan.pppoe.mtu = 1500`
  (or `pppoe_mtu=1500`) puts PPP-Max-Payload in the PADI, and in the PADR
  only if the PADO echoed it; with the PADS echoing it too, LCP asks for
  MRU 1500 (the peer's MRU defaults to 1492 unless it offers more). Before
  the link counts as up, a full-size LCP Echo-Request (1500 B) must come
  back full size within 3 tries of 1 s: then MTU 1500 (no MSS clamping,
  no frag-needed below 1500). Otherwise the session ends (`JumboFailed`)
  and the client stays at 1492 until restarted. `/api/status`
  `pppoe.rfc4638`: in use, not offered by the access concentrator, or
  fell back. The igb accepts frames up to 2048 B (`RCTL.LPE`, `RLPML`):
  1500 B over PPPoE on a VLAN is a 1526 B frame. The lab's rp-pppoe does
  not support it (session at 1492, checked with `pppoe_mtu=1500`); the
  1500 path is host-tested against a simulated AC (agreeing, not agreeing,
  path losing large frames, short echo replies, an AC asking MRU 1492 in LCP
  that takes or refuses our Configure-Nak suggesting 1500). The log line
  `RFC 4638: PADO …, PADS …, our MRU …, peer MRU …, echo …` shows each step.
  On the developer's line (2026-11-18) the AC echoes 1500 in PADO and PADS
  but asks MRU 1492 in LCP and keeps it after our Nak, and its echo replies
  carry no data (8 B for 1500 B): we could receive 1500 but send only 1492,
  and the downstream direction cannot be proven, so the client falls back
  to 1492. Proving the downstream with such an AC would need an IP-level
  check (a full-size ping through the session), not done.
  To check a line: boot once with `pppoe_mtu=1500` (the stored config
  stays as it is) and read that log line. A separate discovery probe while
  the session runs was tried and dropped: ACs that allow one session per
  line (the developer's does) ignore further PADIs from it.
- Reconnect with exponential backoff. Send PADT on shutdown so the ISP
  doesn't keep a stale session. Handle forced daily disconnects.
- On multi-core hardware, NIC RSS can't hash inside PPPoE, so all traffic
  lands on one core. leatos doesn't use RSS: it splits by direction
  (docs/smp.md), which PPPoE doesn't affect.

## DHCP
Crate: `crates/proto-dhcp`. Status: v4 server done (M3), lease
persistence done (M8); the WAN DHCPv4 client is smoltcp's; v6 pending (M7,
docs/ipv6.md).

### DHCPv4 server (LAN), required
**Status (M3): implemented** in `crates/proto-dhcp/src/v4/` (17 tests,
including fuzzing) and wired up in `kernel/src/net/services.rs`. Done:
DORA, static reservations, offer hold, returning client gets the same IP,
renew/rebind, INIT-REBOOT, NAK, RELEASE, DECLINE (10 min hold), INFORM,
expiry, hostname sanitising, and `Bound`/`Released` events to DNS. Replies
are always broadcast. One server per network (`[[network]]`, VLANs,
docs/config-v2.md) with its own domain (option 15). Leases persist in the
store (`persist`, `Server::restore`; docs/config-and-storage.md §4).
Option 121 (RFC 3442, and 249 for clients asking for it) carries the
`[[route]]`s through routers on the client's network plus the default
route (docs/config-v2.md `[[route]]`). Open: conflict probe, option 42
(no NTP server), relay.

- Pools, static reservations by MAC, lease time, T1/T2, DECLINE, RELEASE, INFORM.
- Options: 1 subnet mask, 3 router, 6 DNS (= router IP), 15/119 domain, 42 NTP,
  12 hostname (from the client), 121/249 classless routes (when asked for and `[[route]]`s exist).
- Lease persistence: in memory, flushed periodically and on shutdown. Batch
  writes to limit flash wear. ✅
- Optional ARP or ICMP probe before handing out an address.
- Emit `LeaseAdded{mac, ip, hostname}` so the DNS zone resolves `host.home.arpa`.
- One pool per LAN or VLAN. ✅

### DHCPv4 client (WAN, non-PPPoE ISPs)
**Status: implemented** with smoltcp's `dhcpv4` socket (`net/svc.rs`),
since M2; the lease feeds the forwarder (WAN address, route) and the DNS
upstreams.
- DISCOVER, OFFER, REQUEST, ACK, then renew, rebind and expire. Must work
  before the interface has an IP address (raw L2 frames).
- Open: some ISPs need option 60/61 or MAC cloning.

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
tests, including fuzzing): local `.home.arpa` zone (router, static hosts, DHCP
hostnames, PTR for the LAN subnet; never forwarded), bounded cache with
TTL aging and negative caching, upstreams from the WAN lease, random
transaction IDs, response validation (server + question), merging of
identical in-flight queries, retries across upstreams, SERVFAIL on
timeout, rebind protection, bounded pending queries.
Own upstreams (`dns.upstreams`) and strict DNS over TLS (`dns.tls`,
`crates/proto-dot`, docs/dns-over-tls.md) are implemented; answers to LAN
clients are cut to their EDNS size with TC.
**DNS over TCP from clients** (RFC 7766, 2026-11-19; boot argument
`dns_tcp=0` turns it off): TCP port 53 on every network's address
(`kernel/src/net/dns_tcp.rs`), so a client whose UDP answer came back
truncated gets it whole over TCP (up to 64 KiB, `handle_query_tcp`).
Length-prefixed messages, several queries per connection answered as they
come (pipelining), 4 connections per network, queries up to 1 KiB, at most
16 unanswered per connection (then reading pauses), 128 KiB of queued
answers, closed after 10 s idle (aborted after 30 s). Upstream queries
always announce EDNS with 1232 bytes, whatever the client sent, so the
cache gets whole answers for TCP clients too; clients without EDNS get
their answers without an OPT record (RFC 6891 §7). Counters in
`/api/status` `dns.tcp` (`queries`, `accepted`, `open`), CLI `status`,
the DNS page. Lab check: big.isp.example (an 850-byte TXT answer from the
ISP's dnsmasq) truncated over UDP, whole over TCP; negative control
`LAB_ROUTER_ARGS=dns_tcp=0`. Not done: an upstream answer above 1232 bytes
comes back truncated and is not asked again over TCP (over TLS it is
whole).
**Prefetch** (`dns.prefetch`, default on; boot argument `dns_prefetch=0`):
a cache hit in the last tenth of an entry's TTL (TTLs of 10 s and more) is
answered from the cache and renews the entry in the background with the
query that filled it (EDNS kept), at most one renewal per question and on
a quarter of the pending slots; a client asking once the entry has expired
joins the renewal; a failed renewal leaves the entry to expire as before.
Counters (`queries`, `cache_hits`, `forwarded`, `prefetches`,
`prefetch_failed`, …) in `/api/status` `dns` and the CLI `status`; lab
check in `scripts/lab-test.sh` (negative control
`LAB_ROUTER_ARGS=dns_prefetch=0`).
DNSSEC is passed through, not validated: DO bit and CD flag go upstream,
RRSIGs and AD come back; merging and the cache are per question **and**
those flags (`cache::Key`), so validating clients behind the router never
get an answer fetched without DNSSEC records (and clients without CD never
one that failed validation upstream).
**Serve-stale** (RFC 8767; `dns.stale_secs`, default 86400 = one day,
0 = off; boot argument `dns_stale=`): expired entries are kept that long.
A client asking for one is forwarded as usual but gets the stale answer
(TTL 30 s) when the upstream has not answered within 1.8 s (the resolution
goes on and refreshes the cache), when it fails (all tries timed out,
SERVFAIL/REFUSED), or at once without upstreams (WAN down) or pending
room; after a failure the name is answered stale for 30 s without asking
(failure recheck timer). Our own refusals (rebind protection) are never
replaced by stale data. Counter `stale_answers`; lab check (the ISP's DNS
stopped, negative control `LAB_ROUTER_ARGS=dns_stale=0`).
**Extended DNS Errors** (RFC 8914), to clients that sent EDNS: Stale
Answer (3) / Stale NXDOMAIN Answer (19) on stale answers, No Reachable
Authority (22) on our SERVFAIL when no upstream answered or there is none,
Blocked (15) with a reason on rebind-protection refusals; errors from the
upstream pass through unchanged (with its EDE). Added only where nothing
moves (OPT last, or a new OPT); lab check: the stale answer to a crafted
EDNS query carries EDE 3.
**Open:** retrying truncated upstream answers over TCP, randomised upstream source port
per query (Kaminsky hardening; one fixed random port today), DoH,
blocklists, DNSSEC validation, static local records (`[[dns.host]]`:
in the schema, refused by the kernel so far).

| Function | Priority |
|---|---|
| Forwarder + cache on LAN IPs, UDP **and** TCP port 53; TTLs, negative caching (RFC 2308), deduplicate in-flight queries | required |
| Upstreams from IPCP/DHCP or config; failover and health tracking | required |
| Local zone `.home.arpa`: DHCP hostnames, static hosts, `router.home.arpa`, PTR records for LAN subnets | required |
| **Never resolve for the WAN side** (bind to LAN only, plus a firewall rule) | required |
| DNS rebind protection (drop public answers that contain private IPs) | recommended |
| Bounded LRU cache (memory cap) | recommended |
| DoT upstream | ✅ strict, `dns.tls` (docs/dns-over-tls.md); DoH later |
| Blocklists (Pi-hole style) | later |
| DNSSEC validation (needs correct time, so NTP) | optional |

Resolution order in the request handler: local zone → (later: blocklist) →
cache → forward to the current upstream (the list is replaced when the WAN
lease changes, unless `dns.upstreams` is set).

## NAT and firewall
**Status (M4): implemented** in `crates/fwd` (27 tests, including fuzzing) and
`kernel/src/net/datapath.rs`, verified end to end in the lab:
- NAPT/masquerade on the WAN with **endpoint-independent mapping**
  (RFC 4787) and endpoint-dependent filtering. NAT ports 10000–39999
  (router-local sockets use ≥ 60000; forwarded ports are skipped). Port preservation when free.
- Conntrack: TCP state (SYN → established → closing/closed) with
  timeouts, UDP unreplied/assured, ICMP echo; 16 shards sharing one
  budget of 16384 entries (`conntrack::Budget`); all NAT state flushed when
  the WAN address changes.
- ICMP errors: TTL-exceeded generated (rate-limited, 50/s), and errors
  about NATed flows translated, including the embedded header.
- Firewall: since config v2 (2026-11-15) a zone firewall with ordered
  rules, `reject`, live recheck of tracked connections and WAN
  anti-spoofing (docs/config-v2.md). The default is still M4's policy:
  new flows only LAN→WAN; TCP must start with SYN; WAN→LAN only for
  tracked connections (or port forwards); unknown protocols dropped.
- Port forwarding (DNAT) and hairpin NAT ✅ (2026-11-15, docs/config-v2.md).
- Redirects ✅ (2026-11-16, `[[firewall.redirect]]`, docs/config-v2.md): the
  networks' connections to an outside server on given ports go to a device
  inside (NTP to the LAN's time server, as UniFi's NTP redirect).
- MSS clamping and ICMP "fragmentation needed" for DF packets above the
  egress MTU ✅ (M5, with PPPoE).
- IP fragments through NAT and the firewall ✅ (2026-11-18, `fwd::frag`,
  docs/architecture.md): forwarded as they come, with the first
  fragment's decision; no reassembly.
- Splitting packets larger than the egress MTU ✅ (2026-11-18,
  `wire::SplitPlan`): non-DF packets and fragments (1500 B into a PPPoE
  session's 1492) are cut into fragments (RFC 791); DF ones still get
  "fragmentation needed".
- Open: ICMP
  unreachable for no-route (dropped as `no-route`), UPnP/NAT-PMP, faster
  conntrack structures (hash table + timer wheel instead of BTreeMap +
  O(n) expiry).

## Supporting pieces needed by all of the above
- NAT (masquerade on the WAN) and a stateful firewall: LAN→WAN allowed,
  WAN→LAN only established or related, input protection, an IPv6 firewall
  that blocks inbound by default, and port forwarding.
- SNTP client ✅ (`crates/proto-sntp`, `docs/watchdog-and-time.md`): servers
  from `time.ntp_servers` (default `pool.ntp.org`) resolved through the
  router's DNS forwarder; the RTC (x86_64) is set after each sync but never
  trusted as the time (only a hint for DoT certificate dates). Open: serving NTP to the LAN.
- Persistent config storage: raw store partition with A/B record slots (`docs/config-and-storage.md`); virtio-blk in QEMU, SD on the apu4.

## Target configuration UX (early sketch)
The implemented schema differs: see `docs/config-and-storage.md` §5
(version 1) and `docs/config-v2.md` (version 2: `[[network]]` instead of
`[lan]`, `lease_secs`, `[[network.dhcp.static]]`, `[dns] upstreams`,
`cache_entries`). `[wan.ipv6]` is still to come (M7).
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
domain = "home.arpa"

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
