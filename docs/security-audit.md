# Security audit: threat model and attack surface

Status: phase 1 (threat model + surface table), 2026-11-22, at 5b57a14.
Phase 2 (code review by exposure), phase 3 (tools: long fuzz runs, coverage,
`cargo deny`/`cargo vet`, external scans) and phase 4 (findings, fixes,
regression tests) build on this document.

## 1. What we protect (assets)

| Asset | Why it matters |
|---|---|
| **Availability of forwarding** | the household's internet; any panic is a reboot (`fatal.rs`), any stall a watchdog reset |
| **Integrity of the running kernel** | persistent upgrades (`upgrade.rs`) make a compromise survive reboots |
| **Integrity of the config** | firewall, zones, port forwards, DNS: a changed config opens the LAN |
| **Isolation between zones** | guest/IoT must not reach `lan`, the WAN must not reach anything not forwarded |
| **Secrets** | `mgmt.password_hash`, `mgmt_pass=`, `wan.pppoe.password`, session tokens, entropy pool state |
| **Client privacy** | DHCP leases, host names, DNS queries (DoT protects them upstream) |
| **Correct name resolution** | DNS cache poisoning redirects every client |

## 2. Attackers and trust boundaries

| ID | Attacker | Reaches | Trust |
|---|---|---|---|
| **A1** | Internet host | WAN: raw IP to the router's address, forwarded ports, replies to NAT flows | none |
| **A2** | ISP / on-path on the WAN link | everything A1 can do, plus L2 on the WAN: PPPoE discovery and session, DHCP server answers, RAs, DHCPv6-PD, DNS and NTP answers (plain), ARP/ND | none for content; we depend on it for addressing |
| **A3** | Malicious or compromised LAN client (`lan` zone) | L2 on its network: ARP/ND, DHCP, DNS (UDP/TCP), mDNS, the mgmt web interface, all forwarding | partial: may use services, must not change config without the password |
| **A4** | Guest/IoT client (non-`lan` zone) | as A3, limited by zone policy (`input` service mask, rules) | less than A3: zone policy is the boundary |
| **A5** | Web page in a LAN client's browser | cross-site requests to `http://192.168.1.1` (CSRF), DNS rebinding, XSS through data shown on the mgmt page | none |
| **A6** | Holder of the mgmt password or a session token | config, reboot, upgrades | full control by design: the question is only how hard the credential is to get |
| **A7** | Physical access | serial CLI (no auth by design, `cli.rs`), SD card (store, boot partition), boot arguments | full: out of scope except where a stolen SD card leaks secrets |

Out of scope: hardware/firmware attacks (coreboot, the CCP, the NIC's firmware),
side channels between tasks (no untrusted code runs on the router),
the developer's Mac and the lab scripts.

## 3. Security properties (to be checked, each as a test or lab check)

- **P1** No input from A1–A5 panics the kernel, hangs a task past the watchdog, or overflows a fixed table into misbehaviour (only drops/eviction).
- **P2** Bounded resources: every per-input allocation has a cap (packet pool, conntrack, frag, neighbor, DNS cache, DHCP leases, mDNS hosts, HTTP and DNS-TCP buffers, sessions).
- **P3** WAN input: nothing reaches a router service unless a zone rule allows it (`mgmt=wan` is development only); only port forwards and replies to tracked flows pass inward.
- **P4** Zone isolation: a packet from zone Z reaches zone Y or the router only as `Policy` allows, also for IPv6, fragments, hairpin, redirects and mDNS reflection.
- **P5** Anti-spoofing: WAN packets claiming internal or loopback sources, and LAN packets with sources outside their network, are dropped (v4 and v6).
- **P6** Without the password nothing changes state (config, reboot, upgrade, lease reservation); reads are public only when no password is set.
- **P7** The running and stored kernel is one the owner uploaded (today: one that someone with A6 uploaded).
- **P8** Secrets never appear in API/CLI output or logs (`without_secrets`, `config::Redacted`).
- **P9** The DNS forwarder never caches an answer to a question it did not ask (ID, port, question match) and never hands clients private addresses for public names (rebind protection).
- **P10** Store records are authenticated by structure and CRC only: a corrupted or crafted store must not crash the boot (falls back to defaults or the other slot).

## 4. Attack surface

Columns: **Parser** = where untrusted bytes are first interpreted.
**Limits** = what bounds memory/time. **Fuzz** = target in `fuzz/fuzz_targets/`.
**Review notes** = what phase 2 must look at (hypotheses, not findings).

### 4.1 WAN side (A1, A2)

| Entry point | Parser / state | Limits | Fuzz | Review notes |
|---|---|---|---|---|
| Ethernet + VLAN on wan0 | `net/datapath.rs` (`pop_vlan`), driver RX (`virtio_net.rs`, `igb.rs`) | 8192 packet buffers (`main.rs` `net_pool_size`), 2048 B RX area, 256-entry igb ring | — | runt/oversized frames, VLAN mismatch, driver descriptor lengths trusted from the NIC (DMA) |
| PPPoE discovery + session (PADO/PADS/PADT, LCP, PAP/CHAP, IPCP, IPv6CP) | `crates/proto-pppoe` (`lib.rs` 1525 lines), `wire` decap | `CTRL_RX_MAX` 16 queued control frames; backoff | `pppoe` | A2 controls everything here: option length fields, Configure-Nak loops, echo-flood, MRU negotiation (RFC 4638 path), PADT spoofing by A2 (expected) |
| IPv4/IPv6 forwarding inward | `crates/fwd` `wire` (`Ipv6View` bounded extension walk), `forwarder` (5091 lines) | — | `fwd` | header length vs. buffer, extension-header loops, ICMP-error inner headers (quoted packets), checksum update correctness |
| Conntrack / NAPT | `fwd::conntrack` | 16384 entries × shards (`datapath.rs` `MAX_CONNS`), per-host limit (¼), early drop `EVICT_SCAN` 64, expiry ≤ 256 per pass | `fwd` | SYN flood / scan to forwarded ports, NAT port exhaustion (tested on host), tuple clash, timer values (2 h established) |
| IP fragments | `fwd::frag` | 64 entries per port, 2 s, ≤ 16 parked for 250 ms | `fwd` | overlap/tiny-fragment rules (tiny and offset-1 TCP refused), first-fragment-late, v6 atomic fragments |
| Port forwards / DNAT, hairpin | `forwarder` `PortForward` | below 60000 (validated) | `fwd` | target's own connections out keep the WAN port (`create_from`): can A1 hijack a mapping? |
| Router-local replies (ports ≥ 60000, UDP 68, ICMP non-echo) | `forwarder` "always pass" path | `ROUTER_CLIENT_PORTS` | `fwd` | **this pass bypasses zone policy**: what reaches smoltcp from an arbitrary A1 source on 60000–65535? TCP only from `router_tcp_peers` |
| DHCPv4 client | smoltcp `dhcpv4` socket | smoltcp's own | — (smoltcp) | A2 sets our address, gateway, DNS, routes: sanity checks on lease values (0.0.0.0, our LAN subnet as WAN subnet, lease 0 / huge) |
| IPv6 RA from the ISP | `proto_dhcp::v6::ra::parse_frame`, `wan6.rs` | — | `dhcp6` (`ra::parse_frame`) | RA flood (many prefixes/routers), hop limit 255 check, MTU option |
| DHCPv6-PD client | `proto_dhcp::v6::pd` | — | `dhcp6` | delegated prefix length (/48 … /64, weird /0 or /128), T1/T2 0 or huge, prefix overlapping ULA/ours |
| DNS answers (plain UDP upstream, ports 65000–65535) | `proto-dns` `wire` (pointer limit 16, name ≤ 255), `resolver`, `cache` | cache `max_entries`, TTL ≤ 86400 | `dns` | poisoning: ID + port randomness (source of entropy at boot), question match, bailiwick of extra records, EDNS size handling |
| DoT (TCP 853, local ports 61000–64999) | `proto-dot`: rustls 0.23 unbuffered + own RustCrypto provider (`provider.rs` 816 lines) | 30 s idle, backoff | — | **own crypto provider**: verify signature-scheme mapping, curve checks, RSA PKCS#1/PSS selection; certificate date floor before SNTP |
| SNTP answers | `proto-sntp` | burst + backoff | `sntp` | A2 can move the clock: effects on DoT certificate checks, lease expiry, trial timers (should be monotonic) |
| ARP / ND on WAN | `fwd::neigh`, smoltcp, `NdHints` | `MAX_PENDING` 3, `NEIGH6_MAX` 128, smoltcp cache 256 | `fwd` partly | neighbor table poisoning by A2 (expected), table exhaustion via ND from A1 for unused /64s (`unreachable6` path) |
| ICMP errors we generate (TTL, PTB, unreachable, reject RST) | `forwarder` | rate-limited (reject) | `fwd` | amplification and reflection: are TTL-exceeded / PTB rate-limited too? |

### 4.2 LAN and guest side (A3, A4)

| Entry point | Parser / state | Limits | Fuzz | Review notes |
|---|---|---|---|---|
| Forwarding outward + between networks | `fwd::forwarder` zone `Policy`, rules, `recheck` | as 4.1 | `fwd` | P4 for every path: v6, fragments, hairpin, redirects (`router_serves`), routed subnets (`[[route]]`); anti-spoofing per network (`lan_antispoof`) |
| ARP / ND on LAN, neighbor hints | `device.rs` `NdHints`, `fwd::wire::ipv4_neighbor_hint`/`ipv6_neighbor_hint` | smoltcp cache 256 per network | — | a client spoofing others' addresses (ARP poisoning of the router: expected on a flat L2, but can it poison across networks?); hint injection rate |
| DHCPv4 server | `proto-dhcp` v4 server | persist ≤ 4096 leases, pool .100–.199 | `dhcp` | **pool exhaustion by random MACs** (no per-port limit?), host-name option content (shown in UI, DNS names from leases), option 82/overload, client-chosen lease time |
| Lease host names → DNS | `proto-dns` zone (`add_host_in`) | — | `dns` | a client naming itself `router`, `nas` or a public name: override precedence, label validation |
| DNS UDP :53 | `proto-dns` resolver/zone | reply ≤ 1472 B, cache bound | `dns` | amplification toward a spoofed LAN source (anti-spoofing helps), query rate per client, views (`handle_query_in`): leaks of hidden names via PTR, cache shared across views? |
| DNS TCP :53 | `net/dns_tcp.rs` | 4 conns per network, query ≤ 1024 B, 16 outstanding, 128 KiB out, 10 s idle / 30 s hard | — | 4 sockets per network: trivially taken by one client (DoS of DNS-TCP only) |
| mDNS 5353 (reflector) | `proto-mdns` parse/rebuild, `Reflector` | 128 hosts, 128 services, 64 recent, output ≤ 1472 B | `mdns` | compression loops in parse, rule bypass (service type spoofing), amplification between networks, rate limits |
| RS → RA | `proto_dhcp::v6::ra` | solicited ≥ 3 s apart | — (RS side) | RS flood |
| Web interface :80 | `proto-http` (head ≤ 8 KiB, small body ≤ 64 KiB), `mgmt.rs` (1560 lines) | 4 LAN sockets, 20 s request / 120 s upload timeout, 8 sessions, 12 h idle | `http` | see 4.3 |
| Other router ports | smoltcp | — | — | what does smoltcp answer on closed ports per zone (RST/ICMP), and is `input` mask applied before smoltcp sees the packet? |

### 4.3 Web interface in detail (A3–A6)

| Item | Current design | Review notes |
|---|---|---|
| Routes | 17 routes (`mgmt.rs` ~587); `/` and `GET /api/info` always public; others need auth when a password exists; without one reads public, changes refused (403) | verified in `on_head`: reads need auth only with a password, all changes, `/api/log` and login always; `/api/logout` has no check (harmless? confirm it only drops the presented token) |
| Credentials | Basic `admin` + password → session token (`POST /api/login`), `Bearer` afterwards; `ct_eq` for the boot password, PBKDF2-SHA256 20000 iterations + verify cache for the stored hash; 1 s block after a failure (global) | plain HTTP: password and token visible to anyone sniffing the LAN (Wi-Fi is the AP's problem, but wired guests on a shared segment are not); the 1 s global block is also a DoS lever for A3 against the owner (each wrong guess blocks everyone) |
| Session tokens | 8 sessions, 12 h idle; entropy from `entropy.rs` | token length/entropy at early boot; a 9th login evicts which one? |
| CSRF (A5) | UI sends `Authorization: Bearer` from `localStorage` (cross-site forms cannot set it); since 2026-11-22 cross-origin non-GETs are refused (§5 item 1) | was: **Basic auth is still accepted**: a browser that ever cached Basic credentials (a non-UI request answered with `WWW-Authenticate`) attaches them to cross-site form POSTs. `POST /api/config` accepts TOML, i.e. `text/plain`, which a form can send. No `Origin`/`Host` check found (`grep origin mgmt.rs` empty) |
| DNS rebinding (A5) | rebind protection in the forwarder (private answers for public names blocked); since 2026-11-22 a `Host` check (§5 item 2) | was: covers clients that use the router's DNS; a client with its own resolver (DoH in the browser) is not covered, and without a password `GET /api/status` etc. are public: needs a `Host` check |
| XSS (A3/A4 → owner's browser) | `esc()` (`mgmt.html` 494) escapes `& < > "`; ~30 `innerHTML` assignments | check every client-controlled string (DHCP host name, mDNS names, PPPoE AC name/messages, DNS names, log lines) passes `esc`; `'` is not escaped (fine only in `"`-quoted attributes) |
| Security headers | none found (`Content-Security-Policy`, `X-Frame-Options`) | clickjacking of the config page; a CSP would contain any missed escape |
| Upload | `POST /api/upgrade` streamed into the staging area; `boot-image` validates ELF64 + Multiboot2 + CRC-32 | **no signature**: P7 rests on the password alone; auth is checked on the request head, before any body byte is streamed (`on_head`, verified) |

### 4.4 Local / physical (A7) and boot-time inputs

| Entry point | Parser | Review notes |
|---|---|---|
| Serial CLI | `crates/cli` line editor + parser, `kernel/src/cli.rs` | no auth by design; still must not panic on long lines/escape sequences (no fuzz target yet); secrets masked on `config show` |
| Store partition (SD / virtio-blk) | `crates/config-store` (MBR, header, A/B slots, CRC), `crates/config` TOML (`deny_unknown_fields`), `proto_dhcp::v4::persist` leases | P10; secrets on the card: `mgmt.password_hash` (PBKDF2, fine), **`wan.pppoe.password` in clear** (theft of the SD card leaks it) |
| Stored kernels (`images` area) | `boot-image` | the loader enters whatever the store says is current: an SD card written offline is a persistent compromise (A7, accepted unless signing is added) |
| Boot arguments | `config.rs` parsers | from the bootloader config on the SD card (A7) or DTB; `mgmt_pass=` in clear there |
| Firmware tables (DTB, PVH, Multiboot2, ACPI) | `platform/` | trusted (A7 / firmware), but parsers should still be bounds-checked (`phys.rs` one unsafe constructor) |
| DMA from NICs / storage controller | `mm/dma.rs`, drivers | the device is trusted (no IOMMU); driver must still not trust descriptor lengths beyond the buffer (memory safety, not security boundary) |

### 4.5 Supply chain

| Item | State | Review notes |
|---|---|---|
| Rust dependencies | 177 crates in `Cargo.lock`; `cargo audit` clean on 2026-11-22 | add `cargo deny` (sources, licenses, duplicates) and `cargo vet`; review unsafe in smoltcp, virtio-drivers, talc, safe-mmio, rustls, RustCrypto crates |
| Lab downloads | pinned by SHA-256 (`fetch-alpine.sh`) | lab only, not in the image |
| Image build | `apu-image.sh` (Limine from Homebrew) | the boot loader binary is not pinned |

## 5. First hypotheses for phase 2, by priority

Each becomes a finding (with a test or negative control) or is struck out with
the reason. 1 and 2 were checked on 2026-11-22 (65005d4, aarch64, HVF, QEMU
user networking with `mgmt=wan` and a host port forward; same mgmt code as on
the LAN side), the rest are open.

1. **FIXED (2026-11-22): CSRF via cached Basic credentials** (A5, §4.3).
   A request without `X-Leatos-UI` gets `401` + `WWW-Authenticate: Basic`, so a
   browser that opens any API URL directly prompts and caches the credentials.
   A cross-site `text/plain` POST to `/api/config` with them (`Origin:
   http://evil.example`, `Sec-Fetch-Site: cross-site`) whose body is what an
   HTML form with `enctype="text/plain"` sends (`name=value` CRLF, the name
   carrying the TOML up to `[dns] domain`, the value `"csrf.example"`) was
   answered `200 saved and applied`, no trial, and the stored config had
   `domain = "csrf.example"`. Any field can be set this way (firewall rules,
   port forwards, DNS upstreams); `/api/reboot` and `/api/upgrade` take the same
   path. That browsers attach cached Basic credentials to cross-site top-level
   form POSTs is standard behaviour, not re-checked here in a browser.
   Fix: `proto_http::check_browser_origin`, called by `net::mgmt` before
   routing and auth: a request other than `GET` whose `Origin` is not the
   `Host` it was sent to (or `null`), or without `Origin` with
   `Sec-Fetch-Site: cross-site`/`same-site`, gets `403`. Scripts send
   neither and pass, so Basic stays for them. The content-type restriction
   considered at first was left out: the origin check already covers every
   browser that sends `Origin` on POST (all current ones), and it would have
   broken scripts (`curl --data-binary` sends a form type). Counter
   `/api/status` `mgmt.refused.cross_site`. Lab: the client's `web origin`
   checks (every mode); negative control `LAB_ROUTER_ARGS=mgmt_origin=0`.
2. **FIXED (2026-11-22): no `Host` check**, DNS rebinding reads the API when no password
   is set (A5). With `Host: rebind.evil.example` and a matching `Origin`,
   `/api/status`, `/api/config` and `/api/config.json` answered `200` with
   content (leases, MACs, host names, the whole config without secrets);
   `/api/log` and all changes were refused (`403` without a password, as
   designed). The router's DNS rebind protection only helps clients that use
   the router as their resolver (not browsers with DoH). Fix: the same
   check answers `421` unless `Host` is an IP address literal (an origin
   that is an address cannot be rebound), `localhost`, a single label, or a
   name under one of the router's DNS domains (`dns.domain` and the
   networks' own, `config::local_domains`); every route, the page
   included. Names outside those domains that point at the router (a
   `[[dns.host]]` override of a public name) no longer open the interface.
   Counter `mgmt.refused.host`; same lab checks and negative control.
3. **Unsigned upgrades** (P7): an attacker with the password, or one CSRF, installs a persistent kernel. Candidate fix: Ed25519 signature over the image, key compiled in, `image=golden` unaffected.
4. **REVIEWED, none found (2026-11-22): remote panics in WAN parsers** (P1).
   Survey: clippy `indexing_slicing`, `unwrap_used`, `expect_used`,
   `panic`, `unreachable`, `arithmetic_side_effects` on `proto-pppoe`,
   `proto-dhcp`, `proto-dns`, `fwd` (about 900 sites, 470 of them indexing
   or slicing), plus `proto-dot` and `proto-sntp`; every parser path of
   WAN input read by hand:
   - PPPoE discovery tags, LCP/IPCP/IPv6CP options, PAP/CHAP: lengths via
     `get()` or checked first; option handlers match on the length before
     indexing.
   - DHCPv6 RA and PD: bounds checked; the one `unreachable!` (`message`
     while Bound) is behind `poll`'s early return.
   - DNS: names (≤ 16 pointers, ≤ 255 bytes), records (offsets checked in
     `records`, the ±2/±5 offsets stay inside the record), cache TTL
     offsets from parsed records; the resolver's `upstreams[0]` and `% n`
     behind non-empty checks.
   - DoT: framing and certificate dates checked; the `expect`s are on key
     and IV lengths rustls fixes (`KeyBlockShape`). SNTP: length first.
   - `fwd::wire` views check every header length (IPv6 extension headers
     ≤ 8 / 256 B); port rewrites only for flows whose L4 header was found
     (`l4_len ≥ 8/20`); `tcp_reset`'s `clamp(20, l4_len)` only behind
     `rejectable` (`l4_len ≥ 20`); both ICMP error builders check the
     buffer first; port-range math relies on `PortRange` refusing
     `lo > hi`.
   - Kernel glue (VLAN pop, PPPoE decap, `PacketBuf` asserts): lengths
     checked before; the asserts fire only on internal misuse.
   The low-level accessors (`get16`, `set_port`, view getters) index
   unchecked by contract; every caller traced meets it.
   Fuzzing at the same commit, 40 min each with overflow checks on
   (cargo-fuzz's default): `pppoe` 36 M, `dhcp6` 71 M, `dns` 10 M, `fwd`
   24 M runs, no crash (the one old `fwd` artifact, from 2026-11-20, no
   longer reproduces).
   `overflow-checks` for the kernel's release build: left off. Every
   length traced is a 16-bit field in a `usize`; turning the checks on
   would make a missed overflow a reboot instead of a value a later bounds
   check drops. The fuzzers keep running with them on.
   Not covered: smoltcp's own DHCPv4 client (WAN), the DoT crypto glue
   (item 9).
5. **FIXED a–c, f; d–e accepted (2026-11-22): DHCP pool exhaustion** (A3/A4: any
   client on a network the server answers, guest networks included).
   Measured on `proto_dhcp::v4::server` with the default pool (.100–.199,
   12 h leases), a scratch test with forged `chaddr`s:
   - a. **DISCOVER only:** 100 packets hold the pool for 60 s
     (`OFFER_HOLD_SECS`); repeated every minute, nobody new gets an
     address.
   - b. **DECLINE from one MAC:** the server accepts a DECLINE for any
     `requested_ip`, from any client, whether it was offered that address
     or not; 100 packets take the whole pool out for 600 s
     (`DECLINE_HOLD_SECS`).
   - c. **DECLINE memory:** addresses outside the subnet are stored too:
     1,000,000 DECLINEs grew the heap by 26 MB (26 B each), released only
     by `expire()` after 600 s. At the rate `svc` takes datagrams this is
     hundreds of MB per window, an allocation failure is a panic (reboot);
     not measured in the kernel.
   - d. **Full DORA:** 200 packets bind the pool for the lease time
     (12 h). Inherent to DHCP (no client authentication); the usual answer
     is switch port security, which a SOHO router's LAN lacks.
   - e. **INIT-REBOOT:** a REQUEST naming a free address without a
     DISCOVER binds it: 100 packets, same as d.
   - f. **CPU:** `pick_address` scans the range and checks each address
     against every lease, so a DISCOVER costs O(range × leases).
     `dhcp.range` has no size limit: on a /16 pool with 16,000 addresses
     taken, one DISCOVER took 178 ms on the development Mac (16,000 more
     packets fill it, each bind also O(leases)); a full /16 is about 16×
     that, seconds per packet on the apu4, past the 5 s cross-core
     watchdog. The default /24 pool: well under a millisecond.
   Fixes in `proto_dhcp::v4::server`:
   - b, c: a DECLINE counts only for the address the declining MAC was
     offered or holds (RFC 2131 §4.3.3); others are counted
     (`declines_refused`) and ignored, so the declined table is bounded by
     the pool and the reservations.
   - a: a DISCOVER that finds the pool full takes over the oldest offer of
     another MAC that was never requested (`offers_reclaimed`; reservations'
     offers and bound leases are never taken). Oldest first: a flood takes
     back its own offers before a real client's, which that client requests
     at once.
   - f: leases indexed by address (one lease per address; a new lease
     replaces another MAC's expired one, with its `Released` event), so
     checking an address is O(log n) and picking one at most a pass over
     the pool; `dhcp.range` is capped at 4096 addresses
     (`config::validate::MAX_DHCP_POOL`, the same as the lease snapshot's
     per-network limit). The free-address set considered first was not
     needed with the cap.
   - Counters per network: `/api/status` `networks[].dhcp_stats`
     (`pool_full`, `offers_reclaimed`, `declines_refused`).
   The same probe afterwards: a, b and c no longer keep a new client out
   (C: 0 bytes per DECLINE), d and e still do; f: 1.0 ms per DISCOVER with
   16,000 taken (178 ms before), 0.24 ms at the 4096 cap. Host tests in
   `server.rs` (decline, reclaim, reservation offers, expired-lease
   replacement, the index after every change), config test for the cap,
   `dhcp` fuzz target 10 min clean, `lease-test.sh` (aarch64, x86_64) and
   the base lab pass.
   d and e stay an accepted risk (no client authentication in DHCP; switch
   port security is the usual answer): on guest networks prefer short
   leases and a pool larger than the expected clients, and watch
   `pool_full`.
   Found on the way: `lease-test.sh` had failed its "listed after the
   restart" checks since 206e9e2 (the lease JSON gained `ipv6` between `ip`
   and `hostname`); its grep is fixed, negative control
   `LEASE_TEST_NO_STORE=1` still fails.
6. **FIXED (2026-11-22): web interface lockouts** (A3: a client
   in a zone that may reach the web interface; guests are refused by zone
   input by default). Probed over `mgmt=wan` + a host port forward (the
   same code as on the LAN):
   - a. **Password block is global:** after a wrong password every
     password check is refused for 1 s (`fail_until`), the right one
     included. A client sending a wrong password every 0.7 s: the
     owner's correct login answered 429 in 6 of 10 tries (0 of 10
     without it). Existing sessions (Bearer) are not affected; new logins
     and Basic scripts are.
   - b. **Connection slots:** each network with management has 4 sockets
     (`LAN_SOCKETS`), one connection each. 4 idle connections (nothing
     sent) refuse everyone else until they time out (about 6 s here; the
     limit is `REQUEST_TIMEOUT` 20 s); an attacker that reconnects as
     slots free: 0 of the owner's 20 requests over 60 s answered.
   - Not a problem: session tokens are 128 random bits, compared in
     constant time; a wrong guess against the stored hash costs one
     PBKDF2 (about 5 ms under HVF, 20,000 iterations), at most one per
     second today.
   Fixes:
   - a: `auth::Throttle`: wrong passwords counted per source
     (`auth::source_key`: an IPv4 address, or an IPv6 /64), that source
     alone waits 1 s, doubling per failure in a row up to 30 s, cleared by
     a success or 10 min without failure; at most 64 sources (the least
     recently failed goes). PBKDF2 checks: at most 4 per second in all
     (`HASH_CHECKS_PER_SEC`); a password that already verified costs one
     HMAC and needs none (`Cache::known`); none left: 429, not counted as
     a failure. The boot-argument password is a plain compare.
   - b: 8 slots per network (`LAN_SOCKETS`), and one is always kept
     listening: when the last is taken, a connection whose request head
     has not arrived goes, from the source holding the most slots there,
     the oldest first (`Mgmt::keep_one_listening`; a request that has
     arrived is never cut). The first plan, at most 2 slots per source,
     was dropped: browsers open several connections to one host at once.
     A request head must arrive within 5 s (`HEAD_TIMEOUT`; the body keeps
     20 s, uploads 120 s).
   - Counters: `/api/status` `mgmt.throttle` (`sources`, `throttled`,
     `hash_busy`, `evicted`).
   Tests: `auth` host tests (per-source backoff and doubling, forgetting,
   bounded table, the budget's rate and burst, /64 keys); lab checks in
   every mode (`web lockout`: a second client address guesses twice a
   second while the client's own logs in, 8 of 8 answered and the guesser
   backed off; `web slots`: 8 idle connections from it, the client still
   answered, `evicted` rises); negative controls `LAB_MGMT_SAME_SOURCE=1`
   (the client's logins get 429) and `LAB_ROUTER_ARGS=mgmt_evict=0` (its
   request is refused). Store, upgrade and persist tests pass. The QEMU
   port-forward probe cannot show the per-source split: every host
   connection arrives from 10.0.2.2.
7. **Router-client port pass-through** (§4.1): what A1 can send to 60000–65535 and UDP 68 and what smoltcp does with it.
8. **PPPoE password in clear** on the SD card (A7).
9. **DoT provider**: own RustCrypto glue in `proto-dot/src/provider.rs` is crypto code written here; review against rustls' provider requirements.
10. **Missing fuzz targets**: CLI line parser, config TOML/JSON, config-store records, DoT record layer, DNS-TCP framing.

## 6. Next steps

- Phase 2 starts with hypotheses 1–2 (small, high impact, testable in the lab with `curl` from the client VM), then 4 (WAN parser panic review: `grep -n 'unwrap\|expect\|\[.*\]'` per crate, then reading the paths).
- Each confirmed item gets a host test or lab check with a negative control, per the repo rules.
