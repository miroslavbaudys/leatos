# DNS servers of your own, and DNS over TLS

The forwarder (`crates/proto-dns`) asks the WAN lease's DNS servers by
default. `dns.upstreams` replaces them; with `dns.tls` every upstream
query goes through TLS (RFC 7858), strict (RFC 8310): never plain DNS,
not even when TLS fails.

```toml
[dns]
tls = true
upstreams = ["1.1.1.1#cloudflare-dns.com", "1.0.0.1#cloudflare-dns.com"]
```

| Provider   | `upstreams` |
|------------|-------------|
| Cloudflare | `1.1.1.1#cloudflare-dns.com`, `1.0.0.1#cloudflare-dns.com` |
| Quad9      | `9.9.9.9#dns.quad9.net`, `149.112.112.112#dns.quad9.net` |
| Google     | `8.8.8.8#dns.google`, `8.8.4.4#dns.google` |

Any DoT server works whose certificate chains to a root in Mozilla's
bundle (built in, `webpki-roots`) and carries the name after `#` (a host
name, or the address itself for servers with IP certificates). A private
server with its own CA: put the CA in `dns.tls_ca` (PEM).

Also on the CLI (`config set dns.tls = true`, `config set dns.upstreams =
["1.1.1.1#cloudflare-dns.com"]`), in the web interface (DNS page) and as
boot arguments `dns=1.1.1.1#cloudflare-dns.com,1.0.0.1#cloudflare-dns.com`
and `dns_tls=1|0`.

## Settings (`crates/config`)

- `dns.upstreams`: up to 4 entries `ip[:port][#name]`, in order of
  preference; the resolver rotates through them on timeouts. Port: 53, or
  853 with TLS. Empty = the WAN lease's servers (DHCP option 6, PPPoE
  IPCP).
- `dns.tls`: needs at least one server, and a `#name` on every one
  (validated). Boot arguments fail closed: servers without a name are left
  out, and with none left every query gets SERVFAIL.
- `dns.tls_ca`: up to 8 PEM certificates, 16 KiB, added to Mozilla's
  roots.

## How it works

```text
LAN client ──UDP 53──> Resolver (zone → cache → upstream)
                          │ Action::Upstream { server, query }
                          ▼
            net::services ── dns.tls? ──no──> UDP to server:53
                          │ yes
                          ▼
            net::dot: one proto_dot::Conn per server
              TCP (smoltcp, WAN, local port 61000–64999) ⇄ rustls (unbuffered)
              ⇄ 2-byte-length framing, pipelined queries
```

- **TLS**: rustls 0.23 without `std` through its unbuffered API, in
  `crates/proto-dot` (sans-IO: TCP bytes and DNS messages in and out).
  TLS 1.3 and 1.2 (ECDHE, AEAD only).
- **Crypto provider** (`proto_dot::provider`): RustCrypto, pure Rust, no C
  or assembly to cross-compile. AES-GCM, ChaCha20-Poly1305, X25519,
  P-256, P-384; signatures ECDSA P-256/P-384, Ed25519, RSA PKCS#1 v1.5 and
  PSS (2048–8192 bits). x86_64-unknown-none has no SSE: the crates' SIMD
  backends are switched off there (`.cargo/config.toml`, sha2's
  `force-soft`). Debug builds still optimise these crates (`Cargo.toml`
  `[profile.dev.package]`): a handshake would otherwise take seconds.
- **Connections** (`net::dot`): opened when a query needs one, closed
  after 30 s without queries; session tickets (TLS 1.3 resumption) make
  the next handshake one round trip and skip the certificate check. A
  handshake has 5 s; a failure (bad certificate, refused, timeout) backs
  the server off 2 s doubling to 60 s, its queries are dropped meanwhile
  (the resolver's retry goes to the next server; clients get SERVFAIL
  when all fail). The resolver waits 3 s per try with TLS (1.5 s without).
- **Answers** are matched by ID and question like UDP ones. With TLS on,
  UDP datagrams on the upstream socket are ignored: no query went out by
  UDP, so a datagram with a pending ID would be spoofed.
- **Firewall**: replies to the router's own TCP clients pass only from the
  configured DoT servers (address, port 853) to ports ≥ 60000
  (`fwd::forwarder::Policy::router_tcp_peers`); every other TCP to those
  ports stays WAN input and is dropped silently (lab: the WAN probe of TCP
  61000).
- **Large answers**: over TCP an answer may be up to 64 KiB. Answers to
  LAN clients are cut to the client's EDNS size (512 without EDNS, at most
  1472: one datagram) with TC set (`proto_dns::wire::fit`).

## The clock before SNTP

Certificates have dates; the router learns the time from SNTP, whose
server names it resolves through this resolver, over TLS. Until the first
sync (`proto_dot::verify`):

- a chain is checked as of the moment its leaf became valid (`notBefore`),
  never earlier than the kernel's build time (`RROUTER_BUILD_TIME`, the
  built commit's date, from `build.rs`), so signatures, the name and the
  chain are checked as always, and a certificate that expired before the
  kernel was built is still refused;
- once the clock is set, a connection opened before is closed, and the
  next one checks the dates for real (lab: the ISP's stunnel log shows
  the close at the moment of the sync).

SNTP is unauthenticated, so the dates were only ever as good as it is;
this ordering gives up nothing more.

The battery-backed RTC (x86_64: the CMOS clock, the apu4's included;
`arch::rtc`, read once at boot by `wallclock::init_rtc`) narrows the
window, where it cannot lock DNS out (`proto_dot::verify::unknown_clock_time`):

| RTC (now) | Chain checked at | Log (`up: …`) |
|---|---|---|
| none, or before the build time (reset, dead battery) | leaf `notBefore` (≥ build time) | `dates checked at issue time until SNTP (no usable RTC)` |
| after the leaf's `notBefore`, before its `notAfter` | the RTC's time | `dates checked against the RTC until SNTP` |
| at or after the leaf's `notAfter` | leaf `notBefore` | `expired by the RTC: accepted until SNTP checks the dates` |

The last row is deliberate: an RTC that is ahead (set wrong) would
otherwise refuse every certificate, and DNS (so SNTP, which needs it, so
the fix for the RTC) would stay dead. So an expired leaf is not refused on
the RTC's word alone before SNTP; what the RTC adds is a real time for the
intermediates (one that expired by then fails) and the log line. SNTP then
checks every date (reconnect) and sets the RTC if it is more than 2 s off
(`rtc : was N s off, set to …`). Trust anchors' own dates are never
checked (webpki). aarch64 has no RTC driver (QEMU's PL031 is not mapped).

## Randomness

TLS key shares and randoms come from the kernel's entropy pool
(`kernel/src/entropy.rs`): timing jitter, boot data, management request
and DoT arrival times through SHA-256. No hardware RNG is trusted on the
apu4 (CCP TRNG disabled by firmware, Jaguar RDRAND unreliable), so this is
best effort, as for password salts.

## Observability

- Boot log: `dns-over-tls    : strict, 1.1.1.1#cloudflare-dns.com, …
  (N trust anchors)`, then per connection `… up: TLSv1_3
  TLS13_AES_128_GCM_SHA256` (`, resumed` on resumption), failures with
  the reason and the backoff.
- `/api/status` `dns`: `source`, `upstreams`, `tls` per server (state,
  protocol, queries, answers, dropped, connects, failures, last error);
  the web interface's DNS page shows them.
- CLI `status`: `dns` and one `dns-tls` line per server.

## Tests

- `cargo test -p proto-dot`: handshakes against a rustls server (ring) for
  every TLS 1.3 and 1.2 suite, key exchange group and certificate type
  (ECDSA P-256/P-384, Ed25519, RSA), resumption, wrong name, unknown and
  forged issuers, expired / not yet valid certificates, the unknown-clock
  rule and the build-time floor, split records, close_notify, garbage.
- `cargo test -p config`, `-p fwd` (`tcp_replies_pass_only_from_the_routers_own_tcp_servers`),
  `-p proto-dns` (`udp_limits_and_fitting`).
- `LAB_DOT=1 scripts/lab-test.sh`: the ISP serves DoT (stunnel + dnsmasq)
  with a certificate under a CA made per run (`dns.tls_ca`); the client
  resolves `dot.isp.example` (only the DoT server has it) but not
  `plain.isp.example` (only plain dnsd has it). Negative controls:
  `LAB_DOT_NAME=wrong.example`, `LAB_DOT_CA=0` (both: no connection, and
  still no plain DNS), `LAB_ROUTER_ARGS=dns_tls=0` (plain DNS: both name
  checks fail).
