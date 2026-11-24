# WireGuard server (design)

Status (2026-11-18): design only, nothing implemented. Roadmap row M12.

A WireGuard endpoint on the router itself: phones and laptops (road
warriors) reach the home networks and the internet through it, and later
other sites (site-to-site). Protocol: the WireGuard paper (Donenfeld,
NDSS 2017) and the reference implementations; Noise_IKpsk2 handshake,
ChaCha20-Poly1305 transport, BLAKE2s, X25519.

## 0. What already works without it
A port forward (`[[firewall.forward]]`, UDP 51820, docs/config-v2.md §6)
to a WireGuard server on a LAN host works today: 51820 is below the
router-local ports and accepted by validation
(`crates/config/src/tests.rs`, "WireGuard's port is fine"). The developer's
remote access currently goes through a WireGuard client on a LAN host to an
outside VPS (SSH tunnel to the router's :80); a forward to a LAN server
would remove the VPS. The native server is worth it for: no extra box,
CAKE seeing the flows inside the tunnel (§3), zones for VPN clients, and
the router's own web page and DNS over the tunnel.

## 1. Today (verified in the code, 2026-11-18)
- `crates/fwd` is IPv4 only (M7 pending), so outer and inner IPv4 first.
- Datapath (`kernel/src/net/datapath.rs`): NIC RX → VLAN untag → PPPoE
  decap → `Forwarder::process` → `Verdict::{Local, Forward, Drop}` →
  neighbor (or the PPPoE AC) → qdisc → PPPoE encap → VLAN tag → NIC TX.
  `Local` packets go to `svc` through `LinkShared::local_rx`; forwarded
  packets never leave `dp_down`/`dp_up`.
- Links: `links[0]` = WAN, then `MAX_LINKS - 1` network slots on `lan0`
  (`net/shared.rs`); each link is a forwarder `IfIndex` with a `Role` and
  a zone.
- Packet buffers (`net/packet.rs`): 128 B headroom, 2048 B RX area: room
  for 44 B of WireGuard + UDP + IPv4 header in front of an inner packet
  (plus Ethernet, VLAN, PPPoE) and the 16 B tag behind a 1500 B one.
- Crypto already in the tree (through `crates/proto-dot`):
  `chacha20poly1305` 0.11 (also XChaCha20-Poly1305, for cookies),
  `x25519-dalek` 3. Missing: `blake2`. On x86_64 the soft backends are
  pinned (`.cargo/config.toml`: no SSE in the kernel, serial
  curve25519 backend).
- Shaper overhead is one constant per port (`shape_overhead`, + 8 B
  PPPoE, + 4 B VLAN); there is no per-packet overhead yet.
- Input firewall: `Policy::input` per zone with a service mask
  (`fwd::forwarder::svc`); the WAN zone admits nothing but replies to the
  router's own clients (ports ≥ 60000).
- `arch::rtc` on aarch64 is a stub (no clock before SNTP); x86_64 reads
  the CMOS clock as a hint.
- `boringtun` needs std: usable only as a host-side test peer.

## 2. Packet path
WireGuard is a layer-3 link, `wg0`: a new link (`IfIndex`) after the
network slots, `Role::Lan`, its own zone (e.g. `vpn`), MTU = WAN MTU − 60
(1440 on Ethernet, 1432 under PPPoE; − 80 with an IPv6 outer header
later). No ARP: the next hop is a peer, chosen by cryptokey routing
(longest match on the peers' `allowed_ips`).

**Receive (download direction, `dp_down`).** Before the forwarder, like
the PPPoE decap: a WAN packet that is IPv4/UDP to the WAN address and the
listen port is taken out of the normal path. The check must be a few
compares (ethertype, protocol, destination address and port), since every
WAN packet pays for it.
- Type 4 (transport): look up the receiver index → keypair, check the
  counter against the replay window, decrypt in place, check that the
  inner source is in that peer's `allowed_ips` (else drop reason
  `wg-src`), then process the inner packet as RX on `wg0`
  (`Forwarder::process` with `ingress = wg0`). An authenticated packet
  from a new outer source updates the peer's endpoint (roaming).
- Types 1–3 (handshake initiation, response, cookie reply): to `svc`
  through a bounded queue on `wg0` (drop when full), like `local_rx`.
- Anything else to the port: drop (`wg-bad`).
- WAN anti-spoofing applies to the outer header as today.

**Send (upload direction, `dp_up`).** The forwarder routes to `wg0`
(peers' `allowed_ips` are connected routes there). The packet is queued
**in plaintext** in the WAN qdisc, with `PacketMeta` noting the peer,
and is encrypted and encapsulated when the WAN TX pulls it (§3): counter
assigned, ChaCha20-Poly1305 in place, WireGuard header, UDP (source = the
listen port), IPv4 to the peer's current endpoint, then PPPoE/VLAN as
usual. No session key: drop (`wg-nokey`) and kick `svc` to start a
handshake (the first packets of a session are lost; the reference
implementations queue a few, which would be a second queue outside the
qdisc and is not done here).

**Traffic from and to the router itself** (DNS, the web page over the
tunnel): `Verdict::Local` on `wg0` to `svc`'s smoltcp interface for that
link, like the network slots; its replies route back to `wg0`.

**NAT.** Tunnel subnets count as inside: a peer reaching the internet is
masqueraded on the WAN like a LAN host. The router's own outer packets
(source port 51820) never pass NAPT; validation reserves the listen port
against port forwards and `mgmt.on_wan`, like `:80`.

## 3. CAKE: encrypt when the packet leaves the queue
On Linux the physical interface's qdisc sees one UDP flow per peer: flow
and host fairness inside the tunnel are lost, and a bulk transfer over
the VPN shares one CAKE flow with a call over the same tunnel. Here the
inner packet is queued and encryption happens on dequeue:
- CAKE hashes the inner 5-tuple and the inner (pre-NAT) host, so flows
  inside the tunnel get the same isolation as LAN flows.
- Nonce counters are assigned in send order: monotonic without
  coordination.
- The shaper must charge what goes on the wire: inner length + 60 B
  (IPv4 20 + UDP 8 + WireGuard header 16 + tag 16), plus the port's
  PPPoE/VLAN overhead. This needs a per-packet overhead in `PacketMeta`
  (`crates/qdisc` shaper), set by the forwarder for `wg0` egress.
- Downloads through the tunnel arrive encrypted on the WAN and leave
  decrypted into the LAN qdisc, so the LAN CAKE sees the inner flows
  without any change.
- The rule "the qdisc is the only place packets wait" holds: no
  per-peer staging queue.

## 4. Cores and ownership
Per peer, each direction owns its half of the session:
- `dp_up` (core 1): the sending key, the send counter.
- `dp_down` (core 0): the receiving keys (current, previous, next), the
  replay window (2048-bit bitmap), the endpoint learned from
  authenticated packets.
- `svc` (core 2): static keys, handshake state, cookies, timers.

`svc` publishes a new keypair through `net::shared` (a `spin::Mutex`
swapped per peer, taken once per batch, not per packet); counters and
"bytes sent/received", "last handshake" are atomics read by `/api/status`.
The endpoint is an atomic (address + port in one `u64`) written by
`dp_down`, read by `dp_up`. With 2 cores both directions share core 0;
with 1 core everything runs there, as today.

**Handshakes stay out of the datapath.** A responder handshake costs
about three X25519 operations plus BLAKE2s: estimated a few hundred µs
on the apu4's 1 GHz Jaguar with the serial backend (to be measured, §8).
They run in `svc` (`Priority::Service`). Under load (handshake queue
above a threshold) the cookie mechanism (mac2, XChaCha20-Poly1305 cookie
reply) is mandatory, plus a per-source handshake rate limit; drops are
counted.

## 5. `crates/proto-wg` (sans-IO, `no_std`, `forbid(unsafe_code)`)
- `Noise_IKpsk2` initiator and responder; TAI64N timestamp check (per
  peer, strictly increasing); mac1/mac2; cookie generation (secret
  rotated every 2 min) and cookie replies.
- `Session`: in-place `encrypt(counter, buf)` / `decrypt(buf) ->
  Result<Range>` + `ReplayWindow` (RFC 6479 style).
- Timer state machine driven by `now` (nanoseconds, like the other
  crates): rekey after 120 s or 2^60 messages, reject after 180 s,
  handshake retry every 5 s with jitter up to 90 s, keepalive after 10 s
  without sending when data was received, optional persistent keepalive;
  zero the keys after 540 s. Returns events (`SendHandshake`,
  `SendKeepalive`, `Expired`) and the next deadline.
- Cryptokey routing table: peers' `allowed_ips`, longest match, both
  directions.
- Dependencies: `chacha20poly1305`, `x25519-dalek`, `blake2`, `zeroize`.
- Tests: the protocol's known vectors, handshake + transport against
  `boringtun` (dev-dependency, host only), replay and reorder cases,
  timers on simulated time, mutation fuzzing of the four message parsers
  (roadmap M9: all parsers).

## 6. Config (`crates/config`)
```toml
[wireguard]
listen_port = 51820
private_key = "…"           # secret: generated on the router, never shown
address = "10.99.0.1/24"     # the router on wg0
zone = "vpn"
# mtu = 1420                 # default: WAN MTU − 60

[[wireguard.peer]]
name = "phone"
public_key = "…"
preshared_key = "…"          # secret, optional
allowed_ips = ["10.99.0.2/32"]
# endpoint = "198.51.100.7:51820"   # only needed to initiate (site-to-site)
# keepalive = 25
```
- Secrets like the PPPoE password (`without_secrets` / `keep_secrets`):
  never shown by the API or the CLI, kept when a save leaves them out.
- A missing `private_key` is generated at save from `kernel/src/entropy.rs`
  (like `mgmt.password` → `password_hash`); the public key is shown.
- Validation: key encodings (32 bytes, base64), `address` not overlapping
  a network or the WAN subnet, `allowed_ips` not overlapping each other,
  a network or `address`'s subnet except the peer's own address in it,
  `listen_port` below 60000 and not a forward's port, zone exists, peer
  names unique.
- Zones: `vpn` is an ordinary zone (`forward_to`, `input`, rules apply).
  The WAN zone gets a new input service bit `wg` (accept UDP
  `listen_port` from the WAN), set automatically when `[wireguard]`
  exists.
- `unsupported()` lists `wireguard` until the kernel side lands.
- Live apply: peers added or removed without a restart; a new private key
  or listen port drops all sessions.
- `needs_trial`: no (the management path does not depend on it), unless
  `mgmt` is reached only over the tunnel; keep it simple: no trial.

## 7. Web page, CLI, DNS
- Page section "WireGuard": the router's public key and endpoint, the
  peer table (name, allowed IPs, endpoint, last handshake, RX/TX bytes),
  "Add peer" generating a key pair in the browser (WebCrypto X25519 where
  available) and showing the peer's config as text and a QR code; the
  private key leaves the browser only in that config.
- `/api/status` `wg`: per peer handshake age, bytes, endpoint; drop
  reasons `wg-src`, `wg-bad`, `wg-nokey`, `wg-replay`; handshake and
  cookie counters.
- CLI: `status` shows peers; `config set wireguard.peer.phone.…`.
- DNS: peers' first address resolves as `<name>.<domain>`, and `wg0`'s
  network serves DNS to the peers (the address the peer config names).

## 8. Performance on the apu4 (to be measured first)
No SSE in the kernel: soft ChaCha20 and 64-bit Poly1305. Guess: 10–15
cycles/byte on Jaguar, roughly 500–800 Mbit/s of pure crypto per core
before per-packet costs. The 90/18 Mbit/s line through the tunnel would
take about 10–20 % of the download core. A `selftest` microbenchmark
(MB/s for 1420 B packets, µs per handshake) on the apu4 is the go/no-go
step; if it is far off, the alternative is saving SSE state for the
datapath cores (arch work, out of scope here).

## 9. Tests
- Host: `cargo test -p proto-wg` (§5).
- Lab `LAB_WG=1 scripts/lab-test.sh`: the router boots from a store with
  `[wireguard]` and one peer; the ISP VM is that peer (outside, like a
  phone on mobile data): handshake, ping the router's `wg0` address,
  reach the client VM on the LAN, resolve `labclient.home.arpa` through the
  tunnel, reach the ISP's web server back through the tunnel (NAT),
  `/api/status` counters. First check whether Alpine's virt kernel ships
  `wireguard.ko` in the modloop (it lacks `pppoe.ko`); otherwise
  `wireguard-go` (user mode) on the ISP VM.
- CAKE check: a bulk transfer and a ping through the same tunnel; the
  ping's latency stays low (negative control: a build/boot argument that
  encrypts before the qdisc, `wg_flows=0`, makes it one flow).
- Negative controls: wrong peer public key (no handshake), `allowed_ips`
  excluding the source (`wg-src` counter rises, no reply), a replayed
  captured packet (`wg-replay`), the `vpn` zone without `forward_to`
  (LAN unreachable), no `wg` input bit (`LAB_WG_INPUT=0`: silent).
- The WAN probe check keeps TCP 22/80/61000 and ping silent; UDP 51820
  answers only valid handshakes.
- Matrix: `QEMU_SMP=4`, `LEATOS_ARCH=x86_64`, `QEMU_ACCEL=tcg`,
  `QEMU_NIC=igb`, `LAB_PPPOE=pap` (MTU 1432).

## 10. Order of work
1. `crates/proto-wg` with host tests and fuzzing; the apu4 benchmark
   (§8) decides whether to continue.
2. Config schema, validation, secrets, key generation (`leatstore` and the
   CLI see it; `unsupported()` until step 4).
3. Per-packet shaper overhead in `crates/qdisc` + `PacketMeta`.
4. Kernel: `wg0` link, receive path in `dp_down`, encrypt-on-dequeue in
   `dp_up`, drop reasons; `svc` handshakes, timers, key publication,
   roaming; `LAB_WG=1` with the negative controls.
5. Web page, CLI, DNS names.
6. On the apu4: a phone on mobile data reaches the router page and the
   LAN; bufferbloat through the tunnel.
7. Later: site-to-site (initiating needs an increasing TAI64N across
   reboots: wallclock from the RTC/SNTP, so not before SNTP on aarch64),
   IPv6 outer and inner (with M7).

## 11. Risks
- A new internet-facing crypto protocol: fuzzing, the cookie mechanism
  and rate limits are not optional. Constant-time code stays in the
  RustCrypto crates.
- Every WAN packet pays the port check (§2): keep it minimal and
  measure the per-packet cost before and after.
- First packets of a new session are dropped (no staging queue): fine
  for TCP and ping, visible as one lost packet after idle.
