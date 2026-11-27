# Router-local TCP of our own: smoltcp removed (plan)

Status (2026-11-27): plan. Roadmap M15. Starts after the M14 build is on the apu4 and soaked
(docs/local-stack.md §6). This reverses docs/local-stack.md §1 ("Not a goal: our own TCP"),
by decision of the user on 2026-11-27.

## 1. Goal

Since M14 smoltcp carries only the router's own TCP: the web interface on :80, DNS over TCP on
:53, the DoT client. For that it keeps a second copy of every link's addresses and routes, a
`Device` glue layer and its own timers, and it answers whatever `net::local` does not claim
(RST on closed TCP ports, ICMP protocol unreachable for other protocols).

**Target:** no smoltcp. TCP is a sans-IO crate, `crates/proto-tcp`, driven by `svc` over the
router-local path that UDP already uses: `net::local::take` on receive, `net::local::send_frame`
on send, source addresses from `fwd::local::LocalLink`. One stack, one copy of the link state.

**No fallback.** There is no boot argument to select smoltcp again. If a build breaks the
router, the SD card is reflashed (`scripts/apu-image.sh`) or the previous slot is booted
(docs/upgrades.md). Each step therefore passes its full lab suite before the next starts, and the
apu4 gets the result only at the end (§6).

## 2. What smoltcp does today, and what replaces it

Role, where it lives today, and its replacement:

- **TCP state machine**: mgmt :80 (listen, RX 64 KiB / TX 16 KiB), DNS over TCP :53 (4
  connections), the DoT client (connect, WAN, 16 KiB); `mgmt.rs`, `dns_tcp.rs`, `dot.rs` →
  `proto_tcp`.
- **Addresses and routes per link** (`Interface`, limits 4 / 32): `stack.rs` (`new_iface`,
  `set_host_routes`, the IPv6 sync), `svc.rs`, `pppoe.rs` → deleted; `LocalLink::source4` /
  `source6` and the datapath's routes are the only copy.
- **`Device`** (RX from `local_rx`, TX into the qdisc): the smoltcp part of `device.rs` (`Aqm`
  stays) → `local::send_frame`.
- **Timers** (`poll_delay` in `svc.rs`) → `proto_tcp`'s `next_deadline()`.
- **ISN** from `config.random_seed` (`stack.rs`) → RFC 6528 (keyed hash of the 4-tuple + clock).
- **RST on closed TCP ports** → `proto_tcp` (§3.4).
- **ICMP protocol unreachable / parameter problem** for other protocols and leftover Hop-by-Hop
  packets → dropped silently and counted (§3.4).

The API the three users call is small: `listen`, `connect`, `send_slice`, `recv_slice`, `recv`,
`close`, `abort`, `state`, `can_send`, `can_recv`, `may_send`, `send_queue`, `is_open`,
`is_active`, `remote_endpoint`, `set_timeout`. `proto_tcp` offers the same calls, so the changes
in `mgmt.rs`, `dns_tcp.rs` and `dot.rs` are mechanical.

The bar is what smoltcp gives us, not a full host TCP: it is built without congestion control
(no `socket-tcp-reno` / `socket-tcp-cubic`), without SACK, and ignores Packet Too Big.

## 3. Design

### 3.1 The crate

`crates/proto-tcp`, `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`, sans-IO: segments and
`now` in, segments and events out. No I/O, no clock, no randomness of its own (the kernel passes
the ISN secret from `entropy`).

- `Conn`: one connection, RFC 9293 states. Send buffer and receive buffer as fixed rings
  allocated at open (the sizes the users choose today), no allocation per segment.
- `Listener`: a passive open on (address set, port) with a fixed table of half-open connections;
  a full table drops the SYN (no allocation per SYN).
- `Tcp`: the connection table and demultiplexing by 4-tuple; `receive(seg, now)`,
  `poll(now) -> segments`, `next_deadline()`.

### 3.2 What it implements

- Three-way handshake, active and passive; FIN states, TIME_WAIT short and bounded (a fixed
  number of entries, oldest reused).
- Retransmission: RFC 6298 RTO (SRTT / RTTVAR, Karn, exponential backoff, bounds 200 ms – 60 s),
  and the per-connection timeout for unacknowledged data (10 s today).
- MSS option: sent from the link MTU (1460, PPPoE 1452, IPv6 −20); the peer's honoured.
- Receive: in order, plus a bounded out-of-order store (a few ranges inside the receive ring;
  the WAN reorders, DoT runs there). Window advertised from the ring's free space.
- Zero-window probing, persist timer.
- RFC 5961: RST and SYN accepted only at the exact sequence number, challenge ACK otherwise,
  ACK range check; rate-limited challenge ACKs. The DoT client and `mgmt-wan` face the internet.
- Checksums verified on receive (`fwd::wire`), computed on send.

Not at first (smoltcp has none of them either): window scaling (64 KiB at LAN round-trip times
is enough for the kernel upload), SACK, timestamps, Nagle, keepalive, congestion control.
NewReno is small and can follow if a measurement asks for it.

### 3.3 Kernel glue: `net::tcp`

- **Receive:** `local::take` claims TCP to the router's addresses on the link and hands it to
  `Tcp::receive`. The zone input policy and `Policy::router_tcp_peers` still apply first, in the
  datapath, as today.
- **Send:** segments get IP + TCP headers (`fwd::wire` builders) into a `net::packet` buffer
  and leave through `local::send_frame` (PPPoE into the qdisc, else `Datapath::send_local`).
  Source address from `local::source`. Pool empty or qdisc full: the segment is not sent and the
  retransmission timer covers it (no queue outside the qdisc, CLAUDE.md).
- **Timers:** `svc` adds `Tcp::next_deadline()` to its wake-up, as for the other services.
- `HostIf` loses `iface` and `sockets`; `stack.rs`, `svc.rs`, `pppoe.rs` lose the address and
  route syncing; `device.rs` keeps only the qdisc code (and is renamed if little is left).

### 3.4 What the router answers

- TCP to a closed port, from a zone whose input policy lets it through: RST (as smoltcp does;
  the lab's `LAB_WAN_OPEN=1` control expects it). Refused input stays `fwd`'s
  (`Action::Reject` or drop).
- Other IP protocols to the router, leftover Hop-by-Hop packets: dropped silently and counted
  (`local.other_dropped`), as unbound UDP since 2026-11-27. No ICMP protocol unreachable.

## 4. Steps

Each step passes the CLAUDE.md test table for what it touches before the next one starts.

### Step 1: `crates/proto-tcp`

The crate (§3.1, §3.2), kernel unchanged.

- Host tests: handshake both ways, data both ways, close from each side and simultaneous,
  RST, retransmission and backoff, the data timeout, out-of-order and duplicates, zero window
  and probes, MSS, TIME_WAIT reuse, half-open table full, RFC 5961 cases (blind RST / SYN /
  data out of window).
- A simulated link in the tests (loss, reordering, duplication, delay) transferring a few MiB
  both ways with the checksum of the data compared.
- Interop: the same simulated link against smoltcp's TCP as the peer (dev-dependency, host
  only), both directions, so the two stacks are checked against each other.
- Fuzz target `tcp`: segment sequences against a connection and a listener (no panic, buffers
  bounded, state invariants). 10 min clean before step 2.

### Step 2: `net::tcp` and DNS over TCP

The glue (§3.3) next to smoltcp; `dns_tcp.rs` moves first (smallest, server side, short-lived).
`LAB_DNS_VIEWS=1`, `LAB_DOT=1` (its TCP fallback checks), lab default, also x86_64 and TCG.

### Step 3: the DoT client

`dot.rs` on `proto_tcp` (active open on the WAN, ports 61000–64999, replies through
`router_tcp_peers` as today). `LAB_DOT=1` (also x86_64, TCG), `LAB_IPV6=1` (DoT over IPv6),
`LAB_PPPOE=pap` (MSS 1452).

### Step 4: the web interface

`mgmt.rs` on `proto_tcp`: a listener per link, the kernel upload into the 64 KiB receive ring.
`upgrade-test.sh`, `persist-test.sh` (also `QEMU_STORE_BUS=sd`), `store-test.sh`, `cli-test.sh`,
`LAB_GUEST=1` (the reject RST, the WAN input checks), `LAB_IPV6=1`. Measured before and after
on the same machine (§5): upload time of the kernel image and `svc` CPU during it.

### Step 5: smoltcp removed

- `Interface`, `SocketSet`, `HostIf.iface` / `sockets`, the `Device` impl, the address and route
  syncing, the dependency in `kernel/Cargo.toml`.
- Other protocols dropped silently (§3.4), with a lab check and negative control (§5).
- Docs: kernel/src/net/CLAUDE.md, CLAUDE.md, README.md, docs/architecture.md, local-stack.md,
  ipv6.md, security-audit.md (attack surface table), safety-and-portability.md (dependencies),
  wireguard.md (local traffic of `wg0` goes to `net::local`, not smoltcp), lab-tests.md.
- The full test table: every lab mode, `QEMU_SMP=4`, `QEMU_NIC=igb`, x86_64, TCG.

## 5. Tests and negative controls

- **Transfer integrity:** the kernel upload in `upgrade-test.sh` already compares the stored
  image's hash; a lab check adds a large `/api` download with its hash compared on the client.
- **Loss on the path:** a lab run with the client's link set to drop 5 % (`tc netem` on the
  client VM): mgmt upload and DNS over TCP still complete. Validity: the client's counters show
  the drops happened, else the check is invalid.
- **Closed TCP port:** a LAN probe to an unused port gets a RST (negative control: none for a
  refused zone, as today's `LAB_WAN_OPEN`).
- **Other protocols:** a LAN probe with IP protocol 253 to the router gets no answer and
  `local.other_dropped` rises (negative control: the same probe to a client on the LAN is
  forwarded, so the probe itself works).
- **Blind RST:** the ISP VM sends RSTs off the exact sequence number into the DoT connection:
  it survives and challenge ACKs are counted (negative control: an exact-sequence RST ends it).
- **Measurements:** kernel upload time and `svc` CPU (`cpu.tasks`) with smoltcp and with
  `proto_tcp`, same machine, same image, three runs each; heap per open connection
  (`heap_live`).
- `cargo test`, `cargo clippy`, the `tcp` fuzz target for every change to the crate.

## 6. On the apu4

All steps go at once, after QEMU: `apu-upload.sh` in RAM first (the upload itself still runs on
the old build's smoltcp, so it is not at risk), a day against the previous build's
`/api/status`, uploading the next build over the new TCP (also through the
SSH tunnel used for remote access), then `--persist` and a 72 h soak. If it breaks: boot the other
slot or reflash the SD card (`scripts/apu-image.sh`; the config is seeded again with `--config`).

## 7. Risks and open questions

- **The upgrade path runs on this TCP.** A bug that stalls large uploads cuts off remote
  upgrades; the RAM day includes uploading over the new TCP before anything is persisted.
- **Internet-facing protocol code.** The DoT client always, mgmt with `mgmt-wan`: fuzzing and
  RFC 5961 from step 1, a security-audit.md entry at step 5.
- **No congestion control** (parity with smoltcp): fine for low-volume router TCP behind CAKE,
  which sees every segment; revisit if a measurement shows the DoT client or mgmt flooding a
  queue.
- **Packet Too Big / fragmentation needed** for the router's own TCP: ignored (as smoltcp);
  MSS from the link MTU covers PPPoE. Could lower the connection's MSS later.
