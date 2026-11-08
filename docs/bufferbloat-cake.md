# Bufferbloat mitigation with CAKE

**Goal:** low latency under load is a first-class feature of rrouter, not an
add-on. The target behaviour is that a saturated uplink or downlink adds no
more than about 5–10 ms of queueing delay (in Linux terms, "A+" on bufferbloat
tests), with fair sharing between flows and between LAN hosts.

The chosen algorithm is **CAKE** (Common Applications Kept Enhanced, Linux
`sch_cake`, 2018; paper: Høiland-Jørgensen, Täht, Morton, *"Piece of CAKE"*).

## 1. The problem
The real bottleneck is the ISP link (DSL, cable, fibre or LTE), and the modem
or ISP equipment in front of it has large, dumb FIFO buffers. Under load,
packets wait there for hundreds of milliseconds. The fix is to **shape slightly
below the bottleneck rate** in the router, so the queue forms in the router,
where a smart queue manages it.

## 2. What CAKE consists of (what we have to implement)

| Component | What it does | Notes for rrouter |
|---|---|---|
| **Shaper** | Rate-based (not token bucket): computes when the next packet may leave, with ns precision | Needs **high-resolution, tickless timers** |
| **Overhead compensation** | Counts real on-wire bytes: PPPoE (8), Ethernet (14+4 FCS), VLAN (4), ATM cells (48/53), PTM (64/65), MPU | Essential with PPPoE. The PPPoE layer knows the encapsulation, so derive defaults automatically |
| **Flow queueing** | 1024 queues, 8-way set-associative hash (very few collisions), DRR++ scheduling, sparse-flow boost | Needs a flow hash per packet |
| **Host isolation** | `triple-isolate` (default) / `dual-srchost` / `dual-dsthost`: fairness per *host* first, then per flow | Must use **pre-NAT internal addresses**. Linux needs the `nat` keyword plus a conntrack lookup; **we own conntrack, so we get this for free** |
| **AQM: COBALT** | CoDel (sojourn-time based, 5 ms target, 100 ms interval) combined with BLUE (handles unresponsive flows); ECN marking | Needs an **enqueue timestamp per packet** |
| **DiffServ tins** | `besteffort`, `diffserv3/4/8`: priority tins with bandwidth thresholds, classified by DSCP | Classification at enqueue time |
| **ACK filter** | Drops redundant pure TCP ACKs on asymmetric links (upload-limited DSL) | Optional, but useful for SOHO |
| **Ingress mode** | Shapes *download* traffic. Linux needs an IFB device; drops still count toward the rate | We can do it natively (see §3.4) |
| **Memory limit** | Caps bytes queued, dropping from the fattest flow on overload | Interacts with the packet buffer pools |

We'll port the logic from Linux `sch_cake.c` (about 3k lines of C). It is
dual-licensed GPL-2.0/BSD (**verify the SPDX header before porting**; our
project is MIT/Apache, so we need the BSD option). Related specs: RFC 8289
(CoDel) and RFC 8290 (FQ-CoDel).

## 3. Architectural consequences: design for this now

These constraints affect milestones that come **long before** CAKE itself,
which is why they are recorded here.

### 3.1 No hidden queues (M2, drivers)
The qdisc must be the **only** place where packets wait. Any other buffer
(NIC TX ring, driver software queue, RX backlog) is a "dumb FIFO" that undoes
CAKE.
- **TX is pull-based:** the egress scheduler *pulls* packets from the qdisc
  only when the driver has room and the shaper allows it. Nothing ever pushes
  into a driver queue.
- **Byte-limited TX rings (BQL-style):** limit the bytes in flight in the NIC
  ring and tune the limit from completion events. On virtio the ring drains
  almost instantly, but real NICs (M8+) need this.
- **Drain RX promptly** so the RX ring doesn't become the hidden queue for ingress shaping.
- **Status (M2):** implemented in `drivers/virtio_net.rs` + `net/device.rs`:
  `can_transmit()` = free descriptor **and** in-flight bytes below
  `tx_byte_limit` (fixed, 8 × 1514 B). smoltcp only gets a TX token when
  there is room. Adaptive (BQL) limits follow in M6. The bounded packet pool
  (`net/packet.rs`, 1024 × 2 KiB) carries `PacketMeta` and has 128 B of
  headroom on every received packet, for re-encapsulation without a copy.

### 3.2 Timers and scheduling (M1, kernel core)
- A 1500-byte packet at 50 Mbit/s takes 240 µs, and at 500 Mbit/s 24 µs. The shaper
  needs **µs-precision wakeups**, so timers are **tickless**: program
  `CNTV_CVAL` to the next deadline. No periodic jiffies tick.
- The generic timer runs at 24 MHz under HVF (about 42 ns resolution), which is good enough.
- **Measured in M1:** tickless sleeps land within 0–6 µs while the CPU is
  busy (`idle-poll`). When idle in `wfi`, the *host* (macOS HVF) adds 0.3–3 ms
  of wake-up latency. This is a QEMU-on-macOS artifact, but it would ruin
  shaping accuracy in lab tests. Plan for M6: **hybrid idle**. If the next
  deadline is within a threshold (or the shaper has packets queued), arm the
  comparator early and spin for the last stretch; otherwise `wfi`. Make the
  threshold configurable (≈0 on real hardware). Until then, use the
  `idle-poll` feature for QoS experiments (docs/qemu.md).
- **Executor priorities:** the datapath (RX → forward → qdisc → TX) must
  never wait behind a slow service task (DNS, CLI). M1's executor gets at
  least two priority classes, and the datapath work runs first on every loop
  iteration.
- Interrupt handlers only acknowledge and flag. All work happens in executor
  context, so timer latency stays bounded by the longest task poll. Keep polls short.

### 3.3 Packet buffer metadata (M2, M4)
Every packet buffer carries metadata, computed once:
```rust
struct PacketMeta {
    enqueue_ts: u64,        // CoDel sojourn time
    flow_hash: u32,         // pre-NAT 5-tuple (from conntrack)
    src_host_hash: u16,     // pre-NAT internal host, for host isolation
    dst_host_hash: u16,
    tin: u8,                // from DSCP
    ecn_capable: bool,
    wire_len: u32,          // after overhead compensation
    is_pure_ack: bool,      // ACK filter
}
```
Pool size: the packet buffer pools must be able to hold CAKE's memory limit
(several MB per instance) plus the rings.

### 3.4 Pipeline position (M4)
**Status (M4):** the egress hook exists. `crates/qdisc` defines the `Qdisc`
trait, with `BFifo` (bounded tail-drop) as the placeholder. Every port's
egress, including the router's own smoltcp traffic, goes through it, and
the NIC pulls from it (`Datapath::flush_tx`). `PacketMeta` is filled from
conntrack: a keyed flow hash of the **pre-NAT** original tuple (identical
in both directions), pre-NAT host hashes, DSCP, ECN and pure-ACK. The
only other buffering is the neighbor table's ≤ 3 packets per unresolved
next hop. Not done yet: the ingress hook (download shaping) and the DSCP→tin mapping.

```
WAN RX ─► decap (VLAN/PPPoE) ─► conntrack/NAT ─► classify ─► [CAKE ingress] ─► forward ─► LAN TX
LAN RX ─► conntrack/NAT ─► classify ─► forward ─► [CAKE egress on WAN] ─► encap ─► WAN TX (pull)
```
- **Egress (upload):** one CAKE instance on the WAN interface, at the
  configured upload rate, with overhead matching the WAN encapsulation.
- **Ingress (download):** one CAKE instance in *ingress mode* between WAN RX
  and forwarding, at the configured download rate. This replaces Linux's IFB
  trick and also covers traffic to the router itself and multiple LAN ports.
- Classification happens **after conntrack**, so the flow and host hashes
  use the internal (pre-NAT) addresses in both directions.

### 3.5 Sans-IO implementation (crates/qdisc)
CAKE is pure logic, so it lives in `crates/qdisc` (`no_std`, no I/O). Time is
passed in as a parameter:
```rust
trait Qdisc {
    fn enqueue(&mut self, pkt: PacketRef, now: Nanos) -> EnqueueResult; // may drop or ECN-mark
    fn dequeue(&mut self, now: Nanos) -> Dequeue;  // Packet | WaitUntil(Nanos) | Empty
}
```
The benefit is **deterministic simulation tests** on the host: synthetic
flows, simulated time, and assertions on fairness, sojourn targets and drop
behaviour without any VM.

## 4. Implementation plan (incremental)
1. **CoDel** single queue: get the sojourn-time logic right (RFC 8289).
2. **FQ-CoDel** (RFC 8290): useful on its own and the base of CAKE.
3. **CAKE shaper + overhead compensation**: shape egress at a fixed rate.
4. **COBALT, set-associative hashing, host isolation (via conntrack)**.
5. **Ingress mode** for download shaping.
6. **DiffServ tins, ACK filter**.
7. **Autorate** (later): adjust the shaper rate for variable links (LTE,
   cable) from latency probes, like `cake-autorate`. This is easy to integrate natively.

## 5. Configuration UX
```toml
[qos]
enabled = true

[qos.egress]                 # upload, shaped on the WAN interface
rate = "18mbit"              # ~85–95 % of the measured line rate
[qos.ingress]                # download
rate = "90mbit"

[qos.cake]
overhead = "auto"            # derive from WAN mode: pppoe + vlan + ethernet
# or explicit: overhead = 34, mpu = 64, framing = "ptm" | "atm" | "none"
isolation = "triple-isolate" # dual-srchost | dual-dsthost | flows | hosts
diffserv = "diffserv4"       # besteffort | diffserv3 | diffserv4 | diffserv8
ack_filter = true
ecn = true
```

## 6. Testing
- **Host:** simulation tests in `crates/qdisc` (fairness, latency targets,
  memory limit, overhead math), plus fuzzing.
- **QEMU lab:** the ISP VM emulates a bloated bottleneck link
  (`tc qdisc ... tbf rate 20mbit burst ... limit 1mb` or `netem`). Run
  **flent RRUL** (from bufferbloat.net) and `irtt` from the client VM through
  rrouter. Compare latency under load with QoS off and on. Track the results
  per release.
- **Real line:** the Waveform bufferbloat test, and flent against a remote netserver.

## 6b. Baseline measurements (before CAKE)
Measured with `scripts/bufferbloat.sh` on the developer's MacBook (Wi-Fi to the
home router, rrouter in QEMU/HVF via `scripts/mac-internet.sh`, debug
build, BFifo qdisc):

| Date | Path | Idle p50 | Download | Added (p90) | Upload | Added (p90) |
|---|---|---|---|---|---|---|
| 2026-11-08 | rrouter-debug | 7.8 ms | 55.3 Mbit/s | +55.7 ms (B); p99 117 ms | 45.2 Mbit/s | +58.0 ms (B) |
| 2026-11-08 | rrouter-release | 9.6 ms | 55.0 Mbit/s | +50.7 ms (B); p99 117 ms | 38.0 Mbit/s | +52.0 ms (B) |

**Interpretation (single runs, so treat ±10 % as noise):**
- The release build is several times faster per packet but gives the same throughput, so
  **rrouter is not the bottleneck**. About 55 Mbit/s is the real line or Wi-Fi limit.
- The ~50 ms of added latency therefore most likely builds **upstream**
  (home router, ISP or Wi-Fi), in front of that bottleneck. This is the case CAKE
  addresses: shape slightly below the bottleneck (~50 Mbit/s here) so the
  queue moves into rrouter, where COBALT and flow queueing keep it short.
- First `direct` run (without rrouter; **degraded**: 2 requests rate-limited,
  so it's marked invalid): download +67 ms (p90), similar to rrouter, which is
  consistent with an upstream queue. Upload **+299 ms p90, 600 ms max**, much
  worse than through rrouter (+52–58 ms). A plausible cause: sending directly
  fills macOS's deep Wi-Fi transmit queue, while through rrouter packets pass
  its small bounded queues first (≤ 8 frames in flight, 128 KB FIFO). That
  would be early evidence for the "no hidden queues" design. **Needs clean
  repeats** before drawing conclusions.

## 7. Performance
CAKE costs more CPU than fq_codel. On Linux, low-end ARM routers saturate at a
few hundred Mbit/s with CAKE (approximate; varies by SoC), and modern x86
handles gigabit. Requirements for us: no allocation in the datapath, batching,
O(1) queue operations, and cache-friendly flow tables. Benchmark early in QEMU
to catch regressions; absolute numbers only mean something on real hardware.
