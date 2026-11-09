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
  busy, but when idle in `wfi` the *host* (macOS HVF) adds 0.3–3 ms of wake-up
  latency (roughly 25 % of the sleep, capped at ~3 ms).
- **Hybrid idle (implemented, M6 step 1):** `timer::set_spin_window(w)`. The
  comparator is armed `w` early; when the next deadline is within `w`, the
  executor spins with IRQs enabled instead of `wfi`, and the exact-deadline
  interrupt arrives in microseconds. `w` = 4 ms on QEMU `virt` (detected from
  the DTB root `linux,dummy-virt`) and 0 on physical machines
  (`config::idle_spin_window`). `timer::pending()` also checks the deadline
  directly, so a late or lost interrupt cannot stall timers. Measured (HVF):

  | sleep | wfi only (M1) | hybrid idle | idle-poll |
  |---|---|---|---|
  | 1 ms | +270 µs | **+1 µs** | +1 µs |
  | 10 ms | +2.5 ms | **+1–4 µs** | +1 µs |
  | 100 ms | +0.04–3 ms | **+1–2 µs** | +0–3 µs |
  | idle host CPU | ~0 % | **~0 %** | 100 % |

  TCG: +35–38 µs, previously 0.6–3 ms. The 100 µs sleep in the boot
  self-test shows +220–350 µs **with NICs present, in every idle mode,
  including pure polling** (+5 µs without NICs). That's CPU contention, not
  timer slack: the Datapath-priority network task is busy with boot-time
  DHCP/stack work, and the Service-priority self-test waits, as designed.
  CAKE's datapath work runs at Datapath priority itself, but long datapath
  polls still matter; keep them short.
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

### Status: CoDel (M6 step 2)
`crates/qdisc/src/codel.rs`: RFC 8289 CoDel (target 5 ms, interval 100 ms,
integer control law, ECN marking via `Packet::mark_ce`, resume-count
logic, hard limits with tail drop). It is the egress qdisc on both ports
(384 packets / 384 × 1514 B hard limit). Host simulation with one
Reno-like flow (48 Mbit/s, RTT 20 ms):

| queue | median sojourn | p99 | utilisation |
|---|---|---|---|
| deep FIFO | 250 ms | – | ~100 % |
| CoDel, drop | 0.2 ms | 15.6 ms | 0.86 |
| CoDel, ECN | 0.2 ms | – | 0.86 (21 marks, 0 drops) |

The utilisation follows single-flow Reno theory (≈ 0.89 with a queue of
≈ 0.25 BDP); more flows fill the gaps. The kernel prints per-port qdisc
statistics every 10 s while there's traffic (sent, AQM drops, ECN marks,
overflow drops, backlog, max sojourn), and a boot self-test checks ECN
marking on a real packet buffer.

**Expected effect on the real line:** CoDel only acts where rrouter's
*own* queue builds. If the bottleneck is upstream (home router/ISP/Wi-Fi,
§6b), rrouter's queue stays short and nothing changes. The qdisc stats
show which case applies. The **shaper** (next step) makes rrouter the
bottleneck on purpose, so that CoDel/CAKE control the queue.

### Status: shaper (M6 step 3)
`crates/qdisc/src/shaper.rs`: a rate shaper around any qdisc (CAKE-style:
rate-based `next_tx` instead of a token bucket; 1 ms release window so the
datapath wakes ~1×/ms; no credit after idle). In the kernel, each port is
`Shaper<Codel>`: the **WAN egress** is shaped at the upload rate and the
**LAN egress** at the download rate. With one LAN port, shaping LAN egress
is equivalent to an ingress hook for download traffic. A true ingress stage
(for several LAN ports, counting drops) comes with CAKE. The network task
sleeps until the shaper's next release (`FlushResult::shaper_wake_ns`), and
hybrid idle makes that wake-up µs-precise.

Rates are **boot arguments**: `shape_up=` / `shape_down=` (kbit/s) and
`shape_overhead=` (bytes per packet). Pass them with `QEMU_APPEND`, or with
`scripts/mac-internet.sh --shape 42:50` (Mbit/s).

| Evidence | Result |
|---|---|
| host simulation: rate accuracy (1–100 Mbit/s) | within 1 % |
| host simulation: TCP-like flow, deep dumb downstream buffer at 48 Mbit/s | unshaped **434 ms** downstream queue (util 1.00); shaped at 43 Mbit/s + CoDel **0.10 ms** (util 0.78, single Reno flow) |
| lab (`scripts/lab-test.sh`, shaped 10/10 Mbit/s), HVF | down 9.55 Mbit/s, up 9.50 Mbit/s, ping to router *during* the download avg 7.9 ms / max 19 ms |
| lab, TCG | down 9.53, up 8.2 Mbit/s (TCG overhead on 20 short uploads; near the 8.0 bound) |
| negative control: unshaped router, same client expectations | fails (221 / 137 Mbit/s) |

### First real-line run with shaping (42/50 Mbit/s)
The queue **moved into rrouter**: the WAN shaper throttled 113k times, and
the macOS Wi-Fi path no longer holds the standing queue. But CoDel's
signals barely slowed the senders:

```
qdisc wan0 : shaped 42000 kbit/s, … aqm drops 16, ecn marks 5673, overflow drops 842, backlog 363 pkts, max sojourn 106 ms
```
Upload: 40.4 Mbit/s with **+106 ms** added (p90), down from +199 ms
unshaped. That's exactly the ~105 ms that 363 packets take at 42 Mbit/s: the
queue sat at the hard limit despite ~380 ECN marks per second. Hypotheses:
macOS TCP reacting weakly to ECN (or disabling it per connection), ECN
feedback lost on the path, or a marking problem visible only end to end.
**Diagnostic:** the same run with `ecn=0` (CoDel drops instead). Also,
the ping waits behind the upload because CoDel is a single FIFO: flow
isolation (FQ-CoDel/CAKE) would remove that wait entirely. The download
phase was invalid (Cloudflare rate limit), so the download fallback
sources were added.

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
Measured with `scripts/bufferbloat.sh` on the developer's MacBook: Wi-Fi to
the home router (192.168.8.1), line ≈ 55 Mbit/s down / 46 Mbit/s up.
rrouter runs in QEMU/HVF via `scripts/mac-internet.sh` with a BFifo qdisc
(128 KB tail drop) and NIC rings limited to 8 frames in flight. "Added" is
loaded p90 minus idle p50. Only valid runs are shown (2026-11-08/09):

| Path | Runs | Download added (p90) | Upload added (p90) | Upload max | ↓ / ↑ Mbit/s |
|---|---|---|---|---|---|
| direct | 2 | 66.9, 47.5 ms (≈ 57) | **243.5, 241.7 ms** | 369–403 ms | 54–56 / 46 |
| rrouter-release | 3 | 50.7, 58.6, 45.0 ms (≈ 51) | **52.0, 69.2, 100.1 ms (≈ 74)** | 172–206 ms | 54–55 / 38–48 |
| rrouter-debug | 1 | 55.7 ms | 58.0 ms | 129 ms | 55 / 45 |
| rrouter-release + hybrid idle + CoDel | 1 | 47.8 ms | **199.2 ms** | 323 ms | 53 / 47 |

**Findings:**
1. **Download is the same with or without rrouter** (≈ +50–57 ms at the
   same throughput). The queue builds upstream (home router / ISP), and
   rrouter adds nothing measurable. A fix needs **ingress shaping** in rrouter
   slightly below ~54 Mbit/s (§3.4), so the queue moves into rrouter.
2. ~~Upload is ~3× better through rrouter~~, **corrected 2026-11-09.**
   The early rrouter runs (+52–100 ms vs direct +242 ms) were most likely an
   *accident of rrouter being slow*: before hybrid idle it woke up to 3 ms
   late, and its 128 KB FIFO tail-dropped. Both throttled the Mac's TCP and
   kept the downstream queue short. With hybrid idle + CoDel (384-packet
   hard limit), upload went to **+199 ms**, close to direct. The qdisc
   statistics from that run show why:

   ```
   qdisc wan0 : aqm drops 0, ecn marks 0, overflow drops 2456, max sojourn 15.8–23.2 ms
   ```
   CoDel never acted, because rrouter's queue never *stood* above 5 ms. It
   overflowed in **bursts** (the Mac pushes multi-Gbit/s through vmnet;
   rrouter's TX drains at ~200 Mbit/s), so the standing queue lives
   **downstream of rrouter**: the macOS Wi-Fi transmit path behind
   vmnet-bridged, or the access point, at ~46 Mbit/s. That's a hidden queue
   (§3.1) created by the host, invisible to rrouter.
   **Consequence:** an AQM alone can't help. rrouter must **shape** below
   the real bottleneck (≈ 42 Mbit/s up, ≈ 50 Mbit/s down) to become the
   bottleneck itself; then the queue forms where CoDel/CAKE control it.
   Hybrid idle vs. queue limit as the cause of the change wasn't separated
   (no A/B); neither is a design property worth keeping.
3. **Upload via rrouter still varies (52–100 ms):** the BFifo has no AQM and
   no flow isolation (a ping waits behind the upload). This is what COBALT
   + flow queueing address.
4. **The build type doesn't matter at this rate** (debug ≈ release), so CPU
   is not the limit.

**Implications for M6:** shaping must be accurate at sub-millisecond
granularity (1500 B at 50 Mbit/s = 240 µs), but QEMU-on-macOS `wfi` wake-up
adds up to ~3 ms (§3.2). The **hybrid idle** (early wake + spin) is
therefore a prerequisite for meaningful CAKE results in this setup.

## 7. Performance
CAKE costs more CPU than fq_codel. On Linux, low-end ARM routers saturate at a
few hundred Mbit/s with CAKE (approximate; varies by SoC), and modern x86
handles gigabit. Requirements for us: no allocation in the datapath, batching,
O(1) queue operations, and cache-friendly flow tables. Benchmark early in QEMU
to catch regressions; absolute numbers only mean something on real hardware.
