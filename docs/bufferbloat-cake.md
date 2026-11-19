# Bufferbloat mitigation with CAKE

**Goal:** low latency under load is a first-class feature of leatos, not an
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

| Component | What it does | Notes for leatos |
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
  `tx_byte_limit` (fixed, 8 × 1514 B; the igb driver uses the same limit).
  smoltcp only gets a TX token when there is room. Adaptive (BQL) limits
  are still open (fixed limits so far, also on the apu4). The bounded packet pool
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
  interrupt arrives in microseconds. `w` = 4 ms on virtual machines
  (aarch64: the DTB root `linux,dummy-virt`; x86_64: the CPUID hypervisor
  bit) and 0 on physical machines (`config::idle_spin_window`; boot
  argument `idle_spin_us=`). `timer::pending()` also checks the deadline
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
next hop. Not done yet: the DSCP→tin mapping.

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

**Status: WAN ingress stage ✅ (2026-11-19).** Before it, the download was
shaped on `lan0` egress, so everything leaving `lan0` was held to the
download rate: traffic routed *between* the networks (main → guest/IoT,
all on `lan0`) and the router's own replies too, and it competed with the
internet download. Now (`net::datapath`, `Shared::ingress`):
- `dp_down` runs forwarded packets from the WAN through the forwarder
  (conntrack, NAT, classification as before), then into the ingress
  qdisc: CAKE (`ecn_down`, `isolation`, `qdisc=` as for the ports) behind
  `Shaper::ingress` at `shaping.down_kbit`. The egress link and next hop
  ride in `PacketMeta`; `Datapath::drain_ingress` (each `dp_down` pass,
  which also sleeps until the shaper's next release) hands what the
  shaper releases to the neighbor table and the egress qdisc.
- **Ingress mode** (`qdisc::shaper`): every byte that arrived used the
  downlink, so AQM drops at dequeue and overflow drops at enqueue are
  charged to the rate, and so is WAN traffic that never enters the queue
  (frames for the router, firewall drops, PPPoE control: `Shaper::charge`,
  once per RX batch). The shaper sees frames with the WAN's VLAN tag and
  PPPoE header removed, so their 4 + 8 bytes are added to the overhead as
  on the upload.
- `lan0` egress is CAKE **without a rate**: the NIC's pull-based TX is the
  limit, so between-network traffic runs at what the router can forward
  (lab, HVF: ~230 Mbit/s main → guest with a 10 Mbit/s download shaper;
  9.3 Mbit/s with the old placement).
- Lab (`LAB_GUEST=1`): `lan to guest` (the client's VLAN 20 interface in
  its own network namespace serves 5 MB to the main LAN; must exceed twice
  the download rate; negative control `LAB_ROUTER_ARGS=shape_ingress=0`,
  the old placement); download ECN read from `qdisc ingress`; latency
  under load pings the ISP, so the replies cross the ingress queue
  (negative control `qdisc=codel`: ~7 ms).
- `/api/status` `ingress` (`null` with `shape_ingress=0`), CLI `status`
  line `ingress`, a row in the web page's queue table.
- Packet pool 1536 buffers (three qdiscs of 384 + RX rings).
- Not yet: the second LAN port (the software bridge) puts more than one
  port behind this stage, which needs no change here.

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
5. **Ingress mode** for download shaping ✅ (2026-11-19, §3.4).
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

**Expected effect on the real line:** CoDel only acts where leatos's
*own* queue builds. If the bottleneck is upstream (home router/ISP/Wi-Fi,
§6b), leatos's queue stays short and nothing changes. The qdisc stats
show which case applies. The **shaper** (next step) makes leatos the
bottleneck on purpose, so that CoDel/CAKE control the queue.

### Status: shaper (M6 step 3)
`crates/qdisc/src/shaper.rs`: a rate shaper around any qdisc (CAKE-style:
rate-based `next_tx` instead of a token bucket; 1 ms release window so the
datapath wakes ~1×/ms; no credit after idle). In the kernel, each port is
`Shaper<Codel>` (now `Shaper<FqCodel>`, see below): the **WAN egress** is shaped at the upload rate and the
**LAN egress** at the download rate. With one LAN port, shaping LAN egress
is equivalent to an ingress hook for download traffic, except that it also
caps traffic between networks on that port; the WAN ingress stage (§3.4,
2026-11-19) replaced it (`shape_ingress=0` brings it back). The network task
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
The queue **moved into leatos**: the WAN shaper throttled 113k times, and
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
The download phase was invalid (Cloudflare rate limit), so the download
fallback sources were added.

**A/B, ECN on vs off (2026-11-09, shaped 42/50, one run each):**

| run | upload Mbit/s | upload added p90 | WAN max sojourn | download Mbit/s | download added p90 | LAN max sojourn |
|---|---|---|---|---|---|---|
| ECN on | 40.3 | **+104 ms** | 106 ms (4842 marks, queue at limit) | 44.3 | +83 ms | 90 ms (702 marks) |
| ECN off (`ecn=0`) | 37.6 | **+41 ms** | 41–45 ms (163 drops) | 44.7 | +85 ms | 89 ms (545 drops) |

- **Upload: drops work, CE marks mostly don't.** macOS has classic ECN on
  (`net.inet.tcp.ecn=1`, L4S off), so L4S isn't the explanation. Leading
  hypothesis: **ECN bleaching** upstream (the home router or ISP clears the
  ECN bits after leatos marks them), so the receiver never echoes ECE.
  Diagnostic added: per-port counters of ECN codepoints and TCP ECE/CWR
  flags on forwarded packets (`ecn rx …` console lines). ECE on ACKs
  arriving from the WAN would show that the marks survived.
- **Download: even drops don't contain the queue** (545 drops, still ~89 ms).
  Likely the senders (CDNs, often BBR) barely react to loss. A single-queue
  AQM can't fix that. **Flow isolation** (FQ-CoDel / CAKE: per-flow queues,
  sparse flows first) is the fix: a bulk flow then only delays itself, and
  the ping (or a game, a call, DNS) bypasses it.
- Download throughput (44.5 Mbit/s) was below the 50 Mbit/s shaping rate,
  so at times the real downlink was the bottleneck. Ingress shaping needs
  more margin (CAKE recommends ~85–90 % for ingress).

### Status: FQ-CoDel (M6 step 4)
`crates/qdisc/src/fq_codel.rs` implements RFC 8290. Packets are hashed by
`PacketMeta::flow_hash` (keyed, pre-NAT 5-tuple from conntrack) into 1024
flow queues, each with its own CoDel state. The CoDel control law was
factored out of `codel.rs` (`Vars`, `Source`) for this, so both qdiscs share
one implementation.

- **DRR:** deficit round robin, quantum 1514 B, so sharing is byte-fair
  whatever the packet size.
- **New-flows list:** flows that become active are served first. Sparse
  flows (ping, DNS, games, VoIP, TCP handshakes) always arrive to an empty
  queue, so they always take this fast path.
- **Overflow:** head-drops from the *fattest* flow, never the arriving
  packet.
- **Memory:** a preallocated slab of `max_packets` slots with linked lists
  per flow, so nothing is allocated per packet.
- **Kernel:** each port is `Shaper<FqCodel>`. Router-local frames (smoltcp:
  DNS, DHCP, ping replies) have `flow_hash` 0 and share one sparse queue.
- **A/B:** boot argument `qdisc=fq_codel`; `qdisc=codel` is a single CoDel queue (was `fq_flows=1`).
- **Stats:** the `qdisc` console line shows active flows and activations.

| Evidence | single CoDel | FQ-CoDel |
|---|---|---|
| sim: sender ignoring drops at 125 % of the link + ping every 20 ms | ping p50 **81 ms** | ping p99 **< 0.01 ms**, no ping loss |
| sim: 4 Reno flows, RTT 10/20/40/80 ms + ping (drops) | ping p99 73 ms, Jain fairness 0.64, util 0.95 | ping p99 **0.7 ms**, fairness **0.99**, util 0.98 |
| same with ECN | ping p99 93 ms, fairness 0.59 | ping p99 0.7 ms, fairness 0.99, util 0.97, 0 drops |
| lab, 10/10 Mbit/s, ping to router during the download, HVF | avg 8 ms, max 21 ms (`LAB_ROUTER_ARGS=qdisc=codel`: check **fails**, the negative control) | avg **0.7 ms**, max 1.4 ms |
| lab, TCG | | avg 1.6 ms, max 5.6 ms |

The lab check now requires an average below 3 ms, so it fails without flow
isolation. The simulated single-queue result (ping p99 73–93 ms behind
competing flows) matches the ~85 ms seen on the real line.

### Status: CAKE core (M6 step 5)
`crates/qdisc/src/cake.rs` builds on FQ-CoDel's lists, DRR, overflow drop
and slab, and adds three CAKE features:

- **Set-associative hashing (8 ways):** a flow whose bucket is taken uses a
  free queue in the same set. Only a ninth simultaneous flow in one set
  shares a queue, counted as `collisions`. A queue that changes owner starts
  with fresh AQM state.
- **Host isolation** (`Isolation::{Flows, DualSrcHost, DualDstHost, Triple}`,
  CAKE's names). Each host counts its bulk flows, and a flow's DRR quantum is
  `quantum / bulk flows of its busier host`. Host identities are the keyed
  **pre-NAT** host hashes from conntrack. That makes isolation work per LAN
  host on WAN egress (upload, by source) and on LAN egress (download, by
  destination).
  - `Triple` uses the busier of a flow's two hosts. Many flows to one
    remote server are therefore only flow-fair, which is also how CAKE
    behaves.
- **COBALT = CoDel + BLUE per flow.** BLUE's drop probability rises by 1/256
  each time a flow overflows (at most once per `target`) and falls by 1/4096
  while its queue runs empty. Like CAKE, BLUE drops ECN-capable packets too.
  It therefore contains senders that ignore marks, or whose marks are
  bleached on the path, which was the real-line upload symptom.
  An overflow counts toward BLUE only once CoDel has been signalling that
  flow for two intervals (`CakeParams::blue_after`; CAKE counts every
  overflow): a TCP flow in slow start overflows before CoDel's first
  signal reaches its sender, and counting that made BLUE drop its packets
  for seconds after it had backed off (see "Queue limit follows the rate").

Not yet implemented: DiffServ tins, a rate-aware CoDel target, and
COBALT's own CoDel variant (RFC 8289 CoDel is used). Ingress mode came
later (§3.4), and so did a queue limit that follows the rate and the ACK
filter (below).

**Kernel:** CAKE is the default egress AQM on both ports.
- Boot args `qdisc=cake|fq_codel|codel` for A/B tests, and
  `isolation=triple-isolate|dual-srchost|dual-dsthost|flows`.
- The `qdisc` stats line adds collisions, active hosts and BLUE drops.

| Evidence | Control | CAKE |
|---|---|---|
| sim: host A 1 flow vs host B 8 flows, backlogged, all 4 isolation modes in their direction | `Flows` or the wrong side isolated: A/B ≈ 0.125 | A/B within 0.8–1.25 |
| sim: host A 1 Reno flow vs host B 4 Reno flows | FQ-CoDel: A gets **0.20** | A gets **0.42** (one Reno flow can't fill its half; B takes the slack), util 0.95 |
| sim: sender ignoring ECN at 125 % of the link + ping | FQ-CoDel: flood's own sojourn p50 **77 ms** (queue at the limit), 20.6k overflow drops | p50 **12 ms**, 245 overflow drops, BLUE contains it; ping p99 0.1 ms |
| sim: 4 responsive Reno flows + ping (drops and ECN) | | BLUE drops **0**; util 0.97–0.98, fairness 0.99, ping p99 0.7 ms (as FQ-CoDel) |
| lab 10/10 Mbit/s, ping during the download, HVF | `qdisc=codel`: avg 7 ms, check **fails** | avg 0.8 ms (FQ-CoDel 0.8 ms) |
| lab, TCG | | avg 1.7 ms |

The lab has a single client, so host isolation is tested in simulation
only for now. A second LAN host in the lab is a follow-up.

**Real line, CAKE vs single queue (2026-11-09, shaped 42/45, one run each):**

| run | download Mbit/s | download added p90 | upload Mbit/s | upload added p90 |
|---|---|---|---|---|
| CAKE (default) | 41.9 | **+46 ms** (p50 only +4 ms) | 39.4 | **+14 ms** (grade A) |
| `qdisc=codel` | 35.5 | +73 ms | 40.5 | +102 ms |
| CAKE, download shaped at **36** | 29.1 | **+9.6 ms** (grade A) | 39.1 | +37 ms |

- **Upload is solved for latency-sensitive traffic:** the ping bypasses the
  bulk uploads.
  - The bulk flows' own queues still reach the hard limit (WAN max sojourn
    166–238 ms, 383 overflow drops, only 91 BLUE drops).
- **ECN marks on upload are lost on the path (confirmed).** During the
  upload leatos set ~7,700 CE marks on WAN egress. The Mac's upload data
  was ECT(0), so ECN was negotiated. Yet ACKs arriving from the WAN carried
  ECE only 7 more times (17 → 24). Something between leatos and the
  server clears the CE bits (*ECN bleaching*: the home router at
  192.168.8.1 or the ISP). The single-queue run shows the same (5,484 marks,
  ECE 13 → 17).
- **ECN works on download.** leatos's CE marks on LAN egress reach the
  Mac. The Mac echoes ECE (18.5k → 35.5k ACKs), and the servers answer
  with CWR (279 → 526).
- **The remaining download latency is upstream of leatos.**
  - The ping's own queue in leatos is the sparse fast path.
  - Download throughput (41.9) stayed below the 45 Mbit/s shaping rate, so
    the real downlink was at times the bottleneck and queued in front of
    leatos.
  - Idle latency already varies (p50 8 ms, max 26 ms): the line's rate
    varies. A lower download rate, or later CAKE autorate (M9), addresses
    this.
  - **Confirmed** with the download shaped at 36 Mbit/s: added latency fell
    from +46 to **+9.6 ms**, and the LAN queue's max sojourn from 119–152 ms
    to 40 ms. CAKE got there with ECN marks only (2,303 marks, no BLUE or
    overflow drops).
  - Upload in the same run: +37 ms (vs +14 ms before, same 42 Mbit/s
    setting). ECN bleaching again (2,616 marks, ECE 33 → 40). Upload
    throughput 39.1 < 42 suggests the uplink also dips below its shaping
    rate at times.

### Per-direction ECN (default: drop on upload, mark on download)
The bleaching finding could have led to a "bleaching detector" (switch to
drops when marks get no echo). We decided against it, because it would
overfit one line and one server:
- **Blind to QUIC:** QUIC's ECN feedback is encrypted.
- **Misreads AccECN:** Accurate ECN (used by L4S) reports marks in a
  counter, not with the classic ECE flag, so a detector would wrongly
  call those flows bleached.
- **CAKE already has a safety net:** BLUE, for flows that ignore marks.

Instead leatos follows common SQM practice (OpenWrt's sqm-scripts default
to ECN on ingress, off on egress):
- **`ecn_up` = 0 (upload, WAN egress: drop).** The senders are local, a drop
  costs one retransmission over a short path, and it works on every path.
  On the developer's line it cut upload added latency from +104 to +41 ms
  (single-queue A/B above).
- **`ecn_down` = 1 (download, LAN egress: mark).** A mark saves data that
  already crossed the bottleneck, and the marks demonstrably reach the
  receiver.
- **`ecn=` sets both.** The boot log shows `(drop only)` or `+ ECN` per
  port.

**Lab check** (`scripts/lab-test.sh`):
- **Setup:** the client enables `tcp_ecn=1` and adds one long 3 MB upload
  (`nc` to a `tcpsvd` sink on the ISP), so CoDel acts on WAN egress.
- **Check:** the router's final counters per port. Where ECN is on there
  must be marks; where it is off, drops and no marks.

| router args | upload (wan0) | download (lan0) | result |
|---|---|---|---|
| default | 29 drops, 0 marks | 0 drops, 52 marks | PASS |
| `ecn=1` | 0 drops, 29 marks | 52 marks | PASS |
| `ecn_up=1 ecn_down=0` | 29 marks | 52 drops, 0 marks | PASS |
| `ecn=1` with the default expectation (`LAB_EXPECT_ECN=0:1`), the negative control | 29 marks | | **FAIL** (as it must) |
| default, TCG | 29 drops | 52 marks | PASS |

**Real line with the new defaults (2026-11-09 22:32, shaped 38/36, one run):**
- **Upload:** 28.8 Mbit/s, +35.7 ms. leatos's upload queue now drops
  instead of marking (141 drops, 0 marks). The bulk uploads' own max
  sojourn fell to **41 ms** after the start (121 ms in the first interval),
  against 123–130 ms with marks.
- **Download:** 33.1 Mbit/s, +39.4 ms, against +9.6 ms at the same 36 Mbit/s
  earlier. ECN marks only (3,252); LAN max sojourn 127 → 89 → 48 ms.
- **The line was noisier this time:** idle ping max 134 ms, p99 28 ms.
  The ping bypasses leatos's bulk queues, so its remaining variation
  comes from the line.
- **Conclusion:** single runs on this line can't separate configurations
  that differ by less than ~30 ms. Comparisons need repeated, interleaved
  runs, and a variable-rate line ultimately needs autorate.

### Queue limit follows the rate (2026-11-19)
Every qdisc had the same fixed limit, 384 packets or 384 × 1514 B. That
is a different delay at every rate: 4.6 ms at 1 Gbit/s, 52 ms at
90 Mbit/s, **260 ms at 18 Mbit/s**. CoDel keeps standing queues near 5 ms,
but TCP slow start fills the queue faster than CoDel can stop it (CoDel
waits one interval before its first signal, and the sender reacts a round
trip later), so the limit is what bounds that spike. On the apu4 the
upload started with 130 overflow drops and a 355 ms peak sojourn.

Now a shaped queue's byte limit is the full-size packets its rate (with
overhead) sends in `shaping.queue_ms` (default 100 ms; boot argument
`queue_ms=`, `0` = the old fixed limit), at least 16 × 1514 B and at most
the fixed limit (`qdisc::shaper::Rate::queue_limit_bytes`,
`config::Qos::queue_limit`). Unshaped queues keep the fixed limit; the
384-packet count limit stays everywhere (it protects the packet pool).
Live saves change the limit with the rate, keeping the queue. At 18 Mbit/s
the upload queue holds 145 packets (~100 ms); at 90 Mbit/s the download
stays at 384 packets (the cap: 52 ms). The boot log's `qos` lines and
`/api/status` (`limit_bytes`) show it, and the web page's queue table.

The first simulation run showed a trap: with the smaller limit, slow
start's overflow raised BLUE's drop probability (+1/256 per overflow
event, −1/4096 per empty event), and BLUE then dropped the flow's packets
for seconds after it had already backed off: utilisation **0.24** for one
flow. So overflows now count toward BLUE only for a flow CoDel has been
signalling for two intervals (§ CAKE core). The flood test (a sender
ignoring ECN) is contained as before (p50 12 ms, 0.1 ms ping p99).

| Evidence (host simulation, `rate_based_limit_caps_the_slow_start_spike`: TCP-like senders in slow start, 18 Mbit/s, CAKE) | fixed limit | `queue_ms` 100 | control: every overflow counts toward BLUE |
|---|---|---|---|
| 1 flow, RTT 20 ms | peak **208 ms**, util 0.95 | peak **98 ms**, util 0.95 | util **0.24** |
| 4 flows, RTT 20 ms | peak 228 ms, util 0.92 | peak 97 ms, util 1.00 | util 0.95 |
| 1 flow, RTT 80 ms | peak 189 ms, util 0.62 | peak 97 ms, util 0.83 | util 0.06 |
| 4 flows, RTT 80 ms | peak 183 ms, util 0.82 | peak 95 ms, util 0.83 | util 0.25 |

**Lab** (`scripts/lab-test.sh`, 10/10 Mbit/s, HVF): the client's TCP
upload never reaches either limit (max sojourn ~30 ms, no overflow), so
the client also sends a 2.5 MB UDP burst at its line rate; overflow drops
prove the queue filled. Check `queue limit follows the rate`: worst WAN
sojourn ≤ `LAB_EXPECT_QUEUE_MS` (100) + 20 ms. Default **97 ms** (1610
overflow drops): PASS. Negative control `LAB_ROUTER_ARGS=queue_ms=0`:
**419 ms**: FAIL. All other checks pass in both runs (shaper 9.5/9.4
Mbit/s, latency under load avg 2 ms, ECN per direction).

Not yet measured on the apu4: the upload start-up spike at 90/18 with the
new limit (expected ≤ ~100 ms instead of 355 ms).

### ACK filter (2026-11-19)
On an asymmetric line the download's ACKs take a real share of the
upload: at 90 Mbit/s with delayed ACKs about 3,900 ACKs/s, ~3 Mbit/s with
the PPPoE/VLAN overhead, ~17 % of an 18 Mbit/s upload. While the upload
is idle they pass as a sparse flow; once it is busy (an upload next to the
download, a video call) they queue, and only the newest ACK of a
connection carries information the sender still needs.

`crates/qdisc/src/ack_filter.rs` decides on the packets' bytes whether a
new pure ACK makes a queued one redundant (same connection, both pure
ACKs with the same flags and IP ECN bits, not CE; the new one
acknowledges strictly more, so **duplicate ACKs are never filtered**;
only NOP/EOL/SACK/timestamp options, timestamps not going backwards; the
old one's SACK blocks above the new ACK number covered by the new one's;
IPv4 without IP options). CAKE (`CakeParams::ack_filter`) checks at
enqueue, within the first 64 packets of the ACK's flow queue: if at
least two queued ACKs are redundant, it drops the oldest, like CAKE's
conservative mode, so one older ACK always stays next to the new one.
Dropped ACKs count in `dropped` and `ack_drops`, not as AQM actions (no
CoDel or BLUE state). The forwarder marks pure ACKs (`is_pure_ack`); ACKs
with ECE/CWR/AE are not pure and stay.

Config `shaping.ack_filter` (boot argument `ack_filter=0|1`), **off by
default** (as in CAKE), WAN egress only, switched live. The `qos wan0`
boot line says `ACK filter`, the `qdisc wan0` stats line counts `ack
drops`, `/api/status` `ack_drops`, the web queue table "redundant ACKs".

| Evidence | without | with the filter |
|---|---|---|
| host sim: 3 Mbit/s upload, a greedy upload + a download's ACKs at 4/ms (above their fair share) | ACK sojourn p50 **13.8 ms** (5,218 ACKs dropped by CoDel), upload 1,251 packets | ACK sojourn p50 **0.30 ms** (31,887 filtered), upload **2,208** packets (+76 %), the newest ACK delivered |
| host tests | | ten ACKs back to back → the newest two; duplicate ACKs, other connections in the same queue and data packets kept |
| lab `LAB_ACK=1` (10 Mbit/s down, 150 kbit/s up: the download's ACKs exceed the upload), HVF, one run each | `LAB_ACK_FILTER=0`: 0 ACK drops, check **fails**; download **7.8 Mbit/s** (fails its 8–10.5 range: the queued ACKs hold the sender back) | **748** of ~2,200 ACKs filtered; download **9.1 Mbit/s**, file whole; all checks pass |

Fuzz targets: `ack_filter` (the decision on arbitrary bytes: no panic,
never supersedes itself, never mutual) and `qdisc` (with ACK packets,
well-formed and garbage, and the filter on: conservation and limits).

## 5. Configuration UX
**Implemented** (`[shaping]`, docs/config-and-storage.md §5; boot
arguments `shape_up=`, `shape_down=`, `shape_overhead=`, `qdisc=`,
`isolation=`, `ecn_up=`, `ecn_down=`, `queue_ms=`, `ack_filter=`):
```toml
[shaping]
up_kbit = 18000              # unset = not shaped
down_kbit = 90000
overhead = 20                # bytes per packet; the WAN VLAN (+4) and PPPoE (+8) are added automatically
ecn_up = false
ecn_down = true
qdisc = "cake"               # cake | fq_codel | codel
isolation = "triple-isolate" # dual-srchost | dual-dsthost | flows
queue_ms = 100               # shaped queue limit as time at its rate (§4); 0 = fixed
ack_filter = false           # CAKE's ACK filter on the upload (§4)
```
**Target** (not implemented: framing/MPU, DiffServ, ACK filter, a true
ingress stage):
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
  leatos. Compare latency under load with QoS off and on. Track the results
  per release.
- **Real line:** the Waveform bufferbloat test, and flent against a remote netserver.

## 6b. Baseline measurements (before CAKE)
Measured with `scripts/bufferbloat.sh` on the developer's MacBook: Wi-Fi to
the home router (192.168.8.1), line ≈ 55 Mbit/s down / 46 Mbit/s up.
leatos runs in QEMU/HVF via `scripts/mac-internet.sh` with a BFifo qdisc
(128 KB tail drop) and NIC rings limited to 8 frames in flight. "Added" is
loaded p90 minus idle p50. Only valid runs are shown (2026-11-08/09):

| Path | Runs | Download added (p90) | Upload added (p90) | Upload max | ↓ / ↑ Mbit/s |
|---|---|---|---|---|---|
| direct | 2 | 66.9, 47.5 ms (≈ 57) | **243.5, 241.7 ms** | 369–403 ms | 54–56 / 46 |
| leatos-release | 3 | 50.7, 58.6, 45.0 ms (≈ 51) | **52.0, 69.2, 100.1 ms (≈ 74)** | 172–206 ms | 54–55 / 38–48 |
| leatos-debug | 1 | 55.7 ms | 58.0 ms | 129 ms | 55 / 45 |
| leatos-release + hybrid idle + CoDel | 1 | 47.8 ms | **199.2 ms** | 323 ms | 53 / 47 |

**Findings:**
1. **Download is the same with or without leatos** (≈ +50–57 ms at the
   same throughput). The queue builds upstream (home router / ISP), and
   leatos adds nothing measurable. A fix needs **ingress shaping** in leatos
   slightly below ~54 Mbit/s (§3.4), so the queue moves into leatos.
2. ~~Upload is ~3× better through leatos~~, **corrected 2026-11-09.**
   The early leatos runs (+52–100 ms vs direct +242 ms) were most likely an
   *accident of leatos being slow*: before hybrid idle it woke up to 3 ms
   late, and its 128 KB FIFO tail-dropped. Both throttled the Mac's TCP and
   kept the downstream queue short. With hybrid idle + CoDel (384-packet
   hard limit), upload went to **+199 ms**, close to direct. The qdisc
   statistics from that run show why:

   ```
   qdisc wan0 : aqm drops 0, ecn marks 0, overflow drops 2456, max sojourn 15.8–23.2 ms
   ```
   CoDel never acted, because leatos's queue never *stood* above 5 ms. It
   overflowed in **bursts** (the Mac pushes multi-Gbit/s through vmnet;
   leatos's TX drains at ~200 Mbit/s), so the standing queue lives
   **downstream of leatos**: the macOS Wi-Fi transmit path behind
   vmnet-bridged, or the access point, at ~46 Mbit/s. That's a hidden queue
   (§3.1) created by the host, invisible to leatos.
   **Consequence:** an AQM alone can't help. leatos must **shape** below
   the real bottleneck (≈ 42 Mbit/s up, ≈ 50 Mbit/s down) to become the
   bottleneck itself; then the queue forms where CoDel/CAKE control it.
   Hybrid idle vs. queue limit as the cause of the change wasn't separated
   (no A/B); neither is a design property worth keeping.
3. **Upload via leatos still varies (52–100 ms):** the BFifo has no AQM and
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

### apu4: CPU cost with CAKE, 1 core vs 4 (2026-11-14, M11)
PC Engines apu4 (AMD GX-412TC, 4 × Jaguar 1 GHz, i211), VDSL2 100/20
behind the home router, Windows PC on the LAN, Waveform bufferbloat test.
Kernel `a24541e`, `shape_down=90000 shape_up=18000 shape_overhead=20`.
Router-side record: `/api/status` every 2 s (interface counters, qdisc
counters) and the per-core CPU history (1 s samples).

| | `cores=4` (default) | `cores=1` |
|---|---|---|
| Waveform grade | A+ | A+ |
| Throughput, best 10 s window (router counters) | ~90 / 17.4 Mbit/s | 87.4 / ~18 Mbit/s |
| Layout | download on core 0, upload on core 1, services on core 2 | everything on core 0 |
| Busiest 20 s, average | core 0 20.8 %, core 1 12.9 %, core 2 0.5 % | core 0 33.2 % |
| Peak 1 s | 26.4 % / 13.5 % | 38.5 % |

**Valid:** in both runs CAKE dropped in both directions (WAN 7810 / 9154,
LAN 3545 / 4826 drops), about 450k packets were forwarded, no pool
allocation failures. Window rates above the shaped 90/18 are timing error
(the recorder polled over Wi-Fi with the Mac's clock).

**Reading:**
- The total work is about the same (34 % of one core across two cores
  vs 33 % on one), so the lock and wakeup overhead of the split is
  small.
- At this line rate one core has roughly 3× headroom, so the split buys
  headroom, not throughput. Per direction, the download core runs at
  ~21 % at 90 Mbit/s. A linear extrapolation (optimistic: bursts and
  cache effects grow with rate) puts the single-core limit near
  300 Mbit/s combined, and the split one near 400 Mbit/s download.
- Not measured: gigabit (needs a faster line or a LAN test host).
