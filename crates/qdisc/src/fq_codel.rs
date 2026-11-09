//! FQ-CoDel: flow queueing with CoDel (RFC 8290), the core of CAKE.
//!
//! Packets are hashed by [`Packet::flow_hash`] into one of `flows` queues
//! (1024 by default), each with its own CoDel state, so a bulk flow only
//! builds delay for itself. The queues are served by **deficit round
//! robin** (`quantum` bytes per round, byte-fair whatever the packet size)
//! with two lists:
//! - **new flows**: a flow that becomes active (its queue was empty and not
//!   in any list) goes here and is served first, with a fresh quantum.
//!   Sparse flows (ping, DNS, game and VoIP packets, TCP handshakes) arrive
//!   to an empty queue every time, so they always take this fast path.
//! - **old flows**: a flow that used up its quantum moves here; the bulk
//!   flows rotate on this list.
//!
//! An empty flow on the new list moves to the old list instead of leaving
//! (if the old list is non-empty), so a flow cannot stay "new" forever by
//! sending one quantum per round. On overflow of the shared limit the
//! **fattest** flow (most bytes queued) loses its head packet, not the
//! arriving one: a flood cannot push out sparse traffic.
//!
//! Storage is a preallocated slab of `max_packets` slots with per-flow
//! linked lists, so enqueue/dequeue never allocate. Dequeue is O(1)
//! amortised; overflow scans the flows for the fattest one (as Linux does).

use crate::codel::{MAX_PACKET, Params, Sojourn, Source, Vars};
use crate::{Dequeue, Packet, Qdisc, Stats};
use alloc::collections::VecDeque;
use alloc::vec::Vec;

const NIL: u32 = u32::MAX;

#[derive(Clone, Copy, Debug)]
pub struct FqParams {
    /// CoDel parameters, applied per flow. `max_packets` and `limit_bytes`
    /// are the shared limits over all flows.
    pub codel: Params,
    /// Number of flow queues.
    pub flows: usize,
    /// Bytes a flow may send per DRR round.
    pub quantum: u32,
}

impl Default for FqParams {
    fn default() -> Self {
        Self {
            codel: Params::default(),
            flows: 1024,
            quantum: MAX_PACKET as u32,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum List {
    None,
    New,
    Old,
}

/// A flow's packets: a linked list through the slab.
#[derive(Clone, Copy, Debug)]
struct FlowQueue {
    head: u32,
    tail: u32,
    bytes: usize,
}

struct Flow {
    q: FlowQueue,
    deficit: i32,
    list: List,
    vars: Vars,
}

struct Slot<P> {
    pkt: Option<(P, u64)>,
    next: u32,
}

/// Fixed pool of packet slots with a free list.
struct Slab<P> {
    slots: Vec<Slot<P>>,
    free: u32,
}

impl<P> Slab<P> {
    fn new(cap: usize) -> Self {
        let slots = (0..cap)
            .map(|i| Slot {
                pkt: None,
                next: if i + 1 < cap { (i + 1) as u32 } else { NIL },
            })
            .collect();
        Self {
            slots,
            free: if cap > 0 { 0 } else { NIL },
        }
    }

    fn alloc(&mut self, p: P, ts: u64) -> Result<u32, P> {
        let i = self.free;
        let Some(slot) = self.slots.get_mut(i as usize) else {
            return Err(p);
        };
        self.free = slot.next;
        slot.pkt = Some((p, ts));
        slot.next = NIL;
        Ok(i)
    }
}

impl FlowQueue {
    const EMPTY: Self = Self {
        head: NIL,
        tail: NIL,
        bytes: 0,
    };

    fn push<P>(&mut self, slab: &mut Slab<P>, i: u32, len: usize) {
        match slab.slots.get_mut(self.tail as usize) {
            Some(tail) => tail.next = i,
            None => self.head = i,
        }
        self.tail = i;
        self.bytes += len;
    }

    fn pop<P: Packet>(&mut self, slab: &mut Slab<P>) -> Option<(P, u64)> {
        let i = self.head;
        let slot = slab.slots.get_mut(i as usize)?;
        let (p, ts) = slot.pkt.take()?;
        self.head = slot.next;
        if self.head == NIL {
            self.tail = NIL;
        }
        slot.next = slab.free;
        slab.free = i;
        self.bytes -= p.len_bytes();
        Some((p, ts))
    }
}

/// One flow's queue as CoDel's packet source; keeps the totals in step.
struct FlowSource<'a, P> {
    slab: &'a mut Slab<P>,
    q: &'a mut FlowQueue,
    packets: &'a mut usize,
    bytes: &'a mut usize,
}

impl<P: Packet> Source<P> for FlowSource<'_, P> {
    fn pop(&mut self) -> Option<(P, u64)> {
        let (p, ts) = self.q.pop(self.slab)?;
        *self.packets -= 1;
        *self.bytes -= p.len_bytes();
        Some((p, ts))
    }
    fn backlog_bytes(&self) -> usize {
        *self.bytes
    }
}

pub struct FqCodel<P> {
    p: FqParams,
    slab: Slab<P>,
    flows: Vec<Flow>,
    new_flows: VecDeque<u32>,
    old_flows: VecDeque<u32>,
    packets: usize,
    bytes: usize,
    stats: Stats,
    soj: Sojourn,
    /// Times a flow became active and went on the new list (diagnostics).
    pub new_flow_count: u64,
    /// Overflow drops taken from the fattest flow (subset of `dropped`).
    pub overflow_drops: u64,
}

impl<P: Packet> FqCodel<P> {
    pub fn new(p: FqParams) -> Self {
        let n = p.flows.clamp(1, NIL as usize);
        Self {
            slab: Slab::new(p.codel.max_packets),
            flows: (0..n)
                .map(|_| Flow {
                    q: FlowQueue::EMPTY,
                    deficit: 0,
                    list: List::None,
                    vars: Vars::default(),
                })
                .collect(),
            new_flows: VecDeque::with_capacity(n),
            old_flows: VecDeque::with_capacity(n),
            packets: 0,
            bytes: 0,
            stats: Stats::default(),
            soj: Sojourn::default(),
            new_flow_count: 0,
            overflow_drops: 0,
            p: FqParams { flows: n, ..p },
        }
    }

    /// Flow queue for a hash: multiply-shift ("reciprocal scale"), which
    /// uses the high bits and needs no division.
    fn flow_index(&self, hash: u32) -> usize {
        ((hash as u64 * self.flows.len() as u64) >> 32) as usize
    }

    /// Sojourn time of the last dequeued packet (diagnostics).
    pub fn last_sojourn_ns(&self) -> u64 {
        self.soj.last_ns
    }

    /// Largest sojourn time since the previous call (resets it).
    pub fn take_max_sojourn_ns(&mut self) -> u64 {
        core::mem::take(&mut self.soj.max_ns)
    }

    /// Flows currently on the (new, old) lists.
    pub fn active_flows(&self) -> (usize, usize) {
        (self.new_flows.len(), self.old_flows.len())
    }

    /// Head-drop from the flow with the most bytes queued.
    fn drop_from_fattest(&mut self) -> Option<P> {
        let fat = self.flows.iter_mut().max_by_key(|f| f.q.bytes)?;
        let (p, _) = fat.q.pop(&mut self.slab)?;
        self.packets -= 1;
        self.bytes -= p.len_bytes();
        self.stats.dropped += 1;
        self.overflow_drops += 1;
        Some(p)
    }
}

impl<P: Packet> Qdisc<P> for FqCodel<P> {
    fn enqueue(&mut self, p: P, now_ns: u64) -> Result<(), P> {
        let n = p.len_bytes();
        let (max_packets, limit_bytes) = (self.p.codel.max_packets, self.p.codel.limit_bytes);
        if n > limit_bytes || max_packets == 0 {
            self.stats.dropped += 1;
            return Err(p);
        }
        // Make room by dropping from the fattest flow (maybe this one).
        let mut rejected = None;
        while self.packets >= max_packets || self.bytes + n > limit_bytes {
            match self.drop_from_fattest() {
                Some(d) => rejected = Some(d),
                None => break,
            }
        }
        let fi = self.flow_index(p.flow_hash());
        let slot = match self.slab.alloc(p, now_ns) {
            Ok(slot) => slot,
            Err(p) => {
                self.stats.dropped += 1;
                return Err(p);
            }
        };
        let flow = &mut self.flows[fi];
        flow.q.push(&mut self.slab, slot, n);
        self.packets += 1;
        self.bytes += n;
        self.stats.enqueued += 1;
        if flow.list == List::None {
            flow.list = List::New;
            flow.deficit = self.p.quantum as i32;
            self.new_flows.push_back(fi as u32);
            self.new_flow_count += 1;
        }
        match rejected {
            Some(d) => Err(d),
            None => Ok(()),
        }
    }

    fn dequeue(&mut self, now: u64) -> Dequeue<P> {
        let Self {
            p,
            slab,
            flows,
            new_flows,
            old_flows,
            packets,
            bytes,
            stats,
            soj,
            ..
        } = self;
        loop {
            let (fi, from_new) = match (new_flows.front(), old_flows.front()) {
                (Some(&f), _) => (f, true),
                (None, Some(&f)) => (f, false),
                (None, None) => return Dequeue::Empty,
            };
            let list = if from_new {
                &mut *new_flows
            } else {
                &mut *old_flows
            };
            let flow = &mut flows[fi as usize];
            if flow.deficit <= 0 {
                // Quantum used up: next round, at the back of the old list.
                flow.deficit += p.quantum as i32;
                list.pop_front();
                old_flows.push_back(fi);
                flow.list = List::Old;
                continue;
            }
            let mut src = FlowSource {
                slab,
                q: &mut flow.q,
                packets,
                bytes,
            };
            match flow.vars.dequeue(&mut src, &p.codel, stats, soj, now) {
                Some(pkt) => {
                    flow.deficit -= pkt.len_bytes() as i32;
                    stats.dequeued += 1;
                    return Dequeue::Packet(pkt);
                }
                None => {
                    list.pop_front();
                    if from_new && !old_flows.is_empty() {
                        old_flows.push_back(fi);
                        flow.list = List::Old;
                    } else {
                        flow.list = List::None;
                    }
                }
            }
        }
    }

    fn has_room(&self) -> bool {
        self.packets < self.p.codel.max_packets
            && self.bytes + MAX_PACKET <= self.p.codel.limit_bytes
    }

    fn stats(&self) -> Stats {
        Stats {
            backlog_packets: self.packets,
            backlog_bytes: self.bytes,
            ..self.stats
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::codel::Codel;
    use core::cell::RefCell;
    use std::vec;

    const MS: u64 = 1_000_000;

    std::thread_local! {
        /// Packets dropped inside the qdisc, per flow (set by `Pkt::drop`).
        static DROPS: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    }

    fn drops(flow: usize) -> u64 {
        DROPS.with(|d| d.borrow().get(flow).copied().unwrap_or(0))
    }

    #[derive(Debug)]
    struct Pkt {
        len: usize,
        flow: u32,
        seq: u64,
        sent: u64,
        ect: bool,
        ce: bool,
        delivered: bool,
    }

    impl Drop for Pkt {
        fn drop(&mut self) {
            if !self.delivered {
                DROPS.with(|d| {
                    let mut d = d.borrow_mut();
                    let f = self.flow as usize;
                    if d.len() <= f {
                        d.resize(f + 1, 0);
                    }
                    d[f] += 1;
                });
            }
        }
    }

    impl Packet for Pkt {
        fn len_bytes(&self) -> usize {
            self.len
        }
        fn mark_ce(&mut self) -> bool {
            self.ce |= self.ect;
            self.ect
        }
        /// Spread small flow ids over the hash space, as a keyed hash would.
        fn flow_hash(&self) -> u32 {
            self.flow.wrapping_mul(0x9e37_79b9)
        }
    }

    fn pkt(flow: u32, len: usize, seq: u64) -> Pkt {
        Pkt {
            len,
            flow,
            seq,
            sent: 0,
            ect: false,
            ce: false,
            delivered: false,
        }
    }

    fn take(q: &mut impl Qdisc<Pkt>, now: u64) -> Option<Pkt> {
        match q.dequeue(now) {
            Dequeue::Packet(mut p) => {
                p.delivered = true;
                Some(p)
            }
            _ => None,
        }
    }

    #[test]
    fn distinct_flows_get_distinct_queues() {
        let q: FqCodel<Pkt> = FqCodel::new(FqParams::default());
        let mut seen: Vec<usize> = (0..64)
            .map(|f| q.flow_index(pkt(f, 64, 0).flow_hash()))
            .collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 64);
    }

    #[test]
    fn a_flow_stays_in_order() {
        let mut q = FqCodel::new(FqParams::default());
        for i in 0..100 {
            q.enqueue(pkt(i as u32 % 3, 1000, i), 0).unwrap();
        }
        let mut last = [None::<u64>; 3];
        while let Some(p) = take(&mut q, 0) {
            let l = &mut last[p.flow as usize];
            assert!(l.is_none_or(|l| l < p.seq), "flow {} reordered", p.flow);
            *l = Some(p.seq);
        }
        assert_eq!(q.stats().backlog_packets, 0);
        assert_eq!(q.active_flows(), (0, 0));
    }

    #[test]
    fn sparse_flow_jumps_the_bulk_queue() {
        let mut q = FqCodel::new(FqParams::default());
        for i in 0..200 {
            q.enqueue(pkt(1, 1500, i), 0).unwrap();
        }
        // The bulk flow has been sending for a while (it is on the old list).
        for _ in 0..10 {
            take(&mut q, 0).unwrap();
        }
        q.enqueue(pkt(2, 64, 0), 0).unwrap(); // a ping
        let next = take(&mut q, 0).unwrap();
        assert_eq!(
            next.flow, 2,
            "the sparse packet goes next, ahead of 190 bulk packets"
        );
    }

    #[test]
    fn drr_is_byte_fair_across_packet_sizes() {
        let mut q = FqCodel::new(FqParams {
            codel: Params {
                max_packets: 10_000,
                limit_bytes: 100 << 20,
                ..Params::default()
            },
            ..FqParams::default()
        });
        for i in 0..2000 {
            q.enqueue(pkt(1, 1500, i), 0).unwrap();
            q.enqueue(pkt(2, 300, i), 0).unwrap();
            q.enqueue(pkt(2, 300, i), 0).unwrap();
        }
        let mut bytes = [0usize; 3];
        for _ in 0..1500 {
            let p = take(&mut q, 0).unwrap();
            bytes[p.flow as usize] += p.len;
        }
        let ratio = bytes[1] as f64 / bytes[2] as f64;
        assert!(
            (0.9..1.1).contains(&ratio),
            "byte ratio {ratio:.2} ({bytes:?})"
        );
    }

    #[test]
    fn overflow_drops_from_the_fattest_flow() {
        let mut q = FqCodel::new(FqParams {
            codel: Params {
                max_packets: 10,
                ..Params::default()
            },
            ..FqParams::default()
        });
        for i in 0..9 {
            q.enqueue(pkt(1, 1500, i), 0).unwrap();
        }
        q.enqueue(pkt(2, 64, 0), 0).unwrap();
        // Full. A new sparse packet arrives: the flood's oldest packet goes.
        let dropped = q.enqueue(pkt(3, 64, 0), 0).unwrap_err();
        assert_eq!((dropped.flow, dropped.seq), (1, 0));
        let s = q.stats();
        assert_eq!((s.backlog_packets, s.dropped, s.aqm_actions), (10, 1, 0));
        let mut flows: Vec<u32> = core::iter::from_fn(|| take(&mut q, 0))
            .map(|p| p.flow)
            .collect();
        flows.sort_unstable();
        flows.dedup();
        assert_eq!(flows, vec![1, 2, 3]);
    }

    #[test]
    fn slab_slots_are_reused() {
        let mut q = FqCodel::new(FqParams {
            codel: Params {
                max_packets: 4,
                ..Params::default()
            },
            ..FqParams::default()
        });
        for round in 0..1000u64 {
            for f in 0..4 {
                q.enqueue(pkt(f, 100, round), 0).unwrap();
            }
            assert!(!q.has_room());
            for _ in 0..4 {
                take(&mut q, 0).unwrap();
            }
        }
        assert_eq!(q.stats().dropped, 0);
    }

    // ---- simulation ---------------------------------------------------------------

    enum Source {
        /// Reno-like: +1 packet per RTT, halve on a drop or CE mark (once per RTT).
        Reno {
            rtt_ms: f64,
            cwnd: f64,
            last_signal: u64,
        },
        /// Sends at a fixed rate whatever happens (a loss-insensitive sender
        /// such as a UDP flood, or BBR before it measures the bottleneck).
        Fixed { pkts_per_ms: f64 },
        /// One small packet every `every_ms` (ping, game, VoIP).
        Sparse { every_ms: f64 },
    }

    struct Result {
        /// Sojourn of each sparse-flow packet (ns, sorted).
        sparse_sojourn: Vec<u64>,
        /// Delivered bytes per flow in the measured half.
        delivered: Vec<u64>,
        utilisation: f64,
    }

    /// 20 s at 0.1 ms steps over a 4 packets/ms link (≈ 48 Mbit/s at 1500 B);
    /// the second half is measured. Flow `i` is `sources[i]`.
    fn simulate(q: &mut impl Qdisc<Pkt>, sources: &mut [Source], ecn: bool) -> Result {
        DROPS.with(|d| d.borrow_mut().clear());
        let link = 4.0;
        let total = 200_000u64;
        let mut acc = vec![0.0f64; sources.len()];
        let mut seen_drops = vec![0u64; sources.len()];
        let mut res = Result {
            sparse_sojourn: Vec::new(),
            delivered: vec![0; sources.len()],
            utilisation: 0.0,
        };
        let (mut credit, mut busy, mut slots) = (0.0, 0u64, 0.0);
        let mut seq = 0;
        for t in 0..total {
            let now = t * MS / 10;
            let measuring = t > total / 2;
            for (f, s) in sources.iter_mut().enumerate() {
                let (rate, len) = match s {
                    Source::Reno { rtt_ms, cwnd, .. } => {
                        *cwnd += 0.1 / *rtt_ms; // +1 per RTT
                        (*cwnd / *rtt_ms, 1500)
                    }
                    Source::Fixed { pkts_per_ms } => (*pkts_per_ms, 1500),
                    Source::Sparse { every_ms } => (1.0 / *every_ms, 100),
                };
                acc[f] += rate / 10.0;
                while acc[f] >= 1.0 {
                    acc[f] -= 1.0;
                    seq += 1;
                    // (Not `..pkt()`: dropping that temporary would count as a drop.)
                    let mut p = pkt(f as u32, len, seq);
                    p.sent = now;
                    p.ect = ecn;
                    let _ = q.enqueue(p, now); // a rejected packet is dropped (counted)
                }
            }
            credit += link / 10.0;
            if measuring {
                slots += link / 10.0;
            }
            while credit >= 1.0 {
                let Some(p) = take(q, now) else {
                    credit = 0.0;
                    break;
                };
                credit -= 1.0;
                let f = p.flow as usize;
                if measuring {
                    busy += 1;
                    res.delivered[f] += p.len as u64;
                    if matches!(sources[f], Source::Sparse { .. }) {
                        res.sparse_sojourn.push(now - p.sent);
                    }
                }
                if p.ce {
                    signal(&mut sources[f], now);
                }
            }
            for (f, s) in sources.iter_mut().enumerate() {
                let d = drops(f);
                if d > seen_drops[f] {
                    seen_drops[f] = d;
                    signal(s, now);
                }
            }
        }
        res.sparse_sojourn.sort_unstable();
        res.utilisation = busy as f64 / slots;
        res
    }

    fn signal(s: &mut Source, now: u64) {
        if let Source::Reno {
            rtt_ms,
            cwnd,
            last_signal,
        } = s
            && now - *last_signal > (*rtt_ms * MS as f64) as u64
        {
            *cwnd = (*cwnd / 2.0).max(2.0);
            *last_signal = now;
        }
    }

    fn pct(v: &[u64], p: usize) -> u64 {
        v[(v.len() - 1) * p / 100]
    }

    fn params(ecn: bool) -> Params {
        Params {
            max_packets: 384,
            limit_bytes: 384 * 1514,
            ecn,
            ..Params::default()
        }
    }

    /// The real-line download case (docs/bufferbloat-cake.md §6b): a
    /// sender that ignores drops, at 125 % of the link, plus a ping. With
    /// one CoDel queue the ping waits behind the flood; with flow queueing
    /// it bypasses it.
    #[test]
    fn unresponsive_flood_does_not_delay_a_sparse_flow() {
        let mk = || {
            [
                Source::Fixed { pkts_per_ms: 5.0 },
                Source::Sparse { every_ms: 20.0 },
            ]
        };
        let mut codel = Codel::new(params(false));
        let c = simulate(&mut codel, &mut mk(), false);
        let mut fq = FqCodel::new(FqParams {
            codel: params(false),
            ..FqParams::default()
        });
        let f = simulate(&mut fq, &mut mk(), false);
        std::eprintln!(
            "ping sojourn under a flood: codel p50 {:.2} ms p99 {:.2} ms | fq_codel p50 {:.2} ms p99 {:.2} ms",
            pct(&c.sparse_sojourn, 50) as f64 / 1e6,
            pct(&c.sparse_sojourn, 99) as f64 / 1e6,
            pct(&f.sparse_sojourn, 50) as f64 / 1e6,
            pct(&f.sparse_sojourn, 99) as f64 / 1e6,
        );
        assert!(
            pct(&c.sparse_sojourn, 50) > 20 * MS,
            "control: one queue must bloat"
        );
        assert!(
            pct(&f.sparse_sojourn, 99) < MS,
            "fq_codel ping p99 {} µs",
            pct(&f.sparse_sojourn, 99) / 1000
        );
        assert_eq!(drops(1), 0, "the sparse flow loses nothing");
        assert!(f.utilisation > 0.99);
    }

    /// Four Reno flows with RTTs 10–80 ms plus a ping: flow queueing keeps
    /// the link full, the ping fast, and shares the link far more evenly
    /// than one queue (where short-RTT flows win).
    fn mixed_flows(ecn: bool) {
        let mk = || {
            [10.0, 20.0, 40.0, 80.0]
                .map(|rtt_ms| Source::Reno {
                    rtt_ms,
                    cwnd: 4.0,
                    last_signal: 0,
                })
                .into_iter()
                .chain([Source::Sparse { every_ms: 20.0 }])
                .collect::<Vec<_>>()
        };
        let mut fq = FqCodel::new(FqParams {
            codel: params(ecn),
            ..FqParams::default()
        });
        let f = simulate(&mut fq, &mut mk(), ecn);
        let mut codel = Codel::new(params(ecn));
        let c = simulate(&mut codel, &mut mk(), ecn);
        let jain = |d: &[u64]| {
            let d = &d[..4];
            let s: f64 = d.iter().map(|&x| x as f64).sum();
            let s2: f64 = d.iter().map(|&x| (x as f64).powi(2)).sum();
            s * s / (4.0 * s2)
        };
        std::eprintln!(
            "4 reno + ping (ecn {ecn}): fq_codel util {:.3}, fairness {:.3}, ping p99 {:.2} ms | codel util {:.3}, fairness {:.3}, ping p99 {:.2} ms",
            f.utilisation,
            jain(&f.delivered),
            pct(&f.sparse_sojourn, 99) as f64 / 1e6,
            c.utilisation,
            jain(&c.delivered),
            pct(&c.sparse_sojourn, 99) as f64 / 1e6,
        );
        assert!(f.utilisation > 0.95, "utilisation {:.3}", f.utilisation);
        assert!(pct(&f.sparse_sojourn, 99) < 2 * MS);
        assert!(
            jain(&f.delivered) > 0.95,
            "fairness {:.3}",
            jain(&f.delivered)
        );
        assert!(jain(&f.delivered) > jain(&c.delivered));
        if ecn {
            assert!(fq.stats().marked > 0);
            assert_eq!(fq.stats().dropped, 0);
        } else {
            assert!(fq.stats().aqm_actions > 0);
        }
    }

    #[test]
    fn mixed_rtt_flows_share_fairly_with_drops() {
        mixed_flows(false);
    }

    #[test]
    fn mixed_rtt_flows_share_fairly_with_ecn() {
        mixed_flows(true);
    }
}
