//! CAKE core: FQ-CoDel plus what CAKE adds on top (docs/bufferbloat-cake.md §2).
//!
//! - **Set-associative flow hashing** (8 ways): a flow whose hash lands in
//!   an occupied bucket takes a free queue in the same set instead of
//!   sharing, so collisions between active flows are rare (counted in
//!   [`Cake::way_collisions`]).
//! - **Host isolation** ([`Isolation`]): fairness first between *hosts*,
//!   then between the flows of each host. A LAN host opening 8 downloads
//!   gets the same share as one opening a single download. CAKE's method:
//!   each host counts its **bulk** flows, and a flow's DRR quantum is
//!   divided by that count (in `Triple` mode by the larger of its source
//!   and destination host counts). Host identities come from the
//!   *internal* (pre-NAT) addresses ([`Packet::host_hashes`]).
//! - **COBALT** = CoDel + **BLUE** per flow. CoDel handles flows that respond
//!   to drops or ECN marks. BLUE handles the ones that don't: each time a
//!   flow overflows the queue its drop probability rises, and it falls
//!   again while the flow's queue runs empty. BLUE drops even ECN-capable
//!   packets (as CAKE does), so a sender that ignores marks, or whose marks
//!   are bleached on the path, is still contained.
//!
//! The flow lists (new/sparse first, then old/bulk), DRR, the
//! fattest-flow overflow drop and the slab storage are those of
//! [`crate::fq_codel`]. The CoDel part is RFC 8289 ([`crate::codel`]);
//! CAKE's COBALT variant differs in details (count decay, no MTU rule).
//! DiffServ tins, the ACK filter, rate-aware targets and ingress mode
//! come later.

use crate::codel::{MAX_PACKET, Params, Sojourn, Vars};
use crate::fq_codel::{FlowQueue, FlowSource, NIL, Slab};
use crate::{Dequeue, Packet, Qdisc, Stats};
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Which fairness CAKE enforces (CAKE's `flows`, `dual-srchost`,
/// `dual-dsthost`, `triple-isolate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isolation {
    /// Per flow only (like FQ-CoDel, plus set-associative hashing).
    Flows,
    /// Per source host, then per flow (e.g. upload: per LAN host).
    DualSrcHost,
    /// Per destination host, then per flow (e.g. download: per LAN host).
    DualDstHost,
    /// Per source *and* destination host, then per flow. Works in both
    /// directions without knowing which side is the LAN. A flow's share is
    /// set by the busier of its two hosts, so many flows to *one* remote
    /// server (rare on the internet) are only flow-fair.
    Triple,
}

impl Isolation {
    fn src(self) -> bool {
        matches!(self, Self::DualSrcHost | Self::Triple)
    }
    fn dst(self) -> bool {
        matches!(self, Self::DualDstHost | Self::Triple)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CakeParams {
    /// CoDel parameters per flow; `max_packets` / `limit_bytes` are shared.
    pub codel: Params,
    /// Flow queues (a multiple of `ways`).
    pub flows: usize,
    /// Set associativity of the flow and host tables.
    pub ways: usize,
    /// Host table size (per direction).
    pub hosts: usize,
    pub quantum: u32,
    pub isolation: Isolation,
    /// BLUE for unresponsive flows (COBALT). `false` = CoDel only.
    pub blue: bool,
    /// Seed for BLUE's random drops.
    pub seed: u64,
}

impl Default for CakeParams {
    fn default() -> Self {
        Self {
            codel: Params::default(),
            flows: 1024,
            ways: 8,
            hosts: 1024,
            quantum: MAX_PACKET as u32,
            isolation: Isolation::Triple,
            blue: true,
            seed: 0x2545_f491_4f6c_dd1d,
        }
    }
}

/// BLUE drop probability steps, as fractions of 2^32 (CAKE's values:
/// +1/256 per overflow event, -1/4096 per empty event, at most once per
/// `target`).
const BLUE_INC: u32 = 1 << 24;
const BLUE_DEC: u32 = 1 << 20;

#[derive(Clone, Copy, Debug, Default)]
struct Blue {
    p_drop: u32,
    timer: u64,
}

impl Blue {
    fn queue_full(&mut self, now: u64, target: u64) {
        if now.saturating_sub(self.timer) > target {
            self.p_drop = self.p_drop.saturating_add(BLUE_INC);
            self.timer = now;
        }
    }
    fn queue_empty(&mut self, now: u64, target: u64) {
        if self.p_drop > 0 && now.saturating_sub(self.timer) > target {
            self.p_drop = self.p_drop.saturating_sub(BLUE_DEC);
            self.timer = now;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum List {
    None,
    New,
    Old,
}

struct Flow {
    q: FlowQueue,
    deficit: i32,
    list: List,
    /// Counted as a bulk flow of its hosts.
    bulk: bool,
    tag: u32,
    /// Host table slots while active (NIL if not isolated by that side).
    src: u32,
    dst: u32,
    vars: Vars,
    blue: Blue,
}

#[derive(Clone, Copy, Debug, Default)]
struct Host {
    tag: u32,
    /// Active flows of this host.
    refs: u32,
    /// Bulk flows of this host (≤ refs).
    bulk: u32,
}

/// Spread a hash before bucketing (host hashes may be only 16 bits wide).
fn spread(h: u32) -> u32 {
    let x = h.wrapping_mul(0x9e37_79b1);
    x ^ (x >> 15)
}

/// Set-associative lookup: the way holding `tag`, else a free way (marked
/// with `tag`; `true` = newly assigned), else a shared way (collision).
fn lookup(
    ways: usize,
    len: usize,
    tag: u32,
    tag_of: impl Fn(usize) -> u32,
    free: impl Fn(usize) -> bool,
) -> (usize, Assign) {
    let sets = (len / ways).max(1);
    let h = spread(tag) as usize;
    let base = (h % sets) * ways;
    let set = base..(base + ways).min(len);
    if let Some(i) = set.clone().find(|&i| tag_of(i) == tag) {
        return (i, Assign::Same);
    }
    if let Some(i) = set.clone().find(|&i| free(i)) {
        return (i, Assign::New);
    }
    (base + (h / sets) % (set.len().max(1)), Assign::Collision)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Assign {
    Same,
    New,
    Collision,
}

pub struct Cake<P> {
    p: CakeParams,
    slab: Slab<P>,
    flows: Vec<Flow>,
    src_hosts: Vec<Host>,
    dst_hosts: Vec<Host>,
    new_flows: VecDeque<u32>,
    old_flows: VecDeque<u32>,
    packets: usize,
    bytes: usize,
    stats: Stats,
    soj: Sojourn,
    rng: u64,
    /// Times a flow became active (diagnostics).
    pub new_flow_count: u64,
    /// Overflow drops taken from the fattest flow (subset of `dropped`).
    pub overflow_drops: u64,
    /// Drops by BLUE (subset of `dropped` and `aqm_actions`).
    pub blue_drops: u64,
    /// Flows that had to share a queue because their set was full.
    pub way_collisions: u64,
}

impl<P: Packet> Cake<P> {
    pub fn new(p: CakeParams) -> Self {
        let ways = p.ways.clamp(1, 64);
        let flows = p.flows.clamp(1, NIL as usize - 1).div_ceil(ways) * ways;
        let hosts = p.hosts.clamp(1, 1 << 16).div_ceil(ways) * ways;
        Self {
            slab: Slab::new(p.codel.max_packets),
            flows: (0..flows)
                .map(|_| Flow {
                    q: FlowQueue::EMPTY,
                    deficit: 0,
                    list: List::None,
                    bulk: false,
                    tag: 0,
                    src: NIL,
                    dst: NIL,
                    vars: Vars::default(),
                    blue: Blue::default(),
                })
                .collect(),
            src_hosts: alloc::vec![Host::default(); hosts],
            dst_hosts: alloc::vec![Host::default(); hosts],
            new_flows: VecDeque::with_capacity(flows),
            old_flows: VecDeque::with_capacity(flows),
            packets: 0,
            bytes: 0,
            stats: Stats::default(),
            soj: Sojourn::default(),
            rng: p.seed | 1,
            new_flow_count: 0,
            overflow_drops: 0,
            blue_drops: 0,
            way_collisions: 0,
            p: CakeParams {
                flows,
                hosts,
                ways,
                ..p
            },
        }
    }

    pub fn params(&self) -> &CakeParams {
        &self.p
    }

    /// Sojourn time of the last dequeued packet (diagnostics).
    pub fn last_sojourn_ns(&self) -> u64 {
        self.soj.last_ns
    }

    /// Largest sojourn time since the previous call (resets it).
    pub fn take_max_sojourn_ns(&mut self) -> u64 {
        core::mem::take(&mut self.soj.max_ns)
    }

    /// Flows on the (new, old) lists.
    pub fn active_flows(&self) -> (usize, usize) {
        (self.new_flows.len(), self.old_flows.len())
    }

    /// Hosts with active flows: (source, destination). O(hosts).
    pub fn active_hosts(&self) -> (usize, usize) {
        let n = |t: &[Host]| t.iter().filter(|h| h.refs > 0).count();
        (n(&self.src_hosts), n(&self.dst_hosts))
    }

    fn random(&mut self) -> u32 {
        // xorshift64*
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        (self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
    }

    fn flow_slot(&mut self, hash: u32) -> usize {
        let flows = &self.flows;
        let (i, how) = lookup(
            self.p.ways,
            flows.len(),
            hash,
            |i| flows[i].tag,
            |i| flows[i].list == List::None,
        );
        match how {
            Assign::Same => {}
            Assign::New => {
                // A queue changes owner: the old flow's AQM state is not ours.
                let f = &mut self.flows[i];
                f.tag = hash;
                f.vars = Vars::default();
                f.blue = Blue::default();
            }
            Assign::Collision => self.way_collisions += 1,
        }
        i
    }

    fn host_slot(table: &mut [Host], ways: usize, hash: u32) -> u32 {
        let (i, how) = lookup(
            ways,
            table.len(),
            hash,
            |i| {
                if table[i].refs > 0 {
                    table[i].tag
                } else {
                    !hash
                }
            },
            |i| table[i].refs == 0,
        );
        if how == Assign::New {
            table[i] = Host {
                tag: hash,
                refs: 0,
                bulk: 0,
            };
        }
        table[i].refs += 1;
        i as u32
    }

    /// Quantum for `fi` this round: `quantum / bulk flows of its busiest host`.
    fn quantum_for(&self, fi: usize) -> i32 {
        let f = &self.flows[fi];
        let load = |t: &[Host], i: u32| t.get(i as usize).map_or(0, |h| h.bulk);
        let host_load = load(&self.src_hosts, f.src)
            .max(load(&self.dst_hosts, f.dst))
            .max(1);
        (self.p.quantum / host_load).max(1) as i32
    }

    fn activate(&mut self, fi: usize, hashes: (u32, u32)) {
        let ways = self.p.ways;
        let iso = self.p.isolation;
        let src = if iso.src() {
            Self::host_slot(&mut self.src_hosts, ways, hashes.0)
        } else {
            NIL
        };
        let dst = if iso.dst() {
            Self::host_slot(&mut self.dst_hosts, ways, hashes.1)
        } else {
            NIL
        };
        let f = &mut self.flows[fi];
        f.src = src;
        f.dst = dst;
        f.list = List::New;
        f.bulk = false;
        self.flows[fi].deficit = self.quantum_for(fi);
        self.new_flows.push_back(fi as u32);
        self.new_flow_count += 1;
    }

    fn set_bulk(&mut self, fi: usize, bulk: bool) {
        let f = &mut self.flows[fi];
        if f.bulk == bulk {
            return;
        }
        f.bulk = bulk;
        for (t, i) in [(&mut self.src_hosts, f.src), (&mut self.dst_hosts, f.dst)] {
            if let Some(h) = t.get_mut(i as usize) {
                h.bulk = if bulk { h.bulk + 1 } else { h.bulk - 1 };
            }
        }
    }

    fn deactivate(&mut self, fi: usize) {
        self.set_bulk(fi, false);
        let f = &mut self.flows[fi];
        for (t, i) in [(&mut self.src_hosts, f.src), (&mut self.dst_hosts, f.dst)] {
            if let Some(h) = t.get_mut(i as usize) {
                h.refs -= 1;
            }
        }
        f.src = NIL;
        f.dst = NIL;
        f.list = List::None;
    }

    /// Head-drop from the flow with the most bytes queued; BLUE notes it.
    fn drop_from_fattest(&mut self, now: u64) -> Option<P> {
        let target = self.p.codel.target_ns;
        let fat = self.flows.iter_mut().max_by_key(|f| f.q.bytes)?;
        let (p, _) = fat.q.pop(&mut self.slab)?;
        if self.p.blue {
            fat.blue.queue_full(now, target);
        }
        self.packets -= 1;
        self.bytes -= p.len_bytes();
        self.stats.dropped += 1;
        self.overflow_drops += 1;
        Some(p)
    }

    /// CoDel-dequeue from flow `fi` (drops/marks counted in the stats).
    fn codel_dequeue(&mut self, fi: usize, now: u64) -> Option<P> {
        let f = &mut self.flows[fi];
        let mut src = FlowSource {
            slab: &mut self.slab,
            q: &mut f.q,
            packets: &mut self.packets,
            bytes: &mut self.bytes,
        };
        f.vars
            .dequeue(&mut src, &self.p.codel, &mut self.stats, &mut self.soj, now)
    }
}

impl<P: Packet> Qdisc<P> for Cake<P> {
    fn enqueue(&mut self, p: P, now_ns: u64) -> Result<(), P> {
        let n = p.len_bytes();
        let (max_packets, limit_bytes) = (self.p.codel.max_packets, self.p.codel.limit_bytes);
        if n > limit_bytes || max_packets == 0 {
            self.stats.dropped += 1;
            return Err(p);
        }
        let mut rejected = None;
        while self.packets >= max_packets || self.bytes + n > limit_bytes {
            match self.drop_from_fattest(now_ns) {
                Some(d) => rejected = Some(d),
                None => break,
            }
        }
        let hashes = p.host_hashes();
        let fi = self.flow_slot(p.flow_hash());
        let slot = match self.slab.alloc(p, now_ns) {
            Ok(slot) => slot,
            Err(p) => {
                self.stats.dropped += 1;
                return Err(p);
            }
        };
        self.flows[fi].q.push(&mut self.slab, slot, n);
        self.packets += 1;
        self.bytes += n;
        self.stats.enqueued += 1;
        if self.flows[fi].list == List::None {
            self.activate(fi, hashes);
        }
        match rejected {
            Some(d) => Err(d),
            None => Ok(()),
        }
    }

    fn dequeue(&mut self, now: u64) -> Dequeue<P> {
        let target = self.p.codel.target_ns;
        loop {
            let (fi, from_new) = match (self.new_flows.front(), self.old_flows.front()) {
                (Some(&f), _) => (f as usize, true),
                (None, Some(&f)) => (f as usize, false),
                (None, None) => return Dequeue::Empty,
            };
            if self.flows[fi].deficit <= 0 {
                // Used its quantum: it is a bulk flow; next round at the
                // back of the old list, with a quantum scaled to its host.
                self.set_bulk(fi, true);
                let q = self.quantum_for(fi);
                let f = &mut self.flows[fi];
                f.deficit += q;
                f.list = List::Old;
                if from_new {
                    self.new_flows.pop_front();
                } else {
                    self.old_flows.pop_front();
                }
                self.old_flows.push_back(fi as u32);
                continue;
            }
            match self.codel_dequeue(fi, now) {
                Some(pkt) => {
                    let p_drop = self.flows[fi].blue.p_drop;
                    if self.p.blue && p_drop > 0 && self.random() < p_drop {
                        self.stats.dropped += 1;
                        self.stats.aqm_actions += 1;
                        self.blue_drops += 1;
                        drop(pkt);
                        continue;
                    }
                    self.flows[fi].deficit -= pkt.len_bytes() as i32;
                    self.stats.dequeued += 1;
                    return Dequeue::Packet(pkt);
                }
                None => {
                    self.flows[fi].blue.queue_empty(now, target);
                    if from_new {
                        self.new_flows.pop_front();
                    } else {
                        self.old_flows.pop_front();
                    }
                    if from_new && !self.old_flows.is_empty() {
                        // Not bulk: it ran dry within its quantum. It waits
                        // one round on the old list so it can't stay "new".
                        self.old_flows.push_back(fi as u32);
                        self.flows[fi].list = List::Old;
                    } else {
                        self.deactivate(fi);
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
    use crate::fq_codel::{FqCodel, FqParams};
    use crate::testutil::*;
    use alloc::vec;

    fn big() -> Params {
        Params {
            max_packets: 10_000,
            limit_bytes: 100 << 20,
            ..Params::default()
        }
    }

    fn cake(isolation: Isolation, codel: Params) -> Cake<Pkt> {
        Cake::new(CakeParams {
            codel,
            isolation,
            ..CakeParams::default()
        })
    }

    fn host_pkt(flow: u32, src: u32, dst: u32, seq: u64) -> Pkt {
        let mut p = pkt(flow, 1500, seq);
        p.src_host = src;
        p.dst_host = dst;
        p
    }

    /// Host A runs 1 bulk flow, host B runs 8; all backlogged. Returns
    /// A's share / B's share of the dequeued bytes. `download`: the hosts
    /// are destinations (LAN egress) instead of sources (WAN egress).
    fn host_share(isolation: Isolation, download: bool) -> f64 {
        let mut q = cake(isolation, big());
        let (a, b) = (1, 2);
        for seq in 0..300 {
            // Each flow talks to its own remote server, as on the internet.
            let mk = |flow, host| {
                let remote = 100 + flow;
                if download {
                    host_pkt(flow, remote, host, seq)
                } else {
                    host_pkt(flow, host, remote, seq)
                }
            };
            // A gets enough backlog to stay busy for the whole measurement.
            for _ in 0..4 {
                q.enqueue(mk(0, a), 0).unwrap();
            }
            for f in 1..=8 {
                q.enqueue(mk(f, b), 0).unwrap();
            }
        }
        let mut bytes = [0u64; 2];
        for _ in 0..1800 {
            let p = take(&mut q, 0).unwrap();
            bytes[(p.flow != 0) as usize] += p.len as u64;
        }
        bytes[0] as f64 / bytes[1] as f64
    }

    #[test]
    fn host_isolation_shares_per_host_not_per_flow() {
        for (iso, download) in [
            (Isolation::Triple, false),
            (Isolation::Triple, true),
            (Isolation::DualSrcHost, false),
            (Isolation::DualDstHost, true),
        ] {
            let r = host_share(iso, download);
            assert!(
                (0.8..1.25).contains(&r),
                "{iso:?} download={download}: A/B {r:.2}"
            );
        }
        // Controls: flow fairness only, or isolating the wrong side,
        // gives the 8-flow host 8 shares.
        for (iso, download) in [
            (Isolation::Flows, false),
            (Isolation::DualDstHost, false),
            (Isolation::DualSrcHost, true),
        ] {
            let r = host_share(iso, download);
            assert!(
                (0.1..0.15).contains(&r),
                "{iso:?} download={download}: A/B {r:.2}"
            );
        }
    }

    #[test]
    fn host_counts_return_to_zero() {
        let mut q = cake(Isolation::Triple, big());
        for seq in 0..50 {
            for f in 0..20 {
                q.enqueue(host_pkt(f, f % 3, 7, seq), 0).unwrap();
            }
        }
        assert_eq!(q.active_hosts(), (3, 1));
        while take(&mut q, 0).is_some() {}
        assert_eq!(q.active_hosts(), (0, 0));
        assert!(
            q.src_hosts
                .iter()
                .chain(&q.dst_hosts)
                .all(|h| h.bulk == 0 && h.refs == 0)
        );
        assert_eq!(q.active_flows(), (0, 0));
    }

    #[test]
    fn set_associative_hashing_avoids_collisions() {
        let mut q = cake(Isolation::Flows, big());
        let sets = q.flows.len() / q.p.ways;
        let bucket = |f: u32| spread(pkt(f, 64, 0).flow_hash()) as usize % sets;
        // Nine flows that all hash into the same 8-way set.
        let same: Vec<u32> = (0..).filter(|&f| bucket(f) == bucket(0)).take(9).collect();
        for &f in &same[..8] {
            q.enqueue(pkt(f, 64, 0), 0).unwrap();
        }
        assert_eq!((q.active_flows().0, q.way_collisions), (8, 0));
        q.enqueue(pkt(same[8], 64, 0), 0).unwrap();
        assert_eq!(
            (q.active_flows().0, q.way_collisions),
            (8, 1),
            "the 9th shares"
        );
        // Each of the first eight is still served in order, ahead of nothing.
        while take(&mut q, 0).is_some() {}
        // Once drained, the set is free again.
        q.enqueue(pkt(same[8], 64, 1), 0).unwrap();
        assert_eq!(q.way_collisions, 1);
    }

    #[test]
    fn a_flow_stays_in_order() {
        let mut q = cake(Isolation::Triple, big());
        for i in 0..300 {
            q.enqueue(host_pkt(i as u32 % 7, i as u32 % 3, 1, i), 0)
                .unwrap();
        }
        let mut last = [None::<u64>; 7];
        while let Some(p) = take(&mut q, 0) {
            let l = &mut last[p.flow as usize];
            assert!(l.is_none_or(|l| l < p.seq), "flow {} reordered", p.flow);
            *l = Some(p.seq);
        }
    }

    fn params(ecn: bool) -> Params {
        crate::testutil::params(ecn)
    }

    /// The real-line upload case: a sender that ignores ECN marks (or whose
    /// marks are bleached on the path), at 125 % of the link, plus a ping.
    /// FQ-CoDel only marks it, so its own queue sits at the hard limit.
    /// COBALT's BLUE drops anyway and keeps that queue short.
    #[test]
    fn blue_contains_a_flow_that_ignores_ecn() {
        let mk = || {
            [
                Sender::Fixed { pkts_per_ms: 5.0 },
                Sender::Sparse { every_ms: 20.0 },
            ]
        };
        let mut fq = FqCodel::new(FqParams {
            codel: params(true),
            ..FqParams::default()
        });
        let f = simulate(&mut fq, &mut mk(), true);
        let mut ck = cake(Isolation::Triple, params(true));
        let c = simulate(&mut ck, &mut mk(), true);
        std::eprintln!(
            "ECN-ignoring flood: fq_codel flood sojourn p50 {:.1} ms, overflow drops {} | cake p50 {:.1} ms, overflow {}, blue drops {}, ping p99 {:.2} ms",
            pct(&f.sojourn[0], 50) as f64 / 1e6,
            fq.overflow_drops,
            pct(&c.sojourn[0], 50) as f64 / 1e6,
            ck.overflow_drops,
            ck.blue_drops,
            pct(&c.sparse_sojourn, 99) as f64 / 1e6,
        );
        assert!(
            pct(&f.sojourn[0], 50) > 50 * MS,
            "control: fq_codel queue at the limit"
        );
        assert!(ck.blue_drops > 0);
        assert!(
            pct(&c.sojourn[0], 50) < pct(&f.sojourn[0], 50) / 2,
            "BLUE should at least halve the flood's own queue"
        );
        assert!(pct(&c.sparse_sojourn, 99) < MS);
        assert!(c.utilisation > 0.95, "util {:.3}", c.utilisation);
    }

    /// Responsive flows never overflow, so BLUE stays out of the way, and
    /// CAKE keeps FQ-CoDel's results (ping, fairness, utilisation).
    #[test]
    fn responsive_flows_are_left_to_codel() {
        for ecn in [false, true] {
            let mut senders: Vec<Sender> = [10.0, 20.0, 40.0, 80.0]
                .map(|rtt_ms| Sender::Reno {
                    rtt_ms,
                    cwnd: 4.0,
                    last_signal: 0,
                })
                .into_iter()
                .chain([Sender::Sparse { every_ms: 20.0 }])
                .collect();
            let mut q = cake(Isolation::Triple, params(ecn));
            let r = simulate(&mut q, &mut senders, ecn);
            let d = &r.delivered[..4];
            let s: f64 = d.iter().map(|&x| x as f64).sum();
            let s2: f64 = d.iter().map(|&x| (x as f64).powi(2)).sum();
            let jain = s * s / (4.0 * s2);
            std::eprintln!(
                "cake 4 reno + ping (ecn {ecn}): util {:.3}, fairness {jain:.3}, ping p99 {:.2} ms, blue drops {}",
                r.utilisation,
                pct(&r.sparse_sojourn, 99) as f64 / 1e6,
                q.blue_drops
            );
            assert_eq!(q.blue_drops, 0);
            assert!(r.utilisation > 0.95 && jain > 0.95);
            assert!(pct(&r.sparse_sojourn, 99) < 2 * MS);
        }
    }

    /// Two LAN hosts upload: A with 1 Reno flow, B with 4. Per-host
    /// fairness gives A about half the link (FQ-CoDel: a fifth).
    #[test]
    fn host_fairness_with_tcp_like_flows() {
        let mk = || {
            vec![
                Sender::Reno {
                    rtt_ms: 20.0,
                    cwnd: 4.0,
                    last_signal: 0,
                };
                5
            ]
        };
        let hosts = [1, 2, 2, 2, 2];
        let mut q = cake(Isolation::Triple, params(false));
        let c = simulate_hosts(&mut q, &mut mk(), &hosts, false);
        let mut fq = FqCodel::new(FqParams {
            codel: params(false),
            ..FqParams::default()
        });
        let f = simulate_hosts(&mut fq, &mut mk(), &hosts, false);
        let share = |r: &crate::testutil::Result| {
            r.delivered[0] as f64 / r.delivered.iter().sum::<u64>() as f64
        };
        std::eprintln!(
            "host A (1 flow) vs B (4 flows): cake A share {:.2} (util {:.3}) | fq_codel A share {:.2}",
            share(&c),
            c.utilisation,
            share(&f)
        );
        // A's single Reno flow can't always fill its half (sawtooth); B
        // takes the slack, so A ends a little under 0.5.
        assert!(
            (0.38..0.6).contains(&share(&c)),
            "cake A share {:.2}",
            share(&c)
        );
        assert!(
            share(&f) < 0.25,
            "control: fq_codel A share {:.2}",
            share(&f)
        );
        assert!(c.utilisation > 0.9);
    }
}
