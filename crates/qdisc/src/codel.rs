//! CoDel, "Controlled Delay" active queue management (RFC 8289).
//!
//! CoDel watches the **sojourn time** (how long each packet waited). A
//! queue whose minimum sojourn stays above `target` (5 ms) for a whole
//! `interval` (100 ms) is a *bad* standing queue: CoDel then drops (or
//! ECN-marks) one packet and schedules the next drop at
//! `interval / sqrt(count)`, increasing the rate until the queue drains to
//! below `target`. Short bursts (*good* queues) that drain within an
//! interval are left alone. Time is passed in (ns), so behaviour is
//! deterministic and simulation-tested below.
//!
//! The control law follows the RFC pseudocode, with an integer square root
//! (no floating point in `no_std`). Packets are timestamped on enqueue
//! inside the queue, so the `Packet` type needs no timestamp field.

use crate::{Dequeue, Packet, Qdisc, Stats};
use alloc::collections::VecDeque;

pub const DEFAULT_TARGET_NS: u64 = 5_000_000;
pub const DEFAULT_INTERVAL_NS: u64 = 100_000_000;
/// "Don't drop if less than one MTU is queued" (RFC 8289 §5.5).
pub(crate) const MAX_PACKET: usize = 1514;

#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub target_ns: u64,
    pub interval_ns: u64,
    /// Hard limits; overflow is tail-dropped (CoDel normally never gets there).
    pub max_packets: usize,
    pub limit_bytes: usize,
    pub ecn: bool,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            target_ns: DEFAULT_TARGET_NS,
            interval_ns: DEFAULT_INTERVAL_NS,
            max_packets: 1000,
            limit_bytes: 1 << 20,
            ecn: true,
        }
    }
}

/// Integer square root (floor) of a u64, by Newton's method.
fn isqrt(n: u64) -> u64 {
    if n < 2 {
        return n;
    }
    let mut x = 1u64 << ((64 - n.leading_zeros()) / 2 + 1);
    loop {
        let y = (x + n / x) / 2;
        if y >= x {
            return x;
        }
        x = y;
    }
}

/// `t + interval / sqrt(count)`, in integer arithmetic.
fn control_law(t: u64, interval: u64, count: u32) -> u64 {
    // sqrt(count) in Q16 fixed point: isqrt(count << 32) = sqrt(count) * 2^16.
    let s = isqrt((count.max(1) as u64) << 32);
    t + ((interval as u128) << 16)
        .checked_div(s as u128)
        .unwrap_or(0) as u64
}

/// Per-queue CoDel state (RFC 8289 variable names). [`Codel`] has one;
/// FQ-CoDel keeps one per flow queue.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Vars {
    first_above_time: u64,
    drop_next: u64,
    count: u32,
    lastcount: u32,
    dropping: bool,
}

/// Sojourn-time diagnostics.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sojourn {
    pub last_ns: u64,
    pub max_ns: u64,
}

/// The queue CoDel pulls packets from.
pub(crate) trait Source<P> {
    /// Pop the head packet with its enqueue time (ns).
    fn pop(&mut self) -> Option<(P, u64)>;
    /// Bytes still queued after the pop, for the "at least one MTU
    /// queued" rule (RFC 8289 §5.5; FQ-CoDel uses the total backlog).
    fn backlog_bytes(&self) -> usize;
}

impl Vars {
    /// RFC 8289 `dodequeue`: pop one packet and decide whether CoDel is in
    /// the "persistently above target" state where dropping is allowed.
    fn do_dequeue<P: Packet>(
        &mut self,
        src: &mut impl Source<P>,
        params: &Params,
        soj: &mut Sojourn,
        now: u64,
    ) -> Option<(P, bool)> {
        let Some((p, ts)) = src.pop() else {
            self.first_above_time = 0;
            return None;
        };
        let sojourn = now.saturating_sub(ts);
        soj.last_ns = sojourn;
        soj.max_ns = soj.max_ns.max(sojourn);
        let ok_to_drop = if sojourn < params.target_ns || src.backlog_bytes() <= MAX_PACKET {
            self.first_above_time = 0;
            false
        } else if self.first_above_time == 0 {
            self.first_above_time = now + params.interval_ns;
            false
        } else {
            now >= self.first_above_time
        };
        Some((p, ok_to_drop))
    }

    /// RFC 8289 dequeue: returns the packet to send, after dropping (or
    /// ECN-marking) as the control law demands. Drops are counted in
    /// `stats`; `dequeued` is left to the caller.
    pub(crate) fn dequeue<P: Packet>(
        &mut self,
        src: &mut impl Source<P>,
        params: &Params,
        stats: &mut Stats,
        soj: &mut Sojourn,
        now: u64,
    ) -> Option<P> {
        let Some((mut p, ok_to_drop)) = self.do_dequeue(src, params, soj, now) else {
            self.dropping = false;
            return None;
        };
        if self.dropping {
            if !ok_to_drop {
                self.dropping = false; // sojourn back below target: leave the dropping state
            }
            while self.dropping && now >= self.drop_next {
                if let Some(kept) = congestion_signal(p, params, stats) {
                    // ECN-marked: deliver it, schedule the next signal.
                    self.count += 1;
                    self.drop_next = control_law(self.drop_next, params.interval_ns, self.count);
                    p = kept;
                    break;
                }
                self.count += 1;
                match self.do_dequeue(src, params, soj, now) {
                    None => {
                        self.dropping = false;
                        return None;
                    }
                    Some((next, ok)) => {
                        p = next;
                        if ok {
                            self.drop_next =
                                control_law(self.drop_next, params.interval_ns, self.count);
                        } else {
                            self.dropping = false;
                        }
                    }
                }
            }
        } else if ok_to_drop {
            // Enter the dropping state: signal congestion on this packet. If
            // it was dropped, deliver the next one (RFC 8289 delivers it
            // regardless of its own sojourn; the next signal is scheduled).
            if let Some(kept) = congestion_signal(p, params, stats) {
                p = kept;
            } else if let Some((next, _)) = self.do_dequeue(src, params, soj, now) {
                p = next;
            } else {
                self.enter_dropping(params, now); // the drop emptied the queue
                return None;
            }
            self.enter_dropping(params, now);
        }
        Some(p)
    }

    /// RFC 8289: when re-entering the dropping state soon after leaving it,
    /// resume from the previous drop rate instead of starting at 1.
    fn enter_dropping(&mut self, params: &Params, now: u64) {
        self.dropping = true;
        let delta = self.count.wrapping_sub(self.lastcount);
        self.count = if delta > 1 && now.saturating_sub(self.drop_next) < 16 * params.interval_ns {
            delta
        } else {
            1
        };
        self.drop_next = control_law(now, params.interval_ns, self.count);
        self.lastcount = self.count;
    }
}

/// Drop or ECN-mark `p`. Returns the packet if it was marked (keep it).
fn congestion_signal<P: Packet>(mut p: P, params: &Params, stats: &mut Stats) -> Option<P> {
    stats.aqm_actions += 1;
    if params.ecn && p.mark_ce() {
        stats.marked += 1;
        Some(p)
    } else {
        stats.dropped += 1;
        None
    }
}

/// Single-queue CoDel.
pub struct Codel<P> {
    q: VecDeque<(P, u64)>,
    p: Params,
    bytes: usize,
    vars: Vars,
    stats: Stats,
    soj: Sojourn,
}

struct Fifo<'a, P> {
    q: &'a mut VecDeque<(P, u64)>,
    bytes: &'a mut usize,
}

impl<P: Packet> Source<P> for Fifo<'_, P> {
    fn pop(&mut self) -> Option<(P, u64)> {
        let (p, ts) = self.q.pop_front()?;
        *self.bytes -= p.len_bytes();
        Some((p, ts))
    }
    fn backlog_bytes(&self) -> usize {
        *self.bytes
    }
}

impl<P: Packet> Codel<P> {
    pub fn new(p: Params) -> Self {
        Self {
            q: VecDeque::with_capacity(p.max_packets),
            p,
            bytes: 0,
            vars: Vars::default(),
            stats: Stats::default(),
            soj: Sojourn::default(),
        }
    }

    /// Sojourn time of the last dequeued packet (diagnostics).
    pub fn last_sojourn_ns(&self) -> u64 {
        self.soj.last_ns
    }

    /// Largest sojourn time since the previous call (resets it).
    pub fn take_max_sojourn_ns(&mut self) -> u64 {
        core::mem::take(&mut self.soj.max_ns)
    }
}

impl<P: Packet> Qdisc<P> for Codel<P> {
    fn enqueue(&mut self, p: P, now_ns: u64) -> Result<(), P> {
        let n = p.len_bytes();
        if self.q.len() >= self.p.max_packets || self.bytes + n > self.p.limit_bytes {
            self.stats.dropped += 1;
            return Err(p);
        }
        self.bytes += n;
        self.q.push_back((p, now_ns));
        self.stats.enqueued += 1;
        Ok(())
    }

    fn dequeue(&mut self, now: u64) -> Dequeue<P> {
        let mut src = Fifo {
            q: &mut self.q,
            bytes: &mut self.bytes,
        };
        match self
            .vars
            .dequeue(&mut src, &self.p, &mut self.stats, &mut self.soj, now)
        {
            Some(p) => {
                self.stats.dequeued += 1;
                Dequeue::Packet(p)
            }
            None => Dequeue::Empty,
        }
    }

    fn has_room(&self) -> bool {
        self.q.len() < self.p.max_packets && self.bytes + MAX_PACKET <= self.p.limit_bytes
    }

    fn stats(&self) -> Stats {
        Stats {
            backlog_packets: self.q.len(),
            backlog_bytes: self.bytes,
            ..self.stats
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::fifo::BFifo;
    use alloc::vec::Vec;

    const MS: u64 = 1_000_000;

    #[derive(Debug)]
    struct Pkt {
        len: usize,
        ect: bool,
        ce: bool,
    }
    impl Packet for Pkt {
        fn len_bytes(&self) -> usize {
            self.len
        }
        fn mark_ce(&mut self) -> bool {
            if self.ect {
                self.ce = true;
            }
            self.ect
        }
    }
    /// A packet with its enqueue time, for timing a plain FIFO in tests.
    impl Packet for (Pkt, u64) {
        fn len_bytes(&self) -> usize {
            self.0.len
        }
    }

    fn pkt() -> Pkt {
        Pkt {
            len: 1500,
            ect: false,
            ce: false,
        }
    }

    #[test]
    fn isqrt_and_control_law() {
        for n in [0u64, 1, 2, 3, 4, 15, 16, 17, 1 << 40, u64::MAX] {
            let r = isqrt(n);
            assert!(
                r * r <= n && (r + 1).checked_mul(r + 1).is_none_or(|x| x > n),
                "isqrt({n}) = {r}"
            );
        }
        assert_eq!(control_law(0, 100 * MS, 1), 100 * MS);
        assert_eq!(control_law(0, 100 * MS, 4), 50 * MS);
        let c100 = control_law(0, 100 * MS, 100);
        assert!((9_999_000..=10_001_000).contains(&c100), "{c100}");
    }

    #[test]
    fn short_queue_is_never_dropped() {
        let mut q = Codel::new(Params::default());
        // 2 packets queued, each waits 50 ms: above target, but <= 1 MTU remains after dequeue.
        let mut now = 0;
        for _ in 0..1000 {
            q.enqueue(pkt(), now).unwrap();
            q.enqueue(pkt(), now).unwrap();
            now += 50 * MS;
            assert!(matches!(q.dequeue(now), Dequeue::Packet(_)));
            assert!(matches!(q.dequeue(now), Dequeue::Packet(_)));
        }
        assert_eq!(q.stats().dropped, 0);
    }

    #[test]
    fn good_queue_burst_is_not_dropped() {
        // A 50-packet burst served at 1 packet/ms drains in 50 ms < interval.
        let mut q = Codel::new(Params::default());
        for _ in 0..50 {
            q.enqueue(pkt(), 0).unwrap();
        }
        let mut now = 0;
        while let Dequeue::Packet(_) = q.dequeue(now) {
            now += MS;
        }
        assert_eq!(q.stats().dropped, 0);
    }

    /// Fluid TCP-like source: additive increase once per RTT, halve on a
    /// congestion signal. Link drains `rate` packets/ms. Returns
    /// (median sojourn, p99 sojourn, link utilisation) over the last half.
    fn simulate<Q: Qdisc<Pkt>>(
        q: &mut Q,
        ecn: bool,
        sojourn_of: impl Fn(&mut Q) -> u64,
    ) -> (u64, u64, f64) {
        let link_pps_per_ms = 4.0; // ≈ 48 Mbit/s with 1500 B packets
        let rtt_ms = 20.0;
        let mut cwnd: f64 = 10.0;
        let mut credit = 0.0;
        let mut sent_in_rtt = 0.0;
        let mut since_rtt = 0.0;
        let mut sojourns = Vec::new();
        let (mut busy, mut ticks) = (0u64, 0u64);
        let mut last_signal = 0u64;
        let total_ms = 20_000u64;
        for t in 0..total_ms * 10 {
            let now = t * MS / 10; // 0.1 ms steps
            // Sender: cwnd packets per RTT.
            let send = cwnd / rtt_ms / 10.0;
            sent_in_rtt += send;
            while sent_in_rtt >= 1.0 {
                sent_in_rtt -= 1.0;
                let _ = q.enqueue(
                    Pkt {
                        len: 1500,
                        ect: ecn,
                        ce: false,
                    },
                    now,
                );
            }
            since_rtt += 0.1;
            if since_rtt >= rtt_ms {
                since_rtt = 0.0;
                cwnd += 1.0;
            }
            // Link.
            credit += link_pps_per_ms / 10.0;
            let before = q.stats();
            while credit >= 1.0 {
                match q.dequeue(now) {
                    Dequeue::Packet(p) => {
                        credit -= 1.0;
                        if t > total_ms * 5 {
                            busy += 1;
                            sojourns.push(sojourn_of(q));
                        }
                        if p.ce && now - last_signal > (rtt_ms as u64) * MS {
                            cwnd = (cwnd / 2.0).max(2.0);
                            last_signal = now;
                        }
                    }
                    _ => {
                        credit = 0.0;
                        break;
                    }
                }
            }
            let after = q.stats();
            if after.dropped > before.dropped && now - last_signal > (rtt_ms as u64) * MS {
                cwnd = (cwnd / 2.0).max(2.0);
                last_signal = now;
            }
            if t > total_ms * 5 {
                ticks += 1;
            }
        }
        sojourns.sort_unstable();
        let med = sojourns[sojourns.len() / 2];
        let p99 = sojourns[sojourns.len() * 99 / 100];
        (
            med,
            p99,
            busy as f64 / (ticks as f64 * link_pps_per_ms / 10.0),
        )
    }

    /// Single Reno-like flow, RTT 20 ms, BDP 80 packets. CoDel holds the
    /// queue near target (5 ms ≈ 20 packets ≈ 0.25 BDP), so the window
    /// oscillates between 1.25 and 0.625 BDP and theory gives ~0.89 link
    /// utilisation for one flow (more flows fill the gaps). FIFO buys 100 %
    /// with hundreds of ms of queue; CoDel trades ~10 % of single-flow
    /// throughput for ~20× less delay.
    #[test]
    fn codel_keeps_a_responsive_flow_near_target() {
        let mut q = Codel::new(Params {
            ecn: false,
            ..Params::default()
        });
        let (med, p99, util) = simulate(&mut q, false, |q| q.last_sojourn_ns());
        std::eprintln!(
            "codel drop: median {:.1} ms, p99 {:.1} ms, util {util:.3}, signals {}",
            med as f64 / 1e6,
            p99 as f64 / 1e6,
            q.stats().aqm_actions
        );
        assert!(med < 10 * MS, "median sojourn {} ms", med / MS);
        assert!(p99 < 40 * MS, "p99 sojourn {} ms", p99 / MS);
        assert!(util > 0.80, "utilisation {util:.2} (theory ~0.89)");
        assert!(q.stats().aqm_actions > 0);
    }

    #[test]
    fn fifo_lets_the_same_flow_build_a_standing_queue() {
        // Same flow, deep FIFO: the queue grows to hundreds of ms (bufferbloat).
        struct Timed {
            q: BFifo<(Pkt, u64)>,
            last: u64,
        }
        impl Qdisc<Pkt> for Timed {
            fn enqueue(&mut self, p: Pkt, now: u64) -> Result<(), Pkt> {
                self.q.enqueue((p, now), now).map_err(|(p, _)| p)
            }
            fn dequeue(&mut self, now: u64) -> Dequeue<Pkt> {
                match self.q.dequeue(now) {
                    Dequeue::Packet((p, ts)) => {
                        self.last = now - ts;
                        Dequeue::Packet(p)
                    }
                    Dequeue::Empty => Dequeue::Empty,
                    Dequeue::WaitUntil(t) => Dequeue::WaitUntil(t),
                }
            }
            fn has_room(&self) -> bool {
                self.q.has_room()
            }
            fn stats(&self) -> Stats {
                self.q.stats()
            }
        }
        let mut fifo = Timed {
            q: BFifo::new(1000, 1500 * 1000),
            last: 0,
        };
        let (med, _, _) = simulate(&mut fifo, false, |q| q.last);
        let mut codel = Codel::new(Params {
            ecn: false,
            ..Params::default()
        });
        let (cmed, _, _) = simulate(&mut codel, false, |q| q.last_sojourn_ns());
        std::eprintln!(
            "fifo: median {:.1} ms vs codel {:.1} ms",
            med as f64 / 1e6,
            cmed as f64 / 1e6
        );
        assert!(
            med > 10 * cmed && med > 50 * MS,
            "fifo median {} ms vs codel {} ms",
            med / MS,
            cmed / MS
        );
    }

    #[test]
    fn ecn_marks_instead_of_dropping() {
        let mut q = Codel::new(Params::default());
        let (med, _, util) = simulate(&mut q, true, |q| q.last_sojourn_ns());
        let s = q.stats();
        std::eprintln!(
            "codel ecn: median {:.1} ms, util {util:.3}, marked {}",
            med as f64 / 1e6,
            s.marked
        );
        assert!(s.marked > 0, "should mark");
        assert_eq!(s.dropped, 0, "ECN-capable traffic is marked, not dropped");
        assert!(
            med < 10 * MS && util > 0.80,
            "median {} ms util {util:.2}",
            med / MS
        );
    }

    #[test]
    fn overflow_is_tail_dropped_and_bounded() {
        let mut q = Codel::new(Params {
            max_packets: 10,
            ..Params::default()
        });
        for _ in 0..10 {
            q.enqueue(pkt(), 0).unwrap();
        }
        assert!(!q.has_room());
        assert!(q.enqueue(pkt(), 0).is_err());
        assert_eq!((q.stats().dropped, q.stats().aqm_actions), (1, 0));
    }
}
