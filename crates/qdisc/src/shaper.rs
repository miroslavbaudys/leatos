//! Rate shaper: wraps any qdisc and releases packets no faster than a
//! configured rate, so the router becomes the bottleneck and the queue (and
//! the AQM managing it) lives here instead of in a dumb upstream buffer
//! (docs/bufferbloat-cake.md §1, §6b).
//!
//! Like CAKE's shaper it is rate-based, not a token bucket: each released
//! packet advances `next_tx` by its transmission time at the shaped rate
//! (wire length plus per-packet `overhead`). Two details keep it accurate
//! and cheap:
//! - **Release window** (`burst_ns`): a packet may leave up to `burst_ns`
//!   before `next_tx`, so the datapath wakes about once per window instead of
//!   once per packet (at 42 Mbit/s a 1514 B frame takes 288 µs). The
//!   long-run rate is unaffected because `next_tx` still accumulates.
//! - **No credit after idle**: if `next_tx` fell more than `burst_ns` behind
//!   `now` (the link was idle or the wake-up was late), it restarts from
//!   `now`, so an idle period never turns into a line-rate burst.
//!
//! The inner qdisc sees the shaper's waiting time as sojourn, so CoDel
//! reacts to queues the shaper creates.

use crate::{Dequeue, Packet, Qdisc, Stats};

#[derive(Clone, Copy, Debug)]
pub struct Rate {
    /// Shaped rate in bits per second.
    pub bits_per_sec: u64,
    /// Bytes added to every packet's length for shaping (link-layer framing
    /// the router doesn't see: Ethernet preamble+IFG+FCS, PPPoE, VLAN, ...).
    pub overhead: u32,
    /// Release window, see the module docs.
    pub burst_ns: u64,
}

impl Rate {
    pub fn kbit(kbit_per_sec: u64) -> Self {
        Self {
            bits_per_sec: kbit_per_sec * 1000,
            overhead: 0,
            burst_ns: 1_000_000,
        }
    }

    /// Nanoseconds to send `len` bytes (+ overhead) at this rate.
    pub fn tx_time_ns(&self, len: usize) -> u64 {
        let bits = (len as u64 + self.overhead as u64) * 8;
        (bits as u128 * 1_000_000_000).div_ceil(self.bits_per_sec.max(1) as u128) as u64
    }
}

pub struct Shaper<Q> {
    inner: Q,
    rate: Option<Rate>,
    next_tx: u64,
    /// Times the shaper held back a waiting packet (diagnostics).
    pub throttled: u64,
}

impl<Q> Shaper<Q> {
    /// `rate: None` = pass-through (no shaping).
    pub fn new(inner: Q, rate: Option<Rate>) -> Self {
        Self {
            inner,
            rate,
            next_tx: 0,
            throttled: 0,
        }
    }

    pub fn inner_mut(&mut self) -> &mut Q {
        &mut self.inner
    }

    pub fn rate(&self) -> Option<Rate> {
        self.rate
    }

    pub fn set_rate(&mut self, rate: Option<Rate>) {
        self.rate = rate;
    }
}

impl<P: Packet, Q: Qdisc<P>> Qdisc<P> for Shaper<Q> {
    fn enqueue(&mut self, p: P, now_ns: u64) -> Result<(), P> {
        self.inner.enqueue(p, now_ns)
    }

    fn dequeue(&mut self, now: u64) -> Dequeue<P> {
        let Some(rate) = self.rate else {
            return self.inner.dequeue(now);
        };
        if self.next_tx > now + rate.burst_ns {
            if self.inner.stats().backlog_packets == 0 {
                return Dequeue::Empty;
            }
            self.throttled += 1;
            return Dequeue::WaitUntil(self.next_tx - rate.burst_ns);
        }
        match self.inner.dequeue(now) {
            Dequeue::Packet(p) => {
                // No credit for idle time or late wake-ups beyond the window.
                let base = if self.next_tx + rate.burst_ns < now {
                    now
                } else {
                    self.next_tx
                };
                self.next_tx = base + rate.tx_time_ns(p.len_bytes());
                Dequeue::Packet(p)
            }
            other => other,
        }
    }

    fn has_room(&self) -> bool {
        self.inner.has_room()
    }

    fn stats(&self) -> Stats {
        self.inner.stats()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::codel::{Codel, Params};
    use crate::fifo::BFifo;

    const MS: u64 = 1_000_000;

    #[derive(Debug)]
    struct P(usize);
    impl Packet for P {
        fn len_bytes(&self) -> usize {
            self.0
        }
    }

    /// Drive a shaped qdisc like the datapath does: dequeue until it says
    /// Empty/WaitUntil, then jump to the wake-up time (plus `lateness`).
    /// Returns (bytes released, time of last release).
    fn drain<Q: Qdisc<P>>(q: &mut Q, until: u64, lateness: u64) -> (u64, u64, u64) {
        let (mut now, mut bytes, mut last, mut max_burst) = (0u64, 0u64, 0u64, 0u64);
        while now < until {
            let mut burst = 0;
            loop {
                match q.dequeue(now) {
                    Dequeue::Packet(p) => {
                        bytes += p.0 as u64;
                        burst += p.0 as u64;
                        last = now;
                    }
                    Dequeue::WaitUntil(t) => {
                        now = t.max(now + 1) + lateness;
                        break;
                    }
                    Dequeue::Empty => return (bytes, last, max_burst.max(burst)),
                }
            }
            max_burst = max_burst.max(burst);
        }
        (bytes, last, max_burst)
    }

    #[test]
    fn tx_time() {
        let r = Rate {
            bits_per_sec: 10_000_000,
            overhead: 38,
            burst_ns: 0,
        };
        assert_eq!(r.tx_time_ns(1500), (1538 * 8 * 100) as u64); // 1538 B at 10 Mbit/s
    }

    #[test]
    fn achieves_the_configured_rate() {
        for kbit in [1_000u64, 10_000, 42_000, 100_000] {
            let mut q = Shaper::new(BFifo::new(100_000, usize::MAX), Some(Rate::kbit(kbit)));
            for _ in 0..20_000 {
                q.enqueue(P(1500), 0).unwrap();
            }
            let secs = 2;
            let (bytes, _, _) = drain(&mut q, secs * 1_000 * MS, 0);
            let mbit = bytes as f64 * 8.0 / secs as f64 / 1e3;
            let err = (mbit - kbit as f64).abs() / kbit as f64;
            assert!(err < 0.01, "{kbit} kbit/s: got {mbit:.0} kbit/s");
        }
    }

    #[test]
    fn late_wakeups_do_not_reduce_the_rate_within_the_window() {
        // Waking 300 µs late every time (< 1 ms window): rate still met.
        let mut q = Shaper::new(BFifo::new(100_000, usize::MAX), Some(Rate::kbit(42_000)));
        for _ in 0..20_000 {
            q.enqueue(P(1500), 0).unwrap();
        }
        let (bytes, _, _) = drain(&mut q, 1_000 * MS, 300_000);
        let kbit = bytes as f64 * 8.0 / 1e3;
        assert!(
            (kbit - 42_000.0).abs() / 42_000.0 < 0.02,
            "{kbit:.0} kbit/s"
        );
    }

    #[test]
    fn bursts_are_bounded_by_the_window_and_idle_earns_no_credit() {
        let rate = Rate::kbit(42_000);
        let mut q = Shaper::new(BFifo::new(100_000, usize::MAX), Some(rate));
        // Send one packet, stay idle for 1 s, then queue a large backlog.
        q.enqueue(P(1500), 0).unwrap();
        assert!(matches!(q.dequeue(0), Dequeue::Packet(_)));
        let t = 1_000 * MS;
        for _ in 0..1000 {
            q.enqueue(P(1500), t).unwrap();
        }
        let mut burst = 0;
        while let Dequeue::Packet(_) = q.dequeue(t) {
            burst += 1500;
        }
        // At most one window (1 ms ≈ 5.25 kB at 42 Mbit/s) + one packet at once.
        let window_bytes = rate.bits_per_sec / 8 / 1000;
        assert!(
            burst as u64 <= window_bytes + 1500,
            "burst {burst} B after idle"
        );
    }

    #[test]
    fn pass_through_without_rate() {
        let mut q = Shaper::new(BFifo::new(10, usize::MAX), None);
        for _ in 0..10 {
            q.enqueue(P(1500), 0).unwrap();
        }
        let mut n = 0;
        while let Dequeue::Packet(_) = q.dequeue(0) {
            n += 1;
        }
        assert_eq!(n, 10);
    }

    #[test]
    fn empty_queue_reports_empty_not_wait() {
        let mut q = Shaper::new(BFifo::new(10, usize::MAX), Some(Rate::kbit(1_000)));
        q.enqueue(P(1500), 0).unwrap();
        assert!(matches!(q.dequeue(0), Dequeue::Packet(_)));
        assert!(
            matches!(q.dequeue(0), Dequeue::Empty),
            "nothing queued: don't schedule a wake-up"
        );
    }

    /// The point of the shaper: a TCP-like flow whose real bottleneck is a
    /// deep, dumb downstream buffer (the "Wi-Fi"). Unshaped, the queue builds
    /// downstream; shaped at 90 % of the bottleneck with CoDel, it stays in
    /// our qdisc and short.
    #[test]
    fn shaping_moves_the_queue_from_a_dumb_downstream_buffer_into_codel() {
        fn run(shape: bool) -> (f64, f64) {
            let bottleneck_pkts_per_ms = 4.0; // ≈ 48 Mbit/s downstream link
            let rtt_ms = 20.0;
            let mut ours = Shaper::new(
                Codel::<P>::new(Params {
                    ecn: false,
                    ..Params::default()
                }),
                shape.then(|| Rate::kbit(43_000)),
            );
            let mut downstream: alloc::collections::VecDeque<u64> =
                alloc::collections::VecDeque::new(); // enqueue times
            let down_cap = 2000; // deep dumb buffer
            let (mut cwnd, mut acc, mut since_rtt, mut credit) = (10.0f64, 0.0f64, 0.0f64, 0.0f64);
            let mut last_signal = 0u64;
            let mut delays = alloc::vec::Vec::new();
            let mut delivered = 0u64;
            let total = 20_000u64;
            for step in 0..total * 10 {
                let now = step * MS / 10;
                acc += cwnd / rtt_ms / 10.0;
                while acc >= 1.0 {
                    acc -= 1.0;
                    let _ = ours.enqueue(P(1500), now);
                }
                since_rtt += 0.1;
                if since_rtt >= rtt_ms {
                    since_rtt = 0.0;
                    cwnd += 1.0;
                }
                let drops_before = ours.stats().dropped;
                // Our egress: hand packets to the downstream buffer as the shaper allows.
                while let Dequeue::Packet(_) = ours.dequeue(now) {
                    if downstream.len() < down_cap {
                        downstream.push_back(now);
                    }
                }
                let mut dropped = ours.stats().dropped > drops_before;
                if downstream.len() >= down_cap {
                    dropped = true;
                }
                // Downstream bottleneck.
                credit += bottleneck_pkts_per_ms / 10.0;
                while credit >= 1.0 {
                    let Some(t0) = downstream.pop_front() else {
                        credit = 0.0;
                        break;
                    };
                    credit -= 1.0;
                    if step > total * 5 {
                        delays.push(now - t0);
                        delivered += 1;
                    }
                }
                if dropped && now - last_signal > rtt_ms as u64 * MS {
                    cwnd = (cwnd / 2.0).max(2.0);
                    last_signal = now;
                }
            }
            delays.sort_unstable();
            let med_down_ms = delays[delays.len() / 2] as f64 / 1e6;
            // Measured over the second half: total/2 ms at the bottleneck rate.
            let util = delivered as f64 / (total as f64 / 2.0 * bottleneck_pkts_per_ms);
            (med_down_ms, util)
        }
        let (unshaped_delay, unshaped_util) = run(false);
        let (shaped_delay, shaped_util) = run(true);
        std::eprintln!(
            "downstream queue delay: unshaped {unshaped_delay:.1} ms (util {unshaped_util:.2}), shaped {shaped_delay:.2} ms (util {shaped_util:.2})"
        );
        assert!(
            unshaped_delay > 100.0,
            "unshaped: the dumb buffer should bloat ({unshaped_delay:.1} ms)"
        );
        assert!(
            unshaped_util > 0.95,
            "unshaped utilisation {unshaped_util:.2} (bloat keeps the link busy)"
        );
        assert!(
            shaped_delay < 1.0,
            "shaped: downstream buffer should stay ~empty ({shaped_delay:.2} ms)"
        );
        assert!(
            shaped_util > 0.75,
            "shaped utilisation {shaped_util:.2} (shaped at ~90 % of the bottleneck)"
        );
    }
}
