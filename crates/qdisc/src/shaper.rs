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
//!
//! **Ingress mode** ([`Shaper::ingress`], CAKE's `ingress` keyword): the
//! shaper sits *behind* the link it shapes (the download, between WAN RX
//! and forwarding), so every packet that arrived has already used that
//! link. Packets the inner qdisc drops (AQM at dequeue, overflow at
//! enqueue) are therefore still charged to the rate, and so is traffic
//! that bypasses the queue ([`Shaper::charge`]: frames for the router
//! itself, firewall drops). Without this, a flood of dropped packets would
//! let the rest through faster than the link and the queue would move back
//! upstream.

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
    /// Charge drops and bypassing traffic to the rate (module docs).
    ingress: bool,
    /// Times the shaper held back a waiting packet (diagnostics).
    pub throttled: u64,
    /// Ingress mode: bytes charged without being released (drops and
    /// traffic that bypassed the queue; diagnostics).
    pub charged_bytes: u64,
}

impl<Q> Shaper<Q> {
    /// `rate: None` = pass-through (no shaping).
    pub fn new(inner: Q, rate: Option<Rate>) -> Self {
        Self {
            inner,
            rate,
            next_tx: 0,
            ingress: false,
            throttled: 0,
            charged_bytes: 0,
        }
    }

    /// A shaper behind the link it shapes (module docs: ingress mode).
    pub fn ingress(inner: Q, rate: Option<Rate>) -> Self {
        Self {
            ingress: true,
            ..Self::new(inner, rate)
        }
    }

    pub fn is_ingress(&self) -> bool {
        self.ingress
    }

    /// Ingress mode: `packets` packets of `bytes` bytes in total crossed the
    /// shaped link but never entered the queue (or left it as drops). They
    /// push the next release back by their transmission time. A no-op
    /// without a rate or outside ingress mode.
    pub fn charge(&mut self, bytes: usize, packets: usize, now: u64) {
        if !self.ingress || packets == 0 {
            return;
        }
        let Some(rate) = self.rate else {
            return;
        };
        self.charged_bytes += bytes as u64;
        let bits = (bytes as u64 + packets as u64 * rate.overhead as u64) * 8;
        let t = (bits as u128 * 1_000_000_000).div_ceil(rate.bits_per_sec.max(1) as u128) as u64;
        self.next_tx = self.release_base(rate, now) + t;
    }

    /// Where the next transmission time starts from: `next_tx`, unless the
    /// link was idle beyond the window (no credit for idle time).
    fn release_base(&self, rate: Rate, now: u64) -> u64 {
        if self.next_tx + rate.burst_ns < now {
            now
        } else {
            self.next_tx
        }
    }

    pub fn inner(&self) -> &Q {
        &self.inner
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
        let r = self.inner.enqueue(p, now_ns);
        if let Err(dropped) = &r {
            // Ingress: the dropped packet (maybe an older one) used the link.
            self.charge(dropped.len_bytes(), 1, now_ns);
        }
        r
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
        // Ingress: what the AQM drops while dequeuing is charged too.
        let before = self.ingress.then(|| self.inner.stats());
        let d = self.inner.dequeue(now);
        if let Some(b) = before {
            let a = self.inner.stats();
            let released = match &d {
                Dequeue::Packet(p) => p.len_bytes(),
                _ => 0,
            };
            let gone = b.backlog_bytes.saturating_sub(a.backlog_bytes + released);
            let drops = a.dropped.saturating_sub(b.dropped) as usize;
            self.charge(gone, drops, now);
        }
        match d {
            Dequeue::Packet(p) => {
                // No credit for idle time or late wake-ups beyond the window.
                self.next_tx = self.release_base(rate, now) + rate.tx_time_ns(p.len_bytes());
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

    #[derive(Debug, PartialEq)]
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

    /// Drops every other packet when dequeuing (an AQM in a hurry).
    struct DropHalf {
        q: alloc::collections::VecDeque<P>,
        stats: Stats,
    }

    impl Qdisc<P> for DropHalf {
        fn enqueue(&mut self, p: P, _now: u64) -> Result<(), P> {
            if self.q.len() >= 4 {
                self.stats.dropped += 1;
                return Err(p);
            }
            self.stats.backlog_bytes += p.0;
            self.q.push_back(p);
            Ok(())
        }
        fn dequeue(&mut self, _now: u64) -> Dequeue<P> {
            loop {
                let Some(p) = self.q.pop_front() else {
                    return Dequeue::Empty;
                };
                self.stats.backlog_bytes -= p.0;
                self.stats.dequeued += 1;
                if self.stats.dequeued % 2 == 1 {
                    self.stats.dropped += 1;
                    continue;
                }
                return Dequeue::Packet(p);
            }
        }
        fn has_room(&self) -> bool {
            self.q.len() < 4
        }
        fn stats(&self) -> Stats {
            Stats {
                backlog_packets: self.q.len(),
                ..self.stats
            }
        }
    }

    fn drop_half() -> DropHalf {
        DropHalf {
            q: alloc::collections::VecDeque::new(),
            stats: Stats::default(),
        }
    }

    /// Release times of `n` packets fed one at a time as the shaper allows.
    fn release_span(mut q: Shaper<DropHalf>, n: usize) -> (u64, usize) {
        let (mut now, mut out, mut fed) = (0u64, 0usize, 0usize);
        let mut last = 0;
        while fed < n || q.stats().backlog_packets > 0 {
            while fed < n && q.has_room() {
                q.enqueue(P(1500), now).unwrap();
                fed += 1;
            }
            match q.dequeue(now) {
                Dequeue::Packet(_) => {
                    out += 1;
                    last = now;
                }
                Dequeue::WaitUntil(t) => now = t,
                Dequeue::Empty => now += 1,
            }
        }
        (last, out)
    }

    #[test]
    fn ingress_charges_aqm_drops_to_the_rate() {
        // 1000 packets in, the AQM drops half: egress releases the 500
        // survivors at the full rate, ingress takes as long as for 1000
        // (they all crossed the link already).
        let rate = Rate {
            burst_ns: 0,
            ..Rate::kbit(12_000)
        };
        let per_pkt = rate.tx_time_ns(1500); // 1 ms
        let (egress, out_e) = release_span(Shaper::new(drop_half(), Some(rate)), 1000);
        let (ingress, out_i) = release_span(Shaper::ingress(drop_half(), Some(rate)), 1000);
        assert_eq!((out_e, out_i), (500, 500));
        assert!(egress < 500 * per_pkt, "egress {egress} ns");
        assert!(ingress >= 998 * per_pkt, "ingress {ingress} ns for 1000 packets' worth");
    }

    #[test]
    fn ingress_charges_overflow_drops_and_bypassing_traffic() {
        let rate = Rate {
            burst_ns: 0,
            ..Rate::kbit(12_000)
        };
        let per_pkt = rate.tx_time_ns(1500);
        let mut q = Shaper::ingress(BFifo::new(1, usize::MAX), Some(rate));
        q.enqueue(P(1500), 0).unwrap();
        assert!(q.enqueue(P(1500), 0).is_err(), "full");
        // The overflow drop pushed the release back by one packet time.
        assert_eq!(q.dequeue(0), Dequeue::WaitUntil(per_pkt));
        assert!(matches!(q.dequeue(per_pkt), Dequeue::Packet(_)));
        // Frames that bypassed the queue (for the router) count as well.
        q.charge(3000, 2, 2 * per_pkt);
        q.enqueue(P(1500), 2 * per_pkt).unwrap();
        assert_eq!(q.dequeue(2 * per_pkt), Dequeue::WaitUntil(4 * per_pkt));
        assert_eq!(q.charged_bytes, 4500);
        // Egress mode ignores charges.
        let mut e = Shaper::new(BFifo::new(1, usize::MAX), Some(rate));
        e.charge(3000, 2, 0);
        e.enqueue(P(1500), 0).unwrap();
        assert!(matches!(e.dequeue(0), Dequeue::Packet(_)));
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
