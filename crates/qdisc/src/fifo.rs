//! Bounded tail-drop FIFO with byte and packet limits ("bfifo").
//!
//! The placeholder until CAKE (M6): it bounds the queue but does no AQM.
//! Storage is preallocated, so enqueue never allocates.

use crate::{Dequeue, Packet, Qdisc, Stats};
use alloc::collections::VecDeque;

pub struct BFifo<P> {
    q: VecDeque<P>,
    max_packets: usize,
    limit_bytes: usize,
    bytes: usize,
    stats: Stats,
}

impl<P: Packet> BFifo<P> {
    pub fn new(max_packets: usize, limit_bytes: usize) -> Self {
        Self {
            q: VecDeque::with_capacity(max_packets),
            max_packets,
            limit_bytes,
            bytes: 0,
            stats: Stats::default(),
        }
    }
}

impl<P: Packet> Qdisc<P> for BFifo<P> {
    fn enqueue(&mut self, p: P, _now_ns: u64) -> Result<(), P> {
        let n = p.len_bytes();
        if self.q.len() >= self.max_packets || self.bytes + n > self.limit_bytes {
            self.stats.dropped += 1;
            return Err(p);
        }
        self.bytes += n;
        self.q.push_back(p);
        self.stats.enqueued += 1;
        Ok(())
    }

    fn dequeue(&mut self, _now_ns: u64) -> Dequeue<P> {
        match self.q.pop_front() {
            Some(p) => {
                self.bytes -= p.len_bytes();
                self.stats.dequeued += 1;
                Dequeue::Packet(p)
            }
            None => Dequeue::Empty,
        }
    }

    fn has_room(&self) -> bool {
        self.q.len() < self.max_packets && self.bytes + 1514 <= self.limit_bytes
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
    use super::*;

    struct P(usize);
    impl Packet for P {
        fn len_bytes(&self) -> usize {
            self.0
        }
    }

    #[test]
    fn fifo_order_and_limits() {
        let mut q = BFifo::new(3, 2500);
        assert!(q.enqueue(P(1000), 0).is_ok());
        assert!(q.enqueue(P(1000), 0).is_ok());
        assert!(q.enqueue(P(1000), 0).is_err(), "byte limit");
        assert!(q.enqueue(P(100), 0).is_ok());
        assert!(q.enqueue(P(1), 0).is_err(), "packet limit");
        assert!(matches!(q.dequeue(0), Dequeue::Packet(P(1000))));
        let s = q.stats();
        assert_eq!(
            (s.backlog_packets, s.backlog_bytes, s.dropped),
            (2, 1100, 2)
        );
        q.dequeue(0);
        q.dequeue(0);
        assert!(matches!(q.dequeue(0), Dequeue::Empty));
    }
}
