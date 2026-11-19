//! The qdiscs (`crates/qdisc`): CAKE (shaped, every isolation mode),
//! FQ-CoDel and CoDel under any sequence of enqueues (sizes, flows, hosts,
//! ECN), dequeues and time steps, including time going nowhere for long.
//! Checks: backlog within the limits; packet conservation (every packet
//! enqueued is dequeued, returned as dropped, or counted dropped inside);
//! no packet comes out twice; the queue drains to empty. Some packets are
//! TCP ACKs (well-formed from a few connections, or arbitrary bytes) for
//! CAKE's ACK filter.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use qdisc::cake::{Cake, CakeParams, Isolation};
use qdisc::codel::{Codel, Params};
use qdisc::fq_codel::{FqCodel, FqParams};
use qdisc::shaper::{Rate, Shaper};
use qdisc::{Dequeue, Packet, Qdisc};

#[derive(Debug)]
struct P {
    id: u32,
    len: usize,
    ect: bool,
    flow: u32,
    hosts: (u32, u32),
    ack: Option<Vec<u8>>,
}

impl Packet for P {
    fn len_bytes(&self) -> usize {
        self.len
    }
    fn mark_ce(&mut self) -> bool {
        self.ect
    }
    fn flow_hash(&self) -> u32 {
        self.flow
    }
    fn host_hashes(&self) -> (u32, u32) {
        self.hosts
    }
    fn pure_ack(&self) -> Option<&[u8]> {
        self.ack.as_deref()
    }
}

#[derive(Arbitrary, Debug)]
enum Op {
    Enq { len: u16, ect: bool, flow: u8, src: u8, dst: u8 },
    /// A pure ACK of connection `conn % 4` (one flow), ACK number moved by
    /// `step` (may go back), optional timestamp and SACK block.
    Ack { conn: u8, step: i16, ts: Option<u8>, sack: Option<(u8, u8)> },
    /// Arbitrary bytes presented as a pure ACK.
    RawAck { flow: u8, bytes: Vec<u8> },
    Deq,
    Tick(u32),
}

#[derive(Arbitrary, Debug)]
struct Input {
    kind: u8,
    isolation: u8,
    rate_kbit: Option<u16>,
    small_limits: bool,
    ack_filter: bool,
    ops: Vec<Op>,
}

fn run<Q: Qdisc<P>>(mut q: Q, ops: Vec<Op>, max_packets: usize, limit_bytes: usize) {
    let mut now = 0u64;
    let mut next_id = 0u32;
    let (mut enq, mut out, mut returned) = (0u64, 0u64, 0u64);
    let mut seen = std::collections::HashSet::new();
    let mut acks = [0u32; 4];
    let take = |p: P, seen: &mut std::collections::HashSet<u32>| {
        assert!(seen.insert(p.id), "packet {} out twice", p.id);
    };
    for op in ops.into_iter().take(2000) {
        match op {
            Op::Enq { len, ect, flow, src, dst } => {
                let p = P { id: next_id, len: 60 + usize::from(len) % 1455, ect, flow: u32::from(flow), hosts: (u32::from(src % 8), u32::from(dst % 8)), ack: None };
                next_id += 1;
                enq += 1;
                if let Err(p) = q.enqueue(p, now) {
                    returned += 1;
                    take(p, &mut seen);
                }
            }
            Op::Ack { conn, step, ts, sack } => {
                let c = usize::from(conn % 4);
                acks[c] = acks[c].wrapping_add(step as i32 as u32);
                let a = acks[c];
                let sacks: Vec<(u32, u32)> = sack.map(|(l, n)| (a.wrapping_add(u32::from(l) * 100), a.wrapping_add(u32::from(l) * 100 + u32::from(n) * 100))).into_iter().collect();
                let bytes = qdisc::ack_filter::build_ack(5000 + c as u16, a, 0x10, ts.map(|t| (u32::from(t), 1)), &sacks);
                let p = P { id: next_id, len: bytes.len() + 14, ect: false, flow: 200 + c as u32, hosts: (1, 2), ack: Some(bytes) };
                next_id += 1;
                enq += 1;
                if let Err(p) = q.enqueue(p, now) {
                    returned += 1;
                    take(p, &mut seen);
                }
            }
            Op::RawAck { flow, bytes } => {
                let p = P { id: next_id, len: 60 + bytes.len().min(1400), ect: false, flow: u32::from(flow % 4), hosts: (1, 2), ack: Some(bytes) };
                next_id += 1;
                enq += 1;
                if let Err(p) = q.enqueue(p, now) {
                    returned += 1;
                    take(p, &mut seen);
                }
            }
            Op::Deq => {
                if let Dequeue::Packet(p) = q.dequeue(now) {
                    out += 1;
                    take(p, &mut seen);
                }
            }
            Op::Tick(ns) => now += u64::from(ns) * 16,
        }
        let s = q.stats();
        assert!(s.backlog_packets <= max_packets, "{} packets queued, limit {max_packets}", s.backlog_packets);
        assert!(s.backlog_bytes <= limit_bytes + 1514, "{} bytes queued, limit {limit_bytes}", s.backlog_bytes);
        let inside = s.dropped.saturating_sub(returned);
        assert_eq!(enq, out + returned + inside + s.backlog_packets as u64, "packets lost: {s:?}, enq {enq} out {out} returned {returned}");
    }
    // Drain: time moves to whatever the shaper asks for.
    for _ in 0..100_000 {
        match q.dequeue(now) {
            Dequeue::Packet(p) => {
                out += 1;
                take(p, &mut seen);
            }
            Dequeue::WaitUntil(t) => {
                assert!(t > now, "wait until {t} at {now}");
                now = t;
            }
            Dequeue::Empty => break,
        }
    }
    let s = q.stats();
    assert_eq!((s.backlog_packets, s.backlog_bytes), (0, 0), "not drained: {s:?}");
    let inside = s.dropped.saturating_sub(returned);
    assert_eq!(enq, out + returned + inside, "packets lost at the end: {s:?}");
}

fuzz_target!(|i: Input| {
    let codel = Params { max_packets: if i.small_limits { 16 } else { 1000 }, limit_bytes: if i.small_limits { 8000 } else { 1 << 20 }, ecn: true, ..Params::default() };
    let (mp, lb) = (codel.max_packets, codel.limit_bytes);
    let rate = i.rate_kbit.map(|k| Rate::kbit(u64::from(k) * 100 + 64));
    match i.kind % 4 {
        0 | 1 => {
            let isolation = [Isolation::Flows, Isolation::DualSrcHost, Isolation::DualDstHost, Isolation::Triple][i.isolation as usize % 4];
            let p = CakeParams { codel, isolation, flows: 64, hosts: 16, ways: 8, ack_filter: i.ack_filter, ..CakeParams::default() };
            let q = Cake::new(p);
            if i.kind % 4 == 0 {
                run(Shaper::new(q, rate), i.ops, mp, lb)
            } else {
                run(Shaper::ingress(q, rate), i.ops, mp, lb)
            }
        }
        2 => run(Shaper::new(FqCodel::new(FqParams { codel, ..FqParams::default() }), rate), i.ops, mp, lb),
        _ => run(Codel::new(codel), i.ops, mp, lb),
    }
});
