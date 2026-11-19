//! Shared test harness: a test packet that records its own drops, and a
//! fluid-flow simulation (Reno-like, fixed-rate and sparse sources over a
//! shaped link) used to compare qdiscs.

extern crate std;
use crate::codel::Params;
use crate::{Dequeue, Packet, Qdisc};
use alloc::vec::Vec;
use core::cell::RefCell;
use std::vec;

pub const MS: u64 = 1_000_000;

std::thread_local! {
    /// Packets dropped inside the qdisc, per flow (set by `Pkt::drop`).
    static DROPS: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

/// Forget the drops counted so far (a new simulation run).
pub fn reset_drops() {
    DROPS.with(|d| d.borrow_mut().clear());
}

pub fn drops(flow: usize) -> u64 {
    DROPS.with(|d| d.borrow().get(flow).copied().unwrap_or(0))
}

#[derive(Debug)]
pub struct Pkt {
    pub len: usize,
    pub flow: u32,
    pub seq: u64,
    pub sent: u64,
    pub ect: bool,
    pub ce: bool,
    pub delivered: bool,
    /// Host ids for host isolation (CAKE).
    pub src_host: u32,
    pub dst_host: u32,
    /// IPv4 bytes if this is a pure TCP ACK (ACK filter tests).
    pub ack: Option<Vec<u8>>,
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
    fn host_hashes(&self) -> (u32, u32) {
        (
            self.src_host.wrapping_mul(0x85eb_ca6b),
            self.dst_host.wrapping_mul(0x85eb_ca6b),
        )
    }
    fn pure_ack(&self) -> Option<&[u8]> {
        self.ack.as_deref()
    }
}

pub fn pkt(flow: u32, len: usize, seq: u64) -> Pkt {
    Pkt {
        len,
        flow,
        seq,
        sent: 0,
        ect: false,
        ce: false,
        delivered: false,
        src_host: 0,
        dst_host: 0,
        ack: None,
    }
}

/// A pure ACK of connection `sport` acknowledging `ack`, in flow `flow`.
pub fn ack_pkt(flow: u32, sport: u16, ack: u32, seq: u64) -> Pkt {
    let bytes = crate::ack_filter::build_ack(sport, ack, 0x10, None, &[]);
    let mut p = pkt(flow, bytes.len() + 14, seq);
    p.ack = Some(bytes);
    p
}

pub fn take(q: &mut impl Qdisc<Pkt>, now: u64) -> Option<Pkt> {
    match q.dequeue(now) {
        Dequeue::Packet(mut p) => {
            p.delivered = true;
            Some(p)
        }
        _ => None,
    }
}

// ---- simulation ---------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum Sender {
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

pub struct Result {
    /// Sojourn of each sparse-flow packet (ns, sorted).
    pub sparse_sojourn: Vec<u64>,
    /// Sojourn of every delivered packet per flow (ns, sorted).
    pub sojourn: Vec<Vec<u64>>,
    /// Delivered bytes per flow in the measured half.
    pub delivered: Vec<u64>,
    pub utilisation: f64,
}

/// 20 s at 0.1 ms steps over a 4 packets/ms link (≈ 48 Mbit/s at 1500 B);
/// the second half is measured. Flow `i` is `sources[i]`.
pub fn simulate(q: &mut impl Qdisc<Pkt>, sources: &mut [Sender], ecn: bool) -> Result {
    let hosts: Vec<u32> = (0..sources.len() as u32).collect();
    simulate_hosts(q, sources, &hosts, ecn)
}

/// [`simulate`] with flow `i` sent by LAN host `hosts[i]` (as `src_host`)
/// to its own remote host.
pub fn simulate_hosts(
    q: &mut impl Qdisc<Pkt>,
    sources: &mut [Sender],
    hosts: &[u32],
    ecn: bool,
) -> Result {
    DROPS.with(|d| d.borrow_mut().clear());
    let link = 4.0;
    let total = 200_000u64;
    let mut acc = vec![0.0f64; sources.len()];
    let mut seen_drops = vec![0u64; sources.len()];
    let mut res = Result {
        sparse_sojourn: Vec::new(),
        sojourn: vec![Vec::new(); sources.len()],
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
                Sender::Reno { rtt_ms, cwnd, .. } => {
                    *cwnd += 0.1 / *rtt_ms; // +1 per RTT
                    (*cwnd / *rtt_ms, 1500)
                }
                Sender::Fixed { pkts_per_ms } => (*pkts_per_ms, 1500),
                Sender::Sparse { every_ms } => (1.0 / *every_ms, 100),
            };
            acc[f] += rate / 10.0;
            while acc[f] >= 1.0 {
                acc[f] -= 1.0;
                seq += 1;
                // (Not `..pkt()`: dropping that temporary would count as a drop.)
                let mut p = pkt(f as u32, len, seq);
                p.sent = now;
                p.ect = ecn;
                p.src_host = hosts[f];
                p.dst_host = 1000 + f as u32; // each flow has its own remote server
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
                res.sojourn[f].push(now - p.sent);
                if matches!(sources[f], Sender::Sparse { .. }) {
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
    for s in &mut res.sojourn {
        s.sort_unstable();
    }
    res.utilisation = busy as f64 / slots;
    res
}

pub fn signal(s: &mut Sender, now: u64) {
    if let Sender::Reno {
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

pub fn pct(v: &[u64], p: usize) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v[(v.len() - 1) * p / 100]
}

pub fn params(ecn: bool) -> Params {
    Params {
        max_packets: 384,
        limit_bytes: 384 * 1514,
        ecn,
        ..Params::default()
    }
}
