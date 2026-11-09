//! smoltcp `Device` for one port, sitting **behind the datapath**:
//!
//! - RX: frames the forwarder classified as `Local` (addressed to the
//!   router), from the port's small bounded `local_rx` queue.
//! - TX: frames from the router's own stack go into the port's **qdisc**,
//!   the same queue as forwarded traffic, so CAKE sees all egress traffic.
//!   smoltcp only gets a TX token while the qdisc has room.

use crate::config::{AqmKind, Qos};
use crate::net::packet::PacketBuf;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use qdisc::Qdisc;
use qdisc::cake::{Cake, CakeParams};
use qdisc::fq_codel::{FqCodel, FqParams};
use qdisc::shaper::Shaper;
use qdisc::{Dequeue, Stats};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// Frames smoltcp produced that could not be queued (pool empty or qdisc full).
static TX_DROPS: AtomicU64 = AtomicU64::new(0);

pub fn tx_drops() -> u64 {
    TX_DROPS.load(Ordering::Relaxed)
}

/// Egress on every port: optional rate shaper around the AQM.
pub type PortQdisc = Shaper<Aqm>;

/// The egress AQM, chosen by boot argument (`qdisc=`) for A/B tests.
pub enum Aqm {
    Cake(Cake<PacketBuf>),
    /// FQ-CoDel; with one flow queue it is plain CoDel.
    FqCodel(FqCodel<PacketBuf>),
}

impl Aqm {
    pub fn new(qos: &Qos, ecn: bool, max_packets: usize, limit_bytes: usize, seed: u64) -> Self {
        let codel = qdisc::codel::Params {
            max_packets,
            limit_bytes,
            ecn,
            ..Default::default()
        };
        match qos.aqm {
            AqmKind::Cake => Self::Cake(Cake::new(CakeParams {
                codel,
                isolation: qos.isolation,
                seed,
                ..Default::default()
            })),
            AqmKind::FqCodel | AqmKind::Codel => Self::FqCodel(FqCodel::new(FqParams {
                codel,
                flows: if qos.aqm == AqmKind::Codel { 1 } else { 1024 },
                ..Default::default()
            })),
        }
    }

    /// For the boot log, e.g. "CAKE (Triple, 1024 flows, 8-way, COBALT) + ECN".
    pub fn describe(&self, ecn: bool) -> String {
        let kind = match self {
            Self::Cake(c) => {
                let p = c.params();
                format!(
                    "CAKE ({:?}, {} flows, {}-way, COBALT)",
                    p.isolation, p.flows, p.ways
                )
            }
            Self::FqCodel(f) if f.flows() == 1 => String::from("CoDel (single queue)"),
            Self::FqCodel(f) => format!("FQ-CoDel ({} flows)", f.flows()),
        };
        format!("{kind}{}", if ecn { " + ECN" } else { " (drop only)" })
    }

    pub fn take_max_sojourn_ns(&mut self) -> u64 {
        match self {
            Self::Cake(c) => c.take_max_sojourn_ns(),
            Self::FqCodel(f) => f.take_max_sojourn_ns(),
        }
    }

    /// AQM-specific part of the periodic stats line.
    pub fn diag(&self) -> String {
        match self {
            Self::Cake(c) => {
                let (n, o) = c.active_flows();
                let (sh, dh) = c.active_hosts();
                format!(
                    "flows {n} new + {o} old (activations {}, collisions {}), hosts {sh} src / {dh} dst, blue drops {}, ",
                    c.new_flow_count, c.way_collisions, c.blue_drops
                )
            }
            Self::FqCodel(f) => {
                let (n, o) = f.active_flows();
                format!(
                    "flows {n} new + {o} old (activations {}), ",
                    f.new_flow_count
                )
            }
        }
    }
}

impl Qdisc<PacketBuf> for Aqm {
    fn enqueue(&mut self, p: PacketBuf, now_ns: u64) -> Result<(), PacketBuf> {
        match self {
            Self::Cake(c) => c.enqueue(p, now_ns),
            Self::FqCodel(f) => f.enqueue(p, now_ns),
        }
    }
    fn dequeue(&mut self, now_ns: u64) -> Dequeue<PacketBuf> {
        match self {
            Self::Cake(c) => c.dequeue(now_ns),
            Self::FqCodel(f) => f.dequeue(now_ns),
        }
    }
    fn has_room(&self) -> bool {
        match self {
            Self::Cake(c) => c.has_room(),
            Self::FqCodel(f) => f.has_room(),
        }
    }
    fn stats(&self) -> Stats {
        match self {
            Self::Cake(c) => c.stats(),
            Self::FqCodel(f) => f.stats(),
        }
    }
}

pub struct PortDevice<'a> {
    pub local_rx: &'a mut VecDeque<PacketBuf>,
    pub qdisc: &'a mut PortQdisc,
    pub now_ns: u64,
}

pub struct RxToken(PacketBuf);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0.data())
    }
}

pub struct TxToken<'a> {
    qdisc: &'a mut PortQdisc,
    now_ns: u64,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        match PacketBuf::alloc() {
            Some(mut pkt) => {
                pkt.set_len(len);
                let r = f(pkt.data_mut());
                pkt.meta.wire_len = len as u32;
                pkt.meta.enqueue_ts = self.now_ns;
                if self.qdisc.enqueue(pkt, self.now_ns).is_err() {
                    TX_DROPS.fetch_add(1, Ordering::Relaxed);
                }
                r
            }
            None => {
                // No buffer: let smoltcp build the frame into scratch, then drop it.
                TX_DROPS.fetch_add(1, Ordering::Relaxed);
                let mut scratch = [0u8; 1514];
                f(&mut scratch[..len.min(1514)])
            }
        }
    }
}

impl Device for PortDevice<'_> {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _ts: Instant) -> Option<(RxToken, TxToken<'_>)> {
        let pkt = self.local_rx.pop_front()?;
        Some((
            RxToken(pkt),
            TxToken {
                qdisc: self.qdisc,
                now_ns: self.now_ns,
            },
        ))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<TxToken<'_>> {
        let now_ns = self.now_ns;
        self.qdisc.has_room().then_some(TxToken {
            qdisc: self.qdisc,
            now_ns,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(1);
        caps
    }
}
