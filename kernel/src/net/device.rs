//! smoltcp `Device` for one port, sitting **behind the datapath**:
//!
//! - RX: frames the forwarder classified as `Local` (addressed to the
//!   router), from the port's small bounded `local_rx` queue.
//! - TX: frames from the router's own stack go into the port's **qdisc**,
//!   the same queue as forwarded traffic, so CAKE sees all egress traffic.
//!   smoltcp only gets a TX token while the qdisc has room.

use crate::net::packet::PacketBuf;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU64, Ordering};
use qdisc::Qdisc;
use qdisc::fifo::BFifo;
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// Frames smoltcp produced that could not be queued (pool empty or qdisc full).
static TX_DROPS: AtomicU64 = AtomicU64::new(0);

pub fn tx_drops() -> u64 {
    TX_DROPS.load(Ordering::Relaxed)
}

pub type PortQdisc = BFifo<PacketBuf>;

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
