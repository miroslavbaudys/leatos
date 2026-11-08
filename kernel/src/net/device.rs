//! smoltcp `Device` glue for [`VirtioNet`].
//!
//! smoltcp only gets a TX token when the driver has room (descriptor *and*
//! byte limit), so TX stays pull-based and nothing queues in the driver.

use crate::drivers::virtio_net::VirtioNet;
use crate::net::packet::PacketBuf;
use core::sync::atomic::{AtomicU64, Ordering};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// Frames smoltcp produced that could not be sent (pool empty or ring full).
static TX_DROPS: AtomicU64 = AtomicU64::new(0);

pub fn tx_drops() -> u64 {
    TX_DROPS.load(Ordering::Relaxed)
}

pub struct RxToken(PacketBuf);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0.data())
    }
}

pub struct TxToken<'a>(&'a mut VirtioNet);

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        match PacketBuf::alloc() {
            Some(mut pkt) => {
                pkt.set_len(len);
                let r = f(pkt.data_mut());
                if self.0.transmit(pkt).is_err() {
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

impl Device for VirtioNet {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _ts: Instant) -> Option<(RxToken, TxToken<'_>)> {
        self.reap_tx();
        let pkt = VirtioNet::receive(self)?;
        Some((RxToken(pkt), TxToken(self)))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<TxToken<'_>> {
        self.reap_tx();
        self.can_transmit().then_some(TxToken(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(1);
        caps
    }
}
