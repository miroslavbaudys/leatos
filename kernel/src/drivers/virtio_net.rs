//! virtio-net (PCI) driver on top of `virtio_drivers::VirtIONetRaw`.
//!
//! Ownership makes the DMA hand-off safe: a [`PacketBuf`] lent to the device
//! is **moved into a slot** indexed by its descriptor token and only moved
//! out again after the device returns it. While the device owns a buffer,
//! no Rust reference to it exists. The `unsafe` in this file is exactly the
//! begin/complete pairs of that protocol.
//!
//! CAKE requirements (docs/bufferbloat-cake.md §3.1):
//! - **Pull-based TX:** callers check [`VirtioNet::can_transmit`] and only
//!   then hand over a packet; nothing queues inside the driver.
//! - **Byte-limited TX ring (BQL-style):** at most `tx_byte_limit` bytes
//!   are in flight, regardless of free descriptors. Fixed limit for now;
//!   adaptive BQL is planned with CAKE (M6).
//! - Interrupts work NAPI-style: IRQ → line masked → task polls RX/TX until
//!   empty → line unmasked (see `net::stack`).
//!
//! **MSI-X** (x86_64): `virtio-drivers` 0.13 doesn't assign MSI-X vectors
//! to the queues, and a device with MSI-X enabled but no vector raises no
//! interrupts at all. [`VirtioNet::route_msix`] therefore writes the two
//! vector registers of the virtio common configuration itself, once, after
//! `VirtIONetRaw::new` finished. That is the one place where rrouter
//! touches registers that `virtio-drivers` also maps: its transport uses
//! the common configuration only during init (and when queues are set up),
//! never afterwards, so the accesses never interleave. Remove this when
//! `virtio-drivers` supports MSI-X.

use crate::drivers::Stats;
use crate::mm::dma::DmaHal;
use crate::mmio::Region16;
use crate::net::packet::PacketBuf;
use crate::pci::{Pci, PciDevice};
use alloc::boxed::Box;
use virtio_drivers::device::net::VirtIONetRaw;
use virtio_drivers::transport::pci::PciTransport;

/// Descriptors per queue (RX and TX).
pub const QUEUE_SIZE: usize = 64;
/// Default TX in-flight byte limit: a few full frames. Enough to keep a
/// 1 Gbit/s link busy across ~50 µs of completion latency.
pub const DEFAULT_TX_BYTE_LIMIT: usize = 8 * 1514;
/// Room for the virtio-net header (10 or 12 bytes).
const MAX_HDR: usize = 16;

type Raw = VirtIONetRaw<DmaHal, PciTransport, QUEUE_SIZE>;

pub struct VirtioNet {
    // Declared first: dropped first, which resets the device before the
    // buffers it may still reference are freed.
    raw: Raw,
    // Boxed: keeps the driver struct small (it is moved around at init).
    rx_slots: Box<[Option<PacketBuf>; QUEUE_SIZE]>,
    tx_slots: Box<[Option<PacketBuf>; QUEUE_SIZE]>,
    tx_inflight_bytes: usize,
    tx_byte_limit: usize,
    pub stats: Stats,
}

#[derive(Debug)]
pub enum Error {
    Transport,
    Device,
    NoBuffers,
}

impl VirtioNet {
    /// Initialise the device behind `dev` and fill the RX ring.
    pub fn new(pci: &mut Pci, dev: &PciDevice) -> Result<Self, Error> {
        let transport =
            PciTransport::new::<DmaHal, _>(&mut pci.root, dev.df).map_err(|_| Error::Transport)?;
        let raw = Raw::new(transport).map_err(|_| Error::Device)?;
        let mut nic = Self {
            raw,
            rx_slots: Box::new([const { None }; QUEUE_SIZE]),
            tx_slots: Box::new([const { None }; QUEUE_SIZE]),
            tx_inflight_bytes: 0,
            tx_byte_limit: DEFAULT_TX_BYTE_LIMIT,
            stats: Stats::default(),
        };
        for _ in 0..QUEUE_SIZE {
            let buf = PacketBuf::alloc().ok_or(Error::NoBuffers)?;
            nic.post_rx(buf)?;
        }
        Ok(nic)
    }

    /// Point the RX and TX queues at MSI-X table entry `entry` and disable
    /// configuration-change interrupts (see the module docs).
    pub fn route_msix(&mut self, pci: &Pci, dev: &PciDevice, entry: u16) -> Result<(), Error> {
        const CAP_VENDOR: u8 = 0x09;
        const COMMON_CFG: u32 = 1;
        const MSIX_CONFIG: usize = 0x10;
        const QUEUE_SELECT: usize = 0x16;
        const QUEUE_MSIX_VECTOR: usize = 0x1a;
        const NO_VECTOR: u16 = 0xffff;
        let cap = pci
            .root
            .capabilities(dev.df)
            .find(|c| c.id == CAP_VENDOR && c.private_header >> 8 == COMMON_CFG as u16)
            .ok_or(Error::Transport)?;
        let bar_index = (pci.config_read(dev.df, cap.offset + 4) & 0xff) as usize;
        let offset = pci.config_read(dev.df, cap.offset + 8) as u64;
        let bar = dev
            .bars
            .get(bar_index)
            .copied()
            .flatten()
            .ok_or(Error::Transport)?;
        if offset + 0x38 > bar.size {
            return Err(Error::Transport);
        }
        // SAFETY: the virtio common configuration inside a memory BAR that
        // pci::init mapped as device memory. `virtio-drivers` accesses it
        // only during init, which has finished (`self.raw` exists), and the
        // driver is single-threaded: no interleaving accesses (module docs).
        let mut common = unsafe { Region16::new((bar.addr + offset) as usize, 0x38) };
        common.write16(MSIX_CONFIG, NO_VECTOR);
        for queue in 0..2 {
            common.write16(QUEUE_SELECT, queue);
            common.write16(QUEUE_MSIX_VECTOR, entry);
            if common.read16(QUEUE_MSIX_VECTOR) != entry {
                return Err(Error::Device); // the device couldn't allocate the vector
            }
        }
        Ok(())
    }

    pub fn mac(&self) -> [u8; 6] {
        self.raw.mac_address()
    }

    /// Clear the device's interrupt status (de-asserts legacy INTx).
    pub fn ack_interrupt(&mut self) {
        let _ = self.raw.ack_interrupt();
    }

    fn post_rx(&mut self, mut buf: PacketBuf) -> Result<(), Error> {
        // SAFETY: `buf` is moved into `rx_slots[token]` right below and stays
        // there, untouched, until `poll_receive` reports this token done.
        let token =
            unsafe { self.raw.receive_begin(buf.rx_area_mut()) }.map_err(|_| Error::Device)?;
        let slot = &mut self.rx_slots[token as usize];
        assert!(slot.is_none(), "virtio-net: rx token {token} reused");
        *slot = Some(buf);
        Ok(())
    }

    /// Take one received packet, if any, and refill the ring.
    pub fn receive(&mut self) -> Option<PacketBuf> {
        loop {
            let token = self.raw.poll_receive()?;
            let mut buf = self.rx_slots[token as usize]
                .take()
                .expect("virtio-net: unknown rx token");
            // SAFETY: same buffer (same storage, same `rx_area_mut` slice) as
            // passed to `receive_begin` for this token.
            let done = unsafe { self.raw.receive_complete(token, buf.rx_area_mut()) };
            let Ok((hdr_len, pkt_len)) = done else {
                let _ = self.post_rx(buf); // recycle on error
                continue;
            };
            buf.set_rx_range(hdr_len, pkt_len);
            // Keep the ring full. If the pool is empty, drop this packet and
            // reuse its buffer: the RX ring must never run dry.
            match PacketBuf::alloc() {
                Some(fresh) => {
                    let _ = self.post_rx(fresh);
                }
                None => {
                    self.stats.rx_dropped_no_buf += 1;
                    let _ = self.post_rx(buf);
                    continue;
                }
            }
            self.stats.rx_packets += 1;
            self.stats.rx_bytes += pkt_len as u64;
            return Some(buf);
        }
    }

    /// Free buffers of completed transmissions.
    pub fn reap_tx(&mut self) {
        while let Some(token) = self.raw.poll_transmit() {
            let buf = self.tx_slots[token as usize]
                .take()
                .expect("virtio-net: unknown tx token");
            // SAFETY: same buffer (same `data()` slice) as passed to `transmit_begin`.
            let _ = unsafe { self.raw.transmit_complete(token, buf.data()) };
            self.tx_inflight_bytes -= buf.len();
            // `buf` drops here and returns to the pool.
        }
    }

    /// Room for one more frame? (descriptors *and* the in-flight byte limit)
    pub fn can_transmit(&self) -> bool {
        self.raw.can_send() && self.tx_inflight_bytes < self.tx_byte_limit
    }

    /// Transmit an Ethernet frame. Check [`Self::can_transmit`] first; on a
    /// full ring the packet is handed back.
    pub fn transmit(&mut self, mut pkt: PacketBuf) -> Result<(), PacketBuf> {
        if !self.can_transmit() {
            return Err(pkt);
        }
        let frame_len = pkt.len();
        let mut hdr = [0u8; MAX_HDR];
        let Ok(hdr_len) = self.raw.fill_buffer_header(&mut hdr) else {
            return Err(pkt);
        };
        pkt.push_front(hdr_len).copy_from_slice(&hdr[..hdr_len]);
        // SAFETY: `pkt` is moved into `tx_slots[token]` right below and stays
        // there, untouched, until `poll_transmit` reports this token done.
        let token = match unsafe { self.raw.transmit_begin(pkt.data()) } {
            Ok(t) => t,
            Err(_) => {
                pkt.pull_front(hdr_len);
                return Err(pkt);
            }
        };
        self.tx_inflight_bytes += pkt.len();
        let slot = &mut self.tx_slots[token as usize];
        assert!(slot.is_none(), "virtio-net: tx token {token} reused");
        *slot = Some(pkt);
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += frame_len as u64;
        Ok(())
    }
}
