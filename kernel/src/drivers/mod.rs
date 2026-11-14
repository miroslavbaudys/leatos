//! Device drivers (arch-neutral), and [`Nic`]: the one interface the
//! network stack uses for every NIC model.

#[allow(unsafe_code)] // register window + DMA buffer hand-off (slot ownership)
pub mod igb;
#[allow(unsafe_code)] // DMA buffer hand-off (begin/complete pairs)
pub mod virtio_net;

use crate::net::packet::PacketBuf;
use crate::pci::{Pci, PciDevice};

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_dropped_no_buf: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
}

/// A supported NIC. Same contract for every model: pull-based TX
/// (`can_transmit` before `transmit`), RX refills itself from the packet
/// pool, NAPI-style interrupts (`ack_interrupt`, then poll until empty).
pub enum Nic {
    // Boxed: virtio-drivers' queue state is large (~2.4 KiB).
    Virtio(alloc::boxed::Box<virtio_net::VirtioNet>),
    Igb(igb::Igb),
}

/// Does a driver exist for this PCI function?
pub fn is_nic(dev: &PciDevice) -> bool {
    dev.is_virtio_net() || igb::supports(dev)
}

impl Nic {
    pub fn new(pci: &mut Pci, dev: &PciDevice) -> Result<Self, alloc::string::String> {
        if dev.is_virtio_net() {
            virtio_net::VirtioNet::new(pci, dev)
                .map(|n| Self::Virtio(alloc::boxed::Box::new(n)))
                .map_err(|e| alloc::format!("virtio-net: {e:?}"))
        } else {
            igb::Igb::new(dev)
                .map(Self::Igb)
                .map_err(|e| alloc::format!("igb: {e:?}"))
        }
    }

    /// Model name for the boot log.
    pub fn model(&self) -> &'static str {
        match self {
            Self::Virtio(_) => "virtio-net",
            Self::Igb(n) => n.model,
        }
    }

    /// Device-side MSI-X setup, before `Pci::enable_msix` routes entry 0.
    pub fn prepare_msix(&mut self, pci: &Pci, dev: &PciDevice) -> Result<(), ()> {
        match self {
            Self::Virtio(n) => n.route_msix(pci, dev, 0).map_err(|_| ()),
            Self::Igb(_) => Ok(()),
        }
    }

    /// Unmask the device's interrupts once the line or vector is set up.
    pub fn enable_irq(&mut self, msix: bool) {
        match self {
            Self::Virtio(_) => {} // virtio-drivers enables queue interrupts at init
            Self::Igb(n) => n.enable_irq(msix),
        }
    }

    pub fn mac(&self) -> [u8; 6] {
        match self {
            Self::Virtio(n) => n.mac(),
            Self::Igb(n) => n.mac(),
        }
    }

    /// Link state if it changed since the last call (polled, ~1/s).
    pub fn link_changed(&mut self) -> Option<(bool, u32, bool)> {
        match self {
            Self::Virtio(_) => None,
            Self::Igb(n) => n.link_changed(),
        }
    }

    pub fn ack_interrupt(&mut self) {
        match self {
            Self::Virtio(n) => n.ack_interrupt(),
            Self::Igb(n) => n.ack_interrupt(),
        }
    }

    pub fn receive(&mut self) -> Option<PacketBuf> {
        match self {
            Self::Virtio(n) => n.receive(),
            Self::Igb(n) => n.receive(),
        }
    }

    pub fn reap_tx(&mut self) {
        match self {
            Self::Virtio(n) => n.reap_tx(),
            Self::Igb(n) => n.reap_tx(),
        }
    }

    pub fn can_transmit(&self) -> bool {
        match self {
            Self::Virtio(n) => n.can_transmit(),
            Self::Igb(n) => n.can_transmit(),
        }
    }

    pub fn transmit(&mut self, pkt: PacketBuf) -> Result<(), PacketBuf> {
        match self {
            Self::Virtio(n) => n.transmit(pkt),
            Self::Igb(n) => n.transmit(pkt),
        }
    }

    #[allow(dead_code)] // for stats output
    pub fn stats(&self) -> Stats {
        match self {
            Self::Virtio(n) => n.stats,
            Self::Igb(n) => n.stats,
        }
    }
}
