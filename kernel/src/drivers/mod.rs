//! Device drivers (arch-neutral): [`Nic`], the one interface the network
//! stack uses for every NIC model, and [`Disk`], the one the store uses
//! for every block device.

#[allow(unsafe_code)] // the register window's constructor (read-only TRNG register)
pub mod ccp;
#[allow(unsafe_code)] // the register window's constructor
pub mod i6300esb;
#[allow(unsafe_code)] // register window + DMA buffer hand-off (slot ownership)
pub mod igb;
#[allow(unsafe_code)] // the register window's constructor (PIO, no DMA)
pub mod sdhci;
#[allow(unsafe_code)] // DMA buffer hand-off (submit/complete pairs, driver-owned buffers)
pub mod virtio_blk;
#[allow(unsafe_code)] // DMA buffer hand-off (begin/complete pairs)
pub mod virtio_net;
pub mod watchdog;

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

/// A block device the store can live on: QEMU's virtio-blk, or an SD card
/// behind an SD host controller (the apu4's slot). Both are polled and
/// yield while the device works; requests are at most 64 KiB.
pub enum Disk {
    Virtio(alloc::boxed::Box<virtio_blk::VirtioBlk>),
    Sd(alloc::boxed::Box<sdhci::Sdhci>),
}

#[derive(Clone, Copy, Debug)]
pub enum DiskError {
    Virtio(virtio_blk::Error),
    Sd(sdhci::Error),
}

impl core::fmt::Display for DiskError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Virtio(e) => write!(f, "virtio-blk: {e:?}"),
            Self::Sd(e) => write!(f, "sd: {e:?}"),
        }
    }
}

/// Largest request [`Disk::read`] / [`Disk::write`] take, in sectors.
pub const DISK_MAX_SECTORS: usize = 128;
const _: () = assert!(
    virtio_blk::MAX_REQUEST_SECTORS == DISK_MAX_SECTORS
        && sdhci::MAX_REQUEST_SECTORS == DISK_MAX_SECTORS
);

impl Disk {
    /// The driver for `dev`, if it is a block device we drive: `None`
    /// when not, else the initialised disk or why it failed. SD cards
    /// are initialised here (yielding; at boot under `block_on`).
    pub async fn open(pci: &mut Pci, dev: &PciDevice) -> Option<Result<Self, alloc::string::String>> {
        if dev.is_virtio_blk() {
            Some(
                virtio_blk::VirtioBlk::new(pci, dev)
                    .map(|d| Self::Virtio(alloc::boxed::Box::new(d)))
                    .map_err(|e| alloc::format!("virtio-blk: {e:?}")),
            )
        } else if sdhci::supports(dev) {
            Some(
                sdhci::Sdhci::new(dev)
                    .await
                    .map(|d| Self::Sd(alloc::boxed::Box::new(d)))
                    .map_err(|e| alloc::format!("sd: {e:?}")),
            )
        } else {
            None
        }
    }

    /// Model and size for the log.
    pub fn describe(&self) -> alloc::string::String {
        match self {
            Self::Virtio(d) => alloc::format!("virtio-blk {} MiB", d.capacity() >> 11),
            Self::Sd(d) => alloc::format!("SD card: {}", d.desc),
        }
    }

    /// Size in 512-byte sectors.
    pub fn capacity(&self) -> u64 {
        match self {
            Self::Virtio(d) => d.capacity(),
            Self::Sd(d) => d.capacity(),
        }
    }

    pub fn readonly(&self) -> bool {
        match self {
            Self::Virtio(d) => d.readonly(),
            Self::Sd(d) => d.readonly(),
        }
    }

    pub async fn read(&mut self, lba: u64, sectors: usize) -> Result<alloc::vec::Vec<u8>, DiskError> {
        match self {
            Self::Virtio(d) => d.read(lba, sectors).await.map_err(DiskError::Virtio),
            Self::Sd(d) => d.read(lba, sectors).await.map_err(DiskError::Sd),
        }
    }

    pub async fn write(&mut self, lba: u64, data: alloc::vec::Vec<u8>) -> Result<(), DiskError> {
        match self {
            Self::Virtio(d) => d.write(lba, data).await.map_err(DiskError::Virtio),
            Self::Sd(d) => d.write(lba, &data).await.map_err(DiskError::Sd),
        }
    }

    /// Make completed writes durable. SD: a write completes only once the
    /// card has programmed it, so there is nothing to flush.
    pub fn flush(&mut self) -> Result<(), DiskError> {
        match self {
            Self::Virtio(d) => d.flush().map_err(DiskError::Virtio),
            Self::Sd(_) => Ok(()),
        }
    }
}
