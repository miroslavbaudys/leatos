//! Device drivers (arch-neutral): [`Nic`], the one interface the network
//! stack uses for every NIC model, and [`Disk`], the one the store uses
//! for every block device.

#[allow(unsafe_code)] // the register windows' constructor (DMA through driver-owned DmaRegions)
pub mod ahci;
pub mod cputemp;
#[allow(unsafe_code)] // the register window's constructor (read-only TRNG registers)
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
#[allow(unsafe_code)] // the video memory windows' constructor (no DMA)
pub mod screen;
pub mod watchdog;

use crate::net::packet::PacketBuf;
use crate::pci::{Pci, PciDevice};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_dropped_no_buf: u64,
    /// Frames the NIC itself dropped: its receive FIFO or RX ring was full
    /// (igb `MPC` + `RQDPC`; updated by `Nic::update_stats`).
    pub rx_missed: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
}

/// A supported NIC. Same contract for every model: pull-based TX
/// (`can_transmit` before `transmit`), RX refills itself from the packet
/// pool, NAPI-style interrupts (`ack_interrupt`, then poll until empty).
#[allow(clippy::large_enum_variant)] // one per port, built once at boot and kept in place
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

    /// Can TX completions get their own MSI-X vector (table entry 1, armed
    /// on demand: [`Self::arm_tx_irq`])?
    pub fn has_tx_vector(&self) -> bool {
        matches!(self, Self::Igb(_))
    }

    /// Unmask the device's interrupts once the line or vector is set up;
    /// `tx_vector`: MSI-X table entry 1 is routed too ([`Self::has_tx_vector`]).
    /// igb: RX interrupt moderation from `config::igb_itr_us`.
    pub fn enable_irq(&mut self, msix: bool, tx_vector: bool) {
        match self {
            Self::Virtio(_) => {} // virtio-drivers enables queue interrupts at init
            Self::Igb(n) => n.enable_irq(msix, tx_vector, crate::config::igb_itr_us()),
        }
    }

    /// RX interrupt moderation in µs, if the NIC has it (igb; 0 = none).
    pub fn rx_moderation_us(&self) -> Option<u32> {
        match self {
            Self::Virtio(_) => None,
            Self::Igb(n) => Some(n.itr_us()),
        }
    }

    /// Read the device's own counters into [`Self::stats`] (rarely: they
    /// cost register reads).
    pub fn update_stats(&mut self) {
        match self {
            Self::Virtio(_) => {}
            Self::Igb(n) => n.update_stats(),
        }
    }

    /// TX blocked with packets waiting: arm the TX completion interrupt.
    /// `false` = not armed (no TX vector, or room again: transmit).
    pub fn arm_tx_irq(&mut self) -> bool {
        match self {
            Self::Virtio(_) => false,
            Self::Igb(n) => n.arm_tx_irq(),
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

    /// The device masks its own interrupt when it fires (igb with MSI-X):
    /// the IRQ action then only signals, and the poll re-arms it with
    /// [`Self::unmask_irq`] instead of at the interrupt controller.
    pub fn self_masking(&self) -> bool {
        match self {
            Self::Virtio(_) => false,
            Self::Igb(n) => n.self_masking(),
        }
    }

    /// Re-arm a [`Self::self_masking`] device's interrupt.
    pub fn unmask_irq(&mut self) {
        match self {
            Self::Virtio(_) => {}
            Self::Igb(n) => n.unmask_irq(),
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

    /// Queue a frame; it may wait in the ring until [`Self::kick_tx`].
    pub fn transmit(&mut self, pkt: PacketBuf) -> Result<(), PacketBuf> {
        match self {
            Self::Virtio(n) => n.transmit(pkt),
            Self::Igb(n) => n.transmit(pkt),
        }
    }

    /// Send what [`Self::transmit`] queued (igb: one `TDT` write per batch).
    /// Every batch of transmits ends with it.
    pub fn kick_tx(&mut self) {
        match self {
            Self::Virtio(_) => {} // virtio-drivers notifies per frame
            Self::Igb(n) => n.kick_tx(),
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

/// A block device the store can live on: QEMU's virtio-blk, an SD card
/// behind an SD host controller (the apu4's slot), or a SATA disk on an
/// AHCI port (the apu4's mSATA, Proxmox `sata0`). All are polled and
/// yield while the device works; requests are at most 64 KiB.
pub enum Disk {
    Virtio(alloc::boxed::Box<virtio_blk::VirtioBlk>),
    Sd(alloc::boxed::Box<sdhci::Sdhci>),
    Ahci(alloc::boxed::Box<ahci::Ahci>),
}

#[derive(Clone, Copy, Debug)]
pub enum DiskError {
    Virtio(virtio_blk::Error),
    Sd(sdhci::Error),
    Ahci(ahci::Error),
}

impl core::fmt::Display for DiskError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Virtio(e) => write!(f, "virtio-blk: {e:?}"),
            Self::Sd(e) => write!(f, "sd: {e:?}"),
            Self::Ahci(e) => write!(f, "ahci: {e}"),
        }
    }
}

/// Largest request [`Disk::read`] / [`Disk::write`] take, in sectors.
pub const DISK_MAX_SECTORS: usize = 128;
const _: () = assert!(
    virtio_blk::MAX_REQUEST_SECTORS == DISK_MAX_SECTORS
        && sdhci::MAX_REQUEST_SECTORS == DISK_MAX_SECTORS
        && ahci::MAX_REQUEST_SECTORS == DISK_MAX_SECTORS
);

impl Disk {
    /// The disks on `dev`, if it is a block device we drive (empty when
    /// not): each with its name (the PCI address; `<address>/<port>` on an
    /// AHCI controller, one per port with a device) and the initialised
    /// disk or why it failed. SD cards and AHCI ports are initialised here
    /// (yielding; at boot under `block_on`).
    pub async fn open(pci: &mut Pci, dev: &PciDevice) -> Vec<(String, Result<Self, String>)> {
        let df = format!("{}", dev.df);
        if dev.is_virtio_blk() {
            let d = virtio_blk::VirtioBlk::new(pci, dev)
                .map(|d| Self::Virtio(Box::new(d)))
                .map_err(|e| format!("virtio-blk init failed: {e:?}"));
            vec![(df, d)]
        } else if sdhci::supports(dev) {
            let d = sdhci::Sdhci::new(dev)
                .await
                .map(|d| Self::Sd(Box::new(d)))
                .map_err(|e| format!("sd init failed: {e:?}"));
            vec![(df, d)]
        } else if ahci::supports(dev) {
            match ahci::open_ports(dev).await {
                Err(e) => vec![(df, Err(format!("ahci init failed: {e}")))],
                Ok(ports) => ports
                    .into_iter()
                    .map(|(p, d)| {
                        let d = d.map(|d| Self::Ahci(Box::new(d))).map_err(|e| match e {
                            ahci::Error::NotAta(_) => format!("ahci port {p}: {e}"),
                            _ => format!("ahci port {p} init failed: {e}"),
                        });
                        (format!("{df}/{p}"), d)
                    })
                    .collect(),
            }
        } else {
            Vec::new()
        }
    }

    /// Model and size for the log.
    pub fn describe(&self) -> alloc::string::String {
        match self {
            Self::Virtio(d) => alloc::format!("virtio-blk {} MiB", d.capacity() >> 11),
            Self::Sd(d) => alloc::format!("SD card: {}", d.desc),
            Self::Ahci(d) => d.desc.clone(),
        }
    }

    /// Size in 512-byte sectors.
    pub fn capacity(&self) -> u64 {
        match self {
            Self::Virtio(d) => d.capacity(),
            Self::Sd(d) => d.capacity(),
            Self::Ahci(d) => d.capacity(),
        }
    }

    pub fn readonly(&self) -> bool {
        match self {
            Self::Virtio(d) => d.readonly(),
            Self::Sd(d) => d.readonly(),
            Self::Ahci(d) => d.readonly(),
        }
    }

    pub async fn read(&mut self, lba: u64, sectors: usize) -> Result<alloc::vec::Vec<u8>, DiskError> {
        match self {
            Self::Virtio(d) => d.read(lba, sectors).await.map_err(DiskError::Virtio),
            Self::Sd(d) => d.read(lba, sectors).await.map_err(DiskError::Sd),
            Self::Ahci(d) => d.read(lba, sectors).await.map_err(DiskError::Ahci),
        }
    }

    pub async fn write(&mut self, lba: u64, data: alloc::vec::Vec<u8>) -> Result<(), DiskError> {
        match self {
            Self::Virtio(d) => d.write(lba, data).await.map_err(DiskError::Virtio),
            Self::Sd(d) => d.write(lba, &data).await.map_err(DiskError::Sd),
            Self::Ahci(d) => d.write(lba, &data).await.map_err(DiskError::Ahci),
        }
    }

    /// Make completed writes durable. SD: a write completes only once the
    /// card has programmed it, so there is nothing to flush. virtio-blk:
    /// a blocking flush (`virtio-drivers` has no other). AHCI: FLUSH CACHE.
    pub async fn flush(&mut self) -> Result<(), DiskError> {
        match self {
            Self::Virtio(d) => d.flush().map_err(DiskError::Virtio),
            Self::Sd(_) => Ok(()),
            Self::Ahci(d) => d.flush().await.map_err(DiskError::Ahci),
        }
    }
}
