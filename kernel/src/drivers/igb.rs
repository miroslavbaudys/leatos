//! Intel `igb` family driver: i210 / i211 (apu4, M10) and the 82576 that
//! QEMU emulates (`-device igb`), written from the datasheets.
//!
//! Only what the three share is used, one RX and one TX queue (queue 0):
//! the queue registers, advanced descriptors, `SRRCTL`, `IVAR0` for queue 0
//! and `GPIE` are at the same offsets with the same layout on all of them.
//! No NVM access: the MAC address is read from `RAL0`/`RAH0`, which the
//! hardware loads from NVM / iNVM (i211) at reset.
//!
//! **DMA ownership** follows the virtio driver: a [`PacketBuf`] lent to the
//! device is moved into the slot of its descriptor and only moved out after
//! the device wrote the descriptor back (`DD`). The `unsafe` in this file is
//! the register window ([`Region::new`]) and exactly the two hand-offs that
//! put a buffer address into a ring ([`Igb::give_rx`], [`Igb::transmit`]).
//! Descriptor rings themselves are [`DmaRegion`]s (safe volatile access).
//!
//! CAKE requirements (docs/bufferbloat-cake.md §3.1): pull-based TX
//! ([`Igb::can_transmit`] first), a BQL-style in-flight byte limit, no
//! queue inside the driver, and NAPI-style interrupts (masked while
//! `net::stack` polls, unmasked once drained). No interrupt moderation
//! (`EITR` = 0): masking during the poll already batches.
//!
//! Interrupts: INTx (aarch64 `virt`; `ICR`/`IMS`: the IRQ action masks the
//! line, the poll reads `ICR` to de-assert it) or MSI-X vector 0 (x86_64;
//! `GPIE.MSIX_MODE`, `EIMS`). RX queue 0 and TX queue 0 both map to vector
//! 0 through `IVAR0`. With MSI-X the device masks itself: `EIAM` clears the
//! vector's `EIMS` bit when the message goes out and `EIAC` clears its
//! `EICR` bit, so the IRQ action only signals, no `ICR` read is needed (a
//! non-posted PCIe read), and [`Igb::unmask_irq`] re-arms it with one
//! posted `EIMS` write; a cause that came in meanwhile fires at once.

use crate::drivers::Stats;
use crate::mm::dma::{self, DmaRegion};
use crate::mmio::Region;
use crate::net::packet::{PacketBuf, RX_AREA};
use crate::pci::PciDevice;
use crate::{arch, println, timer};
use alloc::boxed::Box;
use core::time::Duration;

/// RX descriptors. One is always held back (`RDT` never reaches `RDH`), so
/// the device owns at most `RX_RING - 1` buffers.
const RX_RING: usize = 64;
/// TX descriptors. In practice the byte limit binds first.
const TX_RING: usize = 64;
const DESC: usize = 16;
/// Write the RX tail register at most every this many refills (each MMIO
/// write is a VM exit under QEMU); always when the ring is drained.
const RX_TAIL_BATCH: usize = 16;
pub const DEFAULT_TX_BYTE_LIMIT: usize = 8 * 1514;

// Registers (byte offsets in BAR0).
const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const CTRL_EXT: usize = 0x0018;
const MDIC: usize = 0x0020;
const ICR: usize = 0x00c0;
const IMS: usize = 0x00d0;
const IMC: usize = 0x00d8;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const GPIE: usize = 0x1514;
const EIMS: usize = 0x1524;
const EIMC: usize = 0x1528;
const EIAC: usize = 0x152c;
const EIAM: usize = 0x1530;
const EITR0: usize = 0x1680;
const IVAR0: usize = 0x1700;
const RLPML: usize = 0x5004;
const RAL0: usize = 0x5400;
const RAH0: usize = 0x5404;
const RDBAL0: usize = 0xc000;
const RDBAH0: usize = 0xc004;
const RDLEN0: usize = 0xc008;
const SRRCTL0: usize = 0xc00c;
const RDH0: usize = 0xc010;
const RDT0: usize = 0xc018;
const RXDCTL0: usize = 0xc028;
const TDBAL0: usize = 0xe000;
const TDBAH0: usize = 0xe004;
const TDLEN0: usize = 0xe008;
const TDH0: usize = 0xe010;
const TDT0: usize = 0xe018;
const TXDCTL0: usize = 0xe028;
/// All of the above lie below this offset.
const REGS_LEN: usize = 0x10000;

const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;
const CTRL_PHY_RST: u32 = 1 << 31;
const CTRL_RFCE: u32 = 1 << 27;
const CTRL_TFCE: u32 = 1 << 28;
const CTRL_EXT_DRV_LOAD: u32 = 1 << 28;
const STATUS_FD: u32 = 1 << 0;
const STATUS_LU: u32 = 1 << 1;
const RCTL_EN: u32 = 1 << 1;
const RCTL_MPE: u32 = 1 << 4;
/// Long packets: frames above 1522 B, up to `RLPML` (PPPoE with RFC 4638
/// on a VLAN: 1526 B).
const RCTL_LPE: u32 = 1 << 5;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_CT: u32 = 0x0f << 4;
const TCTL_COLD: u32 = 0x3f << 12;
const TCTL_RTLC: u32 = 1 << 24;
const SRRCTL_DESCTYPE_ADV_ONEBUF: u32 = 1 << 25;
const SRRCTL_DROP_EN: u32 = 1 << 31;
const QUEUE_ENABLE: u32 = 1 << 25;
/// TXDCTL.WTHRESH = 1: write back each descriptor as soon as it is done
/// (no batching of completions, which would hide in-flight bytes).
const TXDCTL_WTHRESH_1: u32 = 1 << 16;
const GPIE_NSICR: u32 = 1 << 0;
const GPIE_MSIX_MODE: u32 = 1 << 4;
const GPIE_EIAME: u32 = 1 << 30;
const GPIE_PBA: u32 = 1 << 31;
const IVAR_VALID: u32 = 0x80;
const ICR_TXDW: u32 = 1 << 0;
const ICR_LSC: u32 = 1 << 2;
const ICR_RXDMT0: u32 = 1 << 4;
const ICR_RXO: u32 = 1 << 6;
const ICR_RXT0: u32 = 1 << 7;
const MDIC_READ: u32 = 2 << 26;
const MDIC_WRITE: u32 = 1 << 26;
const MDIC_READY: u32 = 1 << 28;
const MDIC_ERROR: u32 = 1 << 30;
/// Internal PHY address (i210/i211 and 82576 copper).
const PHY_ADDR: u32 = 1;
const PHY_CONTROL: u32 = 0;
const PHY_POWER_DOWN: u16 = 1 << 11;
const PHY_AUTONEG_ENABLE: u16 = 1 << 12;
const PHY_RESTART_AUTONEG: u16 = 1 << 9;

// Advanced descriptors.
const RXD_STAT_DD: u32 = 1 << 0;
const RXD_STAT_EOP: u32 = 1 << 1;
/// CE | SE | SEQ | CXE | RXE in the extended status/error word.
const RXD_ERR_FRAME: u32 = 0x9700_0000;
const TXD_DTYP_DATA: u32 = 0x3 << 20;
const TXD_CMD_EOP: u32 = 1 << 24;
const TXD_CMD_IFCS: u32 = 1 << 25;
const TXD_CMD_RS: u32 = 1 << 27;
const TXD_CMD_DEXT: u32 = 1 << 29;
const TXD_PAYLEN_SHIFT: u32 = 14;
const TXD_STAT_DD: u32 = 1 << 0;

#[derive(Debug)]
pub enum Error {
    NoBar,
    ResetTimeout,
    QueueEnable,
    BadMac,
    NoBuffers,
}

pub fn supports(dev: &PciDevice) -> bool {
    model(dev).is_some()
}

fn model(dev: &PciDevice) -> Option<&'static str> {
    if dev.info.vendor_id != 0x8086 {
        return None;
    }
    Some(match dev.info.device_id {
        0x10c9 => "82576",
        0x1533 | 0x1536 | 0x1537 | 0x1538 | 0x157b => "i210",
        0x1539 => "i211",
        _ => return None,
    })
}

pub struct Igb {
    regs: Region,
    rx_ring: DmaRegion,
    tx_ring: DmaRegion,
    rx_slots: Box<[Option<PacketBuf>; RX_RING]>,
    tx_slots: Box<[Option<PacketBuf>; TX_RING]>,
    /// Next RX descriptor to look at.
    rx_next: usize,
    /// RX descriptors refilled but not yet handed over through `RDT`.
    rx_unflushed: usize,
    /// Next free TX descriptor (= the `TDT` value).
    tx_next: usize,
    /// Oldest in-flight TX descriptor.
    tx_clean: usize,
    tx_inflight_bytes: usize,
    tx_byte_limit: usize,
    mac: [u8; 6],
    /// Last reported link state (for [`Self::link_changed`]).
    link_reported: Option<(bool, u32, bool)>,
    /// MSI-X mode ([`Self::enable_irq`]): the device masks itself.
    msix: bool,
    pub model: &'static str,
    pub stats: Stats,
}

fn busy_wait(d: Duration) {
    let end = timer::uptime() + d;
    while timer::uptime() < end {
        core::hint::spin_loop();
    }
}

impl Igb {
    /// Reset the controller, set up one RX and one TX queue, fill the RX
    /// ring and enable the receiver and transmitter. Interrupts stay
    /// disabled until [`Self::enable_irq`].
    pub fn new(dev: &PciDevice) -> Result<Self, Error> {
        let model = model(dev).ok_or(Error::NoBar)?;
        let bar = dev.bars[0].ok_or(Error::NoBar)?;
        if bar.size < REGS_LEN as u64 {
            return Err(Error::NoBar);
        }
        // SAFETY: BAR0 of this function, mapped as device memory by
        // pci::init; only this driver accesses it (MSI-X lives in BAR3).
        let regs = unsafe { Region::new(bar.addr as usize, REGS_LEN) };
        let mut nic = Self {
            regs,
            rx_ring: DmaRegion::new(RX_RING * DESC, 128),
            tx_ring: DmaRegion::new(TX_RING * DESC, 128),
            rx_slots: Box::new([const { None }; RX_RING]),
            tx_slots: Box::new([const { None }; TX_RING]),
            rx_next: 0,
            rx_unflushed: 0,
            tx_next: 0,
            tx_clean: 0,
            tx_inflight_bytes: 0,
            tx_byte_limit: DEFAULT_TX_BYTE_LIMIT,
            mac: [0; 6],
            link_reported: None,
            msix: false,
            model,
            stats: Stats::default(),
        };
        nic.reset()?;
        nic.mac = nic.read_mac().ok_or(Error::BadMac)?;
        nic.power_up_phy();
        nic.setup_rx()?;
        nic.setup_tx()?;
        Ok(nic)
    }

    fn disable_irqs(&mut self) {
        self.regs.write32(IMC, u32::MAX);
        self.regs.write32(EIMC, u32::MAX);
        let _ = self.regs.read32(ICR);
    }

    fn reset(&mut self) -> Result<(), Error> {
        self.disable_irqs();
        self.regs.write32(RCTL, 0);
        self.regs.write32(TCTL, TCTL_PSP);
        busy_wait(Duration::from_millis(10)); // let pending DMA finish
        self.regs.modify32(CTRL, |c| c | CTRL_RST);
        busy_wait(Duration::from_millis(1));
        let deadline = timer::uptime() + Duration::from_millis(100);
        while self.regs.read32(CTRL) & CTRL_RST != 0 {
            if timer::uptime() > deadline {
                return Err(Error::ResetTimeout);
            }
        }
        busy_wait(Duration::from_millis(10)); // NVM / iNVM auto-load
        self.disable_irqs();
        // Copper link: set link up, autonegotiation (the PHY default).
        // No flow control: pause frames would stall the queue CAKE manages.
        self.regs.modify32(CTRL, |c| {
            (c | CTRL_SLU) & !(CTRL_PHY_RST | CTRL_RFCE | CTRL_TFCE)
        });
        self.regs.modify32(CTRL_EXT, |c| c | CTRL_EXT_DRV_LOAD);
        Ok(())
    }

    fn read_mac(&mut self) -> Option<[u8; 6]> {
        let lo = self.regs.read32(RAL0).to_le_bytes();
        let hi = self.regs.read32(RAH0);
        let mac = [lo[0], lo[1], lo[2], lo[3], hi as u8, (hi >> 8) as u8];
        let valid = mac != [0; 6] && mac != [0xff; 6] && mac[0] & 1 == 0;
        // Address valid (AV): accept unicast frames to it.
        self.regs.write32(RAH0, hi & 0xffff | 1 << 31);
        valid.then_some(mac)
    }

    fn mdic(&mut self, cmd: u32) -> Option<u16> {
        self.regs.write32(MDIC, cmd);
        let deadline = timer::uptime() + Duration::from_millis(10);
        loop {
            let v = self.regs.read32(MDIC);
            if v & MDIC_READY != 0 {
                return (v & MDIC_ERROR == 0).then_some(v as u16);
            }
            if timer::uptime() > deadline {
                return None;
            }
        }
    }

    /// Power up the PHY (firmware may have left it powered down) and
    /// restart autonegotiation; the link comes up asynchronously
    /// ([`Self::link_changed`]).
    fn power_up_phy(&mut self) {
        let addr = PHY_ADDR << 21 | PHY_CONTROL << 16;
        let Some(ctl) = self.mdic(MDIC_READ | addr) else {
            println!("  igb: PHY not reachable over MDIO");
            return;
        };
        let ctl = (ctl & !PHY_POWER_DOWN) | PHY_AUTONEG_ENABLE | PHY_RESTART_AUTONEG;
        if self.mdic(MDIC_WRITE | addr | ctl as u32).is_none() {
            println!("  igb: PHY control write failed");
        }
    }

    fn enable_queue(&mut self, reg: usize, extra: u32) -> Result<(), Error> {
        self.regs.write32(reg, extra | QUEUE_ENABLE);
        let deadline = timer::uptime() + Duration::from_millis(10);
        while self.regs.read32(reg) & QUEUE_ENABLE == 0 {
            if timer::uptime() > deadline {
                return Err(Error::QueueEnable);
            }
        }
        Ok(())
    }

    fn setup_rx(&mut self) -> Result<(), Error> {
        let base = self.rx_ring.bus_addr();
        self.regs.write32(RXDCTL0, 0);
        self.regs.write32(RDBAL0, base as u32);
        self.regs.write32(RDBAH0, (base >> 32) as u32);
        self.regs.write32(RDLEN0, self.rx_ring.len() as u32);
        self.regs.write32(RDH0, 0);
        self.regs.write32(RDT0, 0);
        // Advanced one-buffer descriptors, 2 KiB buffers (BSIZEPACKET is in
        // KiB), and drop when out of descriptors instead of stalling.
        self.regs.write32(
            SRRCTL0,
            (RX_AREA / 1024) as u32 | SRRCTL_DESCTYPE_ADV_ONEBUF | SRRCTL_DROP_EN,
        );
        self.enable_queue(RXDCTL0, 0)?;
        for i in 0..RX_RING {
            let buf = PacketBuf::alloc().ok_or(Error::NoBuffers)?;
            self.give_rx(i, buf);
        }
        arch::cpu::dma_barrier();
        self.regs.write32(RDT0, (RX_RING - 1) as u32);
        // Accept broadcast and all multicast (IPv6 ND), strip the CRC.
        // Frames up to one buffer: larger ones are dropped by the NIC, so a
        // frame never spans descriptors.
        self.regs.write32(RLPML, RX_AREA as u32);
        self.regs
            .write32(RCTL, RCTL_EN | RCTL_BAM | RCTL_MPE | RCTL_SECRC | RCTL_LPE);
        Ok(())
    }

    fn setup_tx(&mut self) -> Result<(), Error> {
        let base = self.tx_ring.bus_addr();
        self.regs.write32(TXDCTL0, 0);
        self.regs.write32(TDBAL0, base as u32);
        self.regs.write32(TDBAH0, (base >> 32) as u32);
        self.regs.write32(TDLEN0, self.tx_ring.len() as u32);
        self.regs.write32(TDH0, 0);
        self.regs.write32(TDT0, 0);
        self.enable_queue(TXDCTL0, TXDCTL_WTHRESH_1)?;
        self.regs
            .write32(TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD | TCTL_RTLC);
        Ok(())
    }

    /// Route queue 0 to interrupt vector 0 and unmask it: MSI-X mode when
    /// `msix` (the PCI MSI-X capability is already enabled), else INTx.
    pub fn enable_irq(&mut self, msix: bool) {
        self.regs.write32(EITR0, 0);
        // IVAR0: byte 0 = RX queue 0, byte 1 = TX queue 0 → vector 0.
        self.regs.write32(IVAR0, IVAR_VALID | IVAR_VALID << 8);
        self.msix = msix;
        if msix {
            self.regs
                .write32(GPIE, GPIE_NSICR | GPIE_MSIX_MODE | GPIE_EIAME | GPIE_PBA);
            self.regs.write32(EIAC, 1); // auto-clear EICR bit 0 on the message
            self.regs.write32(EIAM, 1); // and auto-mask it (EIMS bit 0)
            self.regs.write32(EIMS, 1);
        } else {
            self.regs.write32(GPIE, GPIE_NSICR);
            self.regs
                .write32(IMS, ICR_TXDW | ICR_LSC | ICR_RXDMT0 | ICR_RXO | ICR_RXT0);
        }
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Link state: (up, speed in Mbit/s, full duplex).
    pub fn link(&mut self) -> (bool, u32, bool) {
        let s = self.regs.read32(STATUS);
        let speed = match (s >> 6) & 3 {
            0 => 10,
            1 => 100,
            _ => 1000,
        };
        (s & STATUS_LU != 0, speed, s & STATUS_FD != 0)
    }

    /// The link state, if it changed since the last call.
    pub fn link_changed(&mut self) -> Option<(bool, u32, bool)> {
        let l = self.link();
        (self.link_reported != Some(l)).then(|| {
            self.link_reported = Some(l);
            l
        })
    }

    /// INTx: clear the interrupt cause (read-to-clear; with `GPIE.NSICR`
    /// this also de-asserts the line). MSI-X: nothing to do (`EIAC`).
    pub fn ack_interrupt(&mut self) {
        if !self.msix {
            let _ = self.regs.read32(ICR);
        }
    }

    /// MSI-X: the device masked vector 0 when it fired (`EIAM`); re-arm it.
    pub fn unmask_irq(&mut self) {
        self.regs.write32(EIMS, 1);
    }

    /// The device masks its own interrupt (MSI-X with `EIAM`) and is
    /// re-armed by [`Self::unmask_irq`], not at the interrupt controller.
    pub fn self_masking(&self) -> bool {
        self.msix
    }

    /// Put `buf` into RX descriptor `i`. The device owns it once `RDT`
    /// moves past `i`.
    fn give_rx(&mut self, i: usize, mut buf: PacketBuf) {
        let area = buf.rx_area_mut();
        assert!(area.len() >= RX_AREA);
        let addr = dma::bus_addr(area.as_mut_ptr());
        assert!(self.rx_slots[i].is_none(), "igb: rx slot {i} in use");
        self.rx_slots[i] = Some(buf);
        // SAFETY: the buffer (RX_AREA bytes = SRRCTL.BSIZEPACKET) now lives
        // in `rx_slots[i]` and is only taken out after the device set DD
        // on descriptor `i` (`receive`), or after `Drop` stopped the device.
        unsafe { self.rx_ring.write_buffer_addr(i * DESC, addr) };
        self.rx_ring.write64(i * DESC + 8, 0); // header buffer unused; clears DD
    }

    fn flush_rx_tail(&mut self) {
        if self.rx_unflushed > 0 {
            arch::cpu::dma_barrier(); // descriptors before the doorbell
            // Hand over everything before `rx_next - 1`; that one stays held back.
            let tail = (self.rx_next + RX_RING - 1) % RX_RING;
            self.regs.write32(RDT0, tail as u32);
            self.rx_unflushed = 0;
        }
    }

    /// Take one received frame, if any, and refill its descriptor.
    pub fn receive(&mut self) -> Option<PacketBuf> {
        loop {
            let i = self.rx_next;
            let status = self.rx_ring.read32(i * DESC + 8);
            if status & RXD_STAT_DD == 0 {
                self.flush_rx_tail();
                return None;
            }
            arch::cpu::dma_barrier(); // DD before the rest of the write-back
            let len = (self.rx_ring.read32(i * DESC + 12) & 0xffff) as usize;
            let mut buf = self.rx_slots[i].take().expect("igb: empty rx slot");
            self.rx_next = (i + 1) % RX_RING;
            self.rx_unflushed += 1;
            let good = status & RXD_STAT_EOP != 0 && status & RXD_ERR_FRAME == 0 && len > 0;
            let fresh = if good { PacketBuf::alloc() } else { None };
            let Some(fresh) = fresh else {
                // Bad frame, or the pool is empty: drop it and reuse the
                // buffer. The ring must never run dry.
                if good {
                    self.stats.rx_dropped_no_buf += 1;
                }
                self.give_rx(i, buf);
                if self.rx_unflushed >= RX_TAIL_BATCH {
                    self.flush_rx_tail();
                }
                continue;
            };
            self.give_rx(i, fresh);
            if self.rx_unflushed >= RX_TAIL_BATCH {
                self.flush_rx_tail();
            }
            buf.set_rx_range(0, len.min(RX_AREA));
            self.stats.rx_packets += 1;
            self.stats.rx_bytes += len as u64;
            return Some(buf);
        }
    }

    /// Free buffers of completed transmissions.
    pub fn reap_tx(&mut self) {
        while self.tx_clean != self.tx_next {
            let i = self.tx_clean;
            if self.tx_ring.read32(i * DESC + 12) & TXD_STAT_DD == 0 {
                break;
            }
            arch::cpu::dma_barrier();
            let buf = self.tx_slots[i].take().expect("igb: empty tx slot");
            self.tx_inflight_bytes -= buf.len();
            self.tx_clean = (i + 1) % TX_RING;
            // `buf` drops here and returns to the pool.
        }
    }

    fn tx_inflight(&self) -> usize {
        (self.tx_next + TX_RING - self.tx_clean) % TX_RING
    }

    /// Room for one more frame? (descriptors *and* the in-flight byte limit)
    pub fn can_transmit(&self) -> bool {
        self.tx_inflight() < TX_RING - 1 && self.tx_inflight_bytes < self.tx_byte_limit
    }

    /// Transmit an Ethernet frame (without FCS; the NIC appends it and pads
    /// short frames). Check [`Self::can_transmit`] first.
    pub fn transmit(&mut self, pkt: PacketBuf) -> Result<(), PacketBuf> {
        let len = pkt.len();
        if !self.can_transmit() || len == 0 || len > 0xffff {
            return Err(pkt);
        }
        let i = self.tx_next;
        let addr = dma::bus_addr(pkt.data().as_ptr());
        self.tx_slots[i] = Some(pkt);
        // SAFETY: the packet (`len` bytes at `addr`) now lives in
        // `tx_slots[i]` and is only taken out after the device set DD on
        // descriptor `i` (`reap_tx`).
        unsafe { self.tx_ring.write_buffer_addr(i * DESC, addr) };
        self.tx_ring.write32(
            i * DESC + 8,
            len as u32 | TXD_DTYP_DATA | TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS | TXD_CMD_DEXT,
        );
        self.tx_ring
            .write32(i * DESC + 12, (len as u32) << TXD_PAYLEN_SHIFT);
        self.tx_next = (i + 1) % TX_RING;
        self.tx_inflight_bytes += len;
        arch::cpu::dma_barrier(); // descriptor before the doorbell
        self.regs.write32(TDT0, self.tx_next as u32);
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += len as u64;
        Ok(())
    }
}

impl Drop for Igb {
    /// Stop DMA before the fields drop (slot buffers return to the pool).
    fn drop(&mut self) {
        self.disable_irqs();
        self.regs.write32(RCTL, 0);
        self.regs.write32(TCTL, TCTL_PSP);
        busy_wait(Duration::from_millis(10));
        self.regs.modify32(CTRL, |c| c | CTRL_RST);
        busy_wait(Duration::from_millis(1));
    }
}
