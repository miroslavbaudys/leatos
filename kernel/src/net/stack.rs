//! Ports and the datapath task.
//!
//! - WAN (first NIC: virtio-net or igb, in PCI order), LAN (second NIC).
//! - [`bring_up`] creates per port: the NIC ([`Port`], datapath-owned), the
//!   qdisc and `local_rx` queue (`net::shared::PortShared`), and the router
//!   stack's smoltcp interface (`net::svc::HostIf`, services-owned).
//! - [`run`], the datapath task (`Priority::Datapath`): NIC RX →
//!   `net::datapath` (forward / local / drop) → qdiscs → NIC TX. The
//!   router's own stack and services run in `net::svc::run`
//!   (`Priority::Service`), so they never delay forwarding by more than
//!   one of their polls.
//!
//! Interrupts work NAPI-style: the IRQ action masks the INTx line; this task
//! wakes, clears the device's interrupt status, polls until idle, and
//! unmasks.

use crate::drivers::{self, Nic};
use crate::irq::{self, IrqEvent, Trigger};
use crate::net::datapath::{self, Datapath};
use crate::net::device::{Aqm, PortDevice, PortQdisc};
use crate::net::mgmt::Action;
use crate::net::shared::{self, LOCAL_RX_MAX, PortShared, PortSnap, Shared};
use crate::net::svc::HostIf;
use crate::pci::Pci;
use crate::{arch, println, timer};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::dhcpv4;
use smoltcp::time::Instant as NetInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Cidr};
use spin::Mutex;

/// Egress qdisc hard limits per port (shared by all flows). The AQM keeps
/// standing queues near 5 ms; the limits only bound bursts. Two full queues plus both RX rings
/// (2 × 384 + 128 = 896) stay within the 1024-buffer packet pool.
const QDISC_PACKETS: usize = 384;
const QDISC_BYTES: usize = 384 * 1514;

pub fn lan_cidr() -> Ipv4Cidr {
    let lan = crate::config::lan();
    Ipv4Cidr::new(lan.addr, lan.prefix)
}

/// Per-port variation for the AQM's random seed.
fn mac_seed(mac: &[u8; 6]) -> u64 {
    mac.iter().fold(0, |a, &b| a << 8 | b as u64)
}

/// The datapath's half of a port: the NIC and its interrupt.
pub struct Port {
    pub name: &'static str,
    pub dev: Nic,
    /// Last known link state (up, Mbit/s, full duplex), if the NIC reports one.
    pub link: Option<(bool, u32, bool)>,
    irq: Option<(u32, &'static IrqEvent)>,
    masked: bool,
}

pub fn now() -> NetInstant {
    NetInstant::from_micros(timer::uptime().as_micros() as i64)
}

/// IRQ context: mask the (level-triggered, possibly shared) INTx line until
/// the network task has drained the device.
fn mask_intx(intid: u32) {
    arch::irqchip::disable(intid);
}

/// Bring up the first two supported NICs: first = WAN, second = LAN.
/// WAN egress is shaped at the upload rate, LAN egress at the download rate.
/// Returns the datapath's ports, the services' router-stack interfaces and
/// the shared state (`None` without NICs).
pub fn bring_up(
    pci: &mut Pci,
    qos: &crate::config::Qos,
) -> Option<(Vec<Port>, Vec<HostIf>, &'static Shared)> {
    let devs: Vec<_> = pci
        .devices
        .iter()
        .filter(|d| drivers::is_nic(d))
        .cloned()
        .collect();
    let mut ports = Vec::new();
    let mut shared_ports = Vec::new();
    let mut hosts = Vec::new();
    for (i, d) in devs.iter().enumerate().take(2) {
        let name = if i == 0 { "wan0" } else { "lan0" };
        let mut dev = match Nic::new(pci, d) {
            Ok(dev) => dev,
            Err(e) => {
                println!("  net {name}: init failed: {e:?}");
                continue;
            }
        };
        let mac = dev.mac();
        let rate = qos.rate(if i == 0 { qos.up_kbit } else { qos.down_kbit });
        let ecn = if i == 0 { qos.ecn_up } else { qos.ecn_down };
        let aqm = Aqm::new(
            qos,
            ecn,
            QDISC_PACKETS,
            QDISC_BYTES,
            timer::ticks() ^ mac_seed(&mac),
        );
        let desc = aqm.describe(ecn);
        let qdisc = PortQdisc::new(aqm, rate);
        match rate {
            Some(r) => println!(
                "  qos {name}       : shaped {} kbit/s ({}), overhead {} B, {desc}",
                r.bits_per_sec / 1000,
                if i == 0 { "upload" } else { "download" },
                r.overhead,
            ),
            None => println!("  qos {name}       : unshaped, {desc}"),
        }
        let port = PortShared {
            name,
            model: dev.model(),
            mac,
            qdisc: Mutex::new(qdisc),
            local_rx: Mutex::new(VecDeque::with_capacity(LOCAL_RX_MAX)),
            snap: Mutex::new(PortSnap::default()),
        };
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        config.random_seed = timer::ticks();
        let mut queued = 0;
        let mut device = PortDevice {
            port: &port,
            now_ns: datapath::now_ns(),
            queued: &mut queued,
        };
        let mut iface = Interface::new(config, &mut device, now());
        let mut sockets = SocketSet::new(Vec::new());
        if i == 0 {
            sockets.add(dhcpv4::Socket::new());
        } else {
            iface.update_ip_addrs(|a| a.push(IpCidr::Ipv4(lan_cidr())).expect("lan addr"));
        }
        // Legacy INTx where the platform routes it (aarch64 DTB), otherwise
        // MSI-X (x86_64: INTx routing would need ACPI AML).
        let line = d.intx.map(|intid| (intid, Trigger::Level, "")).or_else(|| {
            let vector = arch::irqchip::msi_vector(i)?;
            dev.prepare_msix(pci, d).ok()?;
            pci.enable_msix(d, vector)?;
            Some((vector, Trigger::Edge, " (MSI-X)"))
        });
        let irq = line.map(|(intid, trigger, kind)| {
            let ev = irq::new_event();
            irq::register(intid, mask_intx, ev);
            arch::irqchip::enable(intid, trigger);
            dev.enable_irq(trigger == Trigger::Edge);
            (intid, ev, kind)
        });
        println!(
            "  net {name}       : {} {} mac {} {}",
            dev.model(),
            d.df,
            EthernetAddress(mac),
            match irq {
                Some((intid, _, kind)) => alloc::format!("intid {intid}{kind}"),
                None => alloc::string::String::from("(no irq: polling)"),
            }
        );
        if i == 1 {
            println!("  net {name}       : {} (static)", lan_cidr());
        }
        ports.push(Port {
            name,
            dev,
            irq: irq.map(|(intid, ev, _)| (intid, ev)),
            masked: false,
            link: None,
        });
        shared_ports.push(port);
        hosts.push(HostIf { iface, sockets });
    }
    if ports.is_empty() {
        return None;
    }
    Some((ports, hosts, shared::init(shared_ports)))
}

/// Wait until any of `events` fires or the sleep ends.
pub struct WaitAny<'a> {
    pub events: &'a [&'static IrqEvent],
    pub sleep: timer::Sleep,
}

impl Future for WaitAny<'_> {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut ready = false;
        for ev in self.events {
            // Non-consuming, and no early return: every event gets the waker,
            // and the main loop still sees (and handles) the fired flags.
            ready |= ev.poll_fired(cx).is_ready();
        }
        if ready || Pin::new(&mut self.sleep).poll(cx).is_ready() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// The datapath task: never returns (except into a reboot or a new kernel).
pub async fn run(mut ports: Vec<Port>, sh: &'static Shared) {
    let mut dp = Datapath::new(sh);
    let mut events: Vec<&'static IrqEvent> =
        ports.iter().filter_map(|n| n.irq.map(|(_, e)| e)).collect();
    events.push(sh.dp_kick);

    loop {
        sh.dp_kick.take();
        // NAPI step 1: IRQ fired → clear device interrupt status.
        for nif in ports.iter_mut() {
            if let Some((_, ev)) = nif.irq
                && ev.take()
            {
                nif.masked = true;
            }
            if nif.masked {
                nif.dev.ack_interrupt();
            }
        }

        // Step 2: received frames → forwarder (forward / local / drop).
        dp.rx(&mut ports);

        // Step 3: messages from the services task.
        let (wan, action) = {
            let mut c = sh.control.lock();
            (c.wan.take(), c.action.take())
        };
        if let Some(w) = wan {
            dp.set_wan(w.addr, w.gateway);
        }
        if let Some(action) = action {
            // Quiesce: dropping the ports resets the NICs (no more DMA).
            drop(ports);
            match action {
                Action::Reboot => arch::power::reset(),
                Action::Exec(staging, prepared, cmdline) => {
                    crate::upgrade::exec(staging, prepared, &cmdline)
                }
            }
        }
        dp.housekeeping(&mut ports);

        // Step 4: qdiscs → NICs (pull, while the NIC has room and the shaper allows).
        let tx = dp.flush_tx(&mut ports);
        dp.publish(&ports);

        // Step 5: unmask lines we masked (a still-pending device re-fires).
        for nif in ports.iter_mut() {
            if nif.masked
                && let Some((intid, _)) = nif.irq
            {
                nif.masked = false;
                arch::irqchip::enable(intid, Trigger::Level);
            }
        }

        // Step 6: sleep until an IRQ, a kick from the services or the next deadline.
        if dp.more_rx {
            crate::executor::yield_now().await;
            continue;
        }
        let hk = dp
            .next_housekeeping()
            .saturating_sub(timer::uptime().as_millis() as u64);
        let mut delay = Duration::from_millis(hk);
        // A shaper holding packets: wake exactly when it releases the next one.
        if let Some(at) = tx.shaper_wake_ns {
            delay = delay.min(Duration::from_nanos(at.saturating_sub(datapath::now_ns())));
        }
        // TX completion normally raises an interrupt; poll as a fallback while
        // a NIC ring is full with a backlog, and for devices without an IRQ.
        if tx.ring_full_backlog || ports.iter().any(|n| n.irq.is_none()) {
            delay = delay.min(Duration::from_millis(1));
        }
        WaitAny {
            events: &events,
            sleep: timer::sleep(delay),
        }
        .await;
    }
}
