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

/// The datapath's half of a port: the NIC and its interrupt. Shared by the
/// two direction tasks (one receives on it, the other transmits), so the
/// NIC is locked; `None` once the NICs were stopped for a reboot/upgrade.
/// Lock order: NIC, then the datapath, then a qdisc (never the reverse).
pub struct Port {
    pub name: &'static str,
    pub dev: Mutex<Option<Nic>>,
    /// Last known link state (up, Mbit/s, full duplex), if the NIC reports one.
    pub link: Mutex<Option<(bool, u32, bool)>>,
    irq: Option<(u32, &'static IrqEvent)>,
}

pub fn now() -> NetInstant {
    NetInstant::from_micros(timer::uptime().as_micros() as i64)
}

/// IRQ context: mask the (level-triggered, possibly shared) INTx line until
/// the network task has drained the device.
fn mask_intx(intid: u32) {
    arch::irqchip::disable(intid);
}

/// Where the network tasks run (docs/smp.md): with two ports one datapath
/// task per direction, on their own cores when there are 3+, and the
/// services on the next core.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// `dp_down` (WAN RX → LAN TX), or the single task with one port.
    pub down: usize,
    /// `dp_up` (LAN RX → WAN TX).
    pub up: usize,
    pub svc: usize,
}

pub fn layout(ports: usize, cores: usize) -> Layout {
    match (ports >= 2, cores) {
        (_, 0 | 1) => Layout {
            down: 0,
            up: 0,
            svc: 0,
        },
        (true, 2) | (false, _) => Layout {
            down: 0,
            up: 0,
            svc: 1,
        },
        (true, _) => Layout {
            down: 0,
            up: 1,
            svc: 2,
        },
    }
}

/// Bring up the first two supported NICs: first = WAN, second = LAN.
/// WAN egress is shaped at the upload rate, LAN egress at the download rate.
/// Returns the datapath's ports, the services' router-stack interfaces and
/// the shared state (`None` without NICs).
pub fn bring_up(
    pci: &mut Pci,
    qos: &crate::config::Qos,
) -> Option<(&'static [Port], Vec<HostIf>, &'static Shared)> {
    let devs: Vec<_> = pci
        .devices
        .iter()
        .filter(|d| drivers::is_nic(d))
        .cloned()
        .collect();
    let mut ports = Vec::new();
    let mut shared_ports = Vec::new();
    let mut hosts = Vec::new();
    let lay = layout(devs.len().min(2), crate::smp::online());
    for (i, d) in devs.iter().enumerate().take(2) {
        // Interrupts go to the core of the task that receives on this port.
        let rx_core = if i == 0 { lay.down } else { lay.up };
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
            pci.enable_msix(d, vector, rx_core)?;
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
            dev: Mutex::new(Some(dev)),
            irq: irq.map(|(intid, ev, _)| (intid, ev)),
            link: Mutex::new(None),
        });
        shared_ports.push(port);
        hosts.push(HostIf { iface, sockets });
    }
    if ports.is_empty() {
        return None;
    }
    Some((
        alloc::boxed::Box::leak(ports.into_boxed_slice()),
        hosts,
        shared::init(shared_ports),
    ))
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

/// One direction of the datapath: receive on port `rx`, forward, transmit
/// the queue of port `tx` (download = WAN → LAN, upload = LAN → WAN; one
/// task for both when there is a single port). The `primary` direction
/// also handles control messages, housekeeping and the status snapshot.
#[derive(Clone, Copy)]
pub struct Dir {
    pub rx: usize,
    pub tx: usize,
    pub primary: bool,
}

/// The forwarding state both directions share.
pub type SharedDatapath = &'static Mutex<Datapath>;

pub fn new_datapath(sh: &'static Shared) -> SharedDatapath {
    alloc::boxed::Box::leak(alloc::boxed::Box::new(Mutex::new(Datapath::new(sh))))
}

/// Wait forever (the NICs were stopped; the primary task is rebooting).
async fn park() -> ! {
    loop {
        timer::sleep(Duration::from_secs(3600)).await;
    }
}

/// Primary only: link state and counters of every port, once a second.
fn poll_links(ports: &[Port], sh: &Shared) {
    for (port, sp) in ports.iter().zip(&sh.ports) {
        let mut g = port.dev.lock();
        let Some(dev) = g.as_mut() else { continue };
        let changed = dev.link_changed();
        let stats = dev.stats();
        drop(g);
        let mut link = port.link.lock();
        if changed.is_some() {
            *link = changed;
        }
        match changed {
            Some((true, speed, fd)) => println!(
                "  net {}       : link up, {speed} Mbit/s {} duplex",
                port.name,
                if fd { "full" } else { "half" }
            ),
            Some((false, ..)) => println!("  net {}       : link down", port.name),
            None => {}
        }
        *sp.snap.lock() = PortSnap { stats, link: *link };
    }
}

/// A datapath direction task: never returns (except into a reboot or a
/// new kernel, from the primary task).
pub async fn run_dir(d: Dir, ports: &'static [Port], sh: &'static Shared, dp: SharedDatapath) {
    let rx = &ports[d.rx];
    let mut events: Vec<&'static IrqEvent> = rx.irq.map(|(_, e)| e).into_iter().collect();
    events.push(sh.tx_kick[d.tx]);
    if d.primary {
        events.push(sh.dp_kick);
    }
    let mut batch = Vec::with_capacity(datapath::RX_BUDGET);
    let mut masked = false;
    let mut next_links = 0u64;
    loop {
        sh.tx_kick[d.tx].take();
        if d.primary {
            sh.dp_kick.take();
        }
        // NAPI step 1: IRQ fired → clear device interrupt status. The TX
        // side of this NIC (the other direction) may have completions.
        if let Some((_, ev)) = rx.irq
            && ev.take()
        {
            masked = true;
            if d.rx != d.tx {
                sh.tx_kick[d.rx].signal();
            }
        }
        // Step 2: take a batch off the NIC (short lock), then forward it.
        let more = {
            let mut g = rx.dev.lock();
            let Some(dev) = g.as_mut() else {
                drop(g);
                park().await
            };
            if masked {
                dev.ack_interrupt();
            }
            while batch.len() < datapath::RX_BUDGET {
                match dev.receive() {
                    Some(p) => batch.push(p),
                    None => break,
                }
            }
            batch.len() == datapath::RX_BUDGET
        };
        let mut touched = [false; 2];
        if !batch.is_empty() {
            let mut g = dp.lock();
            g.rx_batch(d.rx as fwd::IfIndex, &mut batch);
            touched = g.take_touched();
        }

        // Step 3 (primary): control messages, housekeeping, status.
        let mut next_hk = u64::MAX;
        if d.primary {
            let (wan, action) = {
                let mut c = sh.control.lock();
                (c.wan.take(), c.action.take())
            };
            if let Some(action) = action {
                // Quiesce: dropping the NICs resets them (no more DMA); the
                // other direction then parks.
                for port in ports {
                    drop(port.dev.lock().take());
                }
                match action {
                    Action::Reboot => arch::power::reset(),
                    Action::Exec(staging, prepared, cmdline) => {
                        crate::upgrade::exec(staging, prepared, &cmdline)
                    }
                }
            }
            {
                let mut g = dp.lock();
                if let Some(w) = wan {
                    g.set_wan(w.addr, w.gateway);
                }
                g.housekeeping();
                let t = g.take_touched();
                touched = [touched[0] | t[0], touched[1] | t[1]];
                next_hk = g.next_housekeeping();
            }
            let now = timer::uptime().as_millis() as u64;
            if now >= next_links {
                next_links = now + 1000;
                poll_links(ports, sh);
            }
        }
        for (p, &t) in touched.iter().enumerate() {
            if t && p != d.tx && p < sh.tx_kick.len() {
                sh.tx_kick[p].signal();
            }
        }

        // Step 4: this direction's qdisc → NIC.
        let tx = {
            let mut g = ports[d.tx].dev.lock();
            let Some(dev) = g.as_mut() else {
                drop(g);
                park().await
            };
            datapath::flush_port(&sh.ports[d.tx], dev)
        };

        // Step 5: unmask (a still-pending device re-fires). On aarch64 this
        // also routes the line to this core.
        if masked && let Some((intid, _)) = rx.irq {
            masked = false;
            arch::irqchip::enable(intid, Trigger::Level);
        }

        // Step 6: sleep until an IRQ, a kick or the next deadline.
        if more {
            crate::executor::yield_now().await;
            continue;
        }
        // Primary: next housekeeping / link poll; otherwise only events.
        let now_ms = timer::uptime().as_millis() as u64;
        let due = if d.primary {
            next_hk.min(next_links)
        } else {
            u64::MAX
        };
        let mut delay = Duration::from_millis(due.saturating_sub(now_ms).min(1000));
        if let Some(at) = tx.shaper_wake_ns {
            delay = delay.min(Duration::from_nanos(at.saturating_sub(datapath::now_ns())));
        }
        // TX completion normally raises an interrupt (handled by the other
        // direction, which kicks us); poll as a fallback while the ring is
        // full with a backlog, and for devices without an IRQ.
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
