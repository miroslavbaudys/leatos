//! The network task: ports (NIC + qdisc + router stack), the forwarding
//! datapath, and the router's own services.
//!
//! - WAN (first virtio-net): DHCPv4 client (smoltcp socket for now).
//! - LAN (second virtio-net): static 192.168.1.1/24, DHCP server, DNS.
//! - Every received frame goes through `net::datapath` first: frames for
//!   the router reach smoltcp, everything else is forwarded (NAT, firewall).
//! - After a WAN lease: ICMP echo to the gateway (boot self-test).
//!
//! Interrupts work NAPI-style: the IRQ action masks the INTx line; this task
//! wakes, clears the device's interrupt status, polls until idle, and
//! unmasks. The task runs at `Priority::Datapath`.

use crate::drivers::virtio_net::VirtioNet;
use crate::irq::{self, IrqEvent, Trigger};
use crate::net::datapath::{self, Datapath};
use crate::net::device::{Aqm, PortDevice, PortQdisc};
use crate::net::packet::PacketBuf;
use crate::net::services::LanServices;
use crate::pci::Pci;
use crate::{arch, println, timer};
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{dhcpv4, icmp};
use smoltcp::time::Instant as NetInstant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address,
    Ipv4Cidr,
};

/// Set once the WAN has a DHCP lease (read by the boot self-test).
pub static DHCP_OK: AtomicBool = AtomicBool::new(false);
/// Set once the gateway answered a ping.
pub static PING_OK: AtomicBool = AtomicBool::new(false);

const LAN_ADDR: Ipv4Cidr = Ipv4Cidr::new(Ipv4Address::new(192, 168, 1, 1), 24);
const PING_IDENT: u16 = 0x22b;
const PING_COUNT: u16 = 3;
const PING_INTERVAL: Duration = Duration::from_millis(200);

/// Egress qdisc hard limits per port (shared by all flows). The AQM keeps
/// standing queues near 5 ms; the limits only bound bursts. Two full queues plus both RX rings
/// (2 × 384 + 128 = 896) stay within the 1024-buffer packet pool.
const QDISC_PACKETS: usize = 384;
const QDISC_BYTES: usize = 384 * 1514;

/// Per-port variation for the AQM's random seed.
fn mac_seed(mac: &[u8; 6]) -> u64 {
    mac.iter().fold(0, |a, &b| a << 8 | b as u64)
}

pub struct NetIf {
    pub name: &'static str,
    pub dev: VirtioNet,
    /// Egress queue: forwarded traffic and the router's own traffic.
    pub qdisc: PortQdisc,
    /// Frames for the router stack (filled by the datapath, drained by smoltcp).
    pub local_rx: VecDeque<PacketBuf>,
    iface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    irq: Option<(u32, &'static IrqEvent)>,
    masked: bool,
}

fn now() -> NetInstant {
    NetInstant::from_micros(timer::uptime().as_micros() as i64)
}

/// IRQ context: mask the (level-triggered, possibly shared) INTx line until
/// the network task has drained the device.
fn mask_intx(intid: u32) {
    arch::irqchip::disable(intid);
}

/// Bring up every virtio-net device: first = WAN, second = LAN.
/// WAN egress is shaped at the upload rate, LAN egress at the download rate.
pub fn bring_up(pci: &mut Pci, qos: &crate::config::Qos) -> Vec<NetIf> {
    let devs: Vec<_> = pci
        .devices
        .iter()
        .filter(|d| d.is_virtio_net())
        .cloned()
        .collect();
    let mut ifs = Vec::new();
    for (i, d) in devs.iter().enumerate().take(2) {
        let name = if i == 0 { "wan0" } else { "lan0" };
        let dev = match VirtioNet::new(pci, d) {
            Ok(dev) => dev,
            Err(e) => {
                println!("  net {name}: init failed: {e:?}");
                continue;
            }
        };
        let mac = dev.mac();
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        config.random_seed = timer::ticks();
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
        let mut qdisc = PortQdisc::new(aqm, rate);
        match rate {
            Some(r) => println!(
                "  qos {name}       : shaped {} kbit/s ({}), overhead {} B, {desc}",
                r.bits_per_sec / 1000,
                if i == 0 { "upload" } else { "download" },
                r.overhead,
            ),
            None => println!("  qos {name}       : unshaped, {desc}"),
        }
        let mut local_rx = VecDeque::with_capacity(datapath::LOCAL_RX_MAX);
        let mut port = PortDevice {
            local_rx: &mut local_rx,
            qdisc: &mut qdisc,
            now_ns: datapath::now_ns(),
        };
        let mut iface = Interface::new(config, &mut port, now());
        let mut sockets = SocketSet::new(Vec::new());
        if i == 0 {
            sockets.add(dhcpv4::Socket::new());
        } else {
            iface.update_ip_addrs(|a| a.push(IpCidr::Ipv4(LAN_ADDR)).expect("lan addr"));
        }
        let irq = d.intx.map(|intid| {
            let ev = irq::new_event();
            irq::register(intid, mask_intx, ev);
            arch::irqchip::enable(intid, Trigger::Level);
            (intid, ev)
        });
        println!(
            "  net {name}       : virtio-net {} mac {} {}",
            d.df,
            EthernetAddress(mac),
            match irq {
                Some((intid, _)) => alloc::format!("intid {intid}"),
                None => alloc::string::String::from("(no irq: polling)"),
            }
        );
        if i == 1 {
            println!("  net {name}       : {LAN_ADDR} (static)");
        }
        ifs.push(NetIf {
            name,
            dev,
            qdisc,
            local_rx,
            iface,
            sockets,
            irq,
            masked: false,
        });
    }
    ifs
}

/// Wait until any interface IRQ fires or `timeout` passes.
struct WaitAny<'a> {
    events: &'a [&'static IrqEvent],
    sleep: timer::Sleep,
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

struct Pinger {
    socket: SocketHandle,
    target: Option<Ipv4Address>,
    seq: u16,
    sent_at: [Option<timer::Instant>; PING_COUNT as usize],
    next_send: timer::Instant,
    replies: u16,
}

impl Pinger {
    fn new(sockets: &mut SocketSet<'static>) -> Self {
        let rx = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 512]);
        let tx = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 512]);
        let mut sock = icmp::Socket::new(rx, tx);
        sock.bind(icmp::Endpoint::Ident(PING_IDENT))
            .expect("icmp bind");
        Self {
            socket: sockets.add(sock),
            target: None,
            seq: 0,
            sent_at: [None; PING_COUNT as usize],
            next_send: timer::Instant::now(),
            replies: 0,
        }
    }

    fn step(&mut self, sockets: &mut SocketSet<'static>) {
        let Some(target) = self.target else { return };
        let sock = sockets.get_mut::<icmp::Socket>(self.socket);
        let caps = ChecksumCapabilities::default();

        if self.seq < PING_COUNT && sock.can_send() && timer::Instant::now() >= self.next_send {
            let repr = Icmpv4Repr::EchoRequest {
                ident: PING_IDENT,
                seq_no: self.seq,
                data: b"rrouter",
            };
            if let Ok(buf) = sock.send(repr.buffer_len(), IpAddress::Ipv4(target)) {
                repr.emit(&mut Icmpv4Packet::new_unchecked(buf), &caps);
                self.sent_at[self.seq as usize] = Some(timer::Instant::now());
                self.seq += 1;
                self.next_send = timer::Instant::now().checked_add(PING_INTERVAL).unwrap();
            }
        }

        while let Ok((payload, from)) = sock.recv() {
            let Ok(pkt) = Icmpv4Packet::new_checked(payload) else {
                continue;
            };
            if let Ok(Icmpv4Repr::EchoReply {
                ident: PING_IDENT,
                seq_no,
                ..
            }) = Icmpv4Repr::parse(&pkt, &caps)
                && let Some(Some(t0)) = self.sent_at.get(seq_no as usize)
            {
                println!(
                    "  net ping        : {from} seq={seq_no} rtt={} us",
                    t0.elapsed().as_micros()
                );
                self.replies += 1;
                PING_OK.store(true, Ordering::Release);
            }
        }
    }

    fn deadline(&self) -> Option<timer::Instant> {
        (self.target.is_some() && self.seq < PING_COUNT).then_some(self.next_send)
    }
}

/// A WAN lease change: (address/prefix, gateway, DNS servers); `None` fields = lost.
struct LeaseChange {
    addr: Option<(Ipv4Address, u8)>,
    gateway: Option<Ipv4Address>,
    dns: Vec<Ipv4Address>,
}

fn handle_dhcp(nif: &mut NetIf, pinger: &mut Pinger) -> Option<LeaseChange> {
    let (handle, _) = nif
        .sockets
        .iter()
        .find(|(_, s)| matches!(s, smoltcp::socket::Socket::Dhcpv4(_)))?;
    let event = nif.sockets.get_mut::<dhcpv4::Socket>(handle).poll();
    match event {
        Some(dhcpv4::Event::Configured(cfg)) => {
            nif.iface.update_ip_addrs(|a| {
                a.clear();
                a.push(IpCidr::Ipv4(cfg.address)).expect("wan addr");
            });
            match cfg.router {
                Some(gw) => {
                    nif.iface
                        .routes_mut()
                        .add_default_ipv4_route(gw)
                        .expect("route");
                }
                None => {
                    nif.iface.routes_mut().remove_default_ipv4_route();
                }
            }
            let dns: Vec<_> = cfg
                .dns_servers
                .iter()
                .map(|d| alloc::format!("{d}"))
                .collect();
            println!(
                "  net {}         : dhcp lease {} gw {} dns [{}]",
                nif.name,
                cfg.address,
                cfg.router
                    .map(|r| alloc::format!("{r}"))
                    .unwrap_or_else(|| "-".into()),
                dns.join(", ")
            );
            DHCP_OK.store(true, Ordering::Release);
            pinger.target = cfg.router;
            Some(LeaseChange {
                addr: Some((cfg.address.address(), cfg.address.prefix_len())),
                gateway: cfg.router,
                dns: cfg.dns_servers.iter().copied().collect(),
            })
        }
        Some(dhcpv4::Event::Deconfigured) => {
            if DHCP_OK.load(Ordering::Acquire) {
                println!("  net {}         : dhcp lease lost", nif.name);
            }
            nif.iface.update_ip_addrs(|a| a.clear());
            nif.iface.routes_mut().remove_default_ipv4_route();
            DHCP_OK.store(false, Ordering::Release);
            pinger.target = None;
            Some(LeaseChange {
                addr: None,
                gateway: None,
                dns: Vec::new(),
            })
        }
        None => None,
    }
}

fn poll_stacks(ifs: &mut [NetIf]) {
    let t = now();
    let now_ns = datapath::now_ns();
    for nif in ifs.iter_mut() {
        let mut port = PortDevice {
            local_rx: &mut nif.local_rx,
            qdisc: &mut nif.qdisc,
            now_ns,
        };
        nif.iface.poll(t, &mut port, &mut nif.sockets);
    }
}

/// The network task: never returns.
pub async fn run(mut ifs: Vec<NetIf>) {
    if ifs.is_empty() {
        return;
    }
    let mut dp = Datapath::new(&ifs);
    let mut pinger = Pinger::new(&mut ifs[0].sockets);
    let mut services = (ifs.len() >= 2).then(|| {
        let (wan, lan) = ifs.split_at_mut(1);
        LanServices::new(&mut lan[0], Some(&mut wan[0]))
    });
    let events: Vec<&'static IrqEvent> = ifs.iter().filter_map(|n| n.irq.map(|(_, e)| e)).collect();

    loop {
        // NAPI step 1: IRQ fired → clear device interrupt status.
        for nif in ifs.iter_mut() {
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
        dp.rx(&mut ifs);

        // Step 3: the router's own stack and services.
        poll_stacks(&mut ifs);
        if let Some(change) = handle_dhcp(&mut ifs[0], &mut pinger) {
            dp.set_wan(change.addr, change.gateway);
            if let Some(svc) = services.as_mut() {
                svc.set_upstreams(&change.dns);
            }
        }
        pinger.step(&mut ifs[0].sockets);
        if let Some(svc) = services.as_mut() {
            let (wan, lan) = ifs.split_at_mut(1);
            svc.step(&mut lan[0].sockets, Some(&mut wan[0].sockets));
        }
        poll_stacks(&mut ifs);
        dp.housekeeping(&mut ifs);

        // Step 4: qdiscs → NICs (pull, while the NIC has room and the shaper allows).
        let tx = dp.flush_tx(&mut ifs);

        // Step 5: unmask lines we masked (a still-pending device re-fires).
        for nif in ifs.iter_mut() {
            if nif.masked
                && let Some((intid, _)) = nif.irq
            {
                nif.masked = false;
                arch::irqchip::enable(intid, Trigger::Level);
            }
        }

        // Step 6: sleep until an IRQ or the next deadline.
        if dp.more_rx {
            crate::executor::yield_now().await;
            continue;
        }
        let t = now();
        let mut delay = ifs
            .iter_mut()
            .filter_map(|n| n.iface.poll_delay(t, &n.sockets))
            .map(|d| Duration::from_micros(d.total_micros()))
            .min()
            .unwrap_or(Duration::from_secs(1));
        if let Some(svc) = &services {
            delay = delay.min(
                svc.next_deadline()
                    .saturating_duration_since(timer::Instant::now()),
            );
        }
        if let Some(at) = pinger.deadline() {
            delay = delay.min(at.saturating_duration_since(timer::Instant::now()));
        }
        let hk = dp
            .next_housekeeping()
            .saturating_sub(timer::uptime().as_millis() as u64);
        delay = delay.min(Duration::from_millis(hk));
        // A shaper holding packets: wake exactly when it releases the next one.
        if let Some(at) = tx.shaper_wake_ns {
            delay = delay.min(Duration::from_nanos(at.saturating_sub(datapath::now_ns())));
        }
        // TX completion normally raises an interrupt; poll as a fallback while
        // a NIC ring is full with a backlog, and for devices without an IRQ.
        if tx.ring_full_backlog || ifs.iter().any(|n| n.irq.is_none()) {
            delay = delay.min(Duration::from_millis(1));
        }
        WaitAny {
            events: &events,
            sleep: timer::sleep(delay),
        }
        .await;
    }
}
