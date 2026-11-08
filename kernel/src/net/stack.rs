//! The router's own IP stack (smoltcp) on the WAN and LAN interfaces.
//!
//! - WAN (first virtio-net): DHCPv4 client (smoltcp socket for now;
//!   `crates/proto-dhcp` takes over later).
//! - LAN (second virtio-net): static 192.168.1.1/24.
//! - After a lease: ICMP echo to the gateway (proves RX + TX + IRQs).
//!
//! Interrupts work NAPI-style: the IRQ action masks the INTx line; this task
//! wakes, clears the device's interrupt status, polls until idle, and
//! unmasks. The task runs at `Priority::Datapath`.
//!
//! The forwarding plane (M4) will sit beside this: packets *for* the router
//! go to smoltcp, packets *through* it go to `crates/fwd`.

use crate::drivers::virtio_net::VirtioNet;
use crate::irq::{self, IrqEvent, Trigger};
use crate::net::services::LanServices;
use crate::pci::Pci;
use crate::{arch, println, timer};
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

pub struct NetIf {
    pub name: &'static str,
    pub dev: VirtioNet,
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
pub fn bring_up(pci: &mut Pci) -> Vec<NetIf> {
    let devs: Vec<_> = pci
        .devices
        .iter()
        .filter(|d| d.is_virtio_net())
        .cloned()
        .collect();
    let mut ifs = Vec::new();
    for (i, d) in devs.iter().enumerate().take(2) {
        let name = if i == 0 { "wan0" } else { "lan0" };
        let mut dev = match VirtioNet::new(pci, d) {
            Ok(dev) => dev,
            Err(e) => {
                println!("  net {name}: init failed: {e:?}");
                continue;
            }
        };
        let mac = dev.mac();
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        config.random_seed = timer::ticks();
        let mut iface = Interface::new(config, &mut dev, now());
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

/// Returns the new upstream DNS server list when the lease changed.
fn handle_dhcp(nif: &mut NetIf, pinger: &mut Pinger) -> Option<Vec<Ipv4Address>> {
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
            Some(cfg.dns_servers.iter().copied().collect())
        }
        Some(dhcpv4::Event::Deconfigured) => {
            if DHCP_OK.load(Ordering::Acquire) {
                println!("  net {}         : dhcp lease lost", nif.name);
            }
            nif.iface.update_ip_addrs(|a| a.clear());
            nif.iface.routes_mut().remove_default_ipv4_route();
            DHCP_OK.store(false, Ordering::Release);
            pinger.target = None;
            Some(Vec::new())
        }
        None => None,
    }
}

/// The network task: never returns.
pub async fn run(mut ifs: Vec<NetIf>) {
    if ifs.is_empty() {
        return;
    }
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

        // Step 2: process everything pending.
        let t = now();
        for nif in ifs.iter_mut() {
            nif.iface.poll(t, &mut nif.dev, &mut nif.sockets);
        }
        if let Some(upstreams) = handle_dhcp(&mut ifs[0], &mut pinger)
            && let Some(svc) = services.as_mut()
        {
            svc.set_upstreams(&upstreams);
        }
        pinger.step(&mut ifs[0].sockets);
        if let Some(svc) = services.as_mut() {
            let (wan, lan) = ifs.split_at_mut(1);
            svc.step(&mut lan[0].sockets, Some(&mut wan[0].sockets));
        }
        let t = now();
        for nif in ifs.iter_mut() {
            nif.iface.poll(t, &mut nif.dev, &mut nif.sockets);
        }

        // Step 3: unmask lines we masked (a still-pending device re-fires).
        for nif in ifs.iter_mut() {
            if nif.masked
                && let Some((intid, _)) = nif.irq
            {
                nif.masked = false;
                arch::irqchip::enable(intid, Trigger::Level);
            }
        }

        // Step 4: sleep until an IRQ or the next protocol deadline.
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
        // Devices without an IRQ are polled at least every millisecond.
        if ifs.iter().any(|n| n.irq.is_none()) {
            delay = delay.min(Duration::from_millis(1));
        }
        WaitAny {
            events: &events,
            sleep: timer::sleep(delay),
        }
        .await;
    }
}
