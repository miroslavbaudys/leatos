//! The services task (`Priority::Service`): the router's own IP stack
//! (smoltcp, one interface per port) and everything on top of it:
//!
//! - WAN: DHCPv4 client (smoltcp socket); after a lease, ICMP echo to the
//!   gateway (boot self-test).
//! - LAN: DHCP server and DNS forwarder (`net::services`).
//! - Management web interface (`net::mgmt`).
//!
//! Frames reach smoltcp from the datapath through each port's `local_rx`
//! (`net::shared`, `svc_kick` wakes this task); smoltcp's frames go
//! straight into the port's qdisc, then `dp_kick` wakes the datapath. WAN
//! lease changes and reboot/upgrade requests go to the datapath as
//! `net::shared::Control` messages.

use crate::net::datapath;
use crate::net::device::PortDevice;
use crate::net::mgmt::Mgmt;
use crate::net::services::LanServices;
use crate::net::shared::{Shared, WanChange};
use crate::net::stack::{self, WaitAny};
use crate::{println, timer};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{dhcpv4, icmp};
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address};

/// Set once the WAN has a DHCP lease (read by the boot self-test).
pub static DHCP_OK: AtomicBool = AtomicBool::new(false);
/// Set once the gateway answered a ping.
pub static PING_OK: AtomicBool = AtomicBool::new(false);

const PING_IDENT: u16 = 0x22b;
const PING_COUNT: u16 = 3;
const PING_INTERVAL: Duration = Duration::from_millis(200);

/// The services' half of a port: the router stack's interface and sockets.
pub struct HostIf {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
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

fn handle_dhcp(name: &str, host: &mut HostIf, pinger: &mut Pinger) -> Option<LeaseChange> {
    let (handle, _) = host
        .sockets
        .iter()
        .find(|(_, s)| matches!(s, smoltcp::socket::Socket::Dhcpv4(_)))?;
    let event = host.sockets.get_mut::<dhcpv4::Socket>(handle).poll();
    match event {
        Some(dhcpv4::Event::Configured(cfg)) => {
            host.iface.update_ip_addrs(|a| {
                a.clear();
                a.push(IpCidr::Ipv4(cfg.address)).expect("wan addr");
            });
            match cfg.router {
                Some(gw) => {
                    host.iface
                        .routes_mut()
                        .add_default_ipv4_route(gw)
                        .expect("route");
                }
                None => {
                    host.iface.routes_mut().remove_default_ipv4_route();
                }
            }
            let dns: Vec<_> = cfg
                .dns_servers
                .iter()
                .map(|d| alloc::format!("{d}"))
                .collect();
            println!(
                "  net {}         : dhcp lease {} gw {} dns [{}]",
                name,
                cfg.address,
                cfg.router
                    .map(|r| alloc::format!("{r}"))
                    .unwrap_or_else(|| "-".into()),
                dns.join(", ")
            );
            let lan = stack::lan_cidr();
            let shorter = cfg.address.prefix_len().min(lan.prefix_len());
            let net = |a: Ipv4Address| {
                u32::from(a) & (u32::MAX.checked_shl(32 - shorter as u32).unwrap_or(0))
            };
            if net(cfg.address.address()) == net(lan.address()) {
                println!(
                    "  net WARNING     : WAN {} overlaps LAN {lan}: forwarding between them breaks; boot with e.g. lan=10.10.0.1/24",
                    cfg.address
                );
            }
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
                println!("  net {}         : dhcp lease lost", name);
            }
            host.iface.update_ip_addrs(|a| a.clear());
            host.iface.routes_mut().remove_default_ipv4_route();
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

fn lease_json(c: &LeaseChange) -> alloc::string::String {
    use proto_http::json_str;
    let Some((addr, prefix)) = c.addr else {
        return "null".into();
    };
    let dns: Vec<_> = c
        .dns
        .iter()
        .map(|d| json_str(&alloc::format!("{d}")))
        .collect();
    alloc::format!(
        "{{\"addr\":{},\"gateway\":{},\"dns\":[{}]}}",
        json_str(&alloc::format!("{addr}/{prefix}")),
        c.gateway
            .map(|g| json_str(&alloc::format!("{g}")))
            .unwrap_or_else(|| "null".into()),
        dns.join(",")
    )
}

/// Poll every router-stack interface; wake the TX task of each port that
/// got frames in its qdisc.
fn poll_stacks(hosts: &mut [HostIf], sh: &Shared) {
    let t = stack::now();
    let now_ns = datapath::now_ns();
    for (i, (host, port)) in hosts.iter_mut().zip(&sh.ports).enumerate() {
        let mut queued = 0;
        let mut dev = PortDevice {
            port,
            now_ns,
            queued: &mut queued,
        };
        host.iface.poll(t, &mut dev, &mut host.sockets);
        if queued > 0 {
            sh.tx_kick[i].signal();
        }
    }
}

/// Write `config.toml` to the store's `config` area.
async fn save_config(st: &mut crate::store::Store, toml: &str) -> Result<String, String> {
    use crate::config::schema;
    let (slot, h) = st
        .write_record("config", schema::VERSION, schema::VERSION, toml.as_bytes())
        .await
        .map_err(|e| alloc::format!("{e}"))?;
    Ok(alloc::format!(
        "slot {}, seq {}, {} bytes",
        crate::store::slot_name(slot),
        h.seq,
        h.len
    ))
}

/// The services task: never returns.
pub async fn run(
    mut hosts: Vec<HostIf>,
    sh: &'static Shared,
    mut store: Option<crate::store::Store>,
) {
    let mut pinger = Pinger::new(&mut hosts[0].sockets);
    let mut services = (hosts.len() >= 2).then(|| {
        let (wan, lan) = hosts.split_at_mut(1);
        LanServices::new(&mut lan[0], Some(&mut wan[0]))
    });
    let mut mgmt = Mgmt::new(&mut hosts, store.is_some());
    let events = [sh.svc_kick];

    loop {
        sh.svc_kick.take();
        poll_stacks(&mut hosts, sh);
        if let Some(change) = handle_dhcp(sh.ports[0].name, &mut hosts[0], &mut pinger) {
            sh.post_wan(WanChange {
                addr: change.addr,
                gateway: change.gateway,
            });
            mgmt.set_wan_lease(lease_json(&change));
            if let Some(svc) = services.as_mut() {
                svc.set_upstreams(&change.dns);
            }
        }
        pinger.step(&mut hosts[0].sockets);
        if let Some(svc) = services.as_mut() {
            let (wan, lan) = hosts.split_at_mut(1);
            svc.step(&mut lan[0].sockets, Some(&mut wan[0].sockets));
        }
        let action = mgmt.step(&mut hosts, sh, services.as_ref());
        if let Some((conn, toml)) = mgmt.take_save()
            && let Some(st) = store.as_mut()
        {
            // Yields while the disk works: the datapath keeps running.
            let r = save_config(st, &toml).await;
            mgmt.save_done(conn, r);
        }
        if let Some(action) = action {
            // The datapath stops the NICs and acts; nothing left to do here.
            sh.post_action(action);
            loop {
                timer::sleep(Duration::from_secs(3600)).await;
            }
        }
        poll_stacks(&mut hosts, sh);

        // More frames arrived while we worked: go round again, after
        // letting the datapath run.
        if sh.ports.iter().any(|p| !p.local_rx.lock().is_empty()) {
            crate::executor::yield_now().await;
            continue;
        }
        let t = stack::now();
        let mut delay = hosts
            .iter_mut()
            .filter_map(|h| h.iface.poll_delay(t, &h.sockets))
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
        if mgmt.busy() {
            delay = delay.min(Duration::from_millis(10));
        }
        WaitAny {
            events: &events,
            sleep: timer::sleep(delay),
        }
        .await;
    }
}
