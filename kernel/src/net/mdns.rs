//! mDNS across networks (docs/mdns.md): glue between smoltcp and
//! `proto_mdns::Reflector`.
//!
//! On each network a `[[mdns.reflect]]` entry involves, the router joins
//! 224.0.0.251 on that link's interface (smoltcp sends the IGMP report)
//! and listens on UDP 5353. A join waits until the datapath has put the
//! network's link into effect (active, with the network's VLAN ID): after
//! a live change the services task runs ahead of the datapath, and a
//! report queued earlier would carry the link's old tag (none, for a
//! network just added) and never reach the network. A network whose VLAN
//! changed leaves (on the old tag) and joins again (on the new one). Each datagram goes to the reflector with the
//! network's index (`config::networks` order); its copies are sent to
//! `224.0.0.251:5353` on their networks, from the router's address there,
//! with TTL 255 (RFC 6762 §11). Everything happens in the services task;
//! the datapath only passes 5353 up when the zone allows `mdns`.

use crate::config;
use crate::net::shared::LinkShared;
use crate::net::svc::HostIf;
use crate::{println, timer};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddrV4};
use proto_mdns::{GROUP_V4, PORT, Reflector, Stats};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint};

/// Socket buffers per network: a burst of announcements from a device
/// joining fits, a storm is dropped by smoltcp (counted nowhere, bounded).
const DATAGRAMS: usize = 16;
const BUF_BYTES: usize = 24 * 1024;
const HOP_LIMIT: u8 = 255;

/// A network's socket: on which host interface, and the handle.
#[derive(Clone, Copy)]
struct Sock {
    host: usize,
    handle: SocketHandle,
}

/// A group membership on a host interface, for a network with this VID.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Member {
    host: usize,
    vid: u16,
}

pub struct Mdns {
    refl: Reflector,
    /// Joined on these interfaces.
    joined: Vec<Member>,
    /// To join once the datapath shows the link with this VID.
    pending: Vec<Member>,
    /// A join happened in the last step: its report goes out on the next
    /// interface poll.
    just_joined: bool,
    /// Per network (`config::networks` index): its socket, while it takes
    /// part.
    socks: Vec<Option<Sock>>,
    /// Network names the counters belong to (index = `NetId`).
    names: Vec<String>,
    buf: Vec<u8>,
}

fn now_ms() -> u64 {
    timer::uptime().as_millis() as u64
}

fn reflector_config(nets: &[config::Lan]) -> proto_mdns::Config {
    proto_mdns::Config {
        nets: nets
            .iter()
            .map(|n| Some(proto_mdns::Net { addr: n.addr, prefix_len: n.prefix }))
            .collect(),
        rules: config::mdns_rules(),
    }
}

impl Mdns {
    /// Network `k` of `config::networks` is on `hosts[links[k]]`.
    pub fn new(hosts: &mut [HostIf], links: &[usize]) -> Self {
        let mut m = Self {
            refl: Reflector::new(proto_mdns::Config::default()),
            joined: Vec::new(),
            pending: Vec::new(),
            just_joined: false,
            socks: Vec::new(),
            names: Vec::new(),
            buf: vec![0; proto_mdns::wire::MAX_MESSAGE],
        };
        m.reconfigure(hosts, links);
        m
    }

    /// Apply the current config: sockets and group memberships follow the
    /// rules. Counters stay while the network names stay the same.
    pub fn reconfigure(&mut self, hosts: &mut [HostIf], links: &[usize]) {
        let nets = config::networks();
        let names: Vec<String> = nets.iter().map(|n| n.name.clone()).collect();
        if names == self.names {
            self.refl.reconfigure(reflector_config(&nets));
        } else {
            self.refl = Reflector::new(reflector_config(&nets));
        }
        // Memberships: keep those unchanged, leave the others now (sent on
        // the tag still in effect), join new or retagged ones later
        // ([`Self::step`]).
        let want: Vec<Member> = links
            .iter()
            .enumerate()
            .take(nets.len())
            .filter(|&(k, &link)| self.refl.takes_part(k) && link < hosts.len())
            .map(|(k, &link)| Member { host: link, vid: nets[k].vid })
            .collect();
        for m in core::mem::take(&mut self.joined) {
            if want.contains(&m) {
                self.joined.push(m);
            } else {
                let _ = hosts[m.host].iface.leave_multicast_group(IpAddress::Ipv4(GROUP_V4));
            }
        }
        self.pending = want.iter().copied().filter(|m| !self.joined.contains(m)).collect();
        // Sockets: close everything, then open what the rules need (a
        // change drops at most the datagrams queued at that moment).
        for s in self.socks.drain(..).flatten() {
            hosts[s.host].sockets.remove(s.handle);
        }
        for &link in links.iter().take(nets.len()) {
            if !want.iter().any(|m| m.host == link) {
                self.socks.push(None);
                continue;
            }
            let host = &mut hosts[link];
            let buf = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; DATAGRAMS], vec![0; BUF_BYTES]);
            let mut s = udp::Socket::new(buf(), buf());
            s.bind(PORT).expect("bind :5353");
            s.set_hop_limit(Some(HOP_LIMIT));
            self.socks.push(Some(Sock { host: link, handle: host.sockets.add(s) }));
        }
        self.names = names;
        let on: Vec<&str> = (0..self.socks.len())
            .filter(|&k| self.socks[k].is_some())
            .map(|k| self.names[k].as_str())
            .collect();
        if !on.is_empty() {
            println!("  mdns            : reflecting on {}", on.join(", "));
        }
    }

    /// Join where the datapath has caught up, then reflect what arrived
    /// since the last call. `links[i]` belongs to `hosts[i]`.
    pub fn step(&mut self, hosts: &mut [HostIf], links: &[LinkShared]) {
        self.just_joined = false;
        let mut i = 0;
        while i < self.pending.len() {
            let m = self.pending[i];
            let ready = links.get(m.host).is_some_and(|l| l.is_active() && l.vid() == m.vid);
            if !ready {
                i += 1;
                continue;
            }
            self.pending.swap_remove(i);
            match hosts[m.host].iface.join_multicast_group(IpAddress::Ipv4(GROUP_V4)) {
                Ok(()) => {
                    self.joined.push(m);
                    self.just_joined = true;
                }
                Err(e) => println!("  mdns            : cannot join {GROUP_V4} on link {}: {e}", m.host),
            }
        }
        for k in 0..self.socks.len() {
            let Some(s) = self.socks[k] else { continue };
            loop {
                let sock = hosts[s.host].sockets.get_mut::<udp::Socket>(s.handle);
                let Ok((n, meta)) = sock.recv_slice(&mut self.buf) else {
                    break;
                };
                let IpAddr::V4(ip) = IpAddr::from(meta.endpoint.addr) else {
                    continue;
                };
                let src = SocketAddrV4::new(ip, meta.endpoint.port);
                for out in self.refl.handle(now_ms(), k, src, &self.buf[..n]) {
                    let Some(Some(t)) = self.socks.get(out.net).copied() else {
                        continue;
                    };
                    let ep = IpEndpoint::new(IpAddress::Ipv4(GROUP_V4), PORT);
                    // A full TX buffer drops the copy (bounded, like any
                    // other router-local UDP).
                    let _ = hosts[t.host].sockets.get_mut::<udp::Socket>(t.handle).send_slice(&out.msg, ep);
                }
            }
        }
    }

    /// The services task should run again soon: a join waits for the
    /// datapath (which does not wake it), or a report waits for the poll.
    pub fn wants_soon(&self) -> bool {
        !self.pending.is_empty() || self.just_joined
    }

    /// Counters of the networks taking part (status page, CLI).
    pub fn status(&self) -> Vec<(&str, Stats)> {
        (0..self.socks.len())
            .filter(|&k| self.socks[k].is_some())
            .map(|k| (self.names[k].as_str(), self.refl.stats(k)))
            .collect()
    }
}
