//! mDNS across networks (docs/mdns.md): glue between the router's own UDP
//! (`net::local`) and `proto_mdns::Reflector`.
//!
//! On each network a `[[mdns.reflect]]` entry involves, the router joins
//! 224.0.0.251 on that link's interface (smoltcp sends the IGMP report;
//! docs/local-stack.md step 4 moves that out) and listens on UDP 5353. A join waits until the datapath has put the
//! network's link into effect (active, with the network's VLAN ID): after
//! a live change the services task runs ahead of the datapath, and a
//! report queued earlier would carry the link's old tag (none, for a
//! network just added) and never reach the network. A network whose VLAN
//! changed leaves (on the old tag) and joins again (on the new one). Each datagram goes to the reflector with the
//! network's index (`config::networks` order); its copies are sent to
//! `224.0.0.251:5353` on their networks, from the router's address there,
//! with TTL 255 (RFC 6762 §11). With IPv6 on, the same over ff02::fb
//! (docs/ipv6.md step 5b): joined beside 224.0.0.251 (smoltcp sends the
//! MLD report), each copy sent in the family its message came in on, from
//! the router's link-local address. Everything happens in the services
//! task; the datapath only passes 5353 up when the zone allows `mdns`.

use crate::config;
use crate::net::svc::HostIf;
use crate::{println, timer};
use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use proto_mdns::{GROUP_V4, GROUP_V6, PORT, Reflector, Stats};
use crate::net::local::{self, Ends};
use crate::net::shared::Shared;
use smoltcp::wire::IpAddress;

/// RFC 6762 §11: TTL / hop limit 255.
const HOP_LIMIT: u8 = 255;

/// A network's port 5353: on which link (`net::local`, bounded queue: a
/// storm is dropped and counted in `local_udp.dropped`), and the router's
/// IPv4 address there (the source of its copies).
#[derive(Clone, Copy)]
struct Sock {
    host: usize,
    v4: core::net::Ipv4Addr,
}

/// A group membership on a host interface, for a network with this VID.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Member {
    host: usize,
    vid: u16,
    /// ff02::fb too (IPv6 on, the network has its /64).
    v6: bool,
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
}

fn now_ms() -> u64 {
    timer::uptime().as_millis() as u64
}

/// The reflector's networks: IPv4 subnet, and with IPv6 the router's
/// link-local (from the link's MAC), unique local and global addresses.
fn reflector_config(nets: &[config::Lan], hosts: &[HostIf], links: &[usize]) -> proto_mdns::Config {
    proto_mdns::Config {
        nets: nets
            .iter()
            .enumerate()
            .map(|(k, n)| {
                let mut net = proto_mdns::Net::v4(n.addr, n.prefix);
                if config::ipv6() && n.ula.is_some() {
                    let ll = links.get(k).and_then(|&l| hosts.get(l)).map(|h| fwd::wire::link_local(h.mac));
                    net.addrs6 = [ll, n.ula, n.gua];
                }
                Some(net)
            })
            .collect(),
        rules: config::mdns_rules(),
    }
}

fn leave(host: &mut HostIf, m: Member) {
    let _ = host.iface.leave_multicast_group(IpAddress::Ipv4(GROUP_V4));
    if m.v6 {
        let _ = host.iface.leave_multicast_group(IpAddress::Ipv6(GROUP_V6));
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
            self.refl.reconfigure(reflector_config(&nets, hosts, links));
        } else {
            self.refl = Reflector::new(reflector_config(&nets, hosts, links));
        }
        // Memberships: keep those unchanged, leave the others now (sent on
        // the tag still in effect), join new or retagged ones later
        // ([`Self::step`]).
        let want: Vec<Member> = links
            .iter()
            .enumerate()
            .take(nets.len())
            .filter(|&(k, &link)| self.refl.takes_part(k) && link < hosts.len())
            .map(|(k, &link)| Member { host: link, vid: nets[k].vid, v6: config::ipv6() && nets[k].ula.is_some() })
            .collect();
        for m in core::mem::take(&mut self.joined) {
            if want.contains(&m) {
                self.joined.push(m);
            } else {
                leave(&mut hosts[m.host], m);
            }
        }
        self.pending = want.iter().copied().filter(|m| !self.joined.contains(m)).collect();
        // Ports: free everything, then bind what the rules need (a change
        // drops at most the datagrams queued at that moment).
        for s in self.socks.drain(..).flatten() {
            local::unbind(s.host as fwd::IfIndex, PORT);
        }
        for (k, &link) in links.iter().enumerate().take(nets.len()) {
            if !want.iter().any(|m| m.host == link) {
                self.socks.push(None);
                continue;
            }
            local::bind(link as fwd::IfIndex, PORT);
            self.socks.push(Some(Sock { host: link, v4: nets[k].addr }));
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
    pub fn step(&mut self, hosts: &mut [HostIf], sh: &Shared) {
        let links = &sh.links;
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
            if m.v6
                && let Err(e) = hosts[m.host].iface.join_multicast_group(IpAddress::Ipv6(GROUP_V6))
            {
                println!("  mdns            : cannot join {GROUP_V6} on link {}: {e}", m.host);
            }
        }
        for k in 0..self.socks.len() {
            let Some(s) = self.socks[k] else { continue };
            while let Some(d) = local::recv(s.host as fwd::IfIndex, PORT) {
                let src = match d.ends {
                    Ends::V4(e) => SocketAddr::new(IpAddr::V4(e.src), e.sport),
                    Ends::V6(e) => SocketAddr::new(IpAddr::V6(e.src), e.sport),
                };
                for out in self.refl.handle(now_ms(), k, src, &d.payload) {
                    let Some(Some(t)) = self.socks.get(out.net).copied() else {
                        continue;
                    };
                    let link = t.host as fwd::IfIndex;
                    // To the group, from the router's address there (IPv6:
                    // link-local, the source for a link-scoped group).
                    let e = if out.v6 {
                        let Some(IpAddr::V6(src)) = local::source(link, IpAddr::V6(GROUP_V6)) else { continue };
                        Ends::V6(fwd::udp::Ends6 { src, dst: GROUP_V6, sport: PORT, dport: PORT })
                    } else {
                        Ends::V4(fwd::udp::Ends { src: t.v4, dst: GROUP_V4, sport: PORT, dport: PORT })
                    };
                    // No buffer drops the copy (bounded, like any other
                    // router-local UDP).
                    local::send(sh, link, &e, HOP_LIMIT, &out.msg);
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
