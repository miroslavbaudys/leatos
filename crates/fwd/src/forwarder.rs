//! The per-packet forwarding pipeline (run-to-completion, in place).
//!
//! ```text
//! frame ─► L2 checks ─► ARP/non-IPv4/for-us? ──────────────► Local (router stack)
//!            │
//!            ▼
//!        IPv4 parse ─► conntrack lookup (incl. ICMP errors via inner header)
//!            │
//!            ▼
//!        route (on the de-NATed destination) ─► firewall for new flows
//!            │                                   (LAN→WAN only, TCP needs SYN)
//!            ▼
//!        TTL ≤ 1 ? ─► ICMP time exceeded, built in place, back to the sender
//!            │
//!            ▼
//!        TTL−1, NAT rewrite (incremental checksums), conntrack update,
//!        classification for CAKE ─► Forward { egress, next_hop, … }
//! ```
//!
//! The caller resolves `next_hop` to a MAC (`neigh`), writes the Ethernet
//! addresses and enqueues into the egress interface's qdisc.

use crate::IfIndex;
use crate::conntrack::{Conn, Conntrack, Dir, Tuple};
use crate::route::{Route, RouteTable};
use crate::wire::{
    self, ETH_HDR, ETHERTYPE_ARP, ETHERTYPE_IPV4, Ipv4View, Mac, PROTO_ICMP, PROTO_TCP, PROTO_UDP,
};
use alloc::vec::Vec;
use core::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Lan,
    Wan,
}

#[derive(Clone, Copy, Debug)]
pub struct Interface {
    pub mac: Mac,
    /// Address and prefix length, once configured.
    pub addr: Option<(Ipv4Addr, u8)>,
    pub role: Role,
}

/// Per-packet metadata for the qdisc (CAKE), from pre-NAT addresses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Classification {
    pub flow_hash: u32,
    pub src_host_hash: u16,
    pub dst_host_hash: u16,
    pub dscp: u8,
    pub ecn_capable: bool,
    pub is_pure_ack: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    NotForUs,
    Malformed,
    Fragment,
    NoRoute,
    Firewall,
    Invalid,
    TableFull,
    Hairpin,
    IcmpRateLimit,
    Unsupported,
}

pub const DROP_REASONS: usize = 10;

impl DropReason {
    pub fn index(self) -> usize {
        self as usize
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::NotForUs => "not-for-us",
            Self::Malformed => "malformed",
            Self::Fragment => "fragment",
            Self::NoRoute => "no-route",
            Self::Firewall => "firewall",
            Self::Invalid => "invalid",
            Self::TableFull => "table-full",
            Self::Hairpin => "hairpin",
            Self::IcmpRateLimit => "icmp-ratelimit",
            Self::Unsupported => "unsupported",
        }
    }
    pub fn all() -> [DropReason; DROP_REASONS] {
        use DropReason::*;
        [
            NotForUs,
            Malformed,
            Fragment,
            NoRoute,
            Firewall,
            Invalid,
            TableFull,
            Hairpin,
            IcmpRateLimit,
            Unsupported,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Deliver to the router's own IP stack.
    Local,
    /// Send `len` bytes (from the start of the frame) out of `egress` to `next_hop`.
    Forward {
        egress: IfIndex,
        next_hop: Ipv4Addr,
        len: usize,
        class: Classification,
    },
    Drop(DropReason),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub forwarded: u64,
    pub local: u64,
    pub icmp_errors_sent: u64,
    pub drops: [u64; DROP_REASONS],
}

/// What a packet means to conntrack.
enum Key {
    /// A normal flow packet; TCP flags (0 for others).
    Flow(Tuple, u8),
    /// An ICMP error about flow `inner` (as embedded, i.e. as originally sent).
    Related {
        inner: Tuple,
        inner_ip: usize,
        inner_ihl: usize,
    },
    /// Something we don't track (other protocols, odd ICMP).
    Other,
}

/// ICMP errors: token bucket, 50/s with a burst of 20.
const ICMP_RATE_PER_SEC: u64 = 50;
const ICMP_BURST: u64 = 20;

pub struct Forwarder {
    ifs: Vec<Interface>,
    pub routes: RouteTable,
    pub ct: Conntrack,
    pub stats: Stats,
    icmp_tokens: u64,
    icmp_refill_ms: u64,
}

fn broadcast_of(addr: Ipv4Addr, len: u8) -> Ipv4Addr {
    let mask = if len == 0 {
        0
    } else {
        u32::MAX << (32 - len as u32)
    };
    Ipv4Addr::from(u32::from(addr) | !mask)
}

fn extract_key(f: &[u8], v: &Ipv4View) -> Key {
    let (src, dst) = (v.src(f), v.dst(f));
    match v.proto {
        PROTO_TCP if v.l4_len >= 20 => {
            let t = Tuple {
                proto: PROTO_TCP,
                src,
                sport: wire::get16(f, v.l4),
                dst,
                dport: wire::get16(f, v.l4 + 2),
            };
            Key::Flow(t, f[v.l4 + 13])
        }
        PROTO_UDP if v.l4_len >= 8 => Key::Flow(
            Tuple {
                proto: PROTO_UDP,
                src,
                sport: wire::get16(f, v.l4),
                dst,
                dport: wire::get16(f, v.l4 + 2),
            },
            0,
        ),
        PROTO_ICMP if v.l4_len >= 8 => match f[v.l4] {
            wire::ICMP_ECHO_REQUEST | wire::ICMP_ECHO_REPLY => {
                let id = wire::get16(f, v.l4 + 4);
                Key::Flow(
                    Tuple {
                        proto: PROTO_ICMP,
                        src,
                        sport: id,
                        dst,
                        dport: id,
                    },
                    0,
                )
            }
            wire::ICMP_DEST_UNREACH | wire::ICMP_TIME_EXCEEDED => {
                let ip = v.l4 + 8;
                let Some(h) = f.get(ip..ip + 20).filter(|h| h[0] >> 4 == 4) else {
                    return Key::Other;
                };
                let ihl = ((h[0] & 0xf) as usize) * 4;
                let Some(l4) = f
                    .get(ip + ihl..ip + ihl + 8)
                    .filter(|_| ihl >= 20 && ip + ihl + 8 <= v.l4 + v.l4_len)
                else {
                    return Key::Other;
                };
                let (isrc, idst) = (wire::get_ip(f, ip + 12), wire::get_ip(f, ip + 16));
                let inner = match h[9] {
                    p @ (PROTO_TCP | PROTO_UDP) => Tuple {
                        proto: p,
                        src: isrc,
                        sport: wire::get16(l4, 0),
                        dst: idst,
                        dport: wire::get16(l4, 2),
                    },
                    PROTO_ICMP
                        if matches!(l4[0], wire::ICMP_ECHO_REQUEST | wire::ICMP_ECHO_REPLY) =>
                    {
                        let id = wire::get16(l4, 4);
                        Tuple {
                            proto: PROTO_ICMP,
                            src: isrc,
                            sport: id,
                            dst: idst,
                            dport: id,
                        }
                    }
                    _ => return Key::Other,
                };
                Key::Related {
                    inner,
                    inner_ip: ip,
                    inner_ihl: ihl,
                }
            }
            _ => Key::Other,
        },
        _ => Key::Other,
    }
}

impl Forwarder {
    pub fn new(max_conns: usize, hash_key: u64) -> Self {
        Self {
            ifs: Vec::new(),
            routes: RouteTable::new(),
            ct: Conntrack::new(max_conns, hash_key),
            stats: Stats::default(),
            icmp_tokens: ICMP_BURST,
            icmp_refill_ms: 0,
        }
    }

    pub fn add_interface(&mut self, iface: Interface) -> IfIndex {
        self.ifs.push(iface);
        let ifx = (self.ifs.len() - 1) as IfIndex;
        if let Some(a) = iface.addr {
            self.set_addr(ifx, Some(a));
        }
        ifx
    }

    pub fn interface(&self, ifx: IfIndex) -> &Interface {
        &self.ifs[ifx as usize]
    }

    /// Set or clear an interface address; maintains its connected route. A
    /// changed WAN address invalidates all NAT state.
    pub fn set_addr(&mut self, ifx: IfIndex, addr: Option<(Ipv4Addr, u8)>) {
        let old = core::mem::replace(&mut self.ifs[ifx as usize].addr, addr);
        if let Some((a, l)) = old {
            self.routes.remove(a, l);
        }
        if let Some((a, l)) = addr {
            self.routes.set(Route {
                prefix: a,
                len: l,
                egress: ifx,
                gateway: None,
            });
        }
        if self.ifs[ifx as usize].role == Role::Wan && old.map(|o| o.0) != addr.map(|a| a.0) {
            self.ct.flush_nat();
        }
    }

    pub fn set_default_route(&mut self, via: Option<(IfIndex, Ipv4Addr)>) {
        match via {
            Some((egress, gw)) => self.routes.set(Route {
                prefix: Ipv4Addr::UNSPECIFIED,
                len: 0,
                egress,
                gateway: Some(gw),
            }),
            None => self.routes.remove(Ipv4Addr::UNSPECIFIED, 0),
        }
    }

    pub fn expire(&mut self, now: u64) -> usize {
        self.ct.expire(now)
    }

    fn drop(&mut self, r: DropReason) -> Verdict {
        self.stats.drops[r.index()] += 1;
        Verdict::Drop(r)
    }

    fn local(&mut self) -> Verdict {
        self.stats.local += 1;
        Verdict::Local
    }

    fn take_icmp_token(&mut self, now: u64) -> bool {
        let elapsed = now.saturating_sub(self.icmp_refill_ms);
        let add = elapsed * ICMP_RATE_PER_SEC / 1000;
        if add > 0 {
            self.icmp_tokens = (self.icmp_tokens + add).min(ICMP_BURST);
            self.icmp_refill_ms = now;
        }
        if self.icmp_tokens == 0 {
            return false;
        }
        self.icmp_tokens -= 1;
        true
    }

    /// Process one received frame in `buf[..len]`. `buf` may be longer than
    /// `len` (tailroom), which ICMP error generation can use.
    pub fn process(&mut self, now: u64, ingress: IfIndex, buf: &mut [u8], len: usize) -> Verdict {
        let iface = self.ifs[ingress as usize];
        let f = &buf[..len];
        let Some(et) = wire::ethertype(f) else {
            return self.drop(DropReason::Malformed);
        };
        if et == ETHERTYPE_ARP || et != ETHERTYPE_IPV4 {
            return self.local(); // ARP, IPv6 (until M7), …: the router stack decides
        }
        let dmac = wire::dst_mac(f);
        if dmac != iface.mac && !wire::is_multicast_mac(&dmac) {
            return self.drop(DropReason::NotForUs);
        }
        let Some(v) = Ipv4View::parse(f, ETH_HDR) else {
            return self.drop(DropReason::Malformed);
        };
        let Some((my_ip, my_len)) = iface.addr else {
            return self.local();
        }; // e.g. WAN DHCP in progress
        let dst = v.dst(f);
        let to_us = dst == my_ip
            || dst == Ipv4Addr::BROADCAST
            || dst == broadcast_of(my_ip, my_len)
            || dst.is_multicast()
            || self
                .ifs
                .iter()
                .any(|i| i.addr.is_some_and(|(a, _)| a == dst));

        if v.is_fragment {
            return if to_us {
                self.local()
            } else {
                self.drop(DropReason::Fragment)
            };
        }
        let key = extract_key(f, &v);
        let hit = match &key {
            Key::Flow(t, _) => self.ct.lookup(t),
            Key::Related { inner, .. } => self.ct.lookup(&inner.inverse()),
            Key::Other => None,
        };

        // Addressed to the router and not a NAT reply: local delivery.
        let nat_reply = hit
            .is_some_and(|(id, dir)| dir == Dir::Reply && self.ct.get(id).is_some_and(|c| c.nat));
        if to_us && !nat_reply {
            return self.local();
        }

        // Route on the destination after de-NAT.
        let conn: Option<Conn> = hit.and_then(|(id, _)| self.ct.get(id).cloned());
        let out_dst = match (&conn, hit) {
            (Some(c), Some((_, Dir::Reply))) if c.nat => c.translated(Dir::Reply).dst,
            _ => dst,
        };
        let Some(route) = self.routes.lookup(out_dst).copied() else {
            return self.drop(DropReason::NoRoute);
        };
        if route.egress == ingress {
            return self.drop(DropReason::Hairpin);
        }
        let egress_if = self.ifs[route.egress as usize];

        // Firewall + conntrack for new flows.
        let (id, dir) = match hit {
            Some(h) => h,
            None => {
                let Key::Flow(t, flags) = key else {
                    return self.drop(if matches!(key, Key::Related { .. }) {
                        DropReason::Invalid
                    } else {
                        DropReason::Unsupported
                    });
                };
                if !(iface.role == Role::Lan && egress_if.role == Role::Wan) {
                    return self.drop(DropReason::Firewall);
                }
                let new_ok = match t.proto {
                    PROTO_TCP => {
                        flags & (wire::TCP_SYN | wire::TCP_ACK | wire::TCP_RST) == wire::TCP_SYN
                    }
                    PROTO_ICMP => f[v.l4] == wire::ICMP_ECHO_REQUEST,
                    _ => true,
                };
                if !new_ok {
                    return self.drop(DropReason::Invalid);
                }
                let nat_ip = egress_if.addr.map(|(a, _)| a);
                match self.ct.create(now, t, nat_ip, flags) {
                    Some(id) => (id, Dir::Original),
                    None => return self.drop(DropReason::TableFull),
                }
            }
        };

        // TTL: answer with ICMP time exceeded (never about ICMP errors).
        if v.ttl(f) <= 1 {
            if matches!(key, Key::Related { .. }) {
                return self.drop(DropReason::Invalid);
            }
            if !self.take_icmp_token(now) {
                return self.drop(DropReason::IcmpRateLimit);
            }
            return self.time_exceeded(ingress, my_ip, buf, len, &v);
        }

        let tcp_flags = if let Key::Flow(_, fl) = key { fl } else { 0 };
        let conn = self.ct.get(id).cloned().expect("conntrack entry exists");
        v.dec_ttl(buf);
        if conn.nat {
            let tgt = conn.translated(dir);
            match key {
                Key::Flow(..) => match dir {
                    Dir::Original => {
                        v.set_addr(buf, true, tgt.src);
                        v.set_port(buf, true, tgt.sport);
                    }
                    Dir::Reply => {
                        v.set_addr(buf, false, tgt.dst);
                        v.set_port(buf, false, tgt.dport);
                    }
                },
                Key::Related {
                    inner_ip,
                    inner_ihl,
                    inner,
                } => {
                    translate_icmp_error(buf, &v, dir, &tgt, inner.proto, inner_ip, inner_ihl);
                }
                Key::Other => {}
            }
        }
        self.ct.update(now, id, dir, tcp_flags, v.total_len);

        let f = &buf[..len];
        let tos = v.tos(f);
        let (src_h, dst_h) = match dir {
            Dir::Original => (conn.orig_src_hash, conn.orig_dst_hash),
            Dir::Reply => (conn.orig_dst_hash, conn.orig_src_hash),
        };
        let is_pure_ack = v.proto == PROTO_TCP
            && tcp_flags & !(wire::TCP_PSH) == wire::TCP_ACK
            && v.l4_len == ((f[v.l4 + 12] >> 4) as usize) * 4;
        self.stats.forwarded += 1;
        Verdict::Forward {
            egress: route.egress,
            next_hop: route.gateway.unwrap_or(out_dst),
            len,
            class: Classification {
                flow_hash: conn.flow_hash,
                src_host_hash: src_h,
                dst_host_hash: dst_h,
                dscp: tos >> 2,
                ecn_capable: tos & 3 != 0,
                is_pure_ack,
            },
        }
    }

    /// Replace the frame with an ICMP time-exceeded message to its sender.
    fn time_exceeded(
        &mut self,
        ingress: IfIndex,
        my_ip: Ipv4Addr,
        buf: &mut [u8],
        len: usize,
        v: &Ipv4View,
    ) -> Verdict {
        let orig_src = v.src(&buf[..len]);
        let quote_len = (v.ihl + 8).min(v.total_len);
        let mut quote = [0u8; 60 + 8];
        quote[..quote_len].copy_from_slice(&buf[v.ip..v.ip + quote_len]);
        let new_len = ETH_HDR + 20 + 8 + quote_len;
        if buf.len() < new_len {
            return self.drop(DropReason::Malformed);
        }
        let Some(back) = self.routes.lookup(orig_src).copied() else {
            return self.drop(DropReason::NoRoute);
        };
        let ip = &mut buf[ETH_HDR..new_len];
        ip[0] = 0x45;
        ip[1] = 0xc0; // DSCP CS6 (network control)
        wire::put16(ip, 2, (20 + 8 + quote_len) as u16);
        wire::put16(ip, 4, 0);
        wire::put16(ip, 6, 0);
        ip[8] = 64;
        ip[9] = PROTO_ICMP;
        wire::put16(ip, 10, 0);
        wire::put_ip(ip, 12, my_ip);
        wire::put_ip(ip, 16, orig_src);
        let c = wire::checksum(&ip[..20]);
        wire::put16(ip, 10, c);
        let icmp = &mut ip[20..];
        icmp[0] = wire::ICMP_TIME_EXCEEDED;
        icmp[1] = 0;
        icmp[2..8].fill(0);
        icmp[8..8 + quote_len].copy_from_slice(&quote[..quote_len]);
        let c = wire::checksum(icmp);
        wire::put16(icmp, 2, c);
        self.stats.icmp_errors_sent += 1;
        Verdict::Forward {
            egress: ingress,
            next_hop: back.gateway.unwrap_or(orig_src),
            len: new_len,
            class: Classification {
                dscp: 0x30,
                ..Default::default()
            },
        }
    }
}

/// NAT for an ICMP error about a tracked flow: rewrite the side of the outer
/// header that NAT changes, the whole embedded header, and the checksums.
fn translate_icmp_error(
    buf: &mut [u8],
    v: &Ipv4View,
    dir: Dir,
    tgt: &Tuple,
    inner_proto: u8,
    ip: usize,
    ihl: usize,
) {
    match dir {
        Dir::Original => v.set_addr(buf, true, tgt.src),
        Dir::Reply => v.set_addr(buf, false, tgt.dst),
    }
    // The embedded packet travelled the opposite way.
    let inner = tgt.inverse();
    wire::put_ip(buf, ip + 12, inner.src);
    wire::put_ip(buf, ip + 16, inner.dst);
    wire::put16(buf, ip + 10, 0);
    let c = wire::checksum(&buf[ip..ip + ihl]);
    wire::put16(buf, ip + 10, c);
    let l4 = ip + ihl;
    match inner_proto {
        PROTO_TCP | PROTO_UDP => {
            wire::put16(buf, l4, inner.sport);
            wire::put16(buf, l4 + 2, inner.dport);
            if inner_proto == PROTO_UDP {
                wire::put16(buf, l4 + 6, 0); // inner UDP checksum: can't be fixed on a truncated quote; 0 = none
            }
        }
        _ => wire::put16(buf, l4 + 4, inner.sport), // echo identifier
    }
    // Outer ICMP checksum over the whole message.
    wire::put16(buf, v.l4 + 2, 0);
    let c = wire::checksum(&buf[v.l4..v.l4 + v.l4_len]);
    wire::put16(buf, v.l4 + 2, c);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::test_util::*;
    use crate::wire::{ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, TCP_ACK, TCP_SYN};
    use alloc::vec;

    const LAN_MAC: Mac = [2, 0, 0, 0, 0, 2];
    const WAN_MAC: Mac = [2, 0, 0, 0, 0, 1];
    const ROUTER_LAN: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const ROUTER_WAN: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const GW: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
    const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const WAN: IfIndex = 0;
    const LAN: IfIndex = 1;

    fn router() -> Forwarder {
        let mut fw = Forwarder::new(1000, 42);
        fw.add_interface(Interface {
            mac: WAN_MAC,
            addr: Some((ROUTER_WAN, 24)),
            role: Role::Wan,
        });
        fw.add_interface(Interface {
            mac: LAN_MAC,
            addr: Some((ROUTER_LAN, 24)),
            role: Role::Lan,
        });
        fw.set_default_route(Some((WAN, GW)));
        fw
    }

    fn to(mac: Mac, mut f: Vec<u8>) -> Vec<u8> {
        f[0..6].copy_from_slice(&mac);
        f.resize(f.len() + 64, 0); // tailroom
        f
    }

    fn run(fw: &mut Forwarder, now: u64, ifx: IfIndex, f: &mut [u8]) -> Verdict {
        let len = f.len() - 64;
        fw.process(now, ifx, f, len)
    }

    fn view(f: &[u8]) -> Ipv4View {
        Ipv4View::parse(f, ETH_HDR).unwrap()
    }

    /// LAN host opens TCP to SERVER:80; returns the NATed source port.
    fn syn_out(fw: &mut Forwarder) -> u16 {
        let seg = tcp_segment(HOST, SERVER, 40001, 80, TCP_SYN, b"");
        let mut f = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_TCP, 64, &seg));
        let Verdict::Forward {
            egress,
            next_hop,
            len,
            ..
        } = run(fw, 0, LAN, &mut f)
        else {
            panic!()
        };
        assert_eq!((egress, next_hop), (WAN, GW));
        let f = &f[..len];
        let v = view(f);
        assert_eq!((v.src(f), v.ttl(f)), (ROUTER_WAN, 63));
        assert!(checksums_ok(f));
        wire::get16(f, v.l4)
    }

    #[test]
    fn tcp_masquerade_both_directions() {
        let mut fw = router();
        let port = syn_out(&mut fw);
        // SYN+ACK from the server to the NAT port is translated back.
        let seg = tcp_segment(SERVER, ROUTER_WAN, 80, port, TCP_SYN | TCP_ACK, b"");
        let mut f = to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, PROTO_TCP, 50, &seg));
        let Verdict::Forward {
            egress,
            next_hop,
            len,
            class,
        } = run(&mut fw, 1, WAN, &mut f)
        else {
            panic!()
        };
        assert_eq!((egress, next_hop), (LAN, HOST));
        let f = &f[..len];
        let v = view(f);
        assert_eq!((v.dst(f), wire::get16(f, v.l4 + 2)), (HOST, 40001));
        assert!(checksums_ok(f));
        assert_eq!(
            class.flow_hash,
            fw.ct.iter().next().unwrap().flow_hash,
            "both directions share the flow hash"
        );
        assert_eq!(fw.stats.forwarded, 2);
    }

    #[test]
    fn unsolicited_inbound_is_firewalled_and_inbound_to_router_is_local() {
        let mut fw = router();
        let seg = tcp_segment(SERVER, HOST, 1234, 22, TCP_SYN, b"");
        let mut f = to(WAN_MAC, ipv4_frame(SERVER, HOST, PROTO_TCP, 64, &seg));
        assert_eq!(
            run(&mut fw, 0, WAN, &mut f),
            Verdict::Drop(DropReason::Firewall)
        );
        // To the router's own WAN address, no conntrack match: router stack.
        let seg = tcp_segment(SERVER, ROUTER_WAN, 1234, 22, TCP_SYN, b"");
        let mut f = to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, PROTO_TCP, 64, &seg));
        assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Local);
    }

    #[test]
    fn new_tcp_without_syn_is_invalid() {
        let mut fw = router();
        let seg = tcp_segment(HOST, SERVER, 40001, 80, TCP_ACK, b"");
        let mut f = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_TCP, 64, &seg));
        assert_eq!(
            run(&mut fw, 0, LAN, &mut f),
            Verdict::Drop(DropReason::Invalid)
        );
    }

    #[test]
    fn icmp_echo_through_nat() {
        let mut fw = router();
        let mut f = to(
            LAN_MAC,
            ipv4_frame(
                HOST,
                SERVER,
                PROTO_ICMP,
                64,
                &icmp_echo(ICMP_ECHO_REQUEST, 7, 1),
            ),
        );
        let Verdict::Forward { len, .. } = run(&mut fw, 0, LAN, &mut f) else {
            panic!()
        };
        let v = view(&f[..len]);
        let id = wire::get16(&f, v.l4 + 4);
        assert!(checksums_ok(&f[..len]));
        let mut r = to(
            WAN_MAC,
            ipv4_frame(
                SERVER,
                ROUTER_WAN,
                PROTO_ICMP,
                60,
                &icmp_echo(ICMP_ECHO_REPLY, id, 1),
            ),
        );
        let Verdict::Forward { egress, len, .. } = run(&mut fw, 1, WAN, &mut r) else {
            panic!()
        };
        let v = view(&r[..len]);
        assert_eq!(
            (egress, v.dst(&r), wire::get16(&r, v.l4 + 4)),
            (LAN, HOST, 7)
        );
        assert!(checksums_ok(&r[..len]));
    }

    #[test]
    fn inbound_icmp_error_for_nat_flow_is_translated() {
        let mut fw = router();
        let port = syn_out(&mut fw);
        // An intermediate router reports TTL exceeded for our NATed SYN.
        let quote_seg = tcp_segment(ROUTER_WAN, SERVER, port, 80, TCP_SYN, b"");
        let quoted = ipv4_frame(ROUTER_WAN, SERVER, PROTO_TCP, 1, &quote_seg);
        let mut icmp = vec![wire::ICMP_TIME_EXCEEDED, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&quoted[ETH_HDR..ETH_HDR + 28]);
        let c = wire::checksum(&icmp);
        wire::put16(&mut icmp, 2, c);
        let hop = Ipv4Addr::new(198, 51, 100, 1);
        let mut f = to(WAN_MAC, ipv4_frame(hop, ROUTER_WAN, PROTO_ICMP, 60, &icmp));
        let Verdict::Forward { egress, len, .. } = run(&mut fw, 1, WAN, &mut f) else {
            panic!()
        };
        assert_eq!(egress, LAN);
        let f = &f[..len];
        let v = view(f);
        assert_eq!(
            (v.src(f), v.dst(f)),
            (hop, HOST),
            "outer: only the NATed side changes"
        );
        let inner = v.l4 + 8;
        assert_eq!(wire::get_ip(f, inner + 12), HOST, "inner source restored");
        assert_eq!(
            wire::get16(f, inner + 20),
            40001,
            "inner source port restored"
        );
        assert!(checksums_ok(f));
        assert_eq!(
            wire::checksum(&f[inner..inner + 20]),
            0,
            "inner header checksum"
        );
    }

    #[test]
    fn ttl_expiry_generates_icmp_time_exceeded() {
        let mut fw = router();
        let seg = udp_datagram(HOST, SERVER, 5000, 33434, b"traceroute");
        let mut f = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_UDP, 1, &seg));
        let Verdict::Forward {
            egress,
            next_hop,
            len,
            ..
        } = run(&mut fw, 0, LAN, &mut f)
        else {
            panic!()
        };
        assert_eq!((egress, next_hop), (LAN, HOST));
        let f = &f[..len];
        let v = view(f);
        assert_eq!(
            (v.src(f), v.dst(f), v.proto, f[v.l4]),
            (ROUTER_LAN, HOST, PROTO_ICMP, wire::ICMP_TIME_EXCEEDED)
        );
        assert!(checksums_ok(f));
        assert_eq!(
            wire::get_ip(f, v.l4 + 8 + 16),
            SERVER,
            "quotes the original header"
        );
        assert_eq!(fw.stats.icmp_errors_sent, 1);
    }

    #[test]
    fn icmp_errors_are_rate_limited() {
        let mut fw = router();
        let mut sent = 0;
        for i in 0..100u16 {
            let seg = udp_datagram(HOST, SERVER, 5000 + i, 33434, b"x");
            let mut f = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_UDP, 1, &seg));
            if matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { .. }) {
                sent += 1;
            }
        }
        assert_eq!(sent, ICMP_BURST);
    }

    #[test]
    fn local_delivery_cases() {
        let mut fw = router();
        let mut arp = vec![0u8; 64];
        let n = wire::build_arp_request(&mut arp, [2, 0, 0, 0, 0, 9], HOST, ROUTER_LAN);
        assert_eq!(fw.process(0, LAN, &mut arp, n), Verdict::Local);
        for dst in [
            ROUTER_LAN,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(192, 168, 1, 255),
            Ipv4Addr::new(224, 0, 0, 251),
        ] {
            let mut f = to(
                LAN_MAC,
                ipv4_frame(
                    HOST,
                    dst,
                    PROTO_UDP,
                    64,
                    &udp_datagram(HOST, dst, 1, 53, b"q"),
                ),
            );
            assert_eq!(run(&mut fw, 0, LAN, &mut f), Verdict::Local, "{dst}");
        }
        // WAN without an address yet (DHCP in progress): everything is local.
        fw.set_addr(WAN, None);
        let mut f = to(
            WAN_MAC,
            ipv4_frame(
                GW,
                ROUTER_WAN,
                PROTO_UDP,
                64,
                &udp_datagram(GW, ROUTER_WAN, 67, 68, b"offer"),
            ),
        );
        assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Local);
    }

    #[test]
    fn misc_drops() {
        let mut fw = router();
        let seg = udp_datagram(HOST, SERVER, 1, 2, b"");
        let mut f = to(
            [2, 9, 9, 9, 9, 9],
            ipv4_frame(HOST, SERVER, PROTO_UDP, 64, &seg),
        );
        assert_eq!(
            run(&mut fw, 0, LAN, &mut f),
            Verdict::Drop(DropReason::NotForUs)
        );
        let other = Ipv4Addr::new(192, 168, 1, 50);
        let mut f = to(
            LAN_MAC,
            ipv4_frame(
                HOST,
                other,
                PROTO_UDP,
                64,
                &udp_datagram(HOST, other, 1, 2, b""),
            ),
        );
        assert_eq!(
            run(&mut fw, 0, LAN, &mut f),
            Verdict::Drop(DropReason::Hairpin)
        );
        fw.set_default_route(None);
        let mut f = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_UDP, 64, &seg));
        assert_eq!(
            run(&mut fw, 0, LAN, &mut f),
            Verdict::Drop(DropReason::NoRoute)
        );
        let mut f = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_UDP, 64, &seg));
        f[ETH_HDR + 6] = 0x20; // MF: fragment
        let c = {
            f[ETH_HDR + 10] = 0;
            f[ETH_HDR + 11] = 0;
            wire::checksum(&f[ETH_HDR..ETH_HDR + 20])
        };
        wire::put16(&mut f, ETH_HDR + 10, c);
        assert_eq!(
            run(&mut fw, 0, LAN, &mut f),
            Verdict::Drop(DropReason::Fragment)
        );
    }

    #[test]
    fn classification_marks_pure_acks_and_dscp() {
        let mut fw = router();
        let port = syn_out(&mut fw);
        let seg = tcp_segment(SERVER, ROUTER_WAN, 80, port, TCP_SYN | TCP_ACK, b"");
        let mut f = to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, PROTO_TCP, 50, &seg));
        run(&mut fw, 1, WAN, &mut f);
        let seg = tcp_segment(HOST, SERVER, 40001, 80, TCP_ACK, b"");
        let mut frame = ipv4_frame(HOST, SERVER, PROTO_TCP, 64, &seg);
        frame[ETH_HDR + 1] = 0xb8; // DSCP EF
        frame[ETH_HDR + 10] = 0;
        frame[ETH_HDR + 11] = 0;
        let c = wire::checksum(&frame[ETH_HDR..ETH_HDR + 20]);
        wire::put16(&mut frame, ETH_HDR + 10, c);
        let mut f = to(LAN_MAC, frame);
        let Verdict::Forward { class, .. } = run(&mut fw, 2, LAN, &mut f) else {
            panic!()
        };
        assert!(class.is_pure_ack);
        assert_eq!(class.dscp, 46);
        assert_eq!(
            fw.ct.iter().next().unwrap().tcp,
            Some(crate::conntrack::TcpState::Established)
        );
    }

    #[test]
    fn wan_address_change_flushes_nat() {
        let mut fw = router();
        syn_out(&mut fw);
        assert_eq!(fw.ct.len(), 1);
        fw.set_addr(WAN, Some((Ipv4Addr::new(203, 0, 113, 11), 24)));
        assert_eq!(fw.ct.len(), 0);
    }

    #[test]
    fn fuzz_never_panics() {
        let mut fw = router();
        let seg = tcp_segment(HOST, SERVER, 40001, 80, TCP_SYN, b"payload");
        let base = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_TCP, 64, &seg));
        let mut seed = 0xabcd_ef01_u32;
        for i in 0..30_000 {
            let mut f = base.clone();
            for _ in 0..6 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let j = seed as usize % (f.len() - 64);
                f[j] = (seed >> 8) as u8;
            }
            let len = (seed as usize >> 4) % (f.len() - 64 + 1);
            let ifx = (i % 2) as IfIndex;
            let _ = fw.process(i, ifx, &mut f, len);
        }
    }
}
