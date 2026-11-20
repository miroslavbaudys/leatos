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
//!            │                (zone policy: [`Policy`], TCP needs SYN)
//!            ▼
//!        TTL ≤ 1 ? ─► ICMP time exceeded, built in place, back to the sender
//!            │
//!        larger than the egress MTU ? ─► DF: ICMP fragmentation needed
//!            │                            (else dropped: no fragmentation)
//!            ▼
//!        TTL−1, NAT rewrite (incremental checksums), TCP SYN: MSS clamped
//!        to the smaller MTU, conntrack update,
//!        classification for CAKE ─► Forward { egress, next_hop, … }
//! ```
//!
//! The caller resolves `next_hop` to a MAC (`neigh`), writes the Ethernet
//! addresses and enqueues into the egress interface's qdisc.

use crate::IfIndex;
use crate::conntrack::{Conn, Conntrack, Dir, Tuple};
use crate::frag;
use crate::route::{Route, RouteKind, RouteTable};
use crate::wire::Ipv6View as V6;
use crate::wire::{
    self, ETH_HDR, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ICMP_DEST_UNREACH, ICMP_TIME_EXCEEDED, Ipv4View,
    Ipv6View, Mac, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP,
};
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

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
    /// `Wan`: new flows out of it are masqueraded (NAPT); `Lan`: not.
    pub role: Role,
    /// Firewall zone (an index into [`Policy`]).
    pub zone: u8,
}

/// Which kind of destination NAT a new connection takes.
#[derive(Clone, Copy, Debug)]
enum Dnat {
    /// Port forward (index into [`Policy::forwards`]).
    Forward(usize),
    /// Redirect (index into [`Policy::redirects`]).
    Redirect(usize),
}

/// Router services a zone may reach when its input is restricted
/// ([`Policy::input`]): bits of a mask.
pub mod svc {
    pub const DHCP: u8 = 1;
    pub const DNS: u8 = 2;
    pub const NTP: u8 = 4;
    pub const PING: u8 = 8;
    /// The web interface (TCP 80).
    pub const MGMT: u8 = 16;
    /// mDNS (UDP 5353), for the reflector (docs/mdns.md).
    pub const MDNS: u8 = 32;
}

/// The zone firewall (docs/config-v2.md §6), checked for new flows only.
/// Without one ([`Forwarder::set_policy`] never called) the old fixed
/// policy applies: new flows only from `Role::Lan` to `Role::Wan`, all
/// input accepted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// `forward[z]`: bit `j` set = zone `z` may open new flows to zone `j`.
    /// Interfaces of one zone always reach each other.
    pub forward: Vec<u32>,
    /// `input[z]`: what zone `z` may send to the router itself: `None` =
    /// everything, `Some(mask)` = only these [`svc`] services (ARP always).
    pub input: Vec<Option<u8>>,
    /// `reject_input[z]`: what `input` refuses is rejected ([`Action::Reject`]),
    /// not dropped (missing = drop).
    pub reject_input: Vec<bool>,
    /// Exceptions, checked in order before the zone policy; the first
    /// match decides ([`Forwarder::rule_hits`] counts per rule).
    pub rules: Vec<Rule>,
    /// Port forwards from the WAN address ([`Forwarder::forward_hits`]).
    pub forwards: Vec<PortForward>,
    /// Redirects of the networks' connections to outside servers
    /// ([`Forwarder::redirect_hits`]).
    pub redirects: Vec<Redirect>,
    /// TCP servers the router itself connects to (DNS over TLS): segments
    /// from one of these (address, port) to [`ROUTER_CLIENT_PORTS`] are
    /// replies to the router's client and pass like UDP replies do. Any
    /// other TCP to those ports is input like everything else.
    pub router_tcp_peers: Vec<(Ipv4Addr, u16)>,
}

/// A port forward (`[[firewall.forward]]`), compiled: new connections to
/// the WAN address on `lo..=hi` go to `to` (port `to_port + (p - lo)`, or
/// the same port). A forward lets its connections through the firewall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortForward {
    /// [`proto::TCP`] and/or [`proto::UDP`].
    pub protos: u8,
    pub lo: u16,
    pub hi: u16,
    pub to: Ipv4Addr,
    pub to_port: Option<u16>,
    /// Only from this prefix (WAN side); `None` = anyone.
    pub src: Option<(Ipv4Addr, u8)>,
    /// Also for internal clients, through the WAN address (the source is
    /// translated to the router so the target answers through it).
    pub hairpin: bool,
}

fn proto_bit(p: u8) -> u8 {
    match p {
        PROTO_TCP => proto::TCP,
        PROTO_UDP => proto::UDP,
        PROTO_ICMP | PROTO_ICMPV6 => proto::ICMP,
        _ => 0,
    }
}

/// Where a DNAT maps port `dport` of `lo..=hi`: `to`, at `to_port + (dport
/// - lo)` or the same port.
fn dnat_target(protos: u8, (lo, hi): (u16, u16), to: Ipv4Addr, to_port: Option<u16>, p: u8, dport: u16) -> Option<(Ipv4Addr, u16)> {
    (protos & proto_bit(p) != 0 && (lo..=hi).contains(&dport))
        .then(|| (to, to_port.map_or(dport, |t| t.wrapping_add(dport - lo))))
}

/// `ip:port` is one of a DNAT's targets.
fn dnat_is_target(protos: u8, (lo, hi): (u16, u16), to: Ipv4Addr, to_port: Option<u16>, p: u8, ip: Ipv4Addr, port: u16) -> bool {
    let (lo, hi) = match to_port {
        Some(t) => (t, t.saturating_add(hi - lo)),
        None => (lo, hi),
    };
    protos & proto_bit(p) != 0 && ip == to && (lo..=hi).contains(&port)
}

impl PortForward {
    /// The target of a connection to `dport`, if this forward covers it.
    pub fn target(&self, p: u8, dport: u16) -> Option<(Ipv4Addr, u16)> {
        dnat_target(self.protos, (self.lo, self.hi), self.to, self.to_port, p, dport)
    }

    /// `ip:port` is one of this forward's targets.
    fn is_target(&self, p: u8, ip: Ipv4Addr, port: u16) -> bool {
        dnat_is_target(self.protos, (self.lo, self.hi), self.to, self.to_port, p, ip, port)
    }

    /// The WAN port a target `ip:port` is reached on: its connections out
    /// leave from it, so both directions are one connection.
    fn wan_port(&self, p: u8, ip: Ipv4Addr, port: u16) -> Option<u16> {
        self.is_target(p, ip, port)
            .then(|| self.to_port.map_or(port, |t| self.lo.wrapping_add(port - t)))
    }
}

/// A redirect (`[[firewall.redirect]]`), compiled: new connections from
/// zone `from` (`None` = any network) to ports `lo..=hi` of an address
/// outside the networks (the internet), or of the router itself for a
/// port it does not serve ([`router_serves`]), go to `to` instead (port
/// `to_port + (p - lo)`, or the same port). Clients on the target's own
/// network are also translated to the router's address there, so the
/// answer comes back through it. The target's own connections and the
/// ones addressed to it are left alone. A redirect lets its connections
/// through the firewall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redirect {
    pub from: Option<u8>,
    /// [`proto::TCP`] and/or [`proto::UDP`].
    pub protos: u8,
    pub lo: u16,
    pub hi: u16,
    pub to: Ipv4Addr,
    pub to_port: Option<u16>,
}

impl Redirect {
    /// The target of a connection to `dport`, if this redirect covers it.
    pub fn target(&self, p: u8, dport: u16) -> Option<(Ipv4Addr, u16)> {
        dnat_target(self.protos, (self.lo, self.hi), self.to, self.to_port, p, dport)
    }

    /// `ip:port` is one of this redirect's targets.
    fn is_target(&self, p: u8, ip: Ipv4Addr, port: u16) -> bool {
        dnat_is_target(self.protos, (self.lo, self.hi), self.to, self.to_port, p, ip, port)
    }
}

/// Ports the router itself serves to its networks (DHCP, DNS, mDNS, the
/// web interface): connections to a router address there are never
/// redirected.
pub fn router_serves(p: u8, dport: u16) -> bool {
    matches!((p, dport), (PROTO_UDP, 67) | (PROTO_UDP | PROTO_TCP, 53) | (PROTO_UDP, 5353) | (PROTO_TCP, 80))
}

/// Broadcast, multicast and 0.0.0.0: never redirected.
fn not_unicast(ip: Ipv4Addr) -> bool {
    ip.is_broadcast() || ip.is_multicast() || ip.is_unspecified()
}

/// What [`shard_of`] needs to keep both directions of every connection in
/// one shard: the networks' prefixes (flows between them), the WAN
/// address and the port forwards (DNAT and hairpin connections live in the
/// shard of their target endpoint).
#[derive(Clone, Copy, Debug, Default)]
pub struct ShardHints<'a> {
    pub internal: &'a [(Ipv4Addr, u8)],
    /// Subnets routed through a router on one of the networks: inside,
    /// like the networks' own (flows between them and a network are pairs).
    pub routed: &'a [(Ipv4Addr, u8)],
    pub wan: Option<Ipv4Addr>,
    pub forwards: &'a [PortForward],
    /// The redirects: their connections, and everything to and from their
    /// targets' ports, live in the target endpoint's shard.
    pub redirects: &'a [Redirect],
}

/// Where a [`Rule`] applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleTo {
    /// Forwarded or to the router.
    Any,
    /// Traffic for the router itself.
    Router,
    /// Forwarded into this zone.
    Zone(u8),
}

/// Protocols of a [`Rule`]: bits.
pub mod proto {
    pub const TCP: u8 = 1;
    pub const UDP: u8 = 2;
    pub const ICMP: u8 = 4;
    pub const ANY: u8 = 0xff;
}

/// One firewall rule (`[[firewall.rule]]`), compiled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Source zone; `None` = any.
    pub from: Option<u8>,
    pub to: RuleTo,
    /// [`proto`] bits (other IP protocols match only `ANY`).
    pub protos: u8,
    /// (network, prefix length); `None` = any.
    pub src: Option<(Ipv4Addr, u8)>,
    pub dst: Option<(Ipv4Addr, u8)>,
    /// Inclusive destination port range (TCP/UDP only).
    pub dport: Option<(u16, u16)>,
    pub action: Action,
}

/// What a matching [`Rule`] does with a new flow or a packet for the router.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Accept,
    /// Silently.
    Drop,
    /// Answered (rate-limited, [`Stats::rejected`]): TCP gets a RST from
    /// the address it went to, everything else ICMP port unreachable.
    /// Never for ICMP errors, RSTs, fragments, or from or to broadcast and
    /// multicast addresses: those are dropped.
    Reject,
}

fn in_net(ip: Ipv4Addr, net: Option<(Ipv4Addr, u8)>) -> bool {
    net.is_none_or(|(a, l)| broadcast_of(a, l) == broadcast_of(ip, l))
}

impl Rule {
    fn matches(&self, from: u8, to: RuleTo, p: u8, src: Ipv4Addr, dst: Ipv4Addr, dport: Option<u16>) -> bool {
        let pbit = proto_bit(p);
        self.from.is_none_or(|z| z == from)
            && (self.to == RuleTo::Any || self.to == to)
            && (self.protos == proto::ANY || self.protos & pbit != 0)
            && in_net(src, self.src)
            && in_net(dst, self.dst)
            && self
                .dport
                .is_none_or(|(lo, hi)| dport.is_some_and(|d| (lo..=hi).contains(&d)))
    }
}

impl Policy {
    /// The first rule without addresses that matches an IPv6 packet (rules
    /// with IPv4 prefixes are for IPv4 only).
    fn rule6(&self, from: u8, to: RuleTo, p: u8, dport: Option<u16>) -> Option<(usize, Action)> {
        let any = Ipv4Addr::UNSPECIFIED;
        self.rules
            .iter()
            .position(|r| r.src.is_none() && r.dst.is_none() && r.matches(from, to, p, any, any, dport))
            .map(|i| (i, self.rules[i].action))
    }

    /// The first rule that matches: (its index, action).
    fn rule(&self, from: u8, to: RuleTo, p: u8, src: Ipv4Addr, dst: Ipv4Addr, dport: Option<u16>) -> Option<(usize, Action)> {
        self.rules
            .iter()
            .position(|r| r.matches(from, to, p, src, dst, dport))
            .map(|i| (i, self.rules[i].action))
    }

    fn may_forward(&self, from: u8, to: u8) -> bool {
        from == to
            || self
                .forward
                .get(from as usize)
                .is_some_and(|m| to < 32 && m & (1 << to) != 0)
    }

    fn input(&self, zone: u8) -> Option<u8> {
        self.input.get(zone as usize).copied().flatten()
    }

    /// What zone `z`'s refused input gets: [`Action::Reject`] or drop.
    fn input_refusal(&self, zone: u8) -> Action {
        match self.reject_input.get(zone as usize) {
            Some(true) => Action::Reject,
            _ => Action::Drop,
        }
    }
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
    /// Larger than the egress MTU and not split: IP options, or splitting
    /// off (`split`); with DF the sender gets "fragmentation needed".
    TooBig,
    /// To the router itself, from a zone whose input policy refuses it.
    Input,
    /// From the WAN with a source that cannot come from there: loopback or
    /// one of our own networks (ingress filtering, RFC 2827 / RFC 3704).
    Spoofed,
    /// A new connection whose tuple a tracked one already has (e.g. two
    /// internal hosts racing for one external port); not a full table.
    Clash,
    /// A new connection from a host that holds its limit of connections
    /// (`conntrack::Budget::with_host_limit`), none of them early-droppable.
    HostLimit,
}

pub const DROP_REASONS: usize = 15;

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
            Self::TooBig => "too-big",
            Self::Input => "input",
            Self::Spoofed => "spoofed",
            Self::Clash => "clash",
            Self::HostLimit => "host-limit",
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
            TooBig,
            Input,
            Spoofed,
            Clash,
            HostLimit,
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
        /// 0: as it is. Else the egress MTU: the packet (no DF) is larger
        /// and must be split into fragments of at most this many bytes
        /// first ([`wire::SplitPlan`], done by the caller: it owns the
        /// buffers).
        split: u16,
    },
    /// IPv6: send `len` bytes out of `egress` to `next_hop` (never split:
    /// routers do not fragment IPv6).
    Forward6 {
        egress: IfIndex,
        next_hop: Ipv6Addr,
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
    /// Tracked connections removed by [`Forwarder::recheck`].
    pub revoked: u64,
    /// Refused packets answered ([`Action::Reject`]).
    pub rejected: u64,
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

/// The router's own client sockets use ports from here up (DNS upstream,
/// SNTP); traffic to them is replies. NAPT uses 10000–39999 (conntrack
/// `NAT_PORTS`), port forwards anything below this.
pub const ROUTER_CLIENT_PORTS: u16 = 60_000;

/// ICMP errors: token bucket, 50/s with a burst of 20.
const ICMP_RATE_PER_SEC: u64 = 50;
const ICMP_BURST: u64 = 20;

/// Interface MTU unless [`Forwarder::set_mtu`] says otherwise.
pub const DEFAULT_MTU: u16 = 1500;

pub struct Forwarder {
    ifs: Vec<Interface>,
    /// Per interface: largest IP packet it sends (PPPoE: 1492).
    mtus: Vec<u16>,
    pub routes: RouteTable,
    /// Configured routes (destination, prefix length, router); in
    /// `routes` while a connected subnet holds their router.
    statics: Vec<(Ipv4Addr, u8, Ipv4Addr)>,
    pub ct: Conntrack,
    pub stats: Stats,
    icmp_tokens: u64,
    icmp_refill_ms: u64,
    policy: Option<Policy>,
    /// Packets each of the policy's rules decided (reset by a new policy).
    pub rule_hits: Vec<u64>,
    /// New connections each port forward took (reset by a new policy).
    pub forward_hits: Vec<u64>,
    /// New connections each redirect took (reset by a new policy).
    pub redirect_hits: Vec<u64>,
    /// Drop WAN packets with a spoofed source ([`DropReason::Spoofed`]);
    /// off only for the lab's negative control.
    pub wan_antispoof: bool,
    /// Forward IP fragments ([`crate::frag`]); off: dropped, as before
    /// (the lab's negative control).
    pub fragments: bool,
    /// Split packets without DF that are larger than the egress MTU
    /// ([`Verdict::Forward`] `split`); off: dropped as `too-big`, as before
    /// (the lab's negative control).
    pub split: bool,
    /// The last [`Self::process`]'s first fragment, forwarded: what its
    /// datagram's later fragments need ([`Self::take_fragment`]).
    frag: Option<frag::Decision>,
    /// IPv6 (docs/ipv6.md): off = every IPv6 frame is dropped as
    /// `unsupported`.
    pub ipv6: bool,
    /// Per interface: the router's IPv6 addresses besides the link-local
    /// one (from the MAC: [`wire::link_local`]): [unique local, global]
    /// on the networks, [_, the WAN address] on the WAN. Each has its /64
    /// (the WAN: its prefix) as a connected route in `routes6`.
    addrs6: Vec<[Option<(Ipv6Addr, u8)>; 2]>,
    /// IPv6 connections: routed, not translated (same budget as `ct`).
    pub ct6: crate::conntrack::Conntrack<Ipv6Addr>,
    pub routes6: RouteTable<Ipv6Addr>,
    /// Drop IPv6 from a network whose source is not in one of its /64s
    /// (BCP 38; no NAT hides it); off only for the lab's negative control.
    pub lan_antispoof: bool,
}

fn broadcast_of(addr: Ipv4Addr, len: u8) -> Ipv4Addr {
    let mask = if len == 0 {
        0
    } else {
        u32::MAX << (32 - len as u32)
    };
    Ipv4Addr::from(u32::from(addr) | !mask)
}

/// What an IPv6 packet means to conntrack.
enum Key6 {
    Flow(crate::conntrack::Tuple<Ipv6Addr>, u8),
    /// An ICMPv6 error (types 1–4) about the quoted packet's flow.
    Related(crate::conntrack::Tuple<Ipv6Addr>),
    Other,
}

fn key6(f: &[u8], v: &V6) -> Key6 {
    use crate::conntrack::Tuple;
    let (src, dst) = (v.src(f), v.dst(f));
    let l4 = v.l4;
    match v.proto {
        PROTO_TCP if v.l4_len >= 20 => {
            Key6::Flow(Tuple { proto: PROTO_TCP, src, sport: wire::get16(f, l4), dst, dport: wire::get16(f, l4 + 2) }, f[l4 + 13])
        }
        PROTO_UDP if v.l4_len >= 8 => Key6::Flow(Tuple { proto: PROTO_UDP, src, sport: wire::get16(f, l4), dst, dport: wire::get16(f, l4 + 2) }, 0),
        PROTO_ICMPV6 if v.l4_len >= 8 => match f[l4] {
            wire::ICMPV6_ECHO_REQUEST | wire::ICMPV6_ECHO_REPLY => {
                let id = wire::get16(f, l4 + 4);
                Key6::Flow(Tuple { proto: PROTO_ICMPV6, src, sport: id, dst, dport: id }, 0)
            }
            1..=4 => quoted6(f, l4 + 8).map_or(Key6::Other, Key6::Related),
            _ => Key6::Other,
        },
        _ => Key6::Other,
    }
}

/// The flow of the IPv6 packet an ICMPv6 error quotes at `at` (its header
/// and at least 8 bytes behind it; extension headers are not walked).
fn quoted6(f: &[u8], at: usize) -> Option<crate::conntrack::Tuple<Ipv6Addr>> {
    let h = f.get(at..at + 48)?;
    if h[0] >> 4 != 6 {
        return None;
    }
    let (src, dst) = (wire::get_ip6(h, 8), wire::get_ip6(h, 24));
    let l4 = &h[40..];
    let (proto, sport, dport) = match h[6] {
        p @ (PROTO_TCP | PROTO_UDP) => (p, wire::get16(l4, 0), wire::get16(l4, 2)),
        PROTO_ICMPV6 if matches!(l4[0], wire::ICMPV6_ECHO_REQUEST | wire::ICMPV6_ECHO_REPLY) => {
            let id = wire::get16(l4, 4);
            (PROTO_ICMPV6, id, id)
        }
        _ => return None,
    };
    Some(crate::conntrack::Tuple { proto, src, sport, dst, dport })
}

/// Both directions of an IPv6 flow on one shard: a symmetric hash of its
/// two endpoints (no NAT, so they look the same from either side).
fn shard6(frame: &[u8], shards: usize, hash_key: u64) -> usize {
    let Some(v) = V6::parse(frame, ETH_HDR) else {
        return 0;
    };
    if !v.has_l4() {
        return 0;
    }
    let t = match key6(frame, &v) {
        Key6::Flow(t, _) | Key6::Related(t) => t,
        Key6::Other => return 0,
    };
    let end = |a: Ipv6Addr, p: u16| {
        let x = u128::from(a);
        crate::conntrack::mix(hash_key ^ 0x7368_6172_6436, (x as u64) ^ ((x >> 64) as u64).rotate_left(23) ^ u64::from(p))
    };
    let h = end(t.src, t.sport) ^ end(t.dst, t.dport) ^ u64::from(t.proto);
    (crate::conntrack::mix(hash_key, h) % shards as u64) as usize
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

/// Shard of a connection between two internal endpoints (network to
/// network, no NAT): the same from either side.
fn pair_shard(t: &Tuple, shards: usize, hash_key: u64) -> usize {
    let a = (u32::from(t.src) as u64) << 16 | t.sport as u64;
    let b = (u32::from(t.dst) as u64) << 16 | t.dport as u64;
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let v = lo.rotate_left(29) ^ hi ^ (t.proto as u64) << 56;
    (crate::conntrack::mix(hash_key ^ 0x7061_6972, v) % shards as u64) as usize
}

/// Shard of the internal endpoint `(proto, ip, port)`: every connection
/// of one endpoint (EIM shares its NAT port) lives in the same shard.
pub fn endpoint_shard(proto: u8, ip: Ipv4Addr, port: u16, shards: usize, hash_key: u64) -> usize {
    if shards <= 1 {
        return 0;
    }
    let v = (u32::from(ip) as u64) << 24 | (port as u64) << 8 | proto as u64;
    (crate::conntrack::mix(hash_key ^ 0x0073_6861_7264, v) % shards as u64) as usize
}

/// Which of `shards` forwarder shards (`Forwarder::new_shard`, same
/// `hash_key`) a frame received on an interface with `role` belongs to.
/// Both directions of a connection map to the same shard:
/// - LAN ingress: the internal endpoint (source; for an ICMP error, the
///   embedded packet's destination) → [`endpoint_shard`]
/// - WAN ingress: the external (NAT) port, which the shard allocated from
///   its residue class: destination port (for an ICMP error, the embedded
///   packet's source port) `% shards`
///
/// - LAN ingress to another internal network (`hints.internal`: the
///   prefixes of the `Lan` interfaces): no NAT, so the endpoint pair, the
///   same from both sides
/// - port forwards (`hints.forwards`): a connection to a forwarded port of
///   the WAN address (from the WAN, or hairpin from inside), and the
///   target's packets to a router address (hairpin replies): the target
///   endpoint; its replies to the outside are its own endpoint already.
///   ICMP errors about them too: about a packet from a forwarded port of
///   the WAN address (from the outside or a hairpin client), or from the
///   target about a hairpin packet from a router address
/// - redirects (`hints.redirects`): a connection a redirect may take (to
///   its ports outside the networks or at a router address; the zone is
///   not known here, so also ones it then leaves alone: their NAT port
///   comes from that shard, so the WAN side finds them), connections to
///   the target's ports and the target's packets from them to inside: the
///   target endpoint. ICMP errors from inside go where the connection
///   they are about, seen from the sender, does.
///
/// Everything else (ARP, non-IPv4, later fragments, untracked protocols) → 0;
/// those frames are local, dropped, or never tracked.
pub fn shard_of(role: Role, frame: &[u8], shards: usize, hash_key: u64, hints: &ShardHints) -> usize {
    let internal = hints.internal;
    if shards <= 1 {
        return 0;
    }
    match wire::ethertype(frame) {
        Some(ETHERTYPE_IPV4) => {}
        Some(ETHERTYPE_IPV6) => return shard6(frame, shards, hash_key),
        _ => return 0,
    }
    let Some(v) = Ipv4View::parse(frame, ETH_HDR) else {
        return 0;
    };
    // A later fragment has no ports: the datapath sends it to its first
    // fragment's shard ([`crate::frag`]). A first fragment has them.
    if v.frag_offset != 0 {
        return 0;
    }
    let inside = |ip: Ipv4Addr| {
        internal
            .iter()
            .chain(hints.routed)
            .any(|&(a, l)| broadcast_of(a, l) == broadcast_of(ip, l))
    };
    let key = extract_key(frame, &v);
    if let Key::Flow(t, _) = &key {
        // To a forwarded port of the WAN address: the target's shard.
        if hints.wan == Some(t.dst)
            && let Some(to) = hints.forwards.iter().find_map(|f| f.target(t.proto, t.dport))
        {
            return endpoint_shard(t.proto, to.0, to.1, shards, hash_key);
        }
        // A target answering a hairpin client (to the router's address).
        if role == Role::Lan
            && internal.iter().any(|&(a, _)| a == t.dst)
            && hints.forwards.iter().any(|f| f.is_target(t.proto, t.src, t.sport))
        {
            return endpoint_shard(t.proto, t.src, t.sport, shards, hash_key);
        }
    }
    if let Key::Related { inner, .. } = &key {
        // About a packet the router sent from a forwarded port of the WAN
        // address (the target's answer, to the outside or to a hairpin
        // client): the target's shard.
        if hints.wan == Some(inner.src)
            && let Some(to) = hints.forwards.iter().find_map(|f| f.target(inner.proto, inner.sport))
        {
            return endpoint_shard(inner.proto, to.0, to.1, shards, hash_key);
        }
        // The target about a hairpin packet from a router address.
        if role == Role::Lan
            && internal.iter().any(|&(a, _)| a == inner.src)
            && hints.forwards.iter().any(|f| f.is_target(inner.proto, inner.dst, inner.dport))
        {
            return endpoint_shard(inner.proto, inner.dst, inner.dport, shards, hash_key);
        }
    }
    // Port forwards first: they win over redirects in the forwarder too.
    if role == Role::Lan && !hints.redirects.is_empty() {
        let router = |ip: Ipv4Addr| hints.wan == Some(ip) || internal.iter().any(|&(a, _)| a == ip);
        let flow = match &key {
            Key::Flow(t, _) => Some(*t),
            Key::Related { inner, .. } => Some(inner.inverse()),
            Key::Other => None,
        };
        if let Some(t) = flow
            && let Some(to) = redirect_endpoint(hints.redirects, &t, &router, &inside)
        {
            return endpoint_shard(t.proto, to.0, to.1, shards, hash_key);
        }
    }
    match (role, key) {
        (Role::Lan, Key::Flow(t, _)) if inside(t.dst) => pair_shard(&t, shards, hash_key),
        (Role::Lan, Key::Related { inner, .. }) if inside(inner.src) => {
            pair_shard(&inner, shards, hash_key)
        }
        (Role::Lan, Key::Flow(t, _)) => endpoint_shard(t.proto, t.src, t.sport, shards, hash_key),
        (Role::Lan, Key::Related { inner, .. }) => {
            endpoint_shard(inner.proto, inner.dst, inner.dport, shards, hash_key)
        }
        (Role::Wan, Key::Flow(t, _)) => t.dport as usize % shards,
        (Role::Wan, Key::Related { inner, .. }) => inner.sport as usize % shards,
        (_, Key::Other) => 0,
    }
}

/// [`shard_of`] for redirects: the target endpoint whose shard a flow `t`
/// from inside belongs to, if a redirect involves it.
fn redirect_endpoint(
    redirects: &[Redirect],
    t: &Tuple,
    router: &impl Fn(Ipv4Addr) -> bool,
    inside: &impl Fn(Ipv4Addr) -> bool,
) -> Option<(Ipv4Addr, u16)> {
    redirects.iter().find_map(|r| {
        if r.is_target(t.proto, t.dst, t.dport) {
            return Some((t.dst, t.dport));
        }
        if r.is_target(t.proto, t.src, t.sport) && inside(t.dst) {
            return Some((t.src, t.sport));
        }
        let candidate = t.src != r.to && !not_unicast(t.dst) && (router(t.dst) || !inside(t.dst));
        candidate.then(|| r.target(t.proto, t.dport)).flatten()
    })
}

impl Forwarder {
    pub fn new(max_conns: usize, hash_key: u64) -> Self {
        Self::new_shard(max_conns, hash_key, 1, 0)
    }

    /// Shard `shard` of `shards`: its own conntrack (NAT ports in its
    /// residue class); interfaces and routes must be configured the same on
    /// every shard. Feed it only frames [`shard_of`] maps to it.
    pub fn new_shard(max_conns: usize, hash_key: u64, shards: u16, shard: u16) -> Self {
        Self {
            ifs: Vec::new(),
            mtus: Vec::new(),
            routes: RouteTable::new(),
            statics: Vec::new(),
            ct: Conntrack::new_shard(max_conns, hash_key, shards, shard),
            stats: Stats::default(),
            icmp_tokens: ICMP_BURST,
            icmp_refill_ms: 0,
            policy: None,
            rule_hits: Vec::new(),
            forward_hits: Vec::new(),
            redirect_hits: Vec::new(),
            wan_antispoof: true,
            fragments: true,
            split: true,
            frag: None,
            ipv6: false,
            addrs6: Vec::new(),
            ct6: crate::conntrack::Conntrack::new_shard(max_conns, hash_key, shards, shard),
            routes6: RouteTable::new(),
            lan_antispoof: true,
        }
    }

    pub fn add_interface(&mut self, iface: Interface) -> IfIndex {
        self.ifs.push(iface);
        self.mtus.push(DEFAULT_MTU);
        self.addrs6.push([None, None]);
        let ifx = (self.ifs.len() - 1) as IfIndex;
        if let Some(a) = iface.addr {
            self.set_addr(ifx, Some(a));
        }
        ifx
    }

    pub fn interface(&self, ifx: IfIndex) -> &Interface {
        &self.ifs[ifx as usize]
    }

    /// The router's unique local address on an interface (IPv6).
    pub fn set_ula6(&mut self, ifx: IfIndex, addr: Option<Ipv6Addr>) {
        self.set_addr6(ifx, 0, addr.map(|a| (a, 64)));
    }

    /// The router's global IPv6 address on a network (its /64), or the
    /// WAN's (with its prefix length).
    pub fn set_gua6(&mut self, ifx: IfIndex, addr: Option<(Ipv6Addr, u8)>) {
        self.set_addr6(ifx, 1, addr);
    }

    fn set_addr6(&mut self, ifx: IfIndex, slot: usize, addr: Option<(Ipv6Addr, u8)>) {
        let old = core::mem::replace(&mut self.addrs6[ifx as usize][slot], addr);
        if old == addr {
            return;
        }
        if let Some((a, l)) = old {
            self.routes6.remove(a, l);
            // A prefix gone (a new delegation): its connections cannot go on.
            use crate::route::RouteAddr;
            let net = a.masked(l);
            let dead: Vec<_> = self
                .ct6
                .iter_ids()
                .filter(|(_, c)| c.orig.src.masked(l) == net || c.orig.dst.masked(l) == net)
                .map(|(id, _)| id)
                .collect();
            for id in dead {
                self.ct6.remove(id);
            }
        }
        if let Some((a, l)) = addr {
            self.routes6.set(Route { prefix: a, len: l, egress: ifx, gateway: None, kind: RouteKind::Connected });
        }
    }

    /// The IPv6 default route: through `gw` on `egress` (the WAN), or none.
    pub fn set_default_route6(&mut self, via: Option<(IfIndex, Ipv6Addr)>) {
        match via {
            Some((egress, gw)) => self.routes6.set(Route {
                prefix: Ipv6Addr::UNSPECIFIED,
                len: 0,
                egress,
                gateway: Some(gw),
                kind: RouteKind::Default,
            }),
            None => self.routes6.remove(Ipv6Addr::UNSPECIFIED, 0),
        }
    }

    /// One of the router's own IPv6 addresses on `ifx`.
    fn is_mine6(&self, ifx: IfIndex, a: Ipv6Addr) -> bool {
        a == wire::link_local(self.ifs[ifx as usize].mac) || self.addrs6[ifx as usize].iter().flatten().any(|&(m, _)| m == a)
    }

    /// `a` is in one of `ifx`'s prefixes.
    fn on6(&self, ifx: IfIndex, a: Ipv6Addr) -> bool {
        use crate::route::RouteAddr;
        self.addrs6[ifx as usize].iter().flatten().any(|&(m, l)| m.masked(l) == a.masked(l))
    }

    /// The interface's own MAC (a network moved to another port).
    pub fn set_mac(&mut self, ifx: IfIndex, mac: wire::Mac) {
        self.ifs[ifx as usize].mac = mac;
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
                kind: RouteKind::Connected,
            });
        }
        if self.ifs[ifx as usize].role == Role::Wan && old.map(|o| o.0) != addr.map(|a| a.0) {
            self.ct.flush_nat();
        }
        self.sync_static_routes();
    }

    /// The configured routes: (destination, prefix length, router). Each
    /// leaves through the interface whose subnet holds its router, while
    /// one does; a connected subnet or the default route with the same
    /// destination wins.
    pub fn set_static_routes(&mut self, routes: &[(Ipv4Addr, u8, Ipv4Addr)]) {
        self.statics = routes.to_vec();
        self.sync_static_routes();
    }

    fn sync_static_routes(&mut self) {
        self.routes.remove_kind(RouteKind::Static);
        for &(prefix, len, via) in &self.statics {
            let Some(egress) = self.ifs.iter().position(|i| {
                i.addr.is_some_and(|(a, l)| a != via && broadcast_of(a, l) == broadcast_of(via, l))
            }) else {
                continue;
            };
            if self.routes.get(prefix, len).is_some() {
                continue;
            }
            self.routes.set(Route {
                prefix,
                len,
                egress: egress as IfIndex,
                gateway: Some(via),
                kind: RouteKind::Static,
            });
        }
    }

    /// Move an interface to another firewall zone (new flows; tracked
    /// ones: [`Forwarder::recheck`]).
    pub fn set_zone(&mut self, ifx: IfIndex, zone: u8) {
        self.ifs[ifx as usize].zone = zone;
    }

    /// Largest IP packet `ifx` sends; bigger forwarded packets get ICMP
    /// "fragmentation needed" (DF) or are dropped, and TCP SYNs through
    /// it have their MSS clamped to fit.
    pub fn set_mtu(&mut self, ifx: IfIndex, mtu: u16) {
        self.mtus[ifx as usize] = mtu.max(576);
    }

    pub fn mtu(&self, ifx: IfIndex) -> u16 {
        self.mtus[ifx as usize]
    }

    pub fn set_default_route(&mut self, via: Option<(IfIndex, Ipv4Addr)>) {
        match via {
            Some((egress, gw)) => self.routes.set(Route {
                prefix: Ipv4Addr::UNSPECIFIED,
                len: 0,
                egress,
                gateway: Some(gw),
                kind: RouteKind::Default,
            }),
            None => self.routes.remove(Ipv4Addr::UNSPECIFIED, 0),
        }
    }

    /// Count this shard's connections against `budget`, shared with the
    /// other shards (`conntrack::Budget`). Call before the first packet.
    pub fn set_conn_budget(&mut self, budget: alloc::sync::Arc<crate::conntrack::Budget>) {
        self.ct6.set_budget(budget.clone());
        self.ct.set_budget(budget);
    }

    /// Use the zone firewall (`None`: the fixed LAN → WAN policy). Applies
    /// to new flows; [`Forwarder::recheck`] then removes the tracked ones
    /// it no longer allows.
    pub fn set_policy(&mut self, policy: Option<Policy>) {
        self.rule_hits = alloc::vec![0; policy.as_ref().map_or(0, |p| p.rules.len())];
        let fwds = policy.as_ref().map_or(&[][..], |p| &p.forwards[..]);
        self.forward_hits = alloc::vec![0; fwds.len()];
        self.redirect_hits = alloc::vec![0; policy.as_ref().map_or(0, |p| p.redirects.len())];
        let mut reserved = Vec::new();
        for f in fwds {
            for (bit, p) in [(proto::TCP, PROTO_TCP), (proto::UDP, PROTO_UDP)] {
                if f.protos & bit != 0 {
                    reserved.push((p, f.lo, f.hi));
                }
            }
        }
        self.ct.set_reserved(reserved);
        self.policy = policy;
    }

    /// After [`Forwarder::set_policy`] / [`Forwarder::set_zone`]: remove
    /// the tracked connections the firewall would no longer start as they
    /// are (zones, rules, a port forward or redirect gone or pointing
    /// elsewhere, a redirect now taking one, a masquerade on a port now
    /// forwarded). Their next packet is a new flow: refused, or for UDP
    /// and ICMP started again under the new policy (TCP without SYN is
    /// invalid, so a refused TCP connection ends). Connections without a
    /// route (WAN down, network removed) are left to expire. Rule hit
    /// counters are not touched. Returns how many were removed. O(n).
    pub fn recheck(&mut self) -> usize {
        let dead: Vec<_> = self
            .ct
            .iter_ids()
            .filter(|(_, c)| !self.still_allowed(c))
            .map(|(id, _)| id)
            .collect();
        for &id in &dead {
            self.ct.remove(id);
        }
        let dead6: Vec<_> = self
            .ct6
            .iter_ids()
            .filter(|(_, c)| !self.still_allowed6(&c.orig))
            .map(|(id, _)| id)
            .collect();
        for &id in &dead6 {
            self.ct6.remove(id);
        }
        let n = dead.len() + dead6.len();
        self.stats.revoked += n as u64;
        n
    }

    /// [`Forwarder::recheck`] for an IPv6 connection (no translation: the
    /// zones of its two ends and the rules).
    fn still_allowed6(&self, t: &crate::conntrack::Tuple<Ipv6Addr>) -> bool {
        let (Some(a), Some(b)) = (self.routes6.lookup(t.src), self.routes6.lookup(t.dst)) else {
            return true;
        };
        if a.egress == b.egress {
            return false;
        }
        let (from, to) = (self.ifs[a.egress as usize], self.ifs[b.egress as usize]);
        self.allowed6(&from, &to, t.proto, matches!(t.proto, PROTO_TCP | PROTO_UDP).then_some(t.dport)).0
    }

    /// May a new IPv6 flow go from `from` to `to`: (allowed, the rule that
    /// decided). Rules without addresses, then the zone policy; without a
    /// policy only LAN → WAN.
    fn allowed6(&self, from: &Interface, to: &Interface, proto: u8, dport: Option<u16>) -> (bool, Option<usize>) {
        match self.policy.as_ref() {
            Some(p) => match p.rule6(from.zone, RuleTo::Zone(to.zone), proto, dport) {
                Some((i, a)) => (a == Action::Accept, Some(i)),
                None => (p.may_forward(from.zone, to.zone), None),
            },
            None => (from.role == Role::Lan && to.role == Role::Wan, None),
        }
    }

    /// [`Forwarder::recheck`] for one connection.
    fn still_allowed(&self, c: &Conn) -> bool {
        let t = &c.orig;
        let Some(wan) = self.ifs.iter().position(|i| i.role == Role::Wan) else {
            return true;
        };
        // Where its first packet came from: the network it is on or
        // routed through, else the WAN.
        let ingress = self
            .routes
            .lookup(t.src)
            .filter(|r| self.ifs[r.egress as usize].role == Role::Lan)
            .map_or(wan as IfIndex, |r| r.egress);
        let iface = self.ifs[ingress as usize];
        let ported = matches!(t.proto, PROTO_TCP | PROTO_UDP);
        let dnat_now = self
            .forward_for(&iface, t)
            .or_else(|| self.redirect_for(&iface, t))
            .map(|(_, to)| to);
        if ported && (c.reply.src, c.reply.sport) != (t.dst, t.dport) {
            // Port forward or redirect: only while one still takes it there.
            return dnat_now == Some((c.reply.src, c.reply.sport));
        }
        if dnat_now.is_some() {
            return false; // a redirect takes it now
        }
        // Its NAT port is a port forward now: only the forward's own target
        // going out from it may keep it (`Conntrack::create_from`).
        let forwarded_port = Some(c.reply.dst) == self.wan_addr()
            && self.policy.as_ref().is_some_and(|p| {
                p.forwards.iter().any(|f| f.target(t.proto, c.reply.dport).is_some())
                    && !p.forwards.iter().any(|f| f.wan_port(t.proto, t.src, t.sport) == Some(c.reply.dport))
            });
        if ported && forwarded_port {
            return false;
        }
        let Some(route) = self.routes.lookup(t.dst) else {
            return true;
        };
        if route.egress == ingress {
            return false;
        }
        let egress = self.ifs[route.egress as usize];
        let ports = ported.then_some(t.dport);
        let rule = self
            .policy
            .as_ref()
            .and_then(|p| p.rule(iface.zone, RuleTo::Zone(egress.zone), t.proto, t.src, t.dst, ports))
            .map(|(_, a)| a == Action::Accept);
        match (&self.policy, rule) {
            (_, Some(accept)) => accept,
            (Some(p), None) => p.may_forward(iface.zone, egress.zone),
            (None, None) => iface.role == Role::Lan && egress.role == Role::Wan,
        }
    }

    /// The router's WAN address (of the first `Wan` interface).
    /// A source no packet from the WAN may carry: loopback, or an address
    /// in one of our networks (else a port forward would let it in and its
    /// target answer that internal host directly). Addresses in the WAN's
    /// own subnet stay allowed, so a WAN that overlaps a network (a
    /// misconfiguration) keeps reaching its gateway.
    fn spoofed_from_wan(&self, wan: &Interface, src: Ipv4Addr) -> bool {
        let inside = |(a, l): (Ipv4Addr, u8)| broadcast_of(a, l) == broadcast_of(src, l);
        src.is_loopback() || (self.inside_networks(src) && !wan.addr.is_some_and(inside))
    }

    /// `ip` is on one of the networks or routed through a router on one.
    fn inside_networks(&self, ip: Ipv4Addr) -> bool {
        let inside = |(a, l): (Ipv4Addr, u8)| broadcast_of(a, l) == broadcast_of(ip, l);
        self.ifs.iter().any(|i| i.role == Role::Lan && i.addr.is_some_and(inside))
            || self.routes.iter().any(|r| {
                r.kind == RouteKind::Static && self.ifs[r.egress as usize].role == Role::Lan && r.contains(ip)
            })
    }

    fn wan_addr(&self) -> Option<Ipv4Addr> {
        self.ifs.iter().find(|i| i.role == Role::Wan).and_then(|i| i.addr).map(|(a, _)| a)
    }

    /// A port forward for a new connection `t` arriving on `iface` for the
    /// WAN address: (forward index, target). From the WAN when `src`
    /// allows it; from inside only with hairpin.
    fn forward_for(&self, iface: &Interface, t: &Tuple) -> Option<(usize, (Ipv4Addr, u16))> {
        if !matches!(t.proto, PROTO_TCP | PROTO_UDP) || Some(t.dst) != self.wan_addr() {
            return None;
        }
        let fwds = &self.policy.as_ref()?.forwards;
        fwds.iter().enumerate().find_map(|(i, f)| {
            let ok = match iface.role {
                Role::Wan => in_net(t.src, f.src),
                Role::Lan => f.hairpin,
            };
            ok.then(|| f.target(t.proto, t.dport)).flatten().map(|to| (i, to))
        })
    }

    /// A redirect for a new connection `t` from a network on `iface`:
    /// (redirect index, target).
    fn redirect_for(&self, iface: &Interface, t: &Tuple) -> Option<(usize, (Ipv4Addr, u16))> {
        if iface.role != Role::Lan || !matches!(t.proto, PROTO_TCP | PROTO_UDP) || not_unicast(t.dst) {
            return None;
        }
        let rds = &self.policy.as_ref()?.redirects;
        if rds.is_empty() {
            return None;
        }
        if self.ifs.iter().any(|i| i.addr.is_some_and(|(a, _)| a == t.dst)) {
            if router_serves(t.proto, t.dport) {
                return None;
            }
        } else if self.inside_networks(t.dst) {
            return None; // inside a network (the target itself included)
        }
        rds.iter().enumerate().find_map(|(i, r)| {
            let ok = r.from.is_none_or(|z| z == iface.zone) && t.src != r.to;
            ok.then(|| r.target(t.proto, t.dport)).flatten().map(|to| (i, to))
        })
    }

    /// The rule that decides a new flow or packet for the router, counted.
    fn decide(&mut self, from: u8, to: RuleTo, p: u8, src: Ipv4Addr, dst: Ipv4Addr, dport: Option<u16>) -> Option<Action> {
        let (i, action) = self.policy.as_ref()?.rule(from, to, p, src, dst, dport)?;
        if let Some(h) = self.rule_hits.get_mut(i) {
            *h += 1;
        }
        Some(action)
    }

    /// An IPv6 frame (M7 step 1: nothing is forwarded yet). Traffic for the
    /// router's own addresses (link-local, the interface's ULA) and the
    /// link-scope groups it is in goes through [`Self::input6`]; anything
    /// else is dropped.
    fn process6(&mut self, now: u64, ingress: IfIndex, buf: &mut [u8], len: usize) -> Verdict {
        if !self.ipv6 {
            return self.drop(DropReason::Unsupported);
        }
        let iface = self.ifs[ingress as usize];
        let f = &buf[..len];
        let dmac = wire::dst_mac(f);
        if dmac != iface.mac && !wire::is_multicast_mac(&dmac) {
            return self.drop(DropReason::NotForUs);
        }
        let Some(v) = Ipv6View::parse(f, ETH_HDR) else {
            return self.drop(DropReason::Malformed);
        };
        let dst = v.dst(f);
        const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
        const MDNS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
        if dst.is_multicast() {
            if !(dst == ALL_NODES || dst == ALL_ROUTERS || dst == MDNS || wire::is_solicited_node(dst)) {
                return self.drop(DropReason::NotForUs);
            }
        } else if !self.is_mine6(ingress, dst) {
            return self.forward6(now, ingress, buf, len, &v);
        }
        self.input6(ingress, f, &v)
    }

    /// A forwarded IPv6 packet (docs/ipv6.md step 2b): not translated,
    /// tracked in `ct6`, the zone firewall for new flows (rules without
    /// addresses, then the zone policy), anti-spoofing both ways, hop limit
    /// and MTU answered with ICMPv6 errors (never fragmented).
    fn forward6(&mut self, now: u64, ingress: IfIndex, buf: &mut [u8], len: usize, v: &V6) -> Verdict {
        let f = &buf[..len];
        let (src, dst) = (v.src(f), v.dst(f));
        let iface = self.ifs[ingress as usize];
        // Never forwarded (RFC 4291 §2.5.6): link-local either side;
        // unspecified, loopback or multicast sources.
        let link_local = |a: Ipv6Addr| a.segments()[0] & 0xffc0 == 0xfe80;
        if link_local(src) || link_local(dst) || src.is_unspecified() || src.is_loopback() || src.is_multicast() || dst.is_loopback() {
            return self.drop(DropReason::Invalid);
        }
        if self.spoofed6(ingress, src) {
            return self.drop(DropReason::Spoofed);
        }
        // A later fragment reaching here has no recorded first one (the
        // datapath forwards the others: [`Self::forward_fragment`]).
        if !v.has_l4() || (v.is_fragment && !self.fragments) {
            return self.drop(DropReason::Fragment);
        }
        let key = key6(f, v);
        // Never an ICMPv6 error about an ICMPv6 error (RFC 4443 §2.4 e),
        // whether or not its quote is understood.
        let is_error = v.proto == PROTO_ICMPV6 && v.l4_len >= 1 && f[v.l4] < 128;
        if v.hop_limit(f) <= 1 {
            if is_error {
                return self.drop(DropReason::Invalid);
            }
            if !self.take_icmp_token(now) {
                return self.drop(DropReason::IcmpRateLimit);
            }
            return self.icmp6_error(ingress, buf, len, v, 3, 0, 0);
        }
        let Some(route) = self.routes6.lookup(dst).copied() else {
            return self.drop(DropReason::NoRoute);
        };
        if route.egress == ingress {
            return self.drop(DropReason::Hairpin);
        }
        let egress_if = self.ifs[route.egress as usize];
        let hit = match &key {
            Key6::Flow(t, _) => self.ct6.lookup_live(now, t),
            Key6::Related(inner) => self.ct6.lookup_live(now, &inner.inverse()),
            Key6::Other => None,
        };
        let (id, dir) = match hit {
            Some(h) => h,
            None => {
                let Key6::Flow(t, flags) = key else {
                    return self.drop(if matches!(key, Key6::Related(_)) {
                        DropReason::Invalid
                    } else {
                        DropReason::Unsupported
                    });
                };
                let ports = matches!(t.proto, PROTO_TCP | PROTO_UDP).then_some(t.dport);
                let (ok, rule) = self.allowed6(&iface, &egress_if, t.proto, ports);
                if let Some(h) = rule.and_then(|i| self.rule_hits.get_mut(i)) {
                    *h += 1;
                }
                if !ok {
                    return self.drop(DropReason::Firewall);
                }
                let new_ok = match t.proto {
                    PROTO_TCP => flags & (wire::TCP_SYN | wire::TCP_ACK | wire::TCP_RST) == wire::TCP_SYN,
                    PROTO_ICMPV6 => f[v.l4] == wire::ICMPV6_ECHO_REQUEST,
                    _ => true,
                };
                if !new_ok {
                    return self.drop(DropReason::Invalid);
                }
                let (clashes, host_limit) = (self.ct6.stats.clashes, self.ct6.stats.host_limit);
                match self.ct6.create_routed(now, t, flags) {
                    Some(id) => (id, crate::conntrack::Dir::Original),
                    None if self.ct6.stats.clashes != clashes => return self.drop(DropReason::Clash),
                    None if self.ct6.stats.host_limit != host_limit => return self.drop(DropReason::HostLimit),
                    None => return self.drop(DropReason::TableFull),
                }
            }
        };
        let mtu = self.mtus[route.egress as usize];
        if v.total_len() > mtu as usize {
            if is_error {
                return self.drop(DropReason::TooBig);
            }
            if !self.take_icmp_token(now) {
                return self.drop(DropReason::IcmpRateLimit);
            }
            return self.icmp6_error(ingress, buf, len, v, 2, 0, u32::from(mtu));
        }
        let tcp_flags = if let Key6::Flow(_, fl) = key { fl } else { 0 };
        v.dec_hop_limit(buf);
        if v.proto == PROTO_TCP && tcp_flags & wire::TCP_SYN != 0 {
            let path_mtu = mtu.min(self.mtus[ingress as usize]);
            wire::clamp_mss_at(buf, v.l4, v.l4_len, path_mtu.saturating_sub(60));
        }
        self.ct6.update(now, id, dir, tcp_flags, v.total_len());
        let conn = self.ct6.get(id).expect("conntrack entry exists");
        let f = &buf[..len];
        let tc = v.traffic_class(f);
        let (src_h, dst_h) = match dir {
            crate::conntrack::Dir::Original => (conn.orig_src_hash, conn.orig_dst_hash),
            crate::conntrack::Dir::Reply => (conn.orig_dst_hash, conn.orig_src_hash),
        };
        let is_pure_ack = v.proto == PROTO_TCP
            && tcp_flags & !(wire::TCP_PSH) == wire::TCP_ACK
            && v.l4_len == ((f[v.l4 + 12] >> 4) as usize) * 4;
        let class = Classification {
            flow_hash: conn.flow_hash,
            src_host_hash: src_h,
            dst_host_hash: dst_h,
            dscp: tc >> 2,
            ecn_capable: tc & 3 != 0,
            is_pure_ack,
        };
        self.stats.forwarded += 1;
        let next_hop = route.gateway.unwrap_or(dst);
        if v.is_fragment {
            // A first fragment: its decision for the rest (frag).
            self.frag = Some(frag::Decision::V6(frag::Decision6 {
                conn: id,
                dir,
                orig: conn.orig,
                egress: route.egress,
                next_hop,
                class: Classification { is_pure_ack: false, ..class },
            }));
        }
        Verdict::Forward6 {
            egress: route.egress,
            next_hop,
            len,
            class,
        }
    }

    /// An IPv6 source that cannot come from `ingress`: from the WAN one of
    /// our networks', from a network one outside its /64s.
    fn spoofed6(&self, ingress: IfIndex, src: Ipv6Addr) -> bool {
        match self.ifs[ingress as usize].role {
            Role::Wan => self.wan_antispoof && (0..self.ifs.len()).any(|i| self.ifs[i].role == Role::Lan && self.on6(i as IfIndex, src)),
            Role::Lan => self.lan_antispoof && !self.on6(ingress, src),
        }
    }

    /// An ICMPv6 error (RFC 4443) about the packet in `buf`, built in its
    /// place: from the router's address on `ingress` of the sender's
    /// scope, the packet quoted as far as the whole fits 1280 bytes; back
    /// to the sender.
    #[allow(clippy::too_many_arguments)]
    fn icmp6_error(&mut self, ingress: IfIndex, buf: &mut [u8], len: usize, v: &V6, kind: u8, code: u8, param: u32) -> Verdict {
        let f = &buf[..len];
        let to = v.src(f);
        let [ula, gua] = self.addrs6[ingress as usize];
        let ula_src = to.segments()[0] & 0xfe00 == 0xfc00;
        let from = match (ula_src, ula, gua) {
            (true, Some((u, _)), _) => u,
            (false, _, Some((g, _))) => g,
            _ => wire::link_local(self.ifs[ingress as usize].mac),
        };
        let quote_len = v.total_len().min(1280 - 48);
        let new_len = ETH_HDR + 48 + quote_len;
        if buf.len() < new_len {
            return self.drop(DropReason::Malformed);
        }
        let next_hop = match self.routes6.lookup(to) {
            Some(r) if r.egress == ingress => r.gateway.unwrap_or(to),
            _ => to,
        };
        buf.copy_within(v.ip..v.ip + quote_len, ETH_HDR + 48);
        let ip = ETH_HDR;
        buf[ip..ip + 4].copy_from_slice(&[0x6c, 0, 0, 0]); // traffic class CS6
        wire::put16(buf, ip + 4, (8 + quote_len) as u16);
        buf[ip + 6] = PROTO_ICMPV6;
        buf[ip + 7] = 64;
        buf[ip + 8..ip + 24].copy_from_slice(&from.octets());
        buf[ip + 24..ip + 40].copy_from_slice(&to.octets());
        let m = ip + 40;
        buf[m] = kind;
        buf[m + 1] = code;
        buf[m + 2..m + 4].fill(0);
        buf[m + 4..m + 8].copy_from_slice(&param.to_be_bytes());
        let c = wire::icmpv6_checksum(from, to, &buf[m..new_len]);
        wire::put16(buf, m + 2, c);
        self.stats.icmp_errors_sent += 1;
        Verdict::Forward6 {
            egress: ingress,
            next_hop,
            len: new_len,
            class: Classification { dscp: 0x30, ..Default::default() },
        }
    }

    /// IPv6 for the router, like [`Self::input`]: neighbor discovery (hop
    /// limit 255 only), MLD queries, ICMPv6 errors, echo replies and replies
    /// to the router's UDP clients always pass; then rules without
    /// addresses, then the zone's services. Refused input is dropped (no
    /// `reject` answers for IPv6 yet). MLD reports from other hosts are not
    /// needed (no multicast routing) and dropped.
    fn input6(&mut self, ingress: IfIndex, f: &[u8], v: &Ipv6View) -> Verdict {
        let zone = self.ifs[ingress as usize].zone;
        let l4 = |n: usize| v.has_l4() && v.l4_len >= n;
        if v.proto == PROTO_ICMPV6 && l4(1) {
            match f[v.l4] {
                wire::ICMPV6_ROUTER_SOLICIT..=wire::ICMPV6_REDIRECT => {
                    return if v.hop_limit(f) == 255 {
                        self.local()
                    } else {
                        self.drop(DropReason::Invalid)
                    };
                }
                wire::ICMPV6_MLD_QUERY => return self.local(),
                wire::ICMPV6_MLD_REPORT | wire::ICMPV6_MLD_DONE | wire::ICMPV6_MLD2_REPORT => {
                    return self.drop(DropReason::NotForUs);
                }
                1..=4 | wire::ICMPV6_ECHO_REPLY => return self.local(),
                _ => {}
            }
        }
        let dport = (matches!(v.proto, PROTO_TCP | PROTO_UDP) && l4(4)).then(|| wire::get16(f, v.l4 + 2));
        // Replies to the router's UDP clients; 546: its DHCPv6 client.
        if v.proto == PROTO_UDP && dport.is_some_and(|d| d >= ROUTER_CLIENT_PORTS || d == 546) {
            return self.local();
        }
        if let Some((i, action)) = self
            .policy
            .as_ref()
            .and_then(|p| p.rule6(zone, RuleTo::Router, v.proto, dport))
        {
            if let Some(h) = self.rule_hits.get_mut(i) {
                *h += 1;
            }
            return if action == Action::Accept {
                self.local()
            } else {
                self.drop(DropReason::Input)
            };
        }
        let Some(allowed) = self.policy.as_ref().and_then(|p| p.input(zone)) else {
            return self.local();
        };
        let service = match (v.proto, dport) {
            (PROTO_UDP | PROTO_TCP, Some(53)) => svc::DNS,
            (PROTO_UDP, Some(123)) => svc::NTP,
            (PROTO_UDP, Some(5353)) => svc::MDNS,
            (PROTO_TCP, Some(80)) => svc::MGMT,
            (PROTO_ICMPV6, _) if l4(1) && f[v.l4] == wire::ICMPV6_ECHO_REQUEST => svc::PING,
            _ => 0,
        };
        if service & allowed != 0 {
            self.local()
        } else {
            self.drop(DropReason::Input)
        }
    }

    /// Traffic for the router from `ingress`: accepted, or dropped by the
    /// zone's input policy. ARP and non-IPv4 never get here.
    ///
    /// Replies to the router's own clients (ports from
    /// [`ROUTER_CLIENT_PORTS`], the DHCP client's 68, ICMP other than echo
    /// requests) always pass: rules and zone input are about what reaches
    /// the router's services. Its UDP clients (DNS upstream, SNTP, DHCP)
    /// get that pass by port; TCP only from the servers it connects to
    /// ([`Policy::router_tcp_peers`]: DNS over TLS), so the client range
    /// is no way in for anyone else.
    fn input(&mut self, now: u64, ingress: IfIndex, buf: &mut [u8], len: usize, v: &Ipv4View) -> Verdict {
        let f = &buf[..len];
        let zone = self.ifs[ingress as usize].zone;
        let dport = (v.l4_len >= 4 && !v.is_fragment).then(|| wire::get16(f, v.l4 + 2));
        let icmp_type = (v.proto == PROTO_ICMP && v.l4_len >= 1 && !v.is_fragment).then(|| f[v.l4]);
        let reply = match v.proto {
            PROTO_UDP => dport.is_some_and(|d| d >= ROUTER_CLIENT_PORTS || d == 68),
            PROTO_TCP => dport.is_some_and(|d| d >= ROUTER_CLIENT_PORTS) && {
                let peer = (v.src(f), wire::get16(f, v.l4));
                self.policy.as_ref().is_some_and(|p| p.router_tcp_peers.contains(&peer))
            },
            PROTO_ICMP => icmp_type.is_some_and(|t| t != wire::ICMP_ECHO_REQUEST),
            _ => false,
        };
        if reply {
            return self.local();
        }
        let ports = matches!(v.proto, PROTO_TCP | PROTO_UDP).then_some(dport).flatten();
        let (src, dst) = (v.src(f), v.dst(f));
        match self.decide(zone, RuleTo::Router, v.proto, src, dst, ports) {
            Some(Action::Accept) => return self.local(),
            Some(a) => return self.refuse(now, ingress, dst, buf, len, v, DropReason::Input, a),
            None => {}
        }
        let Some(allowed) = self.policy.as_ref().and_then(|p| p.input(zone)) else {
            return self.local();
        };
        let service = match (v.proto, dport) {
            (PROTO_UDP, Some(67)) => svc::DHCP,
            (PROTO_UDP | PROTO_TCP, Some(53)) => svc::DNS,
            (PROTO_UDP, Some(123)) => svc::NTP,
            (PROTO_UDP, Some(5353)) => svc::MDNS,
            (PROTO_TCP, Some(80)) => svc::MGMT,
            (PROTO_ICMP, _) if v.l4_len >= 1 && f[v.l4] == wire::ICMP_ECHO_REQUEST => svc::PING,
            _ => 0,
        };
        if service & allowed != 0 {
            self.local()
        } else {
            let a = self.policy.as_ref().map_or(Action::Drop, |p| p.input_refusal(zone));
            self.refuse(now, ingress, dst, buf, len, v, DropReason::Input, a)
        }
    }

    /// A refused packet: dropped (counted as `reason`), or for
    /// [`Action::Reject`] replaced with the answer, from `from` (a router
    /// address: the one it was sent to, or the ingress interface's for
    /// forwarded traffic) back out of `ingress`.
    #[allow(clippy::too_many_arguments)]
    fn refuse(&mut self, now: u64, ingress: IfIndex, from: Ipv4Addr, buf: &mut [u8], len: usize, v: &Ipv4View, reason: DropReason, action: Action) -> Verdict {
        if action != Action::Reject || !self.rejectable(&buf[..len], v) || !self.take_icmp_token(now) {
            return self.drop(reason);
        }
        let r = if v.proto == PROTO_TCP {
            self.tcp_reset(ingress, buf, len, v)
        } else {
            let my_ip = if from.is_multicast() || from.is_broadcast() {
                match self.ifs[ingress as usize].addr {
                    Some((a, _)) => a,
                    None => return self.drop(reason),
                }
            } else {
                from
            };
            self.icmp_error(ingress, my_ip, buf, len, v, ICMP_DEST_UNREACH, 3, 0)
        };
        if matches!(r, Verdict::Forward { .. }) {
            self.stats.rejected += 1;
        }
        r
    }

    /// Whether a refused packet may be answered: unicast both ways, not a
    /// fragment, not an ICMP error or a RST (never answer those).
    fn rejectable(&self, f: &[u8], v: &Ipv4View) -> bool {
        let (src, dst) = (v.src(f), v.dst(f));
        let bcast = |ip: Ipv4Addr| {
            not_unicast(ip)
                || self
                    .ifs
                    .iter()
                    .any(|i| i.addr.is_some_and(|(a, l)| l < 31 && broadcast_of(a, l) == ip))
        };
        if v.is_fragment || bcast(src) || bcast(dst) {
            return false;
        }
        match v.proto {
            PROTO_TCP => v.l4_len >= 20 && f[v.l4 + 13] & wire::TCP_RST == 0,
            PROTO_ICMP => v.l4_len >= 8 && f[v.l4] == wire::ICMP_ECHO_REQUEST,
            _ => true,
        }
    }

    /// Replace a refused TCP segment with a RST to its sender, from the
    /// address and port it went to (RFC 9293 §3.10.7.1: with ACK, seq =
    /// its ack; else ACK of everything it occupies).
    fn tcp_reset(&mut self, ingress: IfIndex, buf: &mut [u8], len: usize, v: &Ipv4View) -> Verdict {
        let f = &buf[..len];
        let (src, dst) = (v.src(f), v.dst(f));
        let (sport, dport) = (wire::get16(f, v.l4), wire::get16(f, v.l4 + 2));
        let get32 = |o: usize| u32::from_be_bytes([f[o], f[o + 1], f[o + 2], f[o + 3]]);
        let (seq, ack, flags) = (get32(v.l4 + 4), get32(v.l4 + 8), f[v.l4 + 13]);
        let data_off = ((f[v.l4 + 12] >> 4) as usize * 4).clamp(20, v.l4_len);
        let occupies = (v.l4_len - data_off) as u32
            + (flags & wire::TCP_SYN != 0) as u32
            + (flags & wire::TCP_FIN != 0) as u32;
        let (rseq, rack, rflags) = if flags & wire::TCP_ACK != 0 {
            (ack, 0, wire::TCP_RST)
        } else {
            (0, seq.wrapping_add(occupies), wire::TCP_RST | wire::TCP_ACK)
        };
        let Some(back) = self.routes.lookup(src).copied() else {
            return self.drop(DropReason::NoRoute);
        };
        let new_len = ETH_HDR + 40;
        let ip = &mut buf[ETH_HDR..new_len];
        ip[0] = 0x45;
        ip[1] = 0;
        wire::put16(ip, 2, 40);
        wire::put16(ip, 4, 0);
        wire::put16(ip, 6, 0x4000); // DF
        ip[8] = 64;
        ip[9] = PROTO_TCP;
        wire::put16(ip, 10, 0);
        wire::put_ip(ip, 12, dst);
        wire::put_ip(ip, 16, src);
        let c = wire::checksum(&ip[..20]);
        wire::put16(ip, 10, c);
        let tcp = &mut ip[20..];
        wire::put16(tcp, 0, dport);
        wire::put16(tcp, 2, sport);
        tcp[4..8].copy_from_slice(&rseq.to_be_bytes());
        tcp[8..12].copy_from_slice(&rack.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = rflags;
        tcp[14..20].fill(0); // window, checksum, urgent
        let c = wire::l4_checksum(dst, src, PROTO_TCP, tcp);
        wire::put16(tcp, 16, c);
        Verdict::Forward {
            egress: ingress,
            next_hop: back.gateway.unwrap_or(src),
            len: new_len,
            class: Classification::default(),
            split: 0,
        }
    }

    pub fn expire(&mut self, now: u64) -> usize {
        self.ct.expire(now) + self.ct6.expire(now)
    }

    /// [`Forwarder::expire`], removing at most `max` connections.
    pub fn expire_some(&mut self, now: u64, max: usize) -> usize {
        let n = self.ct.expire_some(now, max);
        n + self.ct6.expire_some(now, max - n)
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
        self.frag = None;
        let iface = self.ifs[ingress as usize];
        let f = &buf[..len];
        let Some(et) = wire::ethertype(f) else {
            return self.drop(DropReason::Malformed);
        };
        if et != ETHERTYPE_IPV4 {
            if et == ETHERTYPE_IPV6 {
                return self.process6(now, ingress, buf, len);
            }
            return self.local(); // ARP, …: the router stack decides
        }
        let dmac = wire::dst_mac(f);
        if dmac != iface.mac && !wire::is_multicast_mac(&dmac) {
            return self.drop(DropReason::NotForUs);
        }
        let Some(v) = Ipv4View::parse(f, ETH_HDR) else {
            return self.drop(DropReason::Malformed);
        };
        if iface.role == Role::Wan && self.wan_antispoof && self.spoofed_from_wan(&iface, v.src(f)) {
            return self.drop(DropReason::Spoofed);
        }
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

        // A later fragment reaching here has no recorded first one (the
        // datapath forwards the others: [`Self::forward_fragment`]); a
        // first fragment goes on like a whole packet if it holds its L4
        // header (RFC 1858).
        if v.is_fragment
            && (!self.fragments || v.frag_offset != 0 || !matches!(frag::classify(f), frag::Kind::First(_)))
        {
            return if to_us {
                self.input(now, ingress, buf, len, &v)
            } else {
                self.drop(DropReason::Fragment)
            };
        }
        let key = extract_key(f, &v);
        let hit = match &key {
            Key::Flow(t, _) => self.ct.lookup_live(now, t),
            Key::Related { inner, .. } => self.ct.lookup_live(now, &inner.inverse()),
            Key::Other => None,
        };

        // A new connection to a port forward (from the WAN, or hairpin),
        // or one a redirect takes.
        let dnat = match (&key, hit) {
            (Key::Flow(t, _), None) => self
                .forward_for(&iface, t)
                .map(|(i, to)| (Dnat::Forward(i), to))
                .or_else(|| self.redirect_for(&iface, t).map(|(i, to)| (Dnat::Redirect(i), to))),
            _ => None,
        };
        // Addressed to the router, and neither a translated connection
        // (NAT reply, port forward, redirect) nor a new one to translate:
        // local.
        let nat_conn = hit.is_some_and(|(id, _)| self.ct.get(id).is_some_and(|c| c.nat));
        if to_us && !nat_conn && dnat.is_none() {
            return self.input(now, ingress, buf, len, &v);
        }

        // Route on the destination after translation.
        let conn: Option<Conn> = hit.and_then(|(id, _)| self.ct.get(id).cloned());
        let out_dst = match (&conn, hit, dnat) {
            (Some(c), Some((_, d)), _) if c.nat => c.translated(d).dst,
            (_, _, Some((_, to))) => to.0,
            _ => dst,
        };
        let Some(route) = self.routes.lookup(out_dst).copied() else {
            return self.drop(DropReason::NoRoute);
        };
        // Back out where it came from: only a translated connection
        // (hairpin through the WAN address, a redirect to the same
        // network) may.
        if route.egress == ingress && !nat_conn && dnat.is_none() {
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
                let ports = matches!(t.proto, PROTO_TCP | PROTO_UDP).then_some(t.dport);
                // A port forward or redirect lets its connections in (no
                // rule or zone needed, like OpenWrt redirects).
                let rule = match dnat {
                    Some(_) => Some(Action::Accept),
                    None => self.decide(iface.zone, RuleTo::Zone(egress_if.zone), t.proto, t.src, t.dst, ports),
                };
                let allowed = match (&self.policy, rule) {
                    (_, Some(a)) => a,
                    (Some(p), None) if p.may_forward(iface.zone, egress_if.zone) => Action::Accept,
                    (None, None) if iface.role == Role::Lan && egress_if.role == Role::Wan => Action::Accept,
                    _ => Action::Drop,
                };
                if allowed != Action::Accept {
                    return self.refuse(now, ingress, my_ip, buf, len, &v, DropReason::Firewall, allowed);
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
                // Masquerade towards the WAN only; between networks
                // addresses stay as they are.
                let (clashes, host_limit) = (self.ct.stats.clashes, self.ct.stats.host_limit);
                let created = match dnat {
                    // Port forward: to the target; hairpin (an internal
                    // client) also from the router's address there.
                    // Redirect: to the target; from the router's address
                    // when the client is on the target's network (else
                    // the target would answer it directly).
                    Some((kind, to)) => {
                        let masq = match (kind, iface.role) {
                            (Dnat::Forward(_), Role::Lan) => egress_if.addr.map(|(a, _)| a),
                            (Dnat::Forward(_), Role::Wan) => None,
                            (Dnat::Redirect(_), _) if route.egress == ingress => egress_if.addr.map(|(a, _)| a),
                            (Dnat::Redirect(_), _) => None,
                        };
                        let id = self.ct.create_dnat(now, t, to, masq, flags);
                        let hits = match kind {
                            Dnat::Forward(i) => self.forward_hits.get_mut(i),
                            Dnat::Redirect(i) => self.redirect_hits.get_mut(i),
                        };
                        if id.is_some()
                            && let Some(h) = hits
                        {
                            *h += 1;
                        }
                        id
                    }
                    None => {
                        let nat_ip = match egress_if.role {
                            Role::Wan => egress_if.addr.map(|(a, _)| a),
                            Role::Lan => None,
                        };
                        // A port forward's target going out: from its
                        // forwarded port, so a peer it contacts can also
                        // connect to the forward (one connection, no clash).
                        let port = nat_ip.and_then(|_| {
                            let fwds = &self.policy.as_ref()?.forwards;
                            fwds.iter().find_map(|f| f.wan_port(t.proto, t.src, t.sport))
                        });
                        self.ct.create_from(now, t, nat_ip, port, flags)
                    }
                };
                match created {
                    Some(id) => (id, Dir::Original),
                    None if self.ct.stats.clashes != clashes => return self.drop(DropReason::Clash),
                    None if self.ct.stats.host_limit != host_limit => return self.drop(DropReason::HostLimit),
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
            return self.icmp_error(ingress, my_ip, buf, len, &v, ICMP_TIME_EXCEEDED, 0, 0);
        }

        // MTU: with DF, "fragmentation needed" back (RFC 1191); without,
        // split into fragments after the rewrite (RFC 791), unless it has
        // IP options (not split) or splitting is off.
        let mtu = self.mtus[route.egress as usize];
        let mut split = 0;
        if v.total_len > mtu as usize {
            if !v.dont_fragment(f) {
                if !self.split || v.ihl != 20 {
                    return self.drop(DropReason::TooBig);
                }
                split = mtu;
            } else if matches!(key, Key::Related { .. }) {
                return self.drop(DropReason::TooBig);
            } else {
                if !self.take_icmp_token(now) {
                    return self.drop(DropReason::IcmpRateLimit);
                }
                return self.icmp_error(ingress, my_ip, buf, len, &v, ICMP_DEST_UNREACH, 4, mtu);
            }
        }

        let tcp_flags = if let Key::Flow(_, fl) = key { fl } else { 0 };
        let conn = self.ct.get(id).cloned().expect("conntrack entry exists");
        v.dec_ttl(buf);
        if conn.nat {
            // The tuple as the packet arrived, and what it must become:
            // rewrite whatever differs (masquerade: the source going out,
            // the destination coming back; port forwards: the other way;
            // hairpin: both).
            let seen = match dir {
                Dir::Original => conn.orig,
                Dir::Reply => conn.reply,
            };
            let tgt = conn.translated(dir);
            match key {
                Key::Flow(..) => {
                    if seen.src != tgt.src {
                        v.set_addr(buf, true, tgt.src);
                    }
                    if seen.sport != tgt.sport {
                        v.set_port(buf, true, tgt.sport);
                    }
                    if seen.dst != tgt.dst {
                        v.set_addr(buf, false, tgt.dst);
                    }
                    if seen.dport != tgt.dport && seen.proto != PROTO_ICMP {
                        v.set_port(buf, false, tgt.dport);
                    }
                }
                Key::Related {
                    inner_ip,
                    inner_ihl,
                    inner,
                } => {
                    translate_icmp_error(buf, &v, &seen, &tgt, inner.proto, inner_ip, inner_ihl);
                }
                Key::Other => {}
            }
        }
        if tcp_flags & wire::TCP_SYN != 0 {
            // Both ways: the SYN-ACK tells the LAN host what the server
            // may send.
            let path_mtu = mtu.min(self.mtus[ingress as usize]);
            wire::clamp_mss(buf, &v, path_mtu.saturating_sub(40));
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
        let class = Classification {
            flow_hash: conn.flow_hash,
            src_host_hash: src_h,
            dst_host_hash: dst_h,
            dscp: tos >> 2,
            ecn_capable: tos & 3 != 0,
            is_pure_ack,
        };
        let next_hop = route.gateway.unwrap_or(out_dst);
        if v.is_fragment {
            self.frag = Some(frag::Decision::V4(frag::Decision4 {
                conn: id,
                dir,
                orig: conn.orig,
                egress: route.egress,
                next_hop,
                src: v.src(f),
                dst: v.dst(f),
                class: Classification { is_pure_ack: false, ..class },
            }));
        }
        Verdict::Forward {
            egress: route.egress,
            next_hop,
            len,
            class,
            split,
        }
    }

    /// After [`Self::process`] forwarded a first fragment: the decision its
    /// datagram's later fragments take ([`frag::Table::record_forward`]).
    pub fn take_fragment(&mut self) -> Option<frag::Decision> {
        self.frag.take()
    }

    /// A later fragment of a datagram whose first fragment this shard
    /// forwarded with `d`: the same egress and address rewrite, if its
    /// connection still exists. No ICMP errors (only about first
    /// fragments, RFC 792); too large for the egress: dropped (fragments
    /// are not split).
    pub fn forward_fragment(&mut self, now: u64, ingress: IfIndex, buf: &mut [u8], len: usize, d: &frag::Decision) -> Verdict {
        match d {
            frag::Decision::V4(d) => self.forward_fragment4(now, ingress, buf, len, d),
            frag::Decision::V6(d) => self.forward_fragment6(now, ingress, buf, len, d),
        }
    }

    /// A later IPv6 fragment with its first one's decision: the same
    /// egress and next hop, one hop less, no rewrite (docs/ipv6.md 2c).
    fn forward_fragment6(&mut self, now: u64, ingress: IfIndex, buf: &mut [u8], len: usize, d: &frag::Decision6) -> Verdict {
        let iface = self.ifs[ingress as usize];
        let f = &buf[..len];
        if wire::ethertype(f) != Some(ETHERTYPE_IPV6) || !self.ipv6 {
            return self.drop(DropReason::Malformed);
        }
        let dmac = wire::dst_mac(f);
        if dmac != iface.mac {
            return self.drop(DropReason::NotForUs);
        }
        let Some(v) = V6::parse(f, ETH_HDR) else {
            return self.drop(DropReason::Malformed);
        };
        if self.spoofed6(ingress, v.src(f)) {
            return self.drop(DropReason::Spoofed);
        }
        if !self.fragments || v.frag_offset == 0 || (v.proto == PROTO_TCP && v.frag_offset == 1) {
            return self.drop(DropReason::Fragment);
        }
        if self.ct6.get(d.conn).is_none_or(|c| c.orig != d.orig) || v.hop_limit(f) <= 1 {
            return self.drop(DropReason::Fragment);
        }
        if v.total_len() > self.mtus[d.egress as usize] as usize {
            return self.drop(DropReason::TooBig);
        }
        v.dec_hop_limit(buf);
        self.ct6.update(now, d.conn, d.dir, 0, v.total_len());
        self.stats.forwarded += 1;
        Verdict::Forward6 { egress: d.egress, next_hop: d.next_hop, len, class: d.class }
    }

    fn forward_fragment4(&mut self, now: u64, ingress: IfIndex, buf: &mut [u8], len: usize, d: &frag::Decision4) -> Verdict {
        let iface = self.ifs[ingress as usize];
        let f = &buf[..len];
        if wire::ethertype(f) != Some(ETHERTYPE_IPV4) {
            return self.drop(DropReason::Malformed);
        }
        let dmac = wire::dst_mac(f);
        if dmac != iface.mac && !wire::is_multicast_mac(&dmac) {
            return self.drop(DropReason::NotForUs);
        }
        let Some(v) = Ipv4View::parse(f, ETH_HDR) else {
            return self.drop(DropReason::Malformed);
        };
        if iface.role == Role::Wan && self.wan_antispoof && self.spoofed_from_wan(&iface, v.src(f)) {
            return self.drop(DropReason::Spoofed);
        }
        if !self.fragments || v.frag_offset == 0 || (v.proto == PROTO_TCP && v.frag_offset == 1) {
            return self.drop(DropReason::Fragment);
        }
        if self.ct.get(d.conn).is_none_or(|c| c.orig != d.orig) {
            return self.drop(DropReason::Fragment);
        }
        if v.ttl(f) <= 1 {
            return self.drop(DropReason::Fragment);
        }
        let mtu = self.mtus[d.egress as usize];
        let split = if v.total_len <= mtu as usize {
            0
        } else if self.split && !v.dont_fragment(f) && v.ihl == 20 {
            mtu
        } else {
            return self.drop(DropReason::TooBig);
        };
        v.dec_ttl(buf);
        v.set_ip_addr(buf, true, d.src);
        v.set_ip_addr(buf, false, d.dst);
        self.ct.update(now, d.conn, d.dir, 0, v.total_len);
        self.stats.forwarded += 1;
        Verdict::Forward {
            egress: d.egress,
            next_hop: d.next_hop,
            len,
            class: d.class,
            split,
        }
    }

    /// Replace the frame with an ICMP error to its sender: time exceeded,
    /// or destination unreachable code 4 (fragmentation needed) with the
    /// next hop's MTU.
    #[allow(clippy::too_many_arguments)]
    fn icmp_error(
        &mut self,
        ingress: IfIndex,
        my_ip: Ipv4Addr,
        buf: &mut [u8],
        len: usize,
        v: &Ipv4View,
        kind: u8,
        code: u8,
        next_hop_mtu: u16,
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
        icmp[0] = kind;
        icmp[1] = code;
        icmp[2..6].fill(0);
        wire::put16(icmp, 6, next_hop_mtu);
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
            split: 0,
        }
    }
}

/// NAT for an ICMP error about a tracked flow: rewrite the side of the outer
/// header that NAT changes, the whole embedded header, and the checksums.
/// An ICMP error about a translated connection, travelling as `seen`
/// would (its direction's tuple): the outer addresses that are the
/// connection's endpoints become `tgt`'s, and the embedded packet is
/// rewritten to how the receiver sent it.
fn translate_icmp_error(
    buf: &mut [u8],
    v: &Ipv4View,
    seen: &Tuple,
    tgt: &Tuple,
    inner_proto: u8,
    ip: usize,
    ihl: usize,
) {
    // The reporter may be a router on the path: its address stays.
    if v.src(buf) == seen.src {
        v.set_addr(buf, true, tgt.src);
    }
    if v.dst(buf) == seen.dst {
        v.set_addr(buf, false, tgt.dst);
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
            zone: 0,
        });
        fw.add_interface(Interface {
            mac: LAN_MAC,
            addr: Some((ROUTER_LAN, 24)),
            role: Role::Lan,
            zone: 1,
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
            ..
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
        // MF, offset 128 B: a later fragment whose first one was not seen.
        f[ETH_HDR + 6] = 0x20;
        f[ETH_HDR + 7] = 16;
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
        // Later fragments with a recorded decision, mutated the same way.
        let dgram = udp_datagram(HOST, SERVER, 5000, 4500, &[3u8; 3000]);
        let frames = fragments(LAN_MAC, HOST, SERVER, PROTO_UDP, 5, &dgram, 1480);
        let mut f = frames[0].clone();
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { .. }));
        let d = fw.take_fragment().unwrap();
        for i in 0..30_000 {
            let mut f = frames[1 + i % 2].clone();
            for _ in 0..6 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let j = seed as usize % (f.len() - 64);
                f[j] = (seed >> 8) as u8;
            }
            let len = (seed as usize >> 4) % (f.len() - 64 + 1);
            let _ = fw.forward_fragment(i as u64, (i % 2) as IfIndex, &mut f, len, &d);
        }
    }

    // ---- sharding (M11): both directions of every connection hit one shard

    const SHARDS: usize = 8;

    fn shards() -> Vec<Forwarder> {
        (0..SHARDS)
            .map(|k| {
                let mut fw = Forwarder::new_shard(1000, 42, SHARDS as u16, k as u16);
                fw.add_interface(Interface {
                    mac: WAN_MAC,
                    addr: Some((ROUTER_WAN, 24)),
                    role: Role::Wan,
            zone: 0,
                });
                fw.add_interface(Interface {
                    mac: LAN_MAC,
                    addr: Some((ROUTER_LAN, 24)),
                    role: Role::Lan,
            zone: 1,
                });
                fw.set_default_route(Some((WAN, GW)));
                fw
            })
            .collect()
    }

    /// LAN → WAN through the shard `shard_of` picks; returns (shard, NAT port, translated frame).
    fn out_sharded(
        fws: &mut [Forwarder],
        proto: u8,
        host: Ipv4Addr,
        sport: u16,
        server: Ipv4Addr,
    ) -> (usize, u16, Vec<u8>) {
        let l4 = match proto {
            PROTO_TCP => tcp_segment(host, server, sport, 80, TCP_SYN, b""),
            PROTO_UDP => udp_datagram(host, server, sport, 53, b"q"),
            _ => icmp_echo(ICMP_ECHO_REQUEST, sport, 1),
        };
        let mut f = to(LAN_MAC, ipv4_frame(host, server, proto, 64, &l4));
        let len = f.len() - 64;
        let k = shard_of(Role::Lan, &f[..len], SHARDS, 42, &ShardHints::default());
        let Verdict::Forward { len, .. } = fws[k].process(0, LAN, &mut f, len) else {
            panic!("outbound {proto} {host}:{sport} not forwarded")
        };
        let f = f[..len].to_vec();
        let v = view(&f);
        let port = if proto == PROTO_ICMP {
            wire::get16(&f, v.l4 + 4)
        } else {
            wire::get16(&f, v.l4)
        };
        (k, port, f)
    }

    #[test]
    fn shards_keep_both_directions_together() {
        let mut fws = shards();
        let mut used = [0usize; SHARDS];
        for i in 0..200u16 {
            let proto = [PROTO_TCP, PROTO_UDP, PROTO_ICMP][i as usize % 3];
            let host = Ipv4Addr::new(192, 168, 1, 100 + (i % 50) as u8);
            let (k, port, _) = out_sharded(&mut fws, proto, host, 20_000 + i, SERVER);
            used[k] += 1;
            assert_eq!(
                port as usize % SHARDS,
                k,
                "NAT port outside the shard's class"
            );
            let l4 = match proto {
                PROTO_TCP => tcp_segment(SERVER, ROUTER_WAN, 80, port, TCP_SYN | TCP_ACK, b""),
                PROTO_UDP => udp_datagram(SERVER, ROUTER_WAN, 53, port, b"a"),
                _ => icmp_echo(ICMP_ECHO_REPLY, port, 1),
            };
            let mut r = to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, proto, 50, &l4));
            let len = r.len() - 64;
            assert_eq!(
                shard_of(Role::Wan, &r[..len], SHARDS, 42, &ShardHints::default()),
                k,
                "reply maps to another shard"
            );
            let Verdict::Forward {
                egress, next_hop, ..
            } = fws[k].process(1, WAN, &mut r, len)
            else {
                panic!("reply not forwarded")
            };
            assert_eq!((egress, next_hop), (LAN, host));
            // Negative control: another shard does not know the connection,
            // so the reply is not forwarded (it goes to the router stack).
            let mut r2 = to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, proto, 50, &l4));
            let other = fws[(k + 1) % SHARDS].process(1, WAN, &mut r2, len);
            assert!(
                !matches!(other, Verdict::Forward { .. }),
                "wrong shard forwarded: {other:?}"
            );
        }
        assert!(
            used.iter().all(|&n| n > 0),
            "flows not spread over shards: {used:?}"
        );
    }

    #[test]
    fn shards_keep_endpoint_independent_mapping() {
        let mut fws = shards();
        let (k1, p1, _) = out_sharded(&mut fws, PROTO_UDP, HOST, 5000, SERVER);
        let (k2, p2, _) = out_sharded(
            &mut fws,
            PROTO_UDP,
            HOST,
            5000,
            Ipv4Addr::new(198, 51, 100, 99),
        );
        assert_eq!(
            (k1, p1),
            (k2, p2),
            "one internal endpoint, one shard and one external port"
        );
        // The internal port is kept when it is in the shard's class.
        let preserved = (0..SHARDS as u16 * 4)
            .map(|i| out_sharded(&mut fws, PROTO_UDP, HOST, 30_000 + i, SERVER))
            .filter(|&(_, p, _)| (30_000..30_000 + SHARDS as u16 * 4).contains(&p))
            .count();
        assert!(preserved > 0);
    }

    #[test]
    fn shards_route_icmp_errors_to_the_connection() {
        let mut fws = shards();
        let (k, port, out) = out_sharded(&mut fws, PROTO_UDP, HOST, 6000, SERVER);
        // Destination unreachable from SERVER about our translated packet.
        let mut icmp = vec![wire::ICMP_DEST_UNREACH, 3, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&out[ETH_HDR..ETH_HDR + 28]);
        let c = wire::checksum(&icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let mut e = to(
            WAN_MAC,
            ipv4_frame(SERVER, ROUTER_WAN, PROTO_ICMP, 50, &icmp),
        );
        let len = e.len() - 64;
        assert_eq!(wire::get16(&out, view(&out).l4), port);
        assert_eq!(shard_of(Role::Wan, &e[..len], SHARDS, 42, &ShardHints::default()), k);
        let Verdict::Forward {
            egress, next_hop, ..
        } = fws[k].process(2, WAN, &mut e, len)
        else {
            panic!("ICMP error not forwarded")
        };
        assert_eq!((egress, next_hop), (LAN, HOST));
    }

    #[test]
    fn unsharded_is_unchanged() {
        assert_eq!(shard_of(Role::Lan, &[0u8; 60], 1, 42, &ShardHints::default()), 0);
        let mut fw = router();
        assert_eq!(fw.ct.shard(), (1, 0));
        syn_out(&mut fw);
    }

    /// A TCP segment with options (padded to 4 bytes).
    fn tcp_with_options(src: Ipv4Addr, dst: Ipv4Addr, flags: u8, opts: &[u8]) -> Vec<u8> {
        let mut o = opts.to_vec();
        while !o.len().is_multiple_of(4) {
            o.push(0);
        }
        let mut s = vec![0u8; 20];
        wire::put16(&mut s, 0, 40001);
        wire::put16(&mut s, 2, 80);
        s[12] = (((20 + o.len()) / 4) << 4) as u8;
        s[13] = flags;
        wire::put16(&mut s, 14, 65535);
        s.extend_from_slice(&o);
        let c = wire::l4_checksum(src, dst, PROTO_TCP, &s);
        wire::put16(&mut s, 16, c);
        s
    }

    fn mss_of(f: &[u8], at: usize) -> u16 {
        wire::get16(f, view(f).l4 + at)
    }

    #[test]
    fn mss_clamped_to_the_pppoe_mtu() {
        let mut fw = router();
        fw.set_mtu(WAN, 1492);
        // MSS 1460 at an even offset, then (after a NOP) at an odd one.
        for (opts, at) in [
            (&[2u8, 4, 0x05, 0xb4][..], 22),
            (&[1u8, 2, 4, 0x05, 0xb4][..], 23),
        ] {
            let seg = tcp_with_options(HOST, SERVER, TCP_SYN, opts);
            let mut f = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_TCP, 64, &seg));
            let Verdict::Forward { len, .. } = run(&mut fw, 0, LAN, &mut f) else {
                panic!()
            };
            let f = &f[..len];
            assert_eq!(mss_of(f, at), 1452);
            assert!(checksums_ok(f), "checksum after clamping at offset {at}");
            fw.ct = crate::conntrack::Conntrack::new(100, 42);
        }
        // Already small enough: untouched.
        let seg = tcp_with_options(HOST, SERVER, TCP_SYN, &[2, 4, 0x05, 0x00]);
        let mut f = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_TCP, 64, &seg));
        let Verdict::Forward { len, .. } = run(&mut fw, 0, LAN, &mut f) else {
            panic!()
        };
        assert_eq!(mss_of(&f[..len], 22), 1280);
    }

    #[test]
    fn mss_clamped_on_the_syn_ack_too() {
        let mut fw = router();
        fw.set_mtu(WAN, 1492);
        let port = syn_out(&mut fw);
        let mut seg = tcp_with_options(SERVER, ROUTER_WAN, TCP_SYN | TCP_ACK, &[2, 4, 0x05, 0xb4]);
        wire::put16(&mut seg, 0, 80);
        wire::put16(&mut seg, 2, port);
        wire::put16(&mut seg, 16, 0);
        let c = wire::l4_checksum(SERVER, ROUTER_WAN, PROTO_TCP, &seg);
        wire::put16(&mut seg, 16, c);
        let mut f = to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, PROTO_TCP, 50, &seg));
        let Verdict::Forward { egress, len, .. } = run(&mut fw, 1, WAN, &mut f) else {
            panic!()
        };
        assert_eq!(egress, LAN);
        assert_eq!(mss_of(&f[..len], 22), 1452);
        assert!(checksums_ok(&f[..len]));
    }

    #[test]
    fn without_pppoe_a_standard_mss_is_left_alone() {
        let mut fw = router();
        let seg = tcp_with_options(HOST, SERVER, TCP_SYN, &[2, 4, 0x05, 0xb4]);
        let mut f = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_TCP, 64, &seg));
        let Verdict::Forward { len, .. } = run(&mut fw, 0, LAN, &mut f) else {
            panic!()
        };
        assert_eq!(mss_of(&f[..len], 22), 1460);
        assert!(checksums_ok(&f[..len]));
    }

    /// A LAN host's UDP datagram of `ip_len` bytes, DF set or not.
    fn udp_out(ip_len: usize, df: bool) -> Vec<u8> {
        let payload = vec![0x5a; ip_len - 28];
        let seg = udp_datagram(HOST, SERVER, 5000, 53, &payload);
        let mut f = ipv4_frame(HOST, SERVER, PROTO_UDP, 64, &seg);
        if !df {
            f[ETH_HDR + 6] = 0;
            wire::put16(&mut f, ETH_HDR + 10, 0);
            let c = wire::checksum(&f[ETH_HDR..ETH_HDR + 20]);
            wire::put16(&mut f, ETH_HDR + 10, c);
        }
        to(LAN_MAC, f)
    }

    #[test]
    fn too_big_for_the_wan_mtu() {
        let mut fw = router();
        fw.set_mtu(WAN, 1492);
        // Fits exactly.
        let mut f = udp_out(1492, true);
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { egress: WAN, .. }));
        // One byte more with DF: ICMP fragmentation needed, MTU 1492, back
        // to the host from the router's LAN address.
        let mut f = udp_out(1493, true);
        let Verdict::Forward {
            egress,
            next_hop,
            len,
            ..
        } = run(&mut fw, 1, LAN, &mut f)
        else {
            panic!("no ICMP error")
        };
        assert_eq!((egress, next_hop), (LAN, HOST));
        let f = &f[..len];
        let v = view(f);
        assert_eq!((v.src(f), v.dst(f), v.proto), (ROUTER_LAN, HOST, PROTO_ICMP));
        assert_eq!((f[v.l4], f[v.l4 + 1]), (wire::ICMP_DEST_UNREACH, 4));
        assert_eq!(wire::get16(f, v.l4 + 6), 1492);
        assert_eq!(wire::checksum(&f[v.l4..v.l4 + v.l4_len]), 0);
        // The quoted header is the host's original one.
        assert_eq!(wire::get_ip(f, v.l4 + 8 + 12), HOST);
        // Without DF: forwarded (NAT applied), to be split to 1492.
        let mut f = udp_out(1493, false);
        let Verdict::Forward { egress, len, split, .. } = run(&mut fw, 2, LAN, &mut f) else {
            panic!("not forwarded")
        };
        assert_eq!((egress, split), (WAN, 1492));
        let plan = wire::SplitPlan::new(&f[..len], split).expect("splittable");
        assert_eq!(plan.pieces(), 2);
        assert_eq!(view(&f[..len]).src(&f[..len]), ROUTER_WAN, "translated before splitting");
        // A packet that fits is not split.
        let mut f = udp_out(1492, false);
        assert!(matches!(run(&mut fw, 3, LAN, &mut f), Verdict::Forward { split: 0, .. }));
        // Splitting off (negative control): dropped as before.
        fw.split = false;
        let mut f = udp_out(1493, false);
        assert_eq!(run(&mut fw, 4, LAN, &mut f), Verdict::Drop(DropReason::TooBig));
        assert_eq!(fw.stats.drops[DropReason::TooBig.index()], 1);
    }

    // ---- zones (docs/config-v2.md §6) ----------------------------------

    const GUEST_MAC: Mac = [2, 0, 0, 0, 0, 3];
    const ROUTER_GUEST: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 1);
    const GUEST_HOST: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 100);
    const GUEST: IfIndex = 2;

    /// WAN (zone 0), LAN (zone 1), guest (zone 2): LAN may go anywhere,
    /// guest only to the WAN; guest input only DHCP + DNS.
    fn zoned(fw: &mut Forwarder) {
        fw.add_interface(Interface {
            mac: GUEST_MAC,
            addr: Some((ROUTER_GUEST, 24)),
            role: Role::Lan,
            zone: 2,
        });
        fw.set_policy(Some(Policy {
            forward: vec![0, 0b101, 0b001],
            input: vec![None, None, Some(svc::DHCP | svc::DNS)],
            ..Policy::default()
        }));
    }

    fn tcp_frame(mac: Mac, src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let seg = tcp_segment(src, dst, sport, dport, flags, b"");
        to(mac, ipv4_frame(src, dst, PROTO_TCP, 64, &seg))
    }

    #[test]
    fn zones_decide_new_flows_and_networks_are_not_natted() {
        let mut fw = router();
        zoned(&mut fw);
        // Guest → LAN: refused.
        let mut f = tcp_frame(GUEST_MAC, GUEST_HOST, HOST, 5000, 22, TCP_SYN);
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), Verdict::Drop(DropReason::Firewall));
        // LAN → guest: allowed, addresses untouched (no NAT between networks).
        let mut f = tcp_frame(LAN_MAC, HOST, GUEST_HOST, 6000, 80, TCP_SYN);
        let Verdict::Forward { egress, next_hop, len, .. } = run(&mut fw, 0, LAN, &mut f) else {
            panic!("LAN → guest")
        };
        assert_eq!((egress, next_hop), (GUEST, GUEST_HOST));
        let v = view(&f[..len]);
        assert_eq!((v.src(&f), wire::get16(&f, v.l4)), (HOST, 6000));
        assert!(checksums_ok(&f[..len]));
        // ... and its reply comes back (tracked), though guest → LAN is refused.
        let mut r = tcp_frame(GUEST_MAC, GUEST_HOST, HOST, 80, 6000, TCP_SYN | TCP_ACK);
        assert!(matches!(run(&mut fw, 1, GUEST, &mut r), Verdict::Forward { egress: LAN, .. }));
        // Guest → WAN: masqueraded as before.
        let mut f = tcp_frame(GUEST_MAC, GUEST_HOST, SERVER, 7000, 443, TCP_SYN);
        let Verdict::Forward { egress: WAN, len, .. } = run(&mut fw, 0, GUEST, &mut f) else {
            panic!("guest → WAN")
        };
        assert_eq!(view(&f[..len]).src(&f), ROUTER_WAN);
        // WAN → anything new: refused (the WAN zone forwards nowhere).
        let mut f = tcp_frame(WAN_MAC, SERVER, HOST, 443, 9000, TCP_SYN);
        assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Drop(DropReason::Firewall));
        // Two interfaces of one zone reach each other without a forward bit.
        fw.set_policy(Some(Policy { forward: vec![0, 0b001, 0b001], ..Policy::default() }));
        fw.ifs[GUEST as usize].zone = 1;
        let mut f = tcp_frame(GUEST_MAC, GUEST_HOST, HOST, 5001, 22, TCP_SYN);
        assert!(matches!(run(&mut fw, 0, GUEST, &mut f), Verdict::Forward { egress: LAN, .. }));
    }

    #[test]
    fn input_policy_limits_what_a_zone_reaches_on_the_router() {
        let mut fw = router();
        zoned(&mut fw);
        let udp = |dport| {
            let d = udp_datagram(GUEST_HOST, ROUTER_GUEST, 5353, dport, b"q");
            to(GUEST_MAC, ipv4_frame(GUEST_HOST, ROUTER_GUEST, PROTO_UDP, 64, &d))
        };
        assert_eq!(run(&mut fw, 0, GUEST, &mut udp(53)), Verdict::Local, "DNS allowed");
        assert_eq!(run(&mut fw, 0, GUEST, &mut udp(123)), Verdict::Drop(DropReason::Input), "NTP not");
        // mDNS to the group: refused unless the zone allows it.
        let mdns = || {
            let group = Ipv4Addr::new(224, 0, 0, 251);
            let d = udp_datagram(GUEST_HOST, group, 5353, 5353, b"q");
            to([0x01, 0x00, 0x5e, 0, 0, 0xfb], ipv4_frame(GUEST_HOST, group, PROTO_UDP, 255, &d))
        };
        assert_eq!(run(&mut fw, 0, GUEST, &mut mdns()), Verdict::Drop(DropReason::Input), "mDNS not allowed");
        let mut p = fw.policy.clone().unwrap();
        p.input[2] = p.input[2].map(|m| m | svc::MDNS);
        fw.set_policy(Some(p.clone()));
        assert_eq!(run(&mut fw, 0, GUEST, &mut mdns()), Verdict::Local, "mDNS allowed");
        p.input[2] = p.input[2].map(|m| m & !svc::MDNS);
        fw.set_policy(Some(p));
        // DHCP to the broadcast address.
        let d = udp_datagram(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, 68, 67, b"discover");
        let mut f = to([0xff; 6], ipv4_frame(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, PROTO_UDP, 64, &d));
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), Verdict::Local, "DHCP allowed");
        // The web interface, on the guest address or on the LAN address.
        for dst in [ROUTER_GUEST, ROUTER_LAN] {
            let mut f = tcp_frame(GUEST_MAC, GUEST_HOST, dst, 5000, 80, TCP_SYN);
            assert_eq!(run(&mut fw, 0, GUEST, &mut f), Verdict::Drop(DropReason::Input), "{dst}");
        }
        let echo = icmp_echo(ICMP_ECHO_REQUEST, 7, 1);
        let mut f = to(GUEST_MAC, ipv4_frame(GUEST_HOST, ROUTER_GUEST, PROTO_ICMP, 64, &echo));
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), Verdict::Drop(DropReason::Input), "ping");
        assert_eq!(fw.stats.drops[DropReason::Input.index()], 5, "NTP, mDNS, web ×2, ping");
        // The LAN zone accepts everything.
        let mut f = tcp_frame(LAN_MAC, HOST, ROUTER_LAN, 5000, 80, TCP_SYN);
        assert_eq!(run(&mut fw, 0, LAN, &mut f), Verdict::Local);
    }

    #[test]
    fn wan_input_drops_all_but_replies_to_router_clients() {
        let mut fw = router();
        zoned(&mut fw);
        let mut p = fw.policy.clone().unwrap();
        p.input[0] = Some(0); // the kernel's WAN zone: nothing for the router
        fw.set_policy(Some(p));
        let udp = |dport| {
            let d = udp_datagram(SERVER, ROUTER_WAN, 53, dport, b"a");
            to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, PROTO_UDP, 64, &d))
        };
        assert_eq!(run(&mut fw, 0, WAN, &mut udp(65_100)), Verdict::Local, "DNS upstream reply");
        assert_eq!(run(&mut fw, 0, WAN, &mut udp(60_000)), Verdict::Local, "SNTP reply");
        assert_eq!(run(&mut fw, 0, WAN, &mut udp(68)), Verdict::Local, "DHCP client");
        assert_eq!(run(&mut fw, 0, WAN, &mut udp(53)), Verdict::Drop(DropReason::Input), "no DNS service");
        // TCP: no router clients, so the client range is not a way in.
        for dport in [22, 80, 60_000, 65_535] {
            let mut f = tcp_frame(WAN_MAC, SERVER, ROUTER_WAN, 40_000, dport, TCP_SYN);
            assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Drop(DropReason::Input), "tcp {dport}");
        }
        let echo = icmp_echo(ICMP_ECHO_REQUEST, 7, 1);
        let mut f = to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, PROTO_ICMP, 64, &echo));
        assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Drop(DropReason::Input), "ping");
        let reply = icmp_echo(0, 7, 1);
        let mut f = to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, PROTO_ICMP, 64, &reply));
        assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Local, "echo reply");
    }

    #[test]
    fn tcp_replies_pass_only_from_the_routers_own_tcp_servers() {
        let mut fw = router();
        zoned(&mut fw);
        let mut p = fw.policy.clone().unwrap();
        p.input[0] = Some(0);
        p.router_tcp_peers = vec![(SERVER, 853)];
        fw.set_policy(Some(p));
        let seg = |src, sport, dport| tcp_frame(WAN_MAC, src, ROUTER_WAN, sport, dport, TCP_SYN | TCP_ACK);
        // The DNS-over-TLS server answering the router's connection.
        assert_eq!(run(&mut fw, 0, WAN, &mut seg(SERVER, 853, 61_234)), Verdict::Local, "DoT reply");
        // Not from that server and port, or not to a client port: input.
        let other = Ipv4Addr::new(198, 51, 100, 99);
        for (src, sport, dport) in [(other, 853, 61_234), (SERVER, 443, 61_234), (SERVER, 853, 22), (SERVER, 853, 59_999)] {
            assert_eq!(
                run(&mut fw, 0, WAN, &mut seg(src, sport, dport)),
                Verdict::Drop(DropReason::Input),
                "{src}:{sport} → {dport}"
            );
        }
    }

    #[test]
    fn flows_between_networks_keep_one_shard() {
        let internal = [(ROUTER_LAN, 24), (ROUTER_GUEST, 24)];
        let mut fws: Vec<Forwarder> = shards();
        for fw in &mut fws {
            zoned(fw);
        }
        for i in 0..64u16 {
            let host = Ipv4Addr::new(192, 168, 1, 100 + (i % 20) as u8);
            let mut f = tcp_frame(LAN_MAC, host, GUEST_HOST, 30_000 + i, 80, TCP_SYN);
            let len = f.len() - 64;
            let k = shard_of(Role::Lan, &f[..len], SHARDS, 42, &ShardHints { internal: &internal, ..Default::default() });
            assert!(matches!(fws[k].process(0, LAN, &mut f, len), Verdict::Forward { egress: GUEST, .. }));
            let mut r = tcp_frame(GUEST_MAC, GUEST_HOST, host, 80, 30_000 + i, TCP_SYN | TCP_ACK);
            let len = r.len() - 64;
            let kr = shard_of(Role::Lan, &r[..len], SHARDS, 42, &ShardHints { internal: &internal, ..Default::default() });
            assert_eq!(kr, k, "reply of flow {i} in another shard");
            assert!(matches!(fws[kr].process(1, GUEST, &mut r, len), Verdict::Forward { egress: LAN, .. }));
        }
    }

    // ---- rules (docs/config-v2.md §3) ----------------------------------

    fn rule(from: Option<u8>, to: RuleTo, protos: u8, accept: bool) -> Rule {
        let action = if accept { Action::Accept } else { Action::Drop };
        Rule { from, to, protos, src: None, dst: None, dport: None, action }
    }

    fn with_rules(fw: &mut Forwarder, rules: Vec<Rule>) {
        fw.set_policy(Some(Policy {
            forward: vec![0, 0b101, 0b001],
            input: vec![None, None, Some(svc::DHCP | svc::DNS)],
            rules,
            ..Policy::default()
        }));
    }

    #[test]
    fn rules_decide_before_the_zones_first_match_wins() {
        let mut fw = router();
        zoned(&mut fw);
        let nas = Ipv4Addr::new(192, 168, 1, 10);
        with_rules(&mut fw, vec![
            // Guest may ping the NAS (zones say guest -> lan: no) ...
            Rule { dst: Some((nas, 32)), ..rule(Some(2), RuleTo::Zone(1), proto::ICMP, true) },
            // ... and nothing else of the guest may use port 80 outside.
            Rule { dport: Some((80, 80)), ..rule(Some(2), RuleTo::Any, proto::TCP, false) },
            // Never reached for guest port 80: the rule above matched first.
            Rule { dport: Some((80, 80)), ..rule(Some(2), RuleTo::Zone(0), proto::TCP, true) },
        ]);
        let echo = icmp_echo(ICMP_ECHO_REQUEST, 9, 1);
        let mut f = to(GUEST_MAC, ipv4_frame(GUEST_HOST, nas, PROTO_ICMP, 64, &echo));
        assert!(matches!(run(&mut fw, 0, GUEST, &mut f), Verdict::Forward { egress: LAN, .. }), "accept rule opens it");
        let mut f = to(GUEST_MAC, ipv4_frame(GUEST_HOST, HOST, PROTO_ICMP, 64, &echo));
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), Verdict::Drop(DropReason::Firewall), "another LAN host: zones");
        let mut f = tcp_frame(GUEST_MAC, GUEST_HOST, SERVER, 7000, 80, TCP_SYN);
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), Verdict::Drop(DropReason::Firewall), "drop rule beats the zone");
        let mut f = tcp_frame(GUEST_MAC, GUEST_HOST, SERVER, 7001, 443, TCP_SYN);
        assert!(matches!(run(&mut fw, 0, GUEST, &mut f), Verdict::Forward { egress: WAN, .. }), "443: zones");
        assert_eq!(fw.rule_hits, [1, 1, 0]);
        // Tracked flows are not re-checked: the reply of the NAS ping passes.
        let mut r = to(LAN_MAC, ipv4_frame(nas, GUEST_HOST, PROTO_ICMP, 64, &icmp_echo(ICMP_ECHO_REPLY, 9, 1)));
        assert!(matches!(run(&mut fw, 1, LAN, &mut r), Verdict::Forward { egress: GUEST, .. }));
        assert_eq!(fw.rule_hits, [1, 1, 0]);
        // A new policy starts the counters again.
        with_rules(&mut fw, vec![]);
        assert!(fw.rule_hits.is_empty());
    }

    #[test]
    fn rules_to_the_router_and_replies_to_its_own_clients() {
        let mut fw = router();
        zoned(&mut fw);
        with_rules(&mut fw, vec![
            // The guest may reach the web interface after all ...
            Rule { dport: Some((80, 80)), ..rule(Some(2), RuleTo::Router, proto::TCP, true) },
            // ... and the WAN nothing at all on the router.
            rule(Some(0), RuleTo::Router, proto::ANY, false),
        ]);
        let mut f = tcp_frame(GUEST_MAC, GUEST_HOST, ROUTER_GUEST, 5000, 80, TCP_SYN);
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), Verdict::Local, "accept rule beats the zone's input");
        let mut f = tcp_frame(GUEST_MAC, GUEST_HOST, ROUTER_GUEST, 5000, 22, TCP_SYN);
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), Verdict::Drop(DropReason::Input), "other ports: zone input");
        let mut f = tcp_frame(WAN_MAC, SERVER, ROUTER_WAN, 5000, 80, TCP_SYN);
        assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Drop(DropReason::Input), "drop rule on the WAN");
        // Replies to the router's own clients still pass: DNS upstream,
        // the DHCP client, ICMP errors.
        let d = udp_datagram(SERVER, ROUTER_WAN, 53, 65_100, b"answer");
        let mut f = to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, PROTO_UDP, 64, &d));
        assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Local, "DNS upstream reply");
        let d = udp_datagram(GW, ROUTER_WAN, 67, 68, b"offer");
        let mut f = to(WAN_MAC, ipv4_frame(GW, ROUTER_WAN, PROTO_UDP, 64, &d));
        assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Local, "DHCP client");
        let mut f = to(WAN_MAC, ipv4_frame(GW, ROUTER_WAN, PROTO_ICMP, 64, &icmp_echo(ICMP_ECHO_REPLY, 3, 1)));
        assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Local, "echo reply");
        assert_eq!(fw.rule_hits, [1, 1]);
    }

    // ---- port forwards (docs/config-v2.md §3) ---------------------------

    const NAS: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);

    fn fwd(lo: u16, hi: u16, to_port: Option<u16>, src: Option<(Ipv4Addr, u8)>, hairpin: bool) -> PortForward {
        PortForward { protos: proto::TCP, lo, hi, to: NAS, to_port, src, hairpin }
    }

    fn with_forwards(fw: &mut Forwarder, forwards: Vec<PortForward>) {
        fw.set_policy(Some(Policy {
            forward: vec![0, 0b001],
            input: vec![None, None],
            forwards,
            ..Policy::default()
        }));
    }

    fn ports(f: &[u8]) -> (Ipv4Addr, u16, Ipv4Addr, u16) {
        let v = view(f);
        (v.src(f), wire::get16(f, v.l4), v.dst(f), wire::get16(f, v.l4 + 2))
    }

    #[test]
    fn port_forward_from_the_wan_both_ways() {
        let mut fw = router();
        with_forwards(&mut fw, vec![fwd(8443, 8443, Some(443), None, true)]);
        let mut f = tcp_frame(WAN_MAC, SERVER, ROUTER_WAN, 5555, 8443, TCP_SYN);
        let Verdict::Forward { egress, next_hop, len, .. } = run(&mut fw, 0, WAN, &mut f) else {
            panic!("not forwarded")
        };
        assert_eq!((egress, next_hop), (LAN, NAS));
        assert_eq!(ports(&f[..len]), (SERVER, 5555, NAS, 443), "destination translated");
        assert!(checksums_ok(&f[..len]));
        let mut r = tcp_frame(LAN_MAC, NAS, SERVER, 443, 5555, TCP_SYN | TCP_ACK);
        let Verdict::Forward { egress: WAN, len, .. } = run(&mut fw, 1, LAN, &mut r) else {
            panic!("reply not forwarded")
        };
        assert_eq!(ports(&r[..len]), (ROUTER_WAN, 8443, SERVER, 5555), "answers from the WAN address");
        assert!(checksums_ok(&r[..len]));
        assert_eq!(fw.forward_hits, [1]);
        // Other ports: the router's own (local), never the NAS.
        let mut f = tcp_frame(WAN_MAC, SERVER, ROUTER_WAN, 5556, 8444, TCP_SYN);
        assert_eq!(run(&mut fw, 2, WAN, &mut f), Verdict::Local);
        // UDP is not forwarded by a TCP forward.
        let d = udp_datagram(SERVER, ROUTER_WAN, 5557, 8443, b"x");
        let mut f = to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, PROTO_UDP, 64, &d));
        assert_eq!(run(&mut fw, 3, WAN, &mut f), Verdict::Local);
    }

    #[test]
    fn port_forward_source_restriction_and_ranges() {
        let mut fw = router();
        let only = Some((Ipv4Addr::new(198, 51, 100, 0), 24));
        with_forwards(&mut fw, vec![fwd(8000, 8010, Some(9000), only, false)]);
        let mut f = tcp_frame(WAN_MAC, SERVER, ROUTER_WAN, 5555, 8005, TCP_SYN);
        let Verdict::Forward { len, .. } = run(&mut fw, 0, WAN, &mut f) else { panic!() };
        assert_eq!(ports(&f[..len]).3, 9005, "the range maps onto 9000..");
        let other = Ipv4Addr::new(192, 0, 2, 9);
        let mut f = tcp_frame(WAN_MAC, other, ROUTER_WAN, 5555, 8005, TCP_SYN);
        assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Local, "not from the allowed prefix");
        // Same ports without to_port.
        with_forwards(&mut fw, vec![fwd(8000, 8010, None, None, false)]);
        let mut f = tcp_frame(WAN_MAC, other, ROUTER_WAN, 5555, 8007, TCP_SYN);
        let Verdict::Forward { len, .. } = run(&mut fw, 0, WAN, &mut f) else { panic!() };
        assert_eq!(ports(&f[..len]).3, 8007);
    }

    #[test]
    fn wan_sources_of_our_own_networks_are_spoofed() {
        let mut fw = router();
        with_forwards(&mut fw, vec![fwd(8443, 8443, Some(443), None, true)]);
        let syn = |src| tcp_frame(WAN_MAC, src, ROUTER_WAN, 5555, 8443, TCP_SYN);
        // A LAN address, the router's own LAN address and loopback: dropped
        // before the port forward, the router's stack or conntrack see them.
        for src in [HOST, ROUTER_LAN, Ipv4Addr::new(127, 0, 0, 1)] {
            assert_eq!(run(&mut fw, 0, WAN, &mut syn(src)), Verdict::Drop(DropReason::Spoofed), "{src}");
        }
        let mut f = tcp_frame(WAN_MAC, HOST, ROUTER_WAN, 5555, 80, TCP_SYN);
        assert_eq!(run(&mut fw, 0, WAN, &mut f), Verdict::Drop(DropReason::Spoofed), "to the router too");
        assert_eq!(fw.forward_hits, [0]);
        // Other private sources (an ISP's 10.x gateway) and the internet pass.
        for src in [Ipv4Addr::new(10, 11, 5, 146), SERVER] {
            assert!(matches!(run(&mut fw, 1, WAN, &mut syn(src)), Verdict::Forward { .. }), "{src}");
        }
        assert_eq!(fw.forward_hits, [2]);
        // The same source from the LAN is fine (hairpin).
        let mut f = tcp_frame(LAN_MAC, HOST, ROUTER_WAN, 5556, 8443, TCP_SYN);
        assert!(matches!(run(&mut fw, 2, LAN, &mut f), Verdict::Forward { .. }));
        // Switched off (the lab's negative control): forwarded.
        fw.wan_antispoof = false;
        assert!(matches!(run(&mut fw, 3, WAN, &mut syn(HOST)), Verdict::Forward { .. }));
    }

    const LAB_GW: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);
    const LAB_HOST: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 5);
    const LAB: (Ipv4Addr, u8, Ipv4Addr) = (Ipv4Addr::new(10, 30, 0, 0), 24, LAB_GW);

    #[test]
    fn static_routes_go_through_their_router() {
        let mut fw = router();
        zoned(&mut fw);
        fw.set_static_routes(&[LAB, (Ipv4Addr::new(10, 31, 0, 0), 16, Ipv4Addr::new(172, 16, 0, 1))]);
        // Only the one whose router is on a connected subnet.
        let statics: Vec<_> = fw.routes.iter().filter(|r| r.kind == RouteKind::Static).copied().collect();
        assert_eq!(statics.len(), 1);
        assert_eq!((statics[0].prefix, statics[0].len, statics[0].egress, statics[0].gateway), (LAB.0, 24, LAN, Some(LAB_GW)));
        // Guest → the routed subnet: out on the LAN to its router (no NAT).
        let mut f = tcp_frame(GUEST_MAC, GUEST_HOST, LAB_HOST, 5000, 80, TCP_SYN);
        fw.set_policy(Some(Policy { forward: vec![0, 0b111, 0b011], ..Policy::default() }));
        let Verdict::Forward { egress, next_hop, len, .. } = run(&mut fw, 0, GUEST, &mut f) else { panic!() };
        assert_eq!((egress, next_hop), (LAN, LAB_GW));
        assert_eq!(view(&f[..len]).src(&f), GUEST_HOST);
        // A routed host to the internet: masqueraded; the reply goes back to its router.
        let mut f = tcp_frame(LAN_MAC, LAB_HOST, SERVER, 7000, 80, TCP_SYN);
        let Verdict::Forward { egress, len, .. } = run(&mut fw, 0, LAN, &mut f) else { panic!() };
        assert_eq!(egress, WAN);
        let v = view(&f[..len]);
        let port = wire::get16(&f, v.l4);
        let mut r = tcp_frame(WAN_MAC, SERVER, ROUTER_WAN, 80, port, TCP_SYN | TCP_ACK);
        let Verdict::Forward { egress, next_hop, .. } = run(&mut fw, 1, WAN, &mut r) else { panic!() };
        assert_eq!((egress, next_hop), (LAN, LAB_GW));
        // From the LAN itself: back out the same link, not ours to forward.
        let mut f = tcp_frame(LAN_MAC, HOST, LAB_HOST, 5001, 80, TCP_SYN);
        assert_eq!(run(&mut fw, 2, LAN, &mut f), Verdict::Drop(DropReason::Hairpin));
    }

    #[test]
    fn static_routes_follow_their_routers_subnet() {
        let mut fw = router();
        fw.set_static_routes(&[LAB]);
        let lab = |fw: &Forwarder| fw.routes.lookup(LAB_HOST).map(|r| (r.kind, r.egress));
        assert_eq!(lab(&fw), Some((RouteKind::Static, LAN)));
        // The LAN goes away: so does the route (the default takes over).
        fw.set_addr(LAN, None);
        assert_eq!(lab(&fw), Some((RouteKind::Default, WAN)));
        fw.set_addr(LAN, Some((ROUTER_LAN, 24)));
        assert_eq!(lab(&fw), Some((RouteKind::Static, LAN)));
        // A connected subnet with the same destination wins.
        fw.set_addr(LAN, Some((Ipv4Addr::new(10, 30, 0, 1), 24)));
        assert_eq!(lab(&fw), Some((RouteKind::Connected, LAN)));
        // Routes through the WAN's subnet.
        fw.set_static_routes(&[(Ipv4Addr::new(100, 64, 0, 0), 10, Ipv4Addr::new(203, 0, 113, 2))]);
        let r = fw.routes.lookup(Ipv4Addr::new(100, 64, 1, 1)).unwrap();
        assert_eq!((r.kind, r.egress, r.gateway), (RouteKind::Static, WAN, Some(Ipv4Addr::new(203, 0, 113, 2))));
        fw.set_static_routes(&[]);
        assert!(fw.routes.iter().all(|r| r.kind != RouteKind::Static));
    }

    #[test]
    fn routed_subnets_are_inside_for_antispoofing_and_recheck() {
        let mut fw = router();
        with_forwards(&mut fw, vec![fwd(8443, 8443, Some(443), None, true)]);
        let mut syn = tcp_frame(WAN_MAC, LAB_HOST, ROUTER_WAN, 5555, 8443, TCP_SYN);
        // Without the route it is an outside address (negative control).
        assert!(matches!(run(&mut fw, 0, WAN, &mut syn.clone()), Verdict::Forward { .. }));
        fw.set_static_routes(&[LAB]);
        assert_eq!(run(&mut fw, 1, WAN, &mut syn), Verdict::Drop(DropReason::Spoofed));
        // A routed host's connection out survives a recheck under the same
        // policy (it came in on the LAN, not the WAN).
        let mut f = tcp_frame(LAN_MAC, LAB_HOST, SERVER, 7000, 80, TCP_SYN);
        assert!(matches!(run(&mut fw, 2, LAN, &mut f), Verdict::Forward { .. }));
        assert_eq!(fw.recheck(), 0);
        // Shard hints: a flow from a network to the routed subnet is a pair.
        let internal = [(ROUTER_LAN, 24u8), (Ipv4Addr::new(10, 20, 0, 1), 24)];
        let routed = [(LAB.0, 24u8)];
        let there = tcp_frame(GUEST_MAC, GUEST_HOST, LAB_HOST, 5000, 80, TCP_SYN);
        let back = tcp_frame(LAN_MAC, LAB_HOST, GUEST_HOST, 80, 5000, TCP_SYN | TCP_ACK);
        let hints = ShardHints { internal: &internal, routed: &routed, ..Default::default() };
        let (a, b) = (shard_of(Role::Lan, &there[..there.len() - 64], 16, 42, &hints), shard_of(Role::Lan, &back[..back.len() - 64], 16, 42, &hints));
        assert_eq!(a, b);
    }

    #[test]
    fn wan_overlapping_a_network_keeps_its_own_subnet() {
        let mut fw = router();
        // A misconfigured WAN in the LAN's /24: its neighbours still reach us.
        fw.set_addr(WAN, Some((Ipv4Addr::new(192, 168, 1, 250), 24)));
        let mut f = tcp_frame(WAN_MAC, HOST, Ipv4Addr::new(192, 168, 1, 250), 5555, 80, TCP_SYN);
        assert_ne!(run(&mut fw, 0, WAN, &mut f), Verdict::Drop(DropReason::Spoofed));
    }

    #[test]
    fn hairpin_through_the_wan_address() {
        let mut fw = router();
        with_forwards(&mut fw, vec![fwd(8443, 8443, Some(443), None, true)]);
        let mut f = tcp_frame(LAN_MAC, HOST, ROUTER_WAN, 40_001, 8443, TCP_SYN);
        let Verdict::Forward { egress, next_hop, len, .. } = run(&mut fw, 0, LAN, &mut f) else {
            panic!("hairpin not forwarded")
        };
        assert_eq!((egress, next_hop), (LAN, NAS), "back out of the LAN");
        let (src, sport, dst, dport) = ports(&f[..len]);
        assert_eq!((src, dst, dport), (ROUTER_LAN, NAS, 443), "from the router, so the NAS answers through it");
        assert!(checksums_ok(&f[..len]));
        let mut r = tcp_frame(LAN_MAC, NAS, ROUTER_LAN, 443, sport, TCP_SYN | TCP_ACK);
        let Verdict::Forward { egress: LAN, next_hop, len, .. } = run(&mut fw, 1, LAN, &mut r) else {
            panic!("hairpin reply not forwarded")
        };
        assert_eq!(next_hop, HOST);
        assert_eq!(ports(&r[..len]), (ROUTER_WAN, 8443, HOST, 40_001), "looks like the WAN address answered");
        assert!(checksums_ok(&r[..len]));
        // Without hairpin: the router's own address (local).
        with_forwards(&mut fw, vec![fwd(8443, 8443, Some(443), None, false)]);
        let mut f = tcp_frame(LAN_MAC, HOST, ROUTER_WAN, 40_002, 8443, TCP_SYN);
        assert_eq!(run(&mut fw, 2, LAN, &mut f), Verdict::Local);
    }

    #[test]
    fn napt_never_takes_a_forwarded_port() {
        let mut fw = router();
        with_forwards(&mut fw, vec![fwd(20_000, 20_010, None, None, false)]);
        // Port preservation would keep 20005; it is forwarded.
        let mut f = tcp_frame(LAN_MAC, HOST, SERVER, 20_005, 80, TCP_SYN);
        let Verdict::Forward { len, .. } = run(&mut fw, 0, LAN, &mut f) else { panic!() };
        let p = ports(&f[..len]).1;
        assert!(!(20_000..=20_010).contains(&p), "NAT port {p} is forwarded");
        // Control: without the forward it keeps its port.
        let mut fw = router();
        let mut f = tcp_frame(LAN_MAC, HOST, SERVER, 20_005, 80, TCP_SYN);
        let Verdict::Forward { len, .. } = run(&mut fw, 0, LAN, &mut f) else { panic!() };
        assert_eq!(ports(&f[..len]).1, 20_005);
    }

    #[test]
    fn forwarded_and_hairpin_connections_keep_one_shard() {
        let forwards = [fwd(8443, 8443, Some(443), None, true)];
        let internal = [(ROUTER_LAN, 24)];
        let hints = ShardHints { internal: &internal, routed: &[], wan: Some(ROUTER_WAN), forwards: &forwards, redirects: &[] };
        let mut fws = shards();
        for fw in &mut fws {
            with_forwards(fw, forwards.to_vec());
        }
        for i in 0..32u16 {
            // From the WAN.
            let client = Ipv4Addr::new(198, 51, 100, 1 + i as u8);
            let mut f = tcp_frame(WAN_MAC, client, ROUTER_WAN, 30_000 + i, 8443, TCP_SYN);
            let len = f.len() - 64;
            let k = shard_of(Role::Wan, &f[..len], SHARDS, 42, &hints);
            assert!(matches!(fws[k].process(0, WAN, &mut f, len), Verdict::Forward { egress: LAN, .. }));
            let mut r = tcp_frame(LAN_MAC, NAS, client, 443, 30_000 + i, TCP_SYN | TCP_ACK);
            let len = r.len() - 64;
            assert_eq!(shard_of(Role::Lan, &r[..len], SHARDS, 42, &hints), k, "DNAT reply {i}");
            assert!(matches!(fws[k].process(1, LAN, &mut r, len), Verdict::Forward { egress: WAN, .. }));
            // Hairpin.
            let host = Ipv4Addr::new(192, 168, 1, 100 + (i % 50) as u8);
            let mut f = tcp_frame(LAN_MAC, host, ROUTER_WAN, 31_000 + i, 8443, TCP_SYN);
            let len = f.len() - 64;
            let k = shard_of(Role::Lan, &f[..len], SHARDS, 42, &hints);
            let Verdict::Forward { len, .. } = fws[k].process(0, LAN, &mut f, len) else { panic!("hairpin {i}") };
            let natport = ports(&f[..len]).1;
            let mut r = tcp_frame(LAN_MAC, NAS, ROUTER_LAN, 443, natport, TCP_SYN | TCP_ACK);
            let len = r.len() - 64;
            assert_eq!(shard_of(Role::Lan, &r[..len], SHARDS, 42, &hints), k, "hairpin reply {i}");
            assert!(matches!(fws[k].process(1, LAN, &mut r, len), Verdict::Forward { egress: LAN, .. }));
        }
    }

    #[test]
    fn forward_target_goes_out_from_its_forwarded_port() {
        let mut fw = router();
        with_forwards(&mut fw, vec![fwd(8443, 8443, Some(443), None, true)]);
        // The NAS opens a connection from its forwarded port 443: it leaves
        // from WAN :8443 (reserved for everyone else), not a NAPT port.
        let mut f = tcp_frame(LAN_MAC, NAS, SERVER, 443, 6881, TCP_SYN);
        let Verdict::Forward { egress: WAN, len, .. } = run(&mut fw, 0, LAN, &mut f) else { panic!("out") };
        assert_eq!(ports(&f[..len]), (ROUTER_WAN, 8443, SERVER, 6881));
        // The peer now connects to the forward from that same port: the
        // same connection, delivered (it used to clash: dropped).
        let mut r = tcp_frame(WAN_MAC, SERVER, ROUTER_WAN, 6881, 8443, TCP_SYN | TCP_ACK);
        let Verdict::Forward { egress: LAN, len, .. } = run(&mut fw, 1, WAN, &mut r) else { panic!("in") };
        assert_eq!(ports(&r[..len]), (SERVER, 6881, NAS, 443));
        assert_eq!(fw.ct.stats.clashes, 0);
        // Its other ports, and other hosts, still get NAPT ports.
        let mut f = tcp_frame(LAN_MAC, NAS, SERVER, 444, 6881, TCP_SYN);
        let Verdict::Forward { len, .. } = run(&mut fw, 2, LAN, &mut f) else { panic!() };
        assert!((10_000..40_000).contains(&ports(&f[..len]).1));
        let mut f = tcp_frame(LAN_MAC, HOST, SERVER, 443, 6881, TCP_SYN);
        let Verdict::Forward { len, .. } = run(&mut fw, 3, LAN, &mut f) else { panic!() };
        assert_ne!(ports(&f[..len]).1, 8443, "the reserved port only for the target");
    }

    #[test]
    fn a_clash_is_not_a_full_table() {
        let mut fw = router();
        // The NAS goes out before the forward exists: a NAPT port.
        let mut f = tcp_frame(LAN_MAC, NAS, SERVER, 443, 6881, TCP_SYN);
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { .. }));
        with_forwards(&mut fw, vec![fwd(8443, 8443, Some(443), None, true)]);
        // The peer connects to the new forward: its DNAT reply tuple is the
        // tracked connection's original one.
        let mut r = tcp_frame(WAN_MAC, SERVER, ROUTER_WAN, 6881, 8443, TCP_SYN);
        assert_eq!(run(&mut fw, 1, WAN, &mut r), Verdict::Drop(DropReason::Clash));
        assert_eq!((fw.ct.stats.clashes, fw.ct.stats.table_full), (1, 0));
    }

    #[test]
    fn a_host_at_its_limit_is_not_a_full_table() {
        let mut fw = router();
        fw.set_conn_budget(crate::conntrack::Budget::with_host_limit(100, 2, 7));
        // Two answered UDP connections from the host, then a third.
        for port in [5000, 5001] {
            let d = udp_datagram(HOST, SERVER, port, 53, b"q");
            let mut f = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_UDP, 64, &d));
            assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { .. }));
            let (id, _) = fw.ct.iter_ids().find(|(_, c)| c.orig.sport == port).map(|(id, c)| (id, c.clone())).unwrap();
            fw.ct.update(0, id, crate::conntrack::Dir::Reply, 0, 10);
        }
        let d = udp_datagram(HOST, SERVER, 5002, 53, b"q");
        let mut f = to(LAN_MAC, ipv4_frame(HOST, SERVER, PROTO_UDP, 64, &d));
        assert_eq!(run(&mut fw, 0, LAN, &mut f), Verdict::Drop(DropReason::HostLimit));
        assert_eq!((fw.ct.stats.host_limit, fw.ct.stats.table_full), (1, 0));
        // Another host still gets in.
        let d = udp_datagram(NAS, SERVER, 5002, 53, b"q");
        let mut f = to(LAN_MAC, ipv4_frame(NAS, SERVER, PROTO_UDP, 64, &d));
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { .. }));
    }

    #[test]
    fn forward_target_going_out_keeps_one_shard() {
        let forwards = [PortForward { protos: proto::TCP | proto::UDP, ..fwd(8443, 8443, Some(443), None, true) }];
        let internal = [(ROUTER_LAN, 24)];
        let hints = ShardHints { internal: &internal, routed: &[], wan: Some(ROUTER_WAN), forwards: &forwards, redirects: &[] };
        let mut fws = shards();
        for fw in &mut fws {
            with_forwards(fw, forwards.to_vec());
        }
        for i in 0..32u16 {
            let peer = Ipv4Addr::new(198, 51, 100, 1 + i as u8);
            let d = udp_datagram(NAS, peer, 443, 6881 + i, b"q");
            let mut f = to(LAN_MAC, ipv4_frame(NAS, peer, PROTO_UDP, 64, &d));
            let len = f.len() - 64;
            let k = shard_of(Role::Lan, &f[..len], SHARDS, 42, &hints);
            let Verdict::Forward { len, .. } = fws[k].process(0, LAN, &mut f, len) else { panic!("out {i}") };
            assert_eq!(ports(&f[..len]).1, 8443, "from the forwarded port {i}");
            // The peer, to the forward: same shard, same connection.
            let d = udp_datagram(peer, ROUTER_WAN, 6881 + i, 8443, b"a");
            let mut r = to(WAN_MAC, ipv4_frame(peer, ROUTER_WAN, PROTO_UDP, 64, &d));
            let len = r.len() - 64;
            assert_eq!(shard_of(Role::Wan, &r[..len], SHARDS, 42, &hints), k, "peer {i}");
            let Verdict::Forward { egress: LAN, len, .. } = fws[k].process(1, WAN, &mut r, len) else { panic!("in {i}") };
            assert_eq!(ports(&r[..len]), (peer, 6881 + i, NAS, 443));
        }
        assert!(fws.iter().all(|f| f.ct.stats.clashes == 0));
        assert_eq!(fws.iter().map(|f| f.ct.len()).sum::<usize>(), 32, "one connection per peer");
    }

    /// An ICMP error (`kind`, `code`) from `src` to `dst` about the
    /// translated frame `about`, received on an interface with `mac`.
    fn icmp_about(mac: Mac, src: Ipv4Addr, dst: Ipv4Addr, kind: u8, code: u8, about: &[u8]) -> Vec<u8> {
        let mut icmp = vec![kind, code, 0, 0, 0, 0, 0x05, 0x78];
        icmp.extend_from_slice(&about[ETH_HDR..ETH_HDR + 28]);
        let c = wire::checksum(&icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        to(mac, ipv4_frame(src, dst, PROTO_ICMP, 50, &icmp))
    }

    #[test]
    fn icmp_errors_about_forwarded_and_hairpin_connections_find_their_shard() {
        let forwards = [fwd(8443, 8443, Some(443), None, true)];
        let internal = [(ROUTER_LAN, 24)];
        let hints = ShardHints { internal: &internal, routed: &[], wan: Some(ROUTER_WAN), forwards: &forwards, redirects: &[] };
        // Negative control: the hints without the forwards (the old
        // mapping) put some of them elsewhere.
        let blind = ShardHints { forwards: &[], ..hints };
        let mut missed = [0usize; 3];
        let mut fws = shards();
        for fw in &mut fws {
            with_forwards(fw, forwards.to_vec());
        }
        for i in 0..32u16 {
            // From the WAN: the NAS answers; a router on the way reports
            // "fragmentation needed" about that answer (PMTU discovery).
            let client = Ipv4Addr::new(198, 51, 100, 1 + i as u8);
            let mut f = tcp_frame(WAN_MAC, client, ROUTER_WAN, 30_000 + i, 8443, TCP_SYN);
            let len = f.len() - 64;
            let k = shard_of(Role::Wan, &f[..len], SHARDS, 42, &hints);
            assert!(matches!(fws[k].process(0, WAN, &mut f, len), Verdict::Forward { egress: LAN, .. }));
            let mut r = tcp_frame(LAN_MAC, NAS, client, 443, 30_000 + i, TCP_SYN | TCP_ACK);
            let len = r.len() - 64;
            let Verdict::Forward { egress: WAN, len, .. } = fws[k].process(1, LAN, &mut r, len) else {
                panic!("DNAT reply {i} not forwarded")
            };
            let mut e = icmp_about(WAN_MAC, GW, ROUTER_WAN, ICMP_DEST_UNREACH, 4, &r[..len]);
            let len = e.len() - 64;
            missed[0] += (shard_of(Role::Wan, &e[..len], SHARDS, 42, &blind) != k) as usize;
            assert_eq!(shard_of(Role::Wan, &e[..len], SHARDS, 42, &hints), k, "WAN error {i}");
            let Verdict::Forward { egress, next_hop, len, .. } = fws[k].process(2, WAN, &mut e, len) else {
                panic!("WAN error {i} not forwarded")
            };
            assert_eq!((egress, next_hop), (LAN, NAS));
            assert!(checksums_ok(&e[..len]));

            // Hairpin: the client reports an error about the answer it
            // got from the WAN address.
            let host = Ipv4Addr::new(192, 168, 1, 100 + (i % 50) as u8);
            let mut f = tcp_frame(LAN_MAC, host, ROUTER_WAN, 31_000 + i, 8443, TCP_SYN);
            let len = f.len() - 64;
            let k = shard_of(Role::Lan, &f[..len], SHARDS, 42, &hints);
            let Verdict::Forward { len, .. } = fws[k].process(0, LAN, &mut f, len) else { panic!("hairpin {i}") };
            let syn = f[..len].to_vec();
            let natport = ports(&syn).1;
            let mut r = tcp_frame(LAN_MAC, NAS, ROUTER_LAN, 443, natport, TCP_SYN | TCP_ACK);
            let len = r.len() - 64;
            let Verdict::Forward { len, .. } = fws[k].process(1, LAN, &mut r, len) else { panic!("hairpin reply {i}") };
            let mut e = icmp_about(LAN_MAC, host, ROUTER_LAN, ICMP_DEST_UNREACH, 3, &r[..len]);
            let len = e.len() - 64;
            missed[1] += (shard_of(Role::Lan, &e[..len], SHARDS, 42, &blind) != k) as usize;
            assert_eq!(shard_of(Role::Lan, &e[..len], SHARDS, 42, &hints), k, "hairpin client error {i}");
            let Verdict::Forward { egress, next_hop, .. } = fws[k].process(2, LAN, &mut e, len) else {
                panic!("hairpin client error {i} not forwarded")
            };
            assert_eq!((egress, next_hop), (LAN, NAS));

            // Hairpin: the NAS reports an error about the SYN it got from
            // the router's LAN address.
            let mut e = icmp_about(LAN_MAC, NAS, ROUTER_LAN, ICMP_DEST_UNREACH, 3, &syn);
            let len = e.len() - 64;
            missed[2] += (shard_of(Role::Lan, &e[..len], SHARDS, 42, &blind) != k) as usize;
            assert_eq!(shard_of(Role::Lan, &e[..len], SHARDS, 42, &hints), k, "target error {i}");
            let Verdict::Forward { egress, next_hop, .. } = fws[k].process(3, LAN, &mut e, len) else {
                panic!("target error {i} not forwarded")
            };
            assert_eq!((egress, next_hop), (LAN, host));
        }
        assert!(missed.iter().all(|&n| n > 0), "control: without the forwards each kind misses: {missed:?}");
    }

    // ---- reject: answered refusals ---------------------------------------

    /// [`zoned`] with guest TCP 80 + UDP 161 to the WAN refused by `action`
    /// and guest input `reject_input`.
    fn rejecting(fw: &mut Forwarder, action: Action, reject_input: bool) {
        zoned(fw);
        let r = |protos, port| Rule { dport: Some((port, port)), action, ..rule(Some(2), RuleTo::Zone(0), protos, false) };
        fw.set_policy(Some(Policy {
            forward: vec![0, 0b101, 0b001],
            input: vec![None, None, Some(svc::DHCP | svc::DNS)],
            reject_input: vec![false, false, reject_input],
            rules: vec![r(proto::TCP, 80), r(proto::UDP, 161)],
            ..Policy::default()
        }));
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp_seq_frame(mac: Mac, src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, flags: u8, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let mut seg = tcp_segment(src, dst, sport, dport, flags, payload);
        seg[4..8].copy_from_slice(&seq.to_be_bytes());
        seg[8..12].copy_from_slice(&ack.to_be_bytes());
        seg[16..18].fill(0);
        let c = wire::l4_checksum(src, dst, PROTO_TCP, &seg);
        seg[16..18].copy_from_slice(&c.to_be_bytes());
        to(mac, ipv4_frame(src, dst, PROTO_TCP, 64, &seg))
    }

    fn rst_of(f: &[u8]) -> (Ipv4Addr, u16, Ipv4Addr, u16, u8, u32, u32) {
        let v = view(f);
        let g32 = |o: usize| u32::from_be_bytes(f[o..o + 4].try_into().unwrap());
        let (src, sport, dst, dport) = ports(f);
        (src, sport, dst, dport, f[v.l4 + 13], g32(v.l4 + 4), g32(v.l4 + 8))
    }

    #[test]
    fn reject_rule_answers_forwarded_tcp_with_a_reset() {
        let mut fw = router();
        rejecting(&mut fw, Action::Reject, false);
        // A SYN: RST+ACK of seq + 1, from the server it went to.
        let mut f = tcp_seq_frame(GUEST_MAC, GUEST_HOST, SERVER, 40_000, 80, TCP_SYN, 1000, 0, b"");
        let Verdict::Forward { egress, next_hop, len, .. } = run(&mut fw, 0, GUEST, &mut f) else {
            panic!("SYN not answered")
        };
        assert_eq!((egress, next_hop), (GUEST, GUEST_HOST));
        assert_eq!(rst_of(&f[..len]), (SERVER, 80, GUEST_HOST, 40_000, wire::TCP_RST | TCP_ACK, 0, 1001));
        assert!(checksums_ok(&f[..len]));
        // A segment with ACK and data: RST with its ack as seq.
        let mut f = tcp_seq_frame(GUEST_MAC, GUEST_HOST, SERVER, 40_001, 80, TCP_ACK, 5, 777, b"data");
        let Verdict::Forward { len, .. } = run(&mut fw, 1, GUEST, &mut f) else { panic!("ACK not answered") };
        assert_eq!(rst_of(&f[..len]), (SERVER, 80, GUEST_HOST, 40_001, wire::TCP_RST, 777, 0));
        assert!(checksums_ok(&f[..len]));
        // Never a RST for a RST.
        let mut f = tcp_seq_frame(GUEST_MAC, GUEST_HOST, SERVER, 40_002, 80, wire::TCP_RST, 5, 0, b"");
        assert_eq!(run(&mut fw, 2, GUEST, &mut f), Verdict::Drop(DropReason::Firewall));
        assert_eq!((fw.stats.rejected, fw.rule_hits[0]), (2, 3));
        assert!(fw.ct.is_empty(), "refused flows are not tracked");
        // Negative control: drop is silent.
        let mut fw = router();
        rejecting(&mut fw, Action::Drop, false);
        let mut f = tcp_seq_frame(GUEST_MAC, GUEST_HOST, SERVER, 40_000, 80, TCP_SYN, 1000, 0, b"");
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), Verdict::Drop(DropReason::Firewall));
        assert_eq!(fw.stats.rejected, 0);
    }

    #[test]
    fn reject_rule_answers_forwarded_udp_with_port_unreachable() {
        let mut fw = router();
        rejecting(&mut fw, Action::Reject, false);
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, SERVER, 40_161, 161);
        let orig = f[ETH_HDR..ETH_HDR + 28].to_vec();
        let Verdict::Forward { egress, next_hop, len, .. } = run(&mut fw, 0, GUEST, &mut f) else {
            panic!("not answered")
        };
        assert_eq!((egress, next_hop), (GUEST, GUEST_HOST));
        let v = view(&f[..len]);
        assert_eq!((v.src(&f), v.dst(&f), v.proto), (ROUTER_GUEST, GUEST_HOST, PROTO_ICMP));
        assert_eq!((f[v.l4], f[v.l4 + 1]), (ICMP_DEST_UNREACH, 3));
        assert_eq!(&f[v.l4 + 8..v.l4 + 36], &orig[..], "quotes the datagram");
        assert!(checksums_ok(&f[..len]));
        // Other ports are not rejected (zone: guest → WAN allowed).
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, SERVER, 40_162, 162);
        assert!(matches!(run(&mut fw, 1, GUEST, &mut f), Verdict::Forward { egress: WAN, .. }));
    }

    #[test]
    fn reject_input_answers_unicast_only() {
        let mut fw = router();
        rejecting(&mut fw, Action::Reject, true);
        // TCP 22 to the router: RST from the router's address.
        let mut f = tcp_seq_frame(GUEST_MAC, GUEST_HOST, ROUTER_GUEST, 40_000, 22, TCP_SYN, 9, 0, b"");
        let Verdict::Forward { egress, len, .. } = run(&mut fw, 0, GUEST, &mut f) else { panic!("TCP 22") };
        assert_eq!(egress, GUEST);
        assert_eq!(rst_of(&f[..len]), (ROUTER_GUEST, 22, GUEST_HOST, 40_000, wire::TCP_RST | TCP_ACK, 0, 10));
        // Another router address (the LAN's) answers as itself.
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, ROUTER_LAN, 40_001, 161);
        let Verdict::Forward { len, .. } = run(&mut fw, 1, GUEST, &mut f) else { panic!("UDP 161") };
        let v = view(&f[..len]);
        assert_eq!((v.src(&f), f[v.l4], f[v.l4 + 1]), (ROUTER_LAN, ICMP_DEST_UNREACH, 3));
        // Ping refused: port unreachable too.
        let mut f = to(GUEST_MAC, ipv4_frame(GUEST_HOST, ROUTER_GUEST, PROTO_ICMP, 64, &icmp_echo(ICMP_ECHO_REQUEST, 1, 1)));
        assert!(matches!(run(&mut fw, 2, GUEST, &mut f), Verdict::Forward { egress: GUEST, .. }), "ping");
        // Multicast, broadcast and ICMP errors: never answered.
        let mdns = Ipv4Addr::new(224, 0, 0, 251);
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, mdns, 5353, 5353);
        assert_eq!(run(&mut fw, 3, GUEST, &mut f), Verdict::Drop(DropReason::Input), "mDNS");
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, Ipv4Addr::new(10, 20, 0, 255), 40_002, 137);
        assert_eq!(run(&mut fw, 3, GUEST, &mut f), Verdict::Drop(DropReason::Input), "subnet broadcast");
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, Ipv4Addr::BROADCAST, 40_003, 137);
        assert_eq!(run(&mut fw, 3, GUEST, &mut f), Verdict::Drop(DropReason::Input), "broadcast");
        let mut f = udp_frame(GUEST_MAC, Ipv4Addr::UNSPECIFIED, ROUTER_GUEST, 40_004, 161);
        assert_eq!(run(&mut fw, 3, GUEST, &mut f), Verdict::Drop(DropReason::Input), "from 0.0.0.0");
        assert_eq!(fw.stats.rejected, 3);
        // Allowed services still pass.
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, ROUTER_GUEST, 40_005, 53);
        assert_eq!(run(&mut fw, 4, GUEST, &mut f), Verdict::Local);
        // Negative control: input drop is silent.
        let mut fw = router();
        rejecting(&mut fw, Action::Reject, false);
        let mut f = tcp_seq_frame(GUEST_MAC, GUEST_HOST, ROUTER_GUEST, 40_000, 22, TCP_SYN, 9, 0, b"");
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), Verdict::Drop(DropReason::Input));
    }

    #[test]
    fn rejects_share_the_icmp_rate_limit() {
        let mut fw = router();
        rejecting(&mut fw, Action::Reject, false);
        let answered = (0..100u16)
            .filter(|&i| {
                let mut f = tcp_seq_frame(GUEST_MAC, GUEST_HOST, SERVER, 30_000 + i, 80, TCP_SYN, 1, 0, b"");
                matches!(run(&mut fw, 0, GUEST, &mut f), Verdict::Forward { .. })
            })
            .count();
        assert_eq!(answered as u64, ICMP_BURST, "a burst, then silent drops");
        assert_eq!(fw.stats.drops[DropReason::Firewall.index()], 100 - ICMP_BURST);
    }

    // ---- recheck: a new policy also applies to tracked connections ----

    /// The guest policy of [`zoned`] with `forward` masks and `rules`.
    fn zone_policy(forward: Vec<u32>, rules: Vec<Rule>) -> Option<Policy> {
        Some(Policy { forward, input: vec![None, None, Some(svc::DHCP | svc::DNS)], rules, ..Policy::default() })
    }

    #[test]
    fn recheck_removes_connections_the_new_zones_refuse() {
        let mut fw = router();
        zoned(&mut fw);
        let mut f = tcp_frame(LAN_MAC, HOST, GUEST_HOST, 6000, 80, TCP_SYN);
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { egress: GUEST, .. }), "LAN → guest");
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, SERVER, 7000, 53);
        assert!(matches!(run(&mut fw, 0, GUEST, &mut f), Verdict::Forward { egress: WAN, .. }), "guest → WAN");
        let port = syn_out(&mut fw);
        assert_eq!(fw.ct.len(), 3);
        // Negative control: the same policy again keeps everything.
        fw.set_policy(zone_policy(vec![0, 0b101, 0b001], vec![]));
        assert_eq!(fw.recheck(), 0);
        // LAN only to the WAN, guest nowhere.
        fw.set_policy(zone_policy(vec![0, 0b001, 0], vec![]));
        assert_eq!(fw.recheck(), 2);
        assert_eq!((fw.ct.len(), fw.stats.revoked), (1, 2));
        // The guest's next packets are new flows, refused.
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, SERVER, 7000, 53);
        assert_eq!(run(&mut fw, 1, GUEST, &mut f), Verdict::Drop(DropReason::Firewall));
        let mut f = tcp_frame(GUEST_MAC, GUEST_HOST, HOST, 80, 6000, TCP_SYN | TCP_ACK);
        assert_eq!(run(&mut fw, 1, GUEST, &mut f), Verdict::Drop(DropReason::Firewall));
        // LAN → WAN still runs.
        let seg = tcp_segment(SERVER, ROUTER_WAN, 80, port, TCP_SYN | TCP_ACK, b"");
        let mut f = to(WAN_MAC, ipv4_frame(SERVER, ROUTER_WAN, PROTO_TCP, 50, &seg));
        assert!(matches!(run(&mut fw, 1, WAN, &mut f), Verdict::Forward { egress: LAN, .. }));
        // A network moved into a zone that may not reach the WAN.
        fw.set_zone(LAN, 2);
        assert_eq!(fw.recheck(), 1);
        assert!(fw.ct.is_empty());
    }

    #[test]
    fn recheck_applies_rules_without_counting_them() {
        let mut fw = router();
        zoned(&mut fw);
        syn_out(&mut fw); // LAN → SERVER:80
        let mut f = udp_frame(LAN_MAC, HOST, SERVER, 7001, 53);
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { .. }));
        let no_web = Rule {
            from: Some(1),
            to: RuleTo::Zone(0),
            protos: proto::TCP,
            src: None,
            dst: None,
            dport: Some((80, 80)),
            action: Action::Drop,
        };
        fw.set_policy(zone_policy(vec![0, 0b101, 0b001], vec![no_web]));
        assert_eq!(fw.recheck(), 1, "TCP 80 only");
        assert_eq!(fw.rule_hits, [0], "a recheck is no hit");
        // An accept rule keeps what the zones would refuse.
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, NAS, 7002, 161);
        fw.set_policy(zone_policy(vec![0, 0b101, 0b011], vec![]));
        assert!(matches!(run(&mut fw, 0, GUEST, &mut f), Verdict::Forward { egress: LAN, .. }));
        let snmp = Rule { from: Some(2), to: RuleTo::Zone(1), protos: proto::UDP, src: None, dst: Some((NAS, 32)), dport: Some((161, 161)), action: Action::Accept };
        fw.set_policy(zone_policy(vec![0, 0b101, 0b001], vec![snmp]));
        assert_eq!(fw.recheck(), 0);
        fw.set_policy(zone_policy(vec![0, 0b101, 0b001], vec![]));
        assert_eq!(fw.recheck(), 1, "without the rule");
    }

    #[test]
    fn recheck_follows_port_forwards_and_redirects() {
        let mut fw = router();
        let web = fwd(8443, 8443, Some(443), None, true);
        with_forwards(&mut fw, vec![web]);
        let mut f = tcp_frame(WAN_MAC, SERVER, ROUTER_WAN, 5555, 8443, TCP_SYN);
        assert!(matches!(run(&mut fw, 0, WAN, &mut f), Verdict::Forward { egress: LAN, .. }));
        let mut f = tcp_frame(LAN_MAC, HOST, ROUTER_WAN, 40_001, 8443, TCP_SYN);
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { egress: LAN, .. }), "hairpin");
        with_forwards(&mut fw, vec![web]);
        assert_eq!(fw.recheck(), 0, "the same forward keeps both");
        with_forwards(&mut fw, vec![PortForward { hairpin: false, ..web }]);
        assert_eq!(fw.recheck(), 1, "hairpin off: the internal client's");
        with_forwards(&mut fw, vec![PortForward { to: HOST, ..web }]);
        assert_eq!(fw.recheck(), 1, "another target");
        assert!(fw.ct.is_empty());
        // Forward removed.
        with_forwards(&mut fw, vec![web]);
        let mut f = tcp_frame(WAN_MAC, SERVER, ROUTER_WAN, 5556, 8443, TCP_SYN);
        assert!(matches!(run(&mut fw, 1, WAN, &mut f), Verdict::Forward { .. }));
        with_forwards(&mut fw, vec![]);
        assert_eq!(fw.recheck(), 1);
        // A masquerade whose NAT port is forwarded now (preserved port 20005).
        let mut f = tcp_frame(LAN_MAC, HOST, SERVER, 20_005, 80, TCP_SYN);
        let Verdict::Forward { len, .. } = run(&mut fw, 2, LAN, &mut f) else { panic!() };
        assert_eq!(ports(&f[..len]).1, 20_005);
        with_forwards(&mut fw, vec![fwd(20_000, 20_010, None, None, false)]);
        assert_eq!(fw.recheck(), 1, "masquerade on a forwarded port");

        // The forward's own target going out from its forwarded port (WAN
        // :8443, Conntrack::create_from) keeps it across a new policy (a
        // rule toggled elsewhere), until the forward points elsewhere.
        let mut fw = router();
        let web = PortForward { protos: proto::TCP | proto::UDP, ..web };
        with_forwards(&mut fw, vec![web]);
        let mut f = udp_frame(LAN_MAC, NAS, SERVER, 443, 6881);
        let Verdict::Forward { len, .. } = run(&mut fw, 0, LAN, &mut f) else { panic!() };
        assert_eq!(ports(&f[..len]).1, 8443);
        let mut f = tcp_frame(LAN_MAC, NAS, SERVER, 443, 6882, TCP_SYN);
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { .. }));
        with_forwards(&mut fw, vec![web]);
        assert_eq!(fw.recheck(), 0, "the target's own connections out stay");
        with_forwards(&mut fw, vec![PortForward { to: HOST, ..web }]);
        assert_eq!(fw.recheck(), 2, "the port is another target's now");

        // Redirects: one added takes NTP to the outside from now on.
        let mut fw = router();
        with_redirects(&mut fw, vec![]);
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, SERVER, 40_123, 123);
        assert!(matches!(run(&mut fw, 0, GUEST, &mut f), Verdict::Forward { egress: WAN, .. }));
        with_redirects(&mut fw, vec![]);
        assert_eq!(fw.recheck(), 0);
        with_redirects(&mut fw, vec![ntp_to(NAS, None)]);
        assert_eq!(fw.recheck(), 1, "a redirect takes it now");
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, SERVER, 40_123, 123);
        let Verdict::Forward { next_hop, .. } = run(&mut fw, 1, GUEST, &mut f) else { panic!() };
        assert_eq!(next_hop, NAS, "the next packet is redirected");
        with_redirects(&mut fw, vec![ntp_to(NAS, None)]);
        assert_eq!(fw.recheck(), 0);
        with_redirects(&mut fw, vec![ntp_to(NAS, Some(1))]);
        assert_eq!(fw.recheck(), 1, "the redirect no longer takes guest");
    }

    // ---- redirects (docs/config-v2.md, [[firewall.redirect]]) ---------

    fn ntp_to(to: Ipv4Addr, from: Option<u8>) -> Redirect {
        Redirect { from, protos: proto::UDP, lo: 123, hi: 123, to, to_port: None }
    }

    /// The zoned router (guest: WAN only, input DHCP + DNS) with redirects.
    fn with_redirects(fw: &mut Forwarder, redirects: Vec<Redirect>) {
        zoned(fw);
        fw.set_policy(Some(Policy {
            forward: vec![0, 0b101, 0b001],
            input: vec![None, None, Some(svc::DHCP | svc::DNS)],
            redirects,
            ..Policy::default()
        }));
    }

    fn udp_frame(mac: Mac, src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let d = udp_datagram(src, dst, sport, dport, b"ntp");
        to(mac, ipv4_frame(src, dst, PROTO_UDP, 64, &d))
    }

    #[test]
    fn redirect_from_another_network_both_ways() {
        let mut fw = router();
        with_redirects(&mut fw, vec![ntp_to(NAS, None)]);
        // Guest → an NTP server on the internet: to the NAS on the LAN,
        // although guest may not reach the LAN; the source stays.
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, SERVER, 40_123, 123);
        let Verdict::Forward { egress, next_hop, len, .. } = run(&mut fw, 0, GUEST, &mut f) else {
            panic!("not redirected")
        };
        assert_eq!((egress, next_hop), (LAN, NAS));
        assert_eq!(ports(&f[..len]), (GUEST_HOST, 40_123, NAS, 123));
        assert!(checksums_ok(&f[..len]));
        let mut r = udp_frame(LAN_MAC, NAS, GUEST_HOST, 123, 40_123);
        let Verdict::Forward { egress, next_hop, len, .. } = run(&mut fw, 1, LAN, &mut r) else {
            panic!("reply not forwarded")
        };
        assert_eq!((egress, next_hop), (GUEST, GUEST_HOST));
        assert_eq!(ports(&r[..len]), (SERVER, 123, GUEST_HOST, 40_123), "looks like the server answered");
        assert!(checksums_ok(&r[..len]));
        assert_eq!(fw.redirect_hits, [1]);
        // Control: the NAS itself on another port stays out of reach.
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, NAS, 40_124, 124);
        assert_eq!(run(&mut fw, 2, GUEST, &mut f), Verdict::Drop(DropReason::Firewall));
    }

    #[test]
    fn redirect_on_the_targets_network_answers_through_the_router() {
        let mut fw = router();
        with_redirects(&mut fw, vec![ntp_to(NAS, None)]);
        let mut f = udp_frame(LAN_MAC, HOST, SERVER, 40_123, 123);
        let Verdict::Forward { egress, next_hop, len, .. } = run(&mut fw, 0, LAN, &mut f) else {
            panic!("not redirected")
        };
        assert_eq!((egress, next_hop), (LAN, NAS), "back out of the LAN");
        let (src, sport, dst, dport) = ports(&f[..len]);
        assert_eq!((src, dst, dport), (ROUTER_LAN, NAS, 123), "from the router, else the NAS answers directly");
        assert!(checksums_ok(&f[..len]));
        let mut r = udp_frame(LAN_MAC, NAS, ROUTER_LAN, 123, sport);
        let Verdict::Forward { egress, next_hop, len, .. } = run(&mut fw, 1, LAN, &mut r) else {
            panic!("reply not forwarded")
        };
        assert_eq!((egress, next_hop), (LAN, HOST));
        assert_eq!(ports(&r[..len]), (SERVER, 123, HOST, 40_123));
        assert!(checksums_ok(&r[..len]));
        // To the router's address: it serves no NTP, so redirected too.
        let mut f = udp_frame(LAN_MAC, HOST, ROUTER_LAN, 40_125, 123);
        let Verdict::Forward { next_hop, len, .. } = run(&mut fw, 2, LAN, &mut f) else {
            panic!("router address not redirected")
        };
        assert_eq!((next_hop, ports(&f[..len]).2), (NAS, NAS));
        assert_eq!(fw.redirect_hits, [2]);
    }

    #[test]
    fn redirect_leaves_other_traffic_alone() {
        let mut fw = router();
        with_redirects(&mut fw, vec![ntp_to(NAS, None)]);
        // The target's own queries go out to the internet.
        let mut f = udp_frame(LAN_MAC, NAS, SERVER, 40_123, 123);
        let Verdict::Forward { egress: WAN, len, .. } = run(&mut fw, 0, LAN, &mut f) else {
            panic!("target's query not to the WAN")
        };
        assert_eq!(ports(&f[..len]).2, SERVER);
        // Inside another network: as addressed.
        let mut f = udp_frame(LAN_MAC, HOST, GUEST_HOST, 40_124, 123);
        let Verdict::Forward { egress: GUEST, len, .. } = run(&mut fw, 0, LAN, &mut f) else {
            panic!("LAN → guest host not forwarded")
        };
        assert_eq!(ports(&f[..len]).2, GUEST_HOST);
        // Other ports and protocols.
        let mut f = udp_frame(LAN_MAC, HOST, SERVER, 40_125, 124);
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { egress: WAN, .. }));
        let mut f = tcp_frame(LAN_MAC, HOST, SERVER, 40_126, 123, TCP_SYN);
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { egress: WAN, .. }));
        // Broadcast and the router's own services stay local.
        let mut f = udp_frame(LAN_MAC, HOST, Ipv4Addr::BROADCAST, 40_127, 123);
        assert_eq!(run(&mut fw, 0, LAN, &mut f), Verdict::Local);
        let all = Redirect { protos: proto::TCP | proto::UDP, lo: 1, hi: 1000, ..ntp_to(NAS, None) };
        with_redirects(&mut fw, vec![all]);
        for (p, port) in [(PROTO_UDP, 53), (PROTO_UDP, 67), (PROTO_TCP, 80), (PROTO_TCP, 53)] {
            let mut f = match p {
                PROTO_UDP => udp_frame(LAN_MAC, HOST, ROUTER_LAN, 40_128, port),
                _ => tcp_frame(LAN_MAC, HOST, ROUTER_LAN, 40_128, port, TCP_SYN),
            };
            assert_eq!(run(&mut fw, 0, LAN, &mut f), Verdict::Local, "router's {p}/{port}");
        }
        // …but to the internet the same ports are redirected.
        let mut f = udp_frame(LAN_MAC, HOST, SERVER, 40_129, 53);
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { egress: LAN, next_hop: NAS, .. }));
        assert_eq!(fw.redirect_hits, [1]);
    }

    #[test]
    fn redirect_only_from_its_zone() {
        let mut fw = router();
        with_redirects(&mut fw, vec![ntp_to(NAS, Some(2))]);
        let mut f = udp_frame(LAN_MAC, HOST, SERVER, 40_123, 123);
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { egress: WAN, .. }), "LAN zone: as addressed");
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, SERVER, 40_123, 123);
        assert!(matches!(run(&mut fw, 0, GUEST, &mut f), Verdict::Forward { egress: LAN, next_hop: NAS, .. }));
        // Control: without redirects guest NTP goes to the internet.
        with_redirects(&mut fw, vec![]);
        let mut f = udp_frame(GUEST_MAC, GUEST_HOST, SERVER, 40_124, 123);
        assert!(matches!(run(&mut fw, 0, GUEST, &mut f), Verdict::Forward { egress: WAN, .. }));
    }

    #[test]
    fn redirected_connections_keep_one_shard() {
        // Target on the guest network; the LAN zone may reach it directly.
        let target = Ipv4Addr::new(10, 20, 0, 10);
        let internal = [(ROUTER_LAN, 24), (ROUTER_GUEST, 24)];
        for from in [None, Some(2)] {
            let redirects = [ntp_to(target, from)];
            let hints = ShardHints { internal: &internal, routed: &[], wan: Some(ROUTER_WAN), forwards: &[], redirects: &redirects };
            let mut fws = shards();
            for fw in &mut fws {
                with_redirects(fw, redirects.to_vec());
            }
            let shard = |role, f: &[u8]| shard_of(role, &f[..f.len() - 64], SHARDS, 42, &hints);
            for i in 0..32u16 {
                let host = Ipv4Addr::new(192, 168, 1, 100 + i as u8);
                let sport = 41_000 + i;
                // LAN host → the internet's NTP: redirected (from = any) to
                // the guest target without SNAT, or (from = guest) NATed
                // out to the WAN.
                let mut f = udp_frame(LAN_MAC, host, SERVER, sport, 123);
                let k = shard(Role::Lan, &f);
                let len = f.len() - 64;
                match (from, fws[k].process(0, LAN, &mut f, len)) {
                    (None, Verdict::Forward { egress: GUEST, .. }) => {
                        let mut r = udp_frame(GUEST_MAC, target, host, 123, sport);
                        assert_eq!(shard(Role::Lan, &r), k, "redirect reply {i}");
                        let len = r.len() - 64;
                        assert!(matches!(fws[k].process(1, GUEST, &mut r, len), Verdict::Forward { egress: LAN, .. }));
                        // The target's ICMP error about the query.
                        let q = udp_frame(GUEST_MAC, host, target, sport, 123);
                        let mut icmp = vec![wire::ICMP_DEST_UNREACH, 3, 0, 0, 0, 0, 0, 0];
                        icmp.extend_from_slice(&q[ETH_HDR..ETH_HDR + 28]);
                        let c = wire::checksum(&icmp);
                        icmp[2..4].copy_from_slice(&c.to_be_bytes());
                        let mut e = to(GUEST_MAC, ipv4_frame(target, host, PROTO_ICMP, 64, &icmp));
                        assert_eq!(shard(Role::Lan, &e), k, "ICMP error {i}");
                        let len = e.len() - 64;
                        assert!(matches!(fws[k].process(2, GUEST, &mut e, len), Verdict::Forward { egress: LAN, .. }));
                    }
                    (Some(_), Verdict::Forward { egress: WAN, len, .. }) => {
                        let natport = ports(&f[..len]).1;
                        let mut r = udp_frame(WAN_MAC, SERVER, ROUTER_WAN, 123, natport);
                        assert_eq!(shard(Role::Wan, &r), k, "NAT reply {i}");
                        let len = r.len() - 64;
                        assert!(matches!(fws[k].process(1, WAN, &mut r, len), Verdict::Forward { egress: LAN, .. }));
                    }
                    (_, v) => panic!("{from:?} flow {i}: {v:?}"),
                }
                // LAN host → the target directly (the zones allow it).
                let mut f = udp_frame(LAN_MAC, host, target, sport + 100, 123);
                let k = shard(Role::Lan, &f);
                let len = f.len() - 64;
                assert!(matches!(fws[k].process(3, LAN, &mut f, len), Verdict::Forward { egress: GUEST, .. }));
                let mut r = udp_frame(GUEST_MAC, target, host, 123, sport + 100);
                assert_eq!(shard(Role::Lan, &r), k, "direct reply {i}");
                let len = r.len() - 64;
                assert!(matches!(fws[k].process(3, GUEST, &mut r, len), Verdict::Forward { egress: LAN, .. }));
                // Guest host on the target's network: through the router.
                let ghost = Ipv4Addr::new(10, 20, 0, 100 + i as u8);
                let mut f = udp_frame(GUEST_MAC, ghost, SERVER, sport, 123);
                let k = shard(Role::Lan, &f);
                let len = f.len() - 64;
                let Verdict::Forward { egress: GUEST, len, .. } = fws[k].process(4, GUEST, &mut f, len) else {
                    panic!("guest {i} not redirected")
                };
                let natport = ports(&f[..len]).1;
                let mut r = udp_frame(GUEST_MAC, target, ROUTER_GUEST, 123, natport);
                assert_eq!(shard(Role::Lan, &r), k, "SNAT reply {i}");
                let len = r.len() - 64;
                assert!(matches!(fws[k].process(5, GUEST, &mut r, len), Verdict::Forward { egress: GUEST, .. }));
            }
        }
    }

    // ---- fragments (crate::frag) ----------------------------------------

    /// `l4` as IPv4 fragments of at most `chunk` L4 bytes (a multiple of
    /// 8), IP ID `id`, as frames to `mac`.
    fn fragments(mac: Mac, src: Ipv4Addr, dst: Ipv4Addr, proto: u8, id: u16, l4: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        l4.chunks(chunk)
            .enumerate()
            .map(|(i, c)| {
                let mut f = ipv4_frame(src, dst, proto, 64, c);
                let more = (i + 1) * chunk < l4.len();
                wire::put16(&mut f, ETH_HDR + 4, id);
                wire::put16(&mut f, ETH_HDR + 6, (i * chunk / 8) as u16 | if more { 0x2000 } else { 0 });
                wire::put16(&mut f, ETH_HDR + 10, 0);
                let c = wire::checksum(&f[ETH_HDR..ETH_HDR + 20]);
                wire::put16(&mut f, ETH_HDR + 10, c);
                to(mac, f)
            })
            .collect()
    }

    /// The datagram the forwarded fragments make up again: (source,
    /// destination, L4 bytes), checking each IP header.
    fn reassemble(out: &[(Vec<u8>, usize)]) -> (Ipv4Addr, Ipv4Addr, Vec<u8>) {
        let mut l4 = Vec::new();
        let (f0, l0) = &out[0];
        let first = view(&f0[..*l0]);
        for (f, len) in out {
            let f = &f[..*len];
            let v = view(f);
            assert_eq!(wire::checksum(&f[ETH_HDR..ETH_HDR + 20]), 0, "IP header checksum");
            assert_eq!((v.src(f), v.dst(f), v.id(f)), (first.src(&f0[..*l0]), first.dst(&f0[..*l0]), first.id(&f0[..*l0])));
            assert_eq!(v.frag_offset as usize * 8, l4.len(), "in order, no gaps");
            assert_eq!(v.ttl(f), 63);
            l4.extend_from_slice(&f[v.l4..v.l4 + v.l4_len]);
        }
        (first.src(&f0[..*l0]), first.dst(&f0[..*l0]), l4)
    }

    /// Forward a datagram's fragments in the given order the way the
    /// datapath does: the first through `process`, the others with its
    /// decision (held until it is known).
    fn forward_frags(fw: &mut Forwarder, ifx: IfIndex, frames: Vec<Vec<u8>>, order: &[usize]) -> Vec<(Vec<u8>, usize)> {
        let mut decision = None;
        let mut held = Vec::new();
        let mut out = Vec::new();
        for &i in order {
            let mut f = frames[i].clone();
            let len = f.len() - 64;
            if i == 0 {
                let Verdict::Forward { len, .. } = fw.process(0, ifx, &mut f, len) else { panic!("first fragment not forwarded") };
                decision = fw.take_fragment();
                assert!(decision.is_some());
                out.push((i, f, len));
                for (j, mut h) in core::mem::take(&mut held) {
                    let hl = Vec::len(&h) - 64;
                    let Verdict::Forward { len, .. } = fw.forward_fragment(0, ifx, &mut h, hl, decision.as_ref().unwrap()) else { panic!() };
                    out.push((j, h, len));
                }
            } else if let Some(d) = &decision {
                let Verdict::Forward { len, egress, .. } = fw.forward_fragment(0, ifx, &mut f, len, d) else { panic!() };
                let frag::Decision::V4(d4) = d else { panic!("IPv4 decision") };
                assert_eq!(egress, d4.egress);
                out.push((i, f, len));
            } else {
                held.push((i, f));
            }
        }
        out.sort_by_key(|(i, _, _)| *i);
        out.into_iter().map(|(_, f, l)| (f, l)).collect()
    }

    #[test]
    fn fragmented_udp_through_nat_both_ways() {
        let mut fw = router();
        let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
        let dgram = udp_datagram(HOST, SERVER, 5000, 4500, &payload);
        let frames = fragments(LAN_MAC, HOST, SERVER, PROTO_UDP, 0x4242, &dgram, 1480);
        assert_eq!(frames.len(), 3);
        let out = forward_frags(&mut fw, LAN, frames, &[0, 1, 2]);
        let (src, dst, l4) = reassemble(&out);
        assert_eq!((src, dst), (ROUTER_WAN, SERVER));
        assert_eq!(wire::l4_checksum(src, dst, PROTO_UDP, &l4), 0, "UDP checksum of the whole datagram");
        assert_eq!(&l4[8..], &payload[..]);
        let nat_port = wire::get16(&l4, 0);
        assert_eq!(wire::get16(&l4, 2), 4500);
        // The answer, fragmented, back to the NAT port; the second fragment
        // first (held until the first arrives).
        let reply = udp_datagram(SERVER, ROUTER_WAN, 4500, nat_port, &payload);
        let frames = fragments(WAN_MAC, SERVER, ROUTER_WAN, PROTO_UDP, 0x0777, &reply, 1480);
        let out = forward_frags(&mut fw, WAN, frames, &[1, 0, 2]);
        let (src, dst, l4) = reassemble(&out);
        assert_eq!((src, dst), (SERVER, HOST));
        assert_eq!(wire::get16(&l4, 2), 5000, "back to the host's port");
        assert_eq!(wire::l4_checksum(src, dst, PROTO_UDP, &l4), 0);
        assert_eq!(&l4[8..], &payload[..]);
    }

    #[test]
    fn fragmented_ping_through_nat() {
        let mut fw = router();
        let mut echo = icmp_echo(ICMP_ECHO_REQUEST, 0x77, 1);
        echo.extend((0..2000u32).map(|i| i as u8));
        wire::put16(&mut echo, 2, 0);
        let c = wire::checksum(&echo);
        wire::put16(&mut echo, 2, c);
        let frames = fragments(LAN_MAC, HOST, SERVER, PROTO_ICMP, 9, &echo, 1480);
        let out = forward_frags(&mut fw, LAN, frames, &[0, 1]);
        let (src, _, l4) = reassemble(&out);
        assert_eq!(src, ROUTER_WAN);
        assert_eq!(wire::checksum(&l4), 0, "ICMP checksum after the identifier rewrite");
    }

    #[test]
    fn fragment_refusals() {
        let mut fw = router();
        let dgram = udp_datagram(HOST, SERVER, 5000, 4500, &[1u8; 3000]);
        let frames = fragments(LAN_MAC, HOST, SERVER, PROTO_UDP, 1, &dgram, 1480);
        // A later fragment without its first one.
        let mut f = frames[1].clone();
        assert_eq!(run(&mut fw, 0, LAN, &mut f), Verdict::Drop(DropReason::Fragment));
        let mut f = frames[0].clone();
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { .. }));
        let d = fw.take_fragment().unwrap();
        assert_eq!(fw.take_fragment(), None, "taken once");
        // TTL 1, too large for the egress: dropped, no ICMP error.
        let mut f = frames[1].clone();
        f[ETH_HDR + 8] = 1;
        wire::put16(&mut f, ETH_HDR + 10, 0);
        let c = wire::checksum(&f[ETH_HDR..ETH_HDR + 20]);
        wire::put16(&mut f, ETH_HDR + 10, c);
        let len = f.len() - 64;
        assert_eq!(fw.forward_fragment(0, LAN, &mut f, len, &d), Verdict::Drop(DropReason::Fragment));
        // Larger than the egress: split (a fragment is split again).
        fw.set_mtu(WAN, 1000);
        let mut f = frames[1].clone();
        assert!(matches!(fw.forward_fragment(0, LAN, &mut f, len, &d), Verdict::Forward { split: 1000, .. }));
        fw.split = false;
        let mut f = frames[1].clone();
        assert_eq!(fw.forward_fragment(0, LAN, &mut f, len, &d), Verdict::Drop(DropReason::TooBig));
        fw.split = true;
        fw.set_mtu(WAN, 1500);
        // The connection gone: its fragments go nowhere.
        let frag::Decision::V4(d4) = d else { panic!("IPv4 decision") };
        fw.ct.remove(d4.conn);
        let mut f = frames[1].clone();
        assert_eq!(fw.forward_fragment(0, LAN, &mut f, len, &d), Verdict::Drop(DropReason::Fragment));
        // Tiny first fragment (no room for the ports): refused.
        let tiny = fragments(LAN_MAC, HOST, SERVER, PROTO_UDP, 2, &dgram, 8);
        let mut f = tiny[0].clone();
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward { .. }), "8 bytes hold the UDP header");
        let tcp = tcp_segment(HOST, SERVER, 40001, 80, TCP_SYN, &[0u8; 64]);
        let tiny = fragments(LAN_MAC, HOST, SERVER, PROTO_TCP, 3, &tcp, 16);
        let mut f = tiny[0].clone();
        assert_eq!(run(&mut fw, 0, LAN, &mut f), Verdict::Drop(DropReason::Fragment), "no room for the TCP flags");
        assert_eq!(fw.take_fragment(), None);
        // Tracking off (negative control): first fragments dropped too.
        fw.fragments = false;
        let mut f = frames[0].clone();
        assert_eq!(run(&mut fw, 0, LAN, &mut f), Verdict::Drop(DropReason::Fragment));
        assert_eq!(fw.take_fragment(), None);
        // A first fragment refused by the firewall leaves no decision.
        fw.fragments = true;
        let inbound = udp_datagram(SERVER, HOST, 4500, 5000, &[1u8; 3000]);
        let frames = fragments(WAN_MAC, SERVER, HOST, PROTO_UDP, 4, &inbound, 1480);
        let mut f = frames[0].clone();
        assert!(matches!(run(&mut fw, 0, WAN, &mut f), Verdict::Drop(_)));
        assert_eq!(fw.take_fragment(), None);
    }

    // ---- IPv6 to the router (docs/ipv6.md step 1) ------------------------

    const ULA_LAN: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x1, 0x2, 0, 0, 0, 0, 1);
    const ULA_GUEST: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x1, 0x2, 1, 0, 0, 0, 1);
    const V6_HOST: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x1, 0x2, 0, 0, 0, 0, 0x100);
    const HOST_MAC: Mac = [2, 0, 0, 0, 0, 9];

    /// Ethernet + IPv6 to `dmac`, `ext` = extension headers (their first
    /// byte is patched with the next one), then `proto` and `payload`.
    fn ipv6_frame(dmac: Mac, src: Ipv6Addr, dst: Ipv6Addr, hop: u8, ext: &[(u8, Vec<u8>)], proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for (i, (_, h)) in ext.iter().enumerate() {
            let mut h = h.clone();
            h[0] = ext.get(i + 1).map_or(proto, |e| e.0);
            body.extend_from_slice(&h);
        }
        body.extend_from_slice(payload);
        let mut f = Vec::new();
        f.extend_from_slice(&dmac);
        f.extend_from_slice(&HOST_MAC);
        f.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        f.extend_from_slice(&[0x60, 0, 0, 0]);
        f.extend_from_slice(&(body.len() as u16).to_be_bytes());
        f.push(ext.first().map_or(proto, |e| e.0));
        f.push(hop);
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        f.extend_from_slice(&body);
        f.resize(f.len() + 64, 0); // tailroom, as `run` expects
        f
    }

    fn l4(sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0..2].copy_from_slice(&sport.to_be_bytes());
        p[2..4].copy_from_slice(&dport.to_be_bytes());
        p
    }

    fn icmp6(t: u8) -> Vec<u8> {
        vec![t, 0, 0, 0, 0, 0, 0, 0]
    }

    /// `router()` + the guest zone, IPv6 on, ULAs on LAN and guest.
    fn router6() -> Forwarder {
        let mut fw = router();
        zoned(&mut fw);
        fw.policy.as_mut().unwrap().input[0] = Some(0); // the WAN: silent
        fw.ipv6 = true;
        fw.set_ula6(LAN, Some(ULA_LAN));
        fw.set_ula6(GUEST, Some(ULA_GUEST));
        fw
    }

    fn v6(fw: &mut Forwarder, ifx: IfIndex, mut f: Vec<u8>) -> Verdict {
        run(fw, 0, ifx, &mut f)
    }

    const LOCAL: Verdict = Verdict::Local;
    const fn dropped(r: DropReason) -> Verdict {
        Verdict::Drop(r)
    }

    #[test]
    fn ipv6_off_drops_everything() {
        let mut fw = router6();
        fw.ipv6 = false;
        let f = ipv6_frame(LAN_MAC, V6_HOST, ULA_LAN, 64, &[], PROTO_UDP, &l4(1000, 53));
        assert_eq!(v6(&mut fw, LAN, f), dropped(DropReason::Unsupported));
    }

    #[test]
    fn ipv6_zone_input_applies_to_the_router_addresses() {
        let mut fw = router6();
        let ll = wire::link_local(GUEST_MAC);
        // LAN (input: everything): DNS and the web interface on the ULA and
        // on the link-local address.
        for dst in [ULA_LAN, wire::link_local(LAN_MAC)] {
            for (p, port) in [(PROTO_UDP, 53), (PROTO_TCP, 80)] {
                let f = ipv6_frame(LAN_MAC, V6_HOST, dst, 64, &[], p, &l4(40000, port));
                assert_eq!(v6(&mut fw, LAN, f), LOCAL, "{dst} {port}");
            }
        }
        // Guest (DHCP + DNS only): DNS passes, the web interface and ping
        // do not.
        for dst in [ULA_GUEST, ll] {
            let f = ipv6_frame(GUEST_MAC, V6_HOST, dst, 64, &[], PROTO_UDP, &l4(40000, 53));
            assert_eq!(v6(&mut fw, GUEST, f), LOCAL);
            let f = ipv6_frame(GUEST_MAC, V6_HOST, dst, 64, &[], PROTO_TCP, &l4(40000, 80));
            assert_eq!(v6(&mut fw, GUEST, f), dropped(DropReason::Input));
            let f = ipv6_frame(GUEST_MAC, V6_HOST, dst, 64, &[], PROTO_ICMPV6, &icmp6(wire::ICMPV6_ECHO_REQUEST));
            assert_eq!(v6(&mut fw, GUEST, f), dropped(DropReason::Input));
        }
        // The LAN's ULA from the guest network is forwarding, not input:
        // with a main-LAN source spoofed, with a guest one refused by the
        // zones (guest → WAN only).
        let f = ipv6_frame(GUEST_MAC, V6_HOST, ULA_LAN, 64, &[], PROTO_UDP, &l4(40000, 53));
        assert_eq!(v6(&mut fw, GUEST, f), dropped(DropReason::Spoofed));
        let guest_host = Ipv6Addr::new(0xfd00, 0x1, 0x2, 1, 0, 0, 0, 0x100);
        let f = ipv6_frame(GUEST_MAC, guest_host, ULA_LAN, 64, &[], PROTO_UDP, &l4(40000, 53));
        assert_eq!(v6(&mut fw, GUEST, f), dropped(DropReason::Firewall));
        // The WAN: silent, but neighbor discovery and replies to the
        // router's clients pass.
        let wan_ll = wire::link_local(WAN_MAC);
        let gw = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let f = ipv6_frame(WAN_MAC, gw, wan_ll, 64, &[], PROTO_TCP, &l4(40000, 80));
        assert_eq!(v6(&mut fw, WAN, f), dropped(DropReason::Input));
        let f = ipv6_frame(WAN_MAC, gw, wan_ll, 255, &[], PROTO_ICMPV6, &icmp6(136));
        assert_eq!(v6(&mut fw, WAN, f), LOCAL);
        let f = ipv6_frame(WAN_MAC, gw, wan_ll, 64, &[], PROTO_UDP, &l4(53, 61000));
        assert_eq!(v6(&mut fw, WAN, f), LOCAL);
        assert!(fw.stats.drops[DropReason::Input.index()] >= 3);
    }

    #[test]
    fn ipv6_neighbor_discovery_and_multicast() {
        let mut fw = router6();
        let ll_host = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 9);
        let all_routers = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
        let solicited = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 1);
        let mcast = [0x33, 0x33, 0, 0, 0, 2];
        // RS and NS with hop limit 255: local; 254: invalid (off-link).
        let rs = ipv6_frame(mcast, ll_host, all_routers, 255, &[], PROTO_ICMPV6, &icmp6(133));
        assert_eq!(v6(&mut fw, GUEST, rs), LOCAL); // the guest zone too
        let rs = ipv6_frame(mcast, ll_host, all_routers, 254, &[], PROTO_ICMPV6, &icmp6(133));
        assert_eq!(v6(&mut fw, LAN, rs), dropped(DropReason::Invalid));
        let ns = ipv6_frame(mcast, ll_host, solicited, 255, &[], PROTO_ICMPV6, &icmp6(135));
        assert_eq!(v6(&mut fw, LAN, ns), LOCAL);
        // MLD reports to ff02::16: not needed; a query to all nodes: local.
        let mld = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);
        let r = ipv6_frame(mcast, ll_host, mld, 1, &[], PROTO_ICMPV6, &icmp6(143));
        assert_eq!(v6(&mut fw, LAN, r), dropped(DropReason::NotForUs));
        let all = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let q = ipv6_frame(mcast, ll_host, all, 1, &[], PROTO_ICMPV6, &icmp6(130));
        assert_eq!(v6(&mut fw, LAN, q), LOCAL);
        // mDNS on ff02::fb: the zone's mdns service decides (the guest has none).
        let fb = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
        let m = ipv6_frame(mcast, ll_host, fb, 255, &[], PROTO_UDP, &l4(5353, 5353));
        assert_eq!(v6(&mut fw, LAN, m.clone()), LOCAL);
        assert_eq!(v6(&mut fw, GUEST, m), dropped(DropReason::Input));
        // Other groups and other hosts' unicast: not for us.
        let other = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 2);
        let f = ipv6_frame(mcast, ll_host, other, 1, &[], PROTO_UDP, &l4(1, 2));
        assert_eq!(v6(&mut fw, LAN, f), dropped(DropReason::NotForUs));
        let f = ipv6_frame([2, 9, 9, 9, 9, 9], ll_host, ULA_LAN, 64, &[], PROTO_UDP, &l4(1, 53));
        assert_eq!(v6(&mut fw, LAN, f), dropped(DropReason::NotForUs));
    }

    #[test]
    fn ipv6_rules_without_addresses_apply() {
        let mut fw = router6();
        let p = fw.policy.as_mut().unwrap();
        // An IPv4-only rule (it has a source prefix) and one for any family.
        p.rules = vec![
            Rule { from: Some(2), to: RuleTo::Router, protos: proto::TCP, src: Some((GUEST_HOST, 32)), dst: None, dport: Some((80, 80)), action: Action::Accept },
            Rule { from: Some(2), to: RuleTo::Router, protos: proto::ICMP, src: None, dst: None, dport: None, action: Action::Accept },
        ];
        fw.set_policy(fw.policy.clone());
        let f = ipv6_frame(GUEST_MAC, V6_HOST, ULA_GUEST, 64, &[], PROTO_TCP, &l4(40000, 80));
        assert_eq!(v6(&mut fw, GUEST, f), dropped(DropReason::Input));
        let f = ipv6_frame(GUEST_MAC, V6_HOST, ULA_GUEST, 64, &[], PROTO_ICMPV6, &icmp6(wire::ICMPV6_ECHO_REQUEST));
        assert_eq!(v6(&mut fw, GUEST, f), LOCAL);
        assert_eq!(fw.rule_hits, vec![0, 1]);
    }

    #[test]
    fn ipv6_extension_headers() {
        let mut fw = router6();
        let hbh = (0u8, vec![0u8, 0, 1, 4, 0, 0, 0, 0]); // PadN
        let dest = (60u8, vec![0u8, 0, 1, 4, 0, 0, 0, 0]);
        let rh2 = (43u8, vec![0u8, 0, 2, 0, 0, 0, 0, 0]);
        let rh0 = (43u8, vec![0u8, 0, 0, 0, 0, 0, 0, 0]);
        let frag_first = (44u8, vec![0u8, 0, 0, 1, 0, 0, 0, 7]); // offset 0, M
        let frag_later = (44u8, vec![0u8, 0, 0, 8, 0, 0, 0, 7]); // offset 1
        let web = |ext: &[(u8, Vec<u8>)]| ipv6_frame(GUEST_MAC, V6_HOST, ULA_GUEST, 64, ext, PROTO_TCP, &l4(40000, 80));
        let dns = |ext: &[(u8, Vec<u8>)]| ipv6_frame(GUEST_MAC, V6_HOST, ULA_GUEST, 64, ext, PROTO_UDP, &l4(40000, 53));
        // The walk finds the port behind the headers.
        assert_eq!(v6(&mut fw, GUEST, web(&[hbh.clone(), dest.clone(), rh2.clone()])), dropped(DropReason::Input));
        assert_eq!(v6(&mut fw, GUEST, dns(&[hbh.clone(), dest.clone(), frag_first.clone()])), LOCAL);
        // A later fragment has no port: not a service the guest may use.
        assert_eq!(v6(&mut fw, GUEST, dns(&[frag_later])), dropped(DropReason::Input));
        // Refused: routing type 0, Hop-by-Hop not first, too many headers,
        // a header running past the packet.
        assert_eq!(v6(&mut fw, GUEST, dns(&[rh0])), dropped(DropReason::Malformed));
        assert_eq!(v6(&mut fw, GUEST, dns(&[dest.clone(), hbh.clone()])), dropped(DropReason::Malformed));
        let many: Vec<_> = (0..9).map(|_| dest.clone()).collect();
        assert_eq!(v6(&mut fw, GUEST, dns(&many)), dropped(DropReason::Malformed));
        let mut f = dns(&[dest]);
        f[ETH_HDR + 40 + 1] = 200; // Hdr Ext Len far beyond the packet
        assert_eq!(v6(&mut fw, GUEST, f), dropped(DropReason::Malformed));
        // A payload length beyond the frame, or IPv4 in an IPv6 EtherType.
        let mut f = dns(&[]);
        f[ETH_HDR + 4] = 0xff;
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), dropped(DropReason::Malformed));
        let mut f = dns(&[]);
        f[ETH_HDR] = 0x45;
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), dropped(DropReason::Malformed));
    }

    #[test]
    fn ipv6_link_local_and_solicited_node() {
        assert_eq!(
            wire::link_local([0x52, 0x54, 0, 0x12, 0x34, 0x56]),
            "fe80::5054:ff:fe12:3456".parse::<Ipv6Addr>().unwrap()
        );
        assert!(wire::is_solicited_node("ff02::1:ff12:3456".parse().unwrap()));
        assert!(!wire::is_solicited_node("ff02::1:fe12:3456".parse().unwrap()));
        assert!(!wire::is_solicited_node("ff02::2".parse().unwrap()));
    }

    // ---- IPv6 forwarding (docs/ipv6.md step 2b) --------------------------

    fn a6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }
    const GW6: &str = "2001:db8:ffff::1";
    const H6: &str = "2001:db8:100::10"; // a LAN host
    const G6: &str = "2001:db8:100:1::10"; // a guest host
    const S6: &str = "2001:db8:9::1"; // a server outside

    /// `router6()` with a WAN address and default route, GUAs on LAN and guest.
    fn router6f() -> Forwarder {
        let mut fw = router6();
        fw.set_gua6(WAN, Some((a6("2001:db8:ffff::2"), 64)));
        fw.set_default_route6(Some((WAN, a6(GW6))));
        fw.set_gua6(LAN, Some((a6("2001:db8:100::1"), 64)));
        fw.set_gua6(GUEST, Some((a6("2001:db8:100:1::1"), 64)));
        fw
    }

    fn tcp6(src: &str, dst: &str, sport: u16, dport: u16, flags: u8, mss: Option<u16>) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        wire::put16(&mut t, 0, sport);
        wire::put16(&mut t, 2, dport);
        t[12] = 5 << 4;
        t[13] = flags;
        wire::put16(&mut t, 14, 64240);
        if let Some(m) = mss {
            t.extend_from_slice(&[2, 4, (m >> 8) as u8, m as u8]);
            t[12] = 6 << 4;
        }
        let c = wire::l4_checksum6(a6(src), a6(dst), PROTO_TCP, &t);
        wire::put16(&mut t, 16, c);
        t
    }

    fn udp6(src: &str, dst: &str, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        wire::put16(&mut u, 0, sport);
        wire::put16(&mut u, 2, dport);
        wire::put16(&mut u, 4, (8 + payload.len()) as u16);
        u.extend_from_slice(payload);
        let c = wire::l4_checksum6(a6(src), a6(dst), PROTO_UDP, &u);
        wire::put16(&mut u, 6, c);
        u
    }

    fn echo6(src: &str, dst: &str, kind: u8, id: u16) -> Vec<u8> {
        let mut e = vec![kind, 0, 0, 0, (id >> 8) as u8, id as u8, 0, 1];
        e.extend_from_slice(b"ping6");
        let c = wire::icmpv6_checksum(a6(src), a6(dst), &e);
        wire::put16(&mut e, 2, c);
        e
    }

    fn frame6(mac: Mac, src: &str, dst: &str, hop: u8, proto: u8, l4: &[u8]) -> Vec<u8> {
        ipv6_frame(mac, a6(src), a6(dst), hop, &[], proto, l4)
    }

    /// The forwarded or answered frame's view and its L4 checksum validity.
    fn out6(f: &[u8], len: usize) -> (V6, bool) {
        let f = &f[..len];
        let v = V6::parse(f, ETH_HDR).unwrap();
        let seg = &f[v.l4..v.l4 + v.l4_len];
        let ok = match v.proto {
            PROTO_ICMPV6 => wire::icmpv6_checksum(v.src(f), v.dst(f), seg) == 0,
            p => wire::l4_checksum6(v.src(f), v.dst(f), p, seg) == 0,
        };
        (v, ok)
    }

    #[test]
    fn ipv6_out_and_back_untranslated() {
        let mut fw = router6f();
        let mut f = frame6(LAN_MAC, H6, S6, 64, PROTO_TCP, &tcp6(H6, S6, 40000, 443, wire::TCP_SYN, None));
        let Verdict::Forward6 { egress, next_hop, len, class } = run(&mut fw, 0, LAN, &mut f) else { panic!() };
        assert_eq!((egress, next_hop), (WAN, a6(GW6)));
        let (v, ok) = out6(&f, len);
        assert!(ok, "checksum still valid");
        assert_eq!((v.src(&f), v.dst(&f), v.hop_limit(&f)), (a6(H6), a6(S6), 63));
        assert!(class.flow_hash != 0);
        // The answer comes back to the host directly (on-link).
        let mut r = frame6(WAN_MAC, S6, H6, 60, PROTO_TCP, &tcp6(S6, H6, 443, 40000, wire::TCP_SYN | wire::TCP_ACK, None));
        let Verdict::Forward6 { egress, next_hop, class: rc, .. } = run(&mut fw, 1, WAN, &mut r) else { panic!() };
        assert_eq!((egress, next_hop), (LAN, a6(H6)));
        assert_eq!(rc.flow_hash, class.flow_hash, "one CAKE flow both ways");
        assert_eq!((fw.ct6.len(), fw.ct.len()), (1, 0));
        // Echo out and its reply.
        let mut e = frame6(LAN_MAC, H6, S6, 64, PROTO_ICMPV6, &echo6(H6, S6, 128, 7));
        assert!(matches!(run(&mut fw, 2, LAN, &mut e), Verdict::Forward6 { egress: WAN, .. }));
        let mut e = frame6(WAN_MAC, S6, H6, 60, PROTO_ICMPV6, &echo6(S6, H6, 129, 7));
        assert!(matches!(run(&mut fw, 3, WAN, &mut e), Verdict::Forward6 { egress: LAN, .. }));
    }

    #[test]
    fn ipv6_inbound_refused_and_zones() {
        let mut fw = router6f();
        // New from outside: refused (no rule, wan → lan not allowed).
        let mut f = frame6(WAN_MAC, S6, H6, 60, PROTO_TCP, &tcp6(S6, H6, 5000, 22, wire::TCP_SYN, None));
        assert_eq!(run(&mut fw, 0, WAN, &mut f), dropped(DropReason::Firewall));
        // An unanswered "reply" (no SYN) is no way in either.
        let mut f = frame6(WAN_MAC, S6, H6, 60, PROTO_TCP, &tcp6(S6, H6, 443, 40000, wire::TCP_ACK, None));
        assert_eq!(run(&mut fw, 0, WAN, &mut f), dropped(DropReason::Firewall));
        // Guest → WAN allowed, guest → LAN refused, LAN → guest allowed.
        let mut f = frame6(GUEST_MAC, G6, S6, 64, PROTO_UDP, &udp6(G6, S6, 5000, 53, b"q"));
        assert!(matches!(run(&mut fw, 0, GUEST, &mut f), Verdict::Forward6 { egress: WAN, .. }));
        let mut f = frame6(GUEST_MAC, G6, H6, 64, PROTO_UDP, &udp6(G6, H6, 5000, 53, b"q"));
        assert_eq!(run(&mut fw, 0, GUEST, &mut f), dropped(DropReason::Firewall));
        let mut f = frame6(LAN_MAC, H6, G6, 64, PROTO_UDP, &udp6(H6, G6, 5000, 53, b"q"));
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward6 { egress: GUEST, .. }));
        // A rule without addresses opens wan → lan TCP 22; a new policy
        // without it ends the connection (recheck).
        let mut p = fw.policy.clone().unwrap();
        p.rules = vec![Rule { from: Some(0), to: RuleTo::Zone(1), protos: proto::TCP, src: None, dst: None, dport: Some((22, 22)), action: Action::Accept }];
        fw.set_policy(Some(p));
        let mut f = frame6(WAN_MAC, S6, H6, 60, PROTO_TCP, &tcp6(S6, H6, 5000, 22, wire::TCP_SYN, None));
        assert!(matches!(run(&mut fw, 0, WAN, &mut f), Verdict::Forward6 { egress: LAN, .. }));
        assert_eq!(fw.rule_hits, vec![1]);
        let n = fw.ct6.len();
        let mut p = fw.policy.clone().unwrap();
        p.rules.clear();
        fw.set_policy(Some(p));
        assert_eq!(fw.recheck(), 1);
        assert_eq!(fw.ct6.len(), n - 1);
    }

    #[test]
    fn ipv6_hop_limit_and_packet_too_big() {
        let mut fw = router6f();
        let mut f = frame6(LAN_MAC, H6, S6, 1, PROTO_UDP, &udp6(H6, S6, 5000, 33434, b"x"));
        let Verdict::Forward6 { egress, next_hop, len, .. } = run(&mut fw, 0, LAN, &mut f) else { panic!() };
        assert_eq!((egress, next_hop), (LAN, a6(H6)));
        let (v, ok) = out6(&f, len);
        assert!(ok);
        let m = &f[v.l4..];
        assert_eq!((m[0], m[1], v.src(&f), v.dst(&f)), (3, 0, a6("2001:db8:100::1"), a6(H6)), "Time Exceeded from our GUA");
        assert_eq!(wire::get_ip6(m, 8 + 8), a6(H6), "quotes the packet");
        // Too big for the WAN: Packet Too Big with its MTU.
        fw.set_mtu(WAN, 1400);
        let mut f = frame6(LAN_MAC, H6, S6, 64, PROTO_UDP, &udp6(H6, S6, 5000, 9, &[7u8; 1400]));
        f.resize(f.len() + 100, 0);
        let len_in = f.len() - 164;
        let Verdict::Forward6 { len, .. } = fw.process(0, LAN, &mut f, len_in) else { panic!() };
        let (v, ok) = out6(&f, len);
        assert!(ok && len <= ETH_HDR + 1280);
        assert_eq!((f[v.l4], u32::from_be_bytes(f[v.l4 + 4..v.l4 + 8].try_into().unwrap())), (2, 1400));
        assert_eq!(fw.stats.icmp_errors_sent, 2);
        // An ICMPv6 error never gets one back.
        let mut big = frame6(WAN_MAC, S6, H6, 1, PROTO_ICMPV6, &echo6(S6, H6, 1, 0));
        assert_eq!(run(&mut fw, 0, WAN, &mut big), dropped(DropReason::Invalid));
    }

    #[test]
    fn ipv6_related_error_reaches_the_host() {
        let mut fw = router6f();
        let syn = tcp6(H6, S6, 40000, 443, wire::TCP_SYN, None);
        let mut f = frame6(LAN_MAC, H6, S6, 64, PROTO_TCP, &syn);
        run(&mut fw, 0, LAN, &mut f);
        // A Packet Too Big from a router on the way, quoting our packet.
        let quoted = &frame6(LAN_MAC, H6, S6, 63, PROTO_TCP, &syn)[ETH_HDR..ETH_HDR + 40 + 20];
        let mut ptb = vec![2u8, 0, 0, 0, 0, 0, 0x05, 0x00];
        ptb.extend_from_slice(quoted);
        let hop = "2001:db8:7::1";
        let c = wire::icmpv6_checksum(a6(hop), a6(H6), &ptb);
        wire::put16(&mut ptb, 2, c);
        let mut e = frame6(WAN_MAC, hop, H6, 60, PROTO_ICMPV6, &ptb);
        assert!(matches!(run(&mut fw, 1, WAN, &mut e), Verdict::Forward6 { egress: LAN, .. }));
        // About a flow we never saw: invalid.
        let other = &frame6(LAN_MAC, H6, S6, 63, PROTO_TCP, &tcp6(H6, S6, 40001, 443, wire::TCP_SYN, None))[ETH_HDR..ETH_HDR + 60];
        let mut ptb = vec![2u8, 0, 0, 0, 0, 0, 0x05, 0x00];
        ptb.extend_from_slice(other);
        let c = wire::icmpv6_checksum(a6(hop), a6(H6), &ptb);
        wire::put16(&mut ptb, 2, c);
        let mut e = frame6(WAN_MAC, hop, H6, 60, PROTO_ICMPV6, &ptb);
        assert_eq!(run(&mut fw, 1, WAN, &mut e), dropped(DropReason::Invalid));
    }

    #[test]
    fn ipv6_spoofing_and_never_forwarded() {
        let mut fw = router6f();
        // From the WAN with one of our networks' sources.
        let mut f = frame6(WAN_MAC, "2001:db8:100:1::5", S6, 60, PROTO_UDP, &udp6("2001:db8:100:1::5", S6, 1, 2, b""));
        assert_eq!(run(&mut fw, 0, WAN, &mut f), dropped(DropReason::Spoofed));
        // From the LAN with a source outside its /64s (another network's, or anything).
        for src in ["2001:db8:100:1::5", "2001:db8:999::5", "fd00:1:2:1::5"] {
            let mut f = frame6(LAN_MAC, src, S6, 64, PROTO_UDP, &udp6(src, S6, 1, 2, b""));
            assert_eq!(run(&mut fw, 0, LAN, &mut f), dropped(DropReason::Spoofed), "{src}");
        }
        // The ULA /64 is the network's too.
        let ula_host = "fd00:1:2::77";
        let mut f = frame6(LAN_MAC, ula_host, S6, 64, PROTO_UDP, &udp6(ula_host, S6, 1, 2, b""));
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward6 { .. }));
        // Off (the lab's negative control): passes.
        fw.lan_antispoof = false;
        let mut f = frame6(LAN_MAC, "2001:db8:999::5", S6, 64, PROTO_UDP, &udp6("2001:db8:999::5", S6, 1, 2, b""));
        assert!(matches!(run(&mut fw, 0, LAN, &mut f), Verdict::Forward6 { .. }));
        // Link-local never leaves its link.
        let mut f = frame6(LAN_MAC, "fe80::9", S6, 64, PROTO_UDP, &udp6("fe80::9", S6, 1, 2, b""));
        assert_eq!(run(&mut fw, 0, LAN, &mut f), dropped(DropReason::Invalid));
        // Nowhere to go without a default route.
        fw.set_default_route6(None);
        let mut f = frame6(LAN_MAC, H6, S6, 64, PROTO_UDP, &udp6(H6, S6, 1, 2, b""));
        assert_eq!(run(&mut fw, 0, LAN, &mut f), dropped(DropReason::NoRoute));
    }

    #[test]
    fn ipv6_mss_clamped_and_later_fragments_dropped() {
        let mut fw = router6f();
        fw.set_mtu(WAN, 1400);
        let mut f = frame6(LAN_MAC, H6, S6, 64, PROTO_TCP, &tcp6(H6, S6, 40000, 443, wire::TCP_SYN, Some(1440)));
        let Verdict::Forward6 { len, .. } = run(&mut fw, 0, LAN, &mut f) else { panic!() };
        let (v, ok) = out6(&f, len);
        assert!(ok, "checksum after the clamp");
        assert_eq!(wire::get16(&f, v.l4 + 22), 1340, "MTU 1400 − 60");
        let later = (44u8, vec![0u8, 0, 0, 8, 0, 0, 0, 7]);
        let mut f = ipv6_frame(LAN_MAC, a6(H6), a6(S6), 64, &[later], PROTO_UDP, &[0u8; 16]);
        assert_eq!(run(&mut fw, 0, LAN, &mut f), dropped(DropReason::Fragment));
    }

    #[test]
    fn ipv6_both_directions_share_a_shard() {
        let hints = ShardHints::default();
        for i in 0..200u16 {
            let out = frame6(LAN_MAC, H6, S6, 64, PROTO_TCP, &tcp6(H6, S6, 40000 + i, 443, wire::TCP_ACK, None));
            let back = frame6(WAN_MAC, S6, H6, 60, PROTO_TCP, &tcp6(S6, H6, 443, 40000 + i, wire::TCP_ACK, None));
            let (a, b) = (shard_of(Role::Lan, &out, 16, 42, &hints), shard_of(Role::Wan, &back, 16, 42, &hints));
            assert_eq!(a, b, "flow {i}");
        }
        let spread: alloc::collections::BTreeSet<usize> = (0..200u16)
            .map(|i| shard_of(Role::Lan, &frame6(LAN_MAC, H6, S6, 64, PROTO_UDP, &udp6(H6, S6, 1000 + i, 53, b"")), 16, 42, &hints))
            .collect();
        assert!(spread.len() > 8, "spread over the shards: {spread:?}");
    }

    #[test]
    fn ipv6_fragments_follow_the_first() {
        let mut fw = router6f();
        // First fragment of a UDP datagram out: forwarded and recorded.
        let first_hdr = (44u8, vec![0u8, 0, 0, 1, 0, 0, 0x12, 0x34]); // offset 0, M, id 0x1234
        let mut f = ipv6_frame(LAN_MAC, a6(H6), a6(S6), 64, &[first_hdr], PROTO_UDP, &udp6(H6, S6, 5000, 53, &[1u8; 64]));
        let Verdict::Forward6 { egress, next_hop, .. } = run(&mut fw, 0, LAN, &mut f) else { panic!() };
        assert_eq!((egress, next_hop), (WAN, a6(GW6)));
        let Some(d @ frag::Decision::V6(_)) = fw.take_fragment() else { panic!("no decision") };
        assert_eq!(fw.take_fragment(), None, "taken");
        // A later one goes the same way, one hop less.
        let later_hdr = (44u8, vec![0u8, 0, 0, 9 << 3, 0, 0, 0x12, 0x34]); // offset 9, last
        let mut l = ipv6_frame(LAN_MAC, a6(H6), a6(S6), 64, core::slice::from_ref(&later_hdr), PROTO_UDP, &[2u8; 32]);
        let n = l.len() - 64;
        let Verdict::Forward6 { egress, len, .. } = fw.forward_fragment(1, LAN, &mut l, n, &d) else { panic!() };
        assert_eq!(egress, WAN);
        assert_eq!(V6::parse(&l[..len], ETH_HDR).unwrap().hop_limit(&l), 63);
        // Without the connection (it ended), or with fragments off: dropped.
        fw.ct6.remove(0);
        let mut l2 = ipv6_frame(LAN_MAC, a6(H6), a6(S6), 64, &[later_hdr], PROTO_UDP, &[2u8; 32]);
        assert_eq!(fw.forward_fragment(2, LAN, &mut l2, n, &d), dropped(DropReason::Fragment));
        fw.fragments = false;
        let first_hdr = (44u8, vec![0u8, 0, 0, 1, 0, 0, 0x12, 0x35]);
        let mut f = ipv6_frame(LAN_MAC, a6(H6), a6(S6), 64, &[first_hdr], PROTO_UDP, &udp6(H6, S6, 5001, 53, &[1u8; 64]));
        assert_eq!(run(&mut fw, 3, LAN, &mut f), dropped(DropReason::Fragment));
        // An atomic fragment is a whole packet.
        fw.fragments = true;
        let atomic = (44u8, vec![0u8, 0, 0, 0, 0, 0, 0x12, 0x36]);
        let mut f = ipv6_frame(LAN_MAC, a6(H6), a6(S6), 64, &[atomic], PROTO_UDP, &udp6(H6, S6, 5002, 53, b"q"));
        assert!(matches!(run(&mut fw, 4, LAN, &mut f), Verdict::Forward6 { .. }));
        assert_eq!(fw.take_fragment(), None);
    }

    #[test]
    fn ipv6_wan_dhcpv6_client_and_prefix_change() {
        let mut fw = router6f();
        // The DHCPv6 server answers the router's client on port 546.
        let isp_ll = "fe80::99";
        let wan_ll = alloc::format!("{}", wire::link_local(WAN_MAC));
        let mut f = frame6(WAN_MAC, isp_ll, &wan_ll, 255, PROTO_UDP, &udp6(isp_ll, &wan_ll, 547, 546, b"reply"));
        assert_eq!(run(&mut fw, 0, WAN, &mut f), LOCAL);
        let mut f = frame6(WAN_MAC, isp_ll, &wan_ll, 255, PROTO_UDP, &udp6(isp_ll, &wan_ll, 547, 545, b"no"));
        assert_eq!(run(&mut fw, 0, WAN, &mut f), dropped(DropReason::Input));
        // A connection in the LAN's global /64, then a new prefix there: gone.
        let mut f = frame6(LAN_MAC, H6, S6, 64, PROTO_UDP, &udp6(H6, S6, 5000, 53, b"q"));
        run(&mut fw, 0, LAN, &mut f);
        let mut u = frame6(LAN_MAC, "fd00:1:2::77", S6, 64, PROTO_UDP, &udp6("fd00:1:2::77", S6, 5000, 53, b"q"));
        run(&mut fw, 0, LAN, &mut u);
        assert_eq!(fw.ct6.len(), 2);
        fw.set_gua6(LAN, Some((a6("2001:db8:200::1"), 64)));
        assert_eq!(fw.ct6.len(), 1, "only the ULA one stays");
    }
}
