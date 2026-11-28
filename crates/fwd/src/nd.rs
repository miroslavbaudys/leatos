//! The router's link layer for its own addresses on a link: answers to
//! ARP requests (RFC 826, probes RFC 5227) and Neighbor Solicitations
//! (RFC 4861 §7.2.3–7.2.4, DAD §5.4.3), and claims of its addresses by
//! another MAC. For links whose router stack runs without a link layer
//! (the kernel's `net::local`, docs/lan-neighbors.md): the datapath calls
//! [`answer`] on every ARP / ICMPv6 frame it receives on such a link and
//! sends the reply itself. Learning neighbors stays in
//! [`crate::neigh`] (the datapath snoops the same frames).
//!
//! Sans-IO: a frame (untagged Ethernet) and the link's addresses in, at
//! most one reply frame and a conflict out. No allocation.

use crate::wire::{
    ETH_HDR, ETHERTYPE_ARP, ETHERTYPE_IPV6, Ipv6View, Mac, PROTO_ICMPV6, get_ip6, icmpv6_checksum,
    is_multicast_mac, is_solicited_node, put_ip, put16, set_macs, solicited_node,
};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// ICMPv6 Neighbor Solicitation / Advertisement.
const NS: u8 = 135;
const NA: u8 = 136;
/// NDP options: source / target link-layer address.
const OPT_SLLA: u8 = 1;
const OPT_TLLA: u8 = 2;
/// NA flags (RFC 4861 §4.4).
const NA_ROUTER: u8 = 0x80;
const NA_SOLICITED: u8 = 0x40;
const NA_OVERRIDE: u8 = 0x20;

/// An ARP reply, padded to the minimum Ethernet frame.
pub const ARP_REPLY_LEN: usize = 60;
/// A Neighbor Advertisement with the target link-layer option.
pub const NA_LEN: usize = ETH_HDR + 40 + 32;
/// Room [`answer`] needs for any reply.
pub const REPLY_LEN: usize = NA_LEN;

/// The router's addresses on one link.
#[derive(Clone, Copy, Debug)]
pub struct Link<'a> {
    /// The port's MAC.
    pub mac: Mac,
    /// The link's IPv4 address and prefix length.
    pub v4: Option<(Ipv4Addr, u8)>,
    /// Its IPv6 addresses (link-local, ULA, global).
    pub v6: &'a [Ipv6Addr],
}

/// Switches, for the lab's negative controls.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Answer unicast NS (reachability probes, RFC 4861 §7.3.3). Off: only
    /// those to the solicited-node group, as smoltcp 0.14 (`nd_unicast=0`).
    pub unicast_ns: bool,
    /// The Router flag in NAs (`na_router=0`: cleared, as a host's).
    pub router: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            unicast_ns: true,
            router: true,
        }
    }
}

/// What a frame needs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// A reply of this many bytes is in `out`, to send on the link.
    pub reply: Option<usize>,
    /// Another MAC claims or probes for one of our addresses.
    pub conflict: Option<(IpAddr, Mac)>,
}

/// The reply and conflict for `frame` received on the link `me`; the
/// reply is written to `out`. Anything that is not ARP or ND for one of
/// our addresses gives [`Outcome::default`].
pub fn answer(frame: &[u8], me: &Link<'_>, cfg: Config, out: &mut [u8; REPLY_LEN]) -> Outcome {
    // Never from our own MAC (a loop or a forgery) or a multicast one,
    // whatever the payload says.
    let Some(src) = frame.get(6..12) else {
        return Outcome::default();
    };
    if src == me.mac || src[0] & 1 != 0 {
        return Outcome::default();
    }
    match crate::wire::ethertype(frame) {
        Some(ETHERTYPE_ARP) => arp(frame, me, out),
        Some(ETHERTYPE_IPV6) => nd(frame, me, cfg, out),
        _ => Outcome::default(),
    }
}

fn in_subnet((a, len): (Ipv4Addr, u8), ip: Ipv4Addr) -> bool {
    let m = if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len.min(32))) };
    u32::from(a) & m == u32::from(ip) & m
}

fn arp(frame: &[u8], me: &Link<'_>, out: &mut [u8; REPLY_LEN]) -> Outcome {
    let Some(a) = crate::wire::parse_arp(frame) else {
        return Outcome::default();
    };
    let Some((my_ip, len)) = me.v4 else {
        return Outcome::default();
    };
    if is_multicast_mac(&a.sender_mac) || a.sender_mac == me.mac || a.sender_mac == [0; 6] {
        return Outcome::default();
    }
    let mut o = Outcome::default();
    // Our address claimed (announcement, or a request from it) or probed
    // for (RFC 5227: sender 0.0.0.0) by another MAC.
    let probe = a.sender_ip.is_unspecified();
    if a.sender_ip == my_ip || (probe && a.target_ip == my_ip) {
        o.conflict = Some((IpAddr::V4(my_ip), a.sender_mac));
    }
    // Requests for our address from a neighbor on the subnet, or a probe
    // (answered: it defends the address).
    let sender_ok = probe || (a.sender_ip != my_ip && in_subnet((my_ip, len), a.sender_ip));
    if a.op != 1 || a.target_ip != my_ip || !sender_ok {
        return o;
    }
    let b = &mut out[..ARP_REPLY_LEN];
    b.fill(0);
    set_macs(b, a.sender_mac, me.mac);
    put16(b, 12, ETHERTYPE_ARP);
    let r = &mut b[ETH_HDR..];
    put16(r, 0, 1);
    put16(r, 2, crate::wire::ETHERTYPE_IPV4);
    r[4] = 6;
    r[5] = 4;
    put16(r, 6, 2); // reply
    r[8..14].copy_from_slice(&me.mac);
    put_ip(r, 14, my_ip);
    r[18..24].copy_from_slice(&a.sender_mac);
    put_ip(r, 24, a.sender_ip);
    o.reply = Some(ARP_REPLY_LEN);
    o
}

/// The link-layer address option of `kind` in an ND message's options:
/// `Err` if any option is malformed (length 0 or past the end).
fn lla_option(mut opts: &[u8], kind: u8) -> Result<Option<Mac>, ()> {
    let mut found = None;
    while !opts.is_empty() {
        if opts.len() < 8 {
            return Err(());
        }
        let len = usize::from(opts[1]) * 8;
        if len == 0 || len > opts.len() {
            return Err(());
        }
        if opts[0] == kind && len == 8 && found.is_none() {
            let mut m = [0u8; 6];
            m.copy_from_slice(&opts[2..8]);
            found = Some(m);
        }
        opts = &opts[len..];
    }
    Ok(found)
}

fn nd(frame: &[u8], me: &Link<'_>, cfg: Config, out: &mut [u8; REPLY_LEN]) -> Outcome {
    let ip = ETH_HDR;
    let Some(v) = Ipv6View::parse(frame, ip) else {
        return Outcome::default();
    };
    // RFC 4861 §7.1: no extension headers in front, hop limit 255 (on
    // link), code 0, a valid checksum, at least the fixed part.
    if v.proto != PROTO_ICMPV6 || v.l4 != ip + 40 || v.hop_limit(frame) != 255 || v.l4_len < 24 {
        return Outcome::default();
    }
    let msg = &frame[v.l4..v.l4 + v.l4_len];
    if !matches!(msg[0], NS | NA) || msg[1] != 0 {
        return Outcome::default();
    }
    let (src, dst) = (v.src(frame), v.dst(frame));
    if icmpv6_checksum(src, dst, msg) != 0 {
        return Outcome::default();
    }
    let target = get_ip6(msg, 8);
    if target.is_multicast() || !me.v6.contains(&target) {
        return Outcome::default();
    }
    let mut smac = [0u8; 6];
    smac.copy_from_slice(&frame[6..12]);
    if smac == me.mac || is_multicast_mac(&smac) || me.v6.contains(&src) {
        return Outcome::default();
    }
    let Ok(lla) = lla_option(&msg[24..], if msg[0] == NS { OPT_SLLA } else { OPT_TLLA }) else {
        return Outcome::default();
    };
    if msg[0] == NA {
        // Another node advertising one of our addresses (§7.2.5 would
        // make others follow it).
        let mac = lla.unwrap_or(smac);
        return Outcome {
            reply: None,
            conflict: (mac != me.mac).then_some((IpAddr::V6(target), mac)),
        };
    }
    let dad = src.is_unspecified();
    if dad {
        // §7.1.1: DAD only to the solicited-node group, without SLLA.
        if !is_solicited_node(dst) || dst != solicited_node(target) || lla.is_some() {
            return Outcome::default();
        }
    } else if src.is_multicast() || (dst != solicited_node(target) && !(cfg.unicast_ns && me.v6.contains(&dst))) {
        return Outcome::default();
    }
    // §7.2.4: to the solicitor (its SLLA, else the frame's source MAC);
    // DAD: to all nodes, not solicited (it defends our address).
    let (to_ip, to_mac, flags) = if dad {
        (Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), [0x33, 0x33, 0, 0, 0, 1], NA_OVERRIDE)
    } else {
        (src, lla.unwrap_or(smac), NA_SOLICITED | NA_OVERRIDE)
    };
    if is_multicast_mac(&to_mac) && !dad {
        return Outcome::default();
    }
    let flags = flags | if cfg.router { NA_ROUTER } else { 0 };
    build_na(out, me.mac, to_mac, target, to_ip, flags);
    Outcome {
        reply: Some(NA_LEN),
        conflict: dad.then_some((IpAddr::V6(target), smac)),
    }
}

/// A Neighbor Advertisement for `target` (ours, also the source address)
/// at `mac` to `to_ip` / `to_mac`, with `flags` and the target link-layer
/// option.
fn build_na(out: &mut [u8; REPLY_LEN], mac: Mac, to_mac: Mac, target: Ipv6Addr, to_ip: Ipv6Addr, flags: u8) {
    let o = &mut out[..NA_LEN];
    o.fill(0);
    set_macs(o, to_mac, mac);
    put16(o, 12, ETHERTYPE_IPV6);
    let ip = ETH_HDR;
    o[ip] = 0x60;
    put16(o, ip + 4, 32);
    o[ip + 6] = PROTO_ICMPV6;
    o[ip + 7] = 255;
    o[ip + 8..ip + 24].copy_from_slice(&target.octets());
    o[ip + 24..ip + 40].copy_from_slice(&to_ip.octets());
    let m = ip + 40;
    o[m] = NA;
    o[m + 4] = flags;
    o[m + 8..m + 24].copy_from_slice(&target.octets());
    o[m + 24] = OPT_TLLA;
    o[m + 25] = 1;
    o[m + 26..m + 32].copy_from_slice(&mac);
    let c = icmpv6_checksum(target, to_ip, &o[m..m + 32]);
    put16(o, m + 2, c);
}

#[cfg(test)]
mod tests;
