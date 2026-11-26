//! Minimal Ethernet / ARP / IPv4 / IPv6 / TCP / UDP / ICMP field access and
//! checksum maintenance for the forwarding path.
//!
//! Frames are `&mut [u8]` starting at the Ethernet header. All accessors
//! are bounds-checked by the parse step ([`Ipv4View::parse`]); after a
//! successful parse, field offsets are known to be in range.
//! Checksums are updated incrementally (RFC 1624) when fields change.

use core::net::{Ipv4Addr, Ipv6Addr};

pub const ETH_HDR: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
/// IEEE 802.1Q VLAN tag (C-tag).
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// IEEE 802.1ad service tag (QinQ outer tag).
pub const ETHERTYPE_QINQ: u16 = 0x88a8;
/// Bytes a VLAN tag adds to a frame (TPID + TCI).
pub const VLAN_HDR: usize = 4;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_MLD_QUERY: u8 = 130;
pub const ICMPV6_MLD_REPORT: u8 = 131;
pub const ICMPV6_MLD_DONE: u8 = 132;
pub const ICMPV6_ROUTER_SOLICIT: u8 = 133;
pub const ICMPV6_REDIRECT: u8 = 137;
pub const ICMPV6_MLD2_REPORT: u8 = 143;

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub type Mac = [u8; 6];
pub const BROADCAST_MAC: Mac = [0xff; 6];

pub fn get16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}
pub fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_be_bytes());
}
pub fn get_ip(b: &[u8], off: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[off], b[off + 1], b[off + 2], b[off + 3])
}
pub fn put_ip(b: &mut [u8], off: usize, a: Ipv4Addr) {
    b[off..off + 4].copy_from_slice(&a.octets());
}

pub fn ethertype(frame: &[u8]) -> Option<u16> {
    (frame.len() >= ETH_HDR).then(|| get16(frame, 12))
}
pub fn dst_mac(frame: &[u8]) -> Mac {
    let mut m = [0; 6];
    m.copy_from_slice(&frame[0..6]);
    m
}
pub fn set_macs(frame: &mut [u8], dst: Mac, src: Mac) {
    frame[0..6].copy_from_slice(&dst);
    frame[6..12].copy_from_slice(&src);
}
pub fn is_multicast_mac(m: &Mac) -> bool {
    m[0] & 1 != 0
}

// ---- VLAN (802.1Q) ---------------------------------------------------------------

/// Tag control information: priority (PCP, 0–7) and VLAN ID (0–4095).
pub fn vlan_tci_of(vid: u16, pcp: u8) -> u16 {
    (u16::from(pcp & 7) << 13) | (vid & 0x0fff)
}

/// The TCI of an 802.1Q-tagged frame, `None` if the frame is untagged
/// (or too short for a tag).
pub fn vlan_tci(frame: &[u8]) -> Option<u16> {
    (frame.len() >= ETH_HDR + VLAN_HDR && get16(frame, 12) == ETHERTYPE_VLAN)
        .then(|| get16(frame, 14))
}

/// What to do with a received frame, given the port's VLAN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VlanRx {
    /// Process it; `strip`: remove its tag first ([`vlan_remove`]).
    Accept { strip: bool },
    /// Wrong or missing tag, or stacked tags.
    Drop,
}

/// Ingress rule for a port tagged with VLAN `want` (`None`: untagged).
/// A tagged port accepts only frames with its VID; an untagged port
/// accepts untagged and priority-tagged (VID 0) frames. Stacked tags
/// (QinQ, or 802.1Q in 802.1Q) are dropped everywhere.
pub fn vlan_rx(frame: &[u8], want: Option<u16>) -> VlanRx {
    let Some(et) = ethertype(frame) else {
        return VlanRx::Accept { strip: false }; // runt: the forwarder drops it
    };
    if et == ETHERTYPE_QINQ {
        return VlanRx::Drop;
    }
    if et != ETHERTYPE_VLAN {
        return match want {
            None => VlanRx::Accept { strip: false },
            Some(_) => VlanRx::Drop,
        };
    }
    // MACs + tag + the inner EtherType.
    if frame.len() < ETH_HDR + VLAN_HDR {
        return VlanRx::Drop;
    }
    let (tci, inner) = (get16(frame, 14), get16(frame, 16));
    if inner == ETHERTYPE_VLAN || inner == ETHERTYPE_QINQ {
        return VlanRx::Drop;
    }
    if tci & 0x0fff == want.unwrap_or(0) {
        VlanRx::Accept { strip: true }
    } else {
        VlanRx::Drop
    }
}

/// Remove the tag in place: the MAC addresses move 4 bytes towards the
/// payload. The frame then starts at `frame[VLAN_HDR..]`.
pub fn vlan_remove(frame: &mut [u8]) {
    frame.copy_within(0..12, VLAN_HDR);
}

/// Insert a tag in place. `buf` is the frame with [`VLAN_HDR`] free bytes
/// in front of it (`buf[VLAN_HDR..]` = the untagged frame); afterwards
/// `buf` is the tagged frame.
pub fn vlan_insert(buf: &mut [u8], tci: u16) {
    buf.copy_within(VLAN_HDR..VLAN_HDR + 12, 0);
    put16(buf, 12, ETHERTYPE_VLAN);
    put16(buf, 14, tci);
}

// ---- checksums ------------------------------------------------------------------

/// One's-complement sum of `data` (no final inversion).
fn sum(data: &[u8], mut acc: u32) -> u32 {
    let (chunks, rest) = data.as_chunks::<2>();
    for c in chunks {
        acc += u16::from_be_bytes(*c) as u32;
    }
    if let [last] = rest {
        acc += (*last as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// Internet checksum of `data`.
pub fn checksum(data: &[u8]) -> u16 {
    !fold(sum(data, 0))
}

/// RFC 1624: new checksum after a 16-bit field changed from `old` to `new`.
pub fn csum_update16(csum: u16, old: u16, new: u16) -> u16 {
    !fold((!csum) as u32 + (!old) as u32 + new as u32)
}

/// New checksum after a 32-bit field (an address) changed.
pub fn csum_update_ip(csum: u16, old: Ipv4Addr, new: Ipv4Addr) -> u16 {
    let (o, n) = (old.octets(), new.octets());
    let c = csum_update16(
        csum,
        u16::from_be_bytes([o[0], o[1]]),
        u16::from_be_bytes([n[0], n[1]]),
    );
    csum_update16(
        c,
        u16::from_be_bytes([o[2], o[3]]),
        u16::from_be_bytes([n[2], n[3]]),
    )
}

/// TCP/UDP checksum over pseudo header + segment (for building packets / tests).
pub fn l4_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut acc = sum(&src.octets(), 0);
    acc = sum(&dst.octets(), acc);
    acc += proto as u32 + segment.len() as u32;
    !fold(sum(segment, acc))
}

/// TCP/UDP checksum over the IPv6 pseudo-header (RFC 8200 §8.1).
pub fn l4_checksum6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut acc = sum(&src.octets(), 0);
    acc = sum(&dst.octets(), acc);
    acc = sum(&(segment.len() as u32).to_be_bytes(), acc);
    acc += proto as u32;
    !fold(sum(segment, acc))
}

// ---- IPv4 ------------------------------------------------------------------------

/// Validated offsets into an IPv6-in-Ethernet frame, past the extension
/// headers (RFC 8200 §4): Hop-by-Hop (first only, skipped, not
/// processed: RFC 9098), Destination Options, Routing (type 0 refused,
/// RFC 5095) and Fragment. At most [`Self::MAX_EXT_HEADERS`] of them in
/// [`Self::MAX_EXT_BYTES`]; anything else ends the walk as the upper-layer
/// protocol (`proto`).
#[derive(Clone, Copy, Debug)]
pub struct Ipv6View {
    /// Offset of the IPv6 header.
    pub ip: usize,
    /// Upper-layer protocol (the last Next Header).
    pub proto: u8,
    /// Offset of the upper-layer header.
    pub l4: usize,
    /// Bytes from `l4` to the end of the packet.
    pub l4_len: usize,
    /// A Fragment header that is not atomic (offset or M set).
    pub is_fragment: bool,
    /// Fragment offset in 8-byte units (0: no fragment, or the first).
    pub frag_offset: u16,
    /// The Fragment header's identification (0 without one).
    pub frag_id: u32,
}

impl Ipv6View {
    pub const MAX_EXT_HEADERS: usize = 8;
    pub const MAX_EXT_BYTES: usize = 256;

    /// Parse the IPv6 header at `ip` (14 for plain Ethernet). Checks the
    /// version and the payload length (no jumbograms) and walks the
    /// extension headers.
    pub fn parse(frame: &[u8], ip: usize) -> Option<Self> {
        let h = frame.get(ip..ip + 40)?;
        if h[0] >> 4 != 6 {
            return None;
        }
        let end = ip + 40 + get16(h, 4) as usize;
        if end > frame.len() {
            return None;
        }
        let (mut nh, mut off, mut count) = (h[6], ip + 40, 0);
        let (mut is_fragment, mut frag_offset, mut frag_id) = (false, 0, 0);
        loop {
            let len = match nh {
                0 if count == 0 => (*frame.get(off + 1).filter(|_| off + 2 <= end)? as usize + 1) * 8,
                0 => return None,
                60 => (*frame.get(off + 1).filter(|_| off + 2 <= end)? as usize + 1) * 8,
                43 => {
                    if off + 4 > end || frame[off + 2] == 0 {
                        return None;
                    }
                    (frame[off + 1] as usize + 1) * 8
                }
                44 => {
                    if off + 8 > end {
                        return None;
                    }
                    let fo = get16(frame, off + 2);
                    frag_offset = fo >> 3;
                    is_fragment = frag_offset != 0 || fo & 1 != 0;
                    frag_id = u32::from_be_bytes([frame[off + 4], frame[off + 5], frame[off + 6], frame[off + 7]]);
                    8
                }
                _ => break,
            };
            if off + len > end {
                return None;
            }
            nh = frame[off];
            off += len;
            count += 1;
            if count > Self::MAX_EXT_HEADERS || off - (ip + 40) > Self::MAX_EXT_BYTES {
                return None;
            }
            if frag_offset != 0 {
                break; // a later fragment: no upper-layer header here
            }
        }
        Some(Self {
            ip,
            proto: nh,
            l4: off,
            l4_len: end - off,
            is_fragment,
            frag_offset,
            frag_id,
        })
    }

    pub fn src(&self, f: &[u8]) -> Ipv6Addr {
        get_ip6(f, self.ip + 8)
    }
    pub fn dst(&self, f: &[u8]) -> Ipv6Addr {
        get_ip6(f, self.ip + 24)
    }
    pub fn hop_limit(&self, f: &[u8]) -> u8 {
        f[self.ip + 7]
    }
    /// The upper-layer header is in this packet (not a later fragment).
    pub fn has_l4(&self) -> bool {
        self.frag_offset == 0
    }
    pub fn traffic_class(&self, f: &[u8]) -> u8 {
        (f[self.ip] << 4) | (f[self.ip + 1] >> 4)
    }
    /// Header + payload.
    pub fn total_len(&self) -> usize {
        self.l4 + self.l4_len - self.ip
    }
    /// One hop less (the caller checked it is above 1); no checksum.
    pub fn dec_hop_limit(&self, f: &mut [u8]) {
        f[self.ip + 7] -= 1;
    }
}

pub fn get_ip6(b: &[u8], off: usize) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[off..off + 16]);
    Ipv6Addr::from(a)
}

/// The link-local address of an interface with `mac` (modified EUI-64,
/// RFC 4291 §2.5.1).
pub fn link_local(mac: Mac) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[8] = mac[0] ^ 0x02;
    a[9] = mac[1];
    a[10] = mac[2];
    a[11] = 0xff;
    a[12] = 0xfe;
    a[13] = mac[3];
    a[14] = mac[4];
    a[15] = mac[5];
    Ipv6Addr::from(a)
}

/// ICMPv6 checksum of `msg` (its checksum field included as it is) between
/// `src` and `dst` (RFC 8200 §8.1 pseudo-header).
pub fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, msg: &[u8]) -> u16 {
    let mut acc = sum(&src.octets(), 0);
    acc = sum(&dst.octets(), acc);
    acc = sum(&(msg.len() as u32).to_be_bytes(), acc);
    acc = sum(&[0, 0, 0, PROTO_ICMPV6], acc);
    !fold(sum(msg, acc))
}

/// The solicited-node group of `a`: `ff02::1:ff` + its last 24 bits.
pub fn solicited_node(a: Ipv6Addr) -> Ipv6Addr {
    let o = a.octets();
    Ipv6Addr::from(u128::from(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0)) | u128::from(u32::from_be_bytes([0, o[13], o[14], o[15]])))
}

/// Bytes of a neighbor solicitation frame ([`build_ns`]).
pub const NS_LEN: usize = ETH_HDR + 40 + 32;

/// A Neighbor Solicitation for `target` from `src_ip` (the router's
/// link-local address) at `src_mac`, to the target's solicited-node group
/// (RFC 4861 §7.2.2), with the source link-layer option.
pub fn build_ns(out: &mut [u8; NS_LEN], src_mac: Mac, src_ip: Ipv6Addr, target: Ipv6Addr) {
    let group = solicited_node(target);
    out.fill(0);
    out[0..2].copy_from_slice(&[0x33, 0x33]);
    out[2..6].copy_from_slice(&group.octets()[12..16]);
    out[6..12].copy_from_slice(&src_mac);
    put16(out, 12, ETHERTYPE_IPV6);
    let ip = ETH_HDR;
    out[ip] = 0x60;
    put16(out, ip + 4, 32);
    out[ip + 6] = PROTO_ICMPV6;
    out[ip + 7] = 255;
    out[ip + 8..ip + 24].copy_from_slice(&src_ip.octets());
    out[ip + 24..ip + 40].copy_from_slice(&group.octets());
    let m = ip + 40;
    out[m] = 135;
    out[m + 8..m + 24].copy_from_slice(&target.octets());
    out[m + 24] = 1;
    out[m + 25] = 1;
    out[m + 26..m + 32].copy_from_slice(&src_mac);
    let c = icmpv6_checksum(src_ip, group, &out[m..m + 32]);
    put16(out, m + 2, c);
}

/// Bytes of a router solicitation frame ([`build_rs`]).
pub const RS_LEN: usize = ETH_HDR + 40 + 16;

/// A Router Solicitation from `src_ip` (the WAN's link-local address) at
/// `src_mac` to all routers (RFC 4861 §6.3.7), with the source
/// link-layer option if `lla` (not on PPP: no link-layer address).
/// Returns the frame's length.
pub fn build_rs(out: &mut [u8; RS_LEN], src_mac: Mac, src_ip: Ipv6Addr, lla: bool) -> usize {
    let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
    out.fill(0);
    out[0..6].copy_from_slice(&[0x33, 0x33, 0, 0, 0, 2]);
    out[6..12].copy_from_slice(&src_mac);
    put16(out, 12, ETHERTYPE_IPV6);
    let ip = ETH_HDR;
    out[ip] = 0x60;
    let icmp_len = if lla { 16 } else { 8 };
    put16(out, ip + 4, icmp_len as u16);
    out[ip + 6] = PROTO_ICMPV6;
    out[ip + 7] = 255;
    out[ip + 8..ip + 24].copy_from_slice(&src_ip.octets());
    out[ip + 24..ip + 40].copy_from_slice(&dst.octets());
    let m = ip + 40;
    out[m] = ICMPV6_ROUTER_SOLICIT;
    if lla {
        out[m + 8] = 1;
        out[m + 9] = 1;
        out[m + 10..m + 16].copy_from_slice(&src_mac);
    }
    let c = icmpv6_checksum(src_ip, dst, &out[m..m + icmp_len]);
    put16(out, m + 2, c);
    m + icmp_len
}

/// What a neighbor discovery message tells about a neighbor (RFC 4861
/// §7.2.5, §7.2.3, §6.3.4): a Neighbor Advertisement its target's MAC (the
/// target link-layer option), a Solicitation or a Router Advertisement
/// its sender's (the source link-layer option). Only with hop limit 255
/// (on-link) and a valid checksum; no extension headers.
pub fn parse_nd(frame: &[u8]) -> Option<(Ipv6Addr, Mac)> {
    let ip = ETH_HDR;
    let v = Ipv6View::parse(frame, ip)?;
    if v.proto != PROTO_ICMPV6 || v.l4 != ip + 40 || v.hop_limit(frame) != 255 || v.l4_len < 8 {
        return None;
    }
    let msg = &frame[v.l4..v.l4 + v.l4_len];
    if icmpv6_checksum(v.src(frame), v.dst(frame), msg) != 0 {
        return None;
    }
    let (who, opts_at, want) = match msg[0] {
        135 if msg.len() >= 24 => (v.src(frame), 24, 1), // NS: the sender
        136 if msg.len() >= 24 => (get_ip6(msg, 8), 24, 2), // NA: the target
        134 if msg.len() >= 16 => (v.src(frame), 16, 1), // RA: the router
        _ => return None,
    };
    if who.is_unspecified() || who.is_multicast() {
        return None;
    }
    let mut o = &msg[opts_at..];
    while o.len() >= 8 {
        let len = o[1] as usize * 8;
        if len == 0 || len > o.len() {
            return None;
        }
        if o[0] == want && len == 8 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&o[2..8]);
            return (!is_multicast_mac(&mac)).then_some((who, mac));
        }
        o = &o[len..];
    }
    None
}

/// `ff02::1:ffXX:XXXX` (RFC 4291 §2.7.1).
pub fn is_solicited_node(a: Ipv6Addr) -> bool {
    let o = a.octets();
    o[..11] == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0] && o[11] == 1 && o[12] == 0xff
}

/// Validated offsets into an IPv4-in-Ethernet frame.
#[derive(Clone, Copy, Debug)]
pub struct Ipv4View {
    /// Offset of the IPv4 header.
    pub ip: usize,
    pub ihl: usize,
    pub total_len: usize,
    pub proto: u8,
    /// Offset of the L4 header (= ip + ihl).
    pub l4: usize,
    /// Bytes of L4 header + payload present (total_len - ihl).
    pub l4_len: usize,
    pub is_fragment: bool,
    /// Fragment offset in 8-byte units (0: whole datagram or its first
    /// fragment).
    pub frag_offset: u16,
}

impl Ipv4View {
    /// Parse the IPv4 header at `ip` (14 for plain Ethernet). Checks version,
    /// IHL, lengths and the header checksum.
    pub fn parse(frame: &[u8], ip: usize) -> Option<Self> {
        let h = frame.get(ip..ip + 20)?;
        if h[0] >> 4 != 4 {
            return None;
        }
        let ihl = ((h[0] & 0xf) as usize) * 4;
        let total_len = get16(h, 2) as usize;
        if ihl < 20 || total_len < ihl || frame.len() < ip + total_len {
            return None;
        }
        if checksum(&frame[ip..ip + ihl]) != 0 {
            return None;
        }
        let frag = get16(h, 6);
        Some(Self {
            ip,
            ihl,
            total_len,
            proto: h[9],
            l4: ip + ihl,
            l4_len: total_len - ihl,
            is_fragment: frag & 0x2000 != 0 || frag & 0x1fff != 0,
            frag_offset: frag & 0x1fff,
        })
    }

    pub fn src(&self, f: &[u8]) -> Ipv4Addr {
        get_ip(f, self.ip + 12)
    }
    pub fn dst(&self, f: &[u8]) -> Ipv4Addr {
        get_ip(f, self.ip + 16)
    }
    pub fn ttl(&self, f: &[u8]) -> u8 {
        f[self.ip + 8]
    }
    pub fn tos(&self, f: &[u8]) -> u8 {
        f[self.ip + 1]
    }
    /// Don't Fragment set: too large for the next link means an ICMP
    /// "fragmentation needed" back to the sender (RFC 1191).
    pub fn dont_fragment(&self, f: &[u8]) -> bool {
        f[self.ip + 6] & 0x40 != 0
    }
    fn ip_csum(&self, f: &[u8]) -> u16 {
        get16(f, self.ip + 10)
    }

    /// Decrement TTL (caller checked TTL > 1), updating the header checksum.
    pub fn dec_ttl(&self, f: &mut [u8]) {
        let old = get16(f, self.ip + 8);
        f[self.ip + 8] -= 1;
        let new = get16(f, self.ip + 8);
        let c = csum_update16(self.ip_csum(f), old, new);
        put16(f, self.ip + 10, c);
    }

    /// Offset of the L4 checksum field, if this protocol has one we maintain.
    fn l4_csum_off(&self) -> Option<usize> {
        match self.proto {
            PROTO_TCP if self.l4_len >= 20 => Some(self.l4 + 16),
            PROTO_UDP if self.l4_len >= 8 => Some(self.l4 + 6),
            _ => None,
        }
    }

    /// Rewrite the source or destination address (+ IP and L4 checksums).
    pub fn set_addr(&self, f: &mut [u8], is_src: bool, new: Ipv4Addr) {
        let off = self.ip + if is_src { 12 } else { 16 };
        let old = get_ip(f, off);
        if old == new {
            return;
        }
        put_ip(f, off, new);
        let c = csum_update_ip(self.ip_csum(f), old, new);
        put16(f, self.ip + 10, c);
        if let Some(co) = self.l4_csum_off() {
            let cur = get16(f, co);
            if !(self.proto == PROTO_UDP && cur == 0) {
                let mut c = csum_update_ip(cur, old, new);
                if self.proto == PROTO_UDP && c == 0 {
                    c = 0xffff;
                }
                put16(f, co, c);
            }
        }
    }

    /// Rewrite the source or destination address in the IP header only:
    /// a fragment after the first carries no L4 header (its checksum,
    /// in the first fragment, already covers the new address).
    pub fn set_ip_addr(&self, f: &mut [u8], is_src: bool, new: Ipv4Addr) {
        let off = self.ip + if is_src { 12 } else { 16 };
        let old = get_ip(f, off);
        if old == new {
            return;
        }
        put_ip(f, off, new);
        let c = csum_update_ip(self.ip_csum(f), old, new);
        put16(f, self.ip + 10, c);
    }

    /// The IP identification field (fragments of one datagram share it).
    pub fn id(&self, f: &[u8]) -> u16 {
        get16(f, self.ip + 4)
    }

    /// Rewrite the source or destination port (TCP/UDP) or the echo
    /// identifier (ICMP; `is_src` ignored), updating the L4 checksum.
    pub fn set_port(&self, f: &mut [u8], is_src: bool, new: u16) {
        let (off, csum_off) = match self.proto {
            PROTO_TCP | PROTO_UDP => (self.l4 + if is_src { 0 } else { 2 }, self.l4_csum_off()),
            PROTO_ICMP => (self.l4 + 4, Some(self.l4 + 2)),
            _ => return,
        };
        let old = get16(f, off);
        if old == new {
            return;
        }
        put16(f, off, new);
        if let Some(co) = csum_off {
            let cur = get16(f, co);
            if !(self.proto == PROTO_UDP && cur == 0) {
                let mut c = csum_update16(cur, old, new);
                if self.proto == PROTO_UDP && c == 0 {
                    c = 0xffff;
                }
                if self.proto == PROTO_ICMP && c == 0 {
                    // 0x0000 is right only if the message sums to 0xffff; an
                    // all-zero one needs 0xffff, which the incremental update
                    // cannot tell apart (no pseudo-header in ICMP). Rare:
                    // recount.
                    put16(f, co, 0);
                    let end = (self.l4 + self.l4_len).min(f.len());
                    c = checksum(&f[self.l4..end]);
                }
                put16(f, co, c);
            }
        }
    }
}

/// TCP option: maximum segment size.
const TCP_OPT_MSS: u8 = 2;

/// Lower the MSS option of a TCP SYN to at most `max` (RFC 879: the
/// largest segment the sender of the SYN accepts), updating the TCP
/// checksum. Returns whether it changed. Segments without an MSS option
/// are left alone (their default, 536, is already small).
pub fn clamp_mss(f: &mut [u8], v: &Ipv4View, max: u16) -> bool {
    v.proto == PROTO_TCP && clamp_mss_at(f, v.l4, v.l4_len, max)
}

/// [`clamp_mss`] for the TCP segment at `l4` (`l4_len` bytes present):
/// for IPv6 too (the checksum update does not involve the pseudo-header).
pub fn clamp_mss_at(f: &mut [u8], l4: usize, l4_len: usize, max: u16) -> bool {
    if l4_len < 20 {
        return false;
    }
    let doff = ((f[l4 + 12] >> 4) as usize) * 4;
    if doff < 20 || doff > l4_len {
        return false;
    }
    let (mut i, end) = (l4 + 20, l4 + doff);
    while i < end {
        match f[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let Some(&len) = f.get(i + 1).filter(|_| i + 1 < end) else {
                    break;
                };
                let len = len as usize;
                if len < 2 || i + len > end {
                    break;
                }
                if kind == TCP_OPT_MSS && len == 4 {
                    let old = get16(f, i + 2);
                    if old <= max {
                        return false;
                    }
                    put16(f, i + 2, max);
                    // At an odd offset from the segment start the field
                    // straddles two checksum words: its bytes count
                    // swapped (RFC 1071 byte-order independence).
                    let (o, n) = if (i + 2 - l4).is_multiple_of(2) {
                        (old, max)
                    } else {
                        (old.swap_bytes(), max.swap_bytes())
                    };
                    let c = csum_update16(get16(f, l4 + 16), o, n);
                    put16(f, l4 + 16, c);
                    return true;
                }
                i += len;
            }
        }
    }
    false
}

// ---- ARP ----------------------------------------------------------------------------

/// Parsed Ethernet/IPv4 ARP packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sender_mac: Mac,
    pub sender_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
}

pub fn parse_arp(frame: &[u8]) -> Option<Arp> {
    let a = frame.get(ETH_HDR..ETH_HDR + 28)?;
    if get16(a, 0) != 1 || get16(a, 2) != ETHERTYPE_IPV4 || a[4] != 6 || a[5] != 4 {
        return None;
    }
    let mut sender_mac = [0; 6];
    sender_mac.copy_from_slice(&a[8..14]);
    Some(Arp {
        op: get16(a, 6),
        sender_mac,
        sender_ip: get_ip(a, 14),
        target_ip: get_ip(a, 24),
    })
}

/// Write an ARP request (who-has `target`) into `buf`; returns the length.
pub fn build_arp_request(
    buf: &mut [u8],
    src_mac: Mac,
    src_ip: Ipv4Addr,
    target: Ipv4Addr,
) -> usize {
    let len = ETH_HDR + 28;
    let b = &mut buf[..len];
    set_macs(b, BROADCAST_MAC, src_mac);
    put16(b, 12, ETHERTYPE_ARP);
    let a = &mut b[ETH_HDR..];
    put16(a, 0, 1);
    put16(a, 2, ETHERTYPE_IPV4);
    a[4] = 6;
    a[5] = 4;
    put16(a, 6, 1); // request
    a[8..14].copy_from_slice(&src_mac);
    put_ip(a, 14, src_ip);
    a[18..24].fill(0);
    put_ip(a, 24, target);
    len
}

/// An ICMP or ICMPv6 echo request or reply (ping) in an Ethernet frame,
/// with or without one 802.1Q tag: the sparse flow whose queue delay the
/// qdisc statistics keep apart (`net::device::Delay`). IPv6 only without
/// extension headers.
pub fn is_echo(frame: &[u8]) -> bool {
    let (mut t, mut ip) = match ethertype(frame) {
        Some(t) => (t, ETH_HDR),
        None => return false,
    };
    if t == ETHERTYPE_VLAN {
        if frame.len() < ETH_HDR + 4 {
            return false;
        }
        (t, ip) = (get16(frame, ETH_HDR + 2), ETH_HDR + 4);
    }
    match t {
        ETHERTYPE_IPV4 => {
            let Some(&vihl) = frame.get(ip) else { return false };
            let l4 = ip + ((vihl & 0x0f) as usize) * 4;
            vihl >> 4 == 4
                && frame.get(ip + 9) == Some(&PROTO_ICMP)
                && frame.get(l4).is_some_and(|&ty| ty == ICMP_ECHO_REQUEST || ty == ICMP_ECHO_REPLY)
        }
        ETHERTYPE_IPV6 => {
            frame.get(ip).is_some_and(|v| v >> 4 == 6)
                && frame.get(ip + 6) == Some(&PROTO_ICMPV6)
                && frame.get(ip + 40).is_some_and(|&ty| ty == ICMPV6_ECHO_REQUEST || ty == ICMPV6_ECHO_REPLY)
        }
        _ => false,
    }
}

/// IPv4 fragmentation (RFC 791 §2.3): how a packet too large for the
/// next link is cut. Data goes in pieces of a multiple of 8 bytes; each
/// piece gets a copy of the header with its own offset and length. A
/// fragment is split the same way: the pieces keep its place in the
/// datagram, and only the last one keeps its "more fragments" flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitPlan {
    ihl: usize,
    total_len: usize,
    /// Data bytes per piece (a multiple of 8; the last may be shorter).
    chunk: usize,
    /// The packet's own offset (8-byte units) and MF flag.
    offset: u16,
    more: bool,
}

impl SplitPlan {
    /// The plan for the IPv4 packet at [`ETH_HDR`] of `frame` and pieces
    /// of at most `mtu` bytes of IP. `None` if it must not or cannot be
    /// split: DF set, IP options (they would need per-option copying),
    /// already small enough, or `mtu` too small for 8 bytes of data.
    pub fn new(frame: &[u8], mtu: u16) -> Option<Self> {
        let v = Ipv4View::parse(frame, ETH_HDR)?;
        let mtu = usize::from(mtu);
        if v.dont_fragment(frame) || v.ihl != 20 || v.total_len <= mtu || mtu < v.ihl + 8 {
            return None;
        }
        let flags = get16(frame, v.ip + 6);
        Some(SplitPlan {
            ihl: v.ihl,
            total_len: v.total_len,
            chunk: (mtu - v.ihl) / 8 * 8,
            offset: v.frag_offset,
            more: flags & 0x2000 != 0,
        })
    }

    /// How many pieces.
    pub fn pieces(&self) -> usize {
        (self.total_len - self.ihl).div_ceil(self.chunk)
    }

    /// Frame length (Ethernet + IP) of piece `i`.
    pub fn piece_len(&self, i: usize) -> usize {
        let data = self.total_len - self.ihl;
        let len = self.chunk.min(data - i * self.chunk);
        ETH_HDR + self.ihl + len
    }

    /// Write piece `i` (1.., not the first) of `src`'s packet into `out`
    /// (at least [`Self::piece_len`] bytes): Ethernet and IP header copied,
    /// then its data. Returns the frame length.
    pub fn write_piece(&self, src: &[u8], i: usize, out: &mut [u8]) -> usize {
        let len = self.piece_len(i);
        let hdr = ETH_HDR + self.ihl;
        let data = hdr + i * self.chunk;
        out[..hdr].copy_from_slice(&src[..hdr]);
        out[hdr..len].copy_from_slice(&src[data..data + (len - hdr)]);
        self.fix_header(out, i, len);
        len
    }

    /// Cut `f` down to piece 0 in place (after the others were written).
    /// Returns its frame length.
    pub fn truncate_first(&self, f: &mut [u8]) -> usize {
        let len = self.piece_len(0);
        self.fix_header(f, 0, len);
        len
    }

    fn fix_header(&self, f: &mut [u8], i: usize, len: usize) {
        let ip = ETH_HDR;
        let last = i + 1 == self.pieces();
        let more = !last || self.more;
        let off = self.offset + (i * self.chunk / 8) as u16;
        put16(f, ip + 2, (len - ETH_HDR) as u16);
        put16(f, ip + 6, off | if more { 0x2000 } else { 0 });
        put16(f, ip + 10, 0);
        let c = checksum(&f[ip..ip + self.ihl]);
        put16(f, ip + 10, c);
    }
}

#[cfg(test)]
pub mod test_util {
    //! Builders for test frames.
    use super::*;
    use alloc::vec::Vec;

    pub fn ipv4_frame(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, ttl: u8, l4: &[u8]) -> Vec<u8> {
        let mut f = alloc::vec![0u8; ETH_HDR + 20];
        put16(&mut f, 12, ETHERTYPE_IPV4);
        let ip = &mut f[ETH_HDR..];
        ip[0] = 0x45;
        put16(ip, 2, (20 + l4.len()) as u16);
        put16(ip, 6, 0x4000); // DF
        ip[8] = ttl;
        ip[9] = proto;
        put_ip(ip, 12, src);
        put_ip(ip, 16, dst);
        let c = checksum(&ip[..20]);
        put16(ip, 10, c);
        f.extend_from_slice(l4);
        f
    }

    pub fn tcp_segment(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut s = alloc::vec![0u8; 20];
        put16(&mut s, 0, sport);
        put16(&mut s, 2, dport);
        s[12] = 5 << 4;
        s[13] = flags;
        put16(&mut s, 14, 65535);
        s.extend_from_slice(payload);
        let c = l4_checksum(src, dst, PROTO_TCP, &s);
        put16(&mut s, 16, c);
        s
    }

    pub fn udp_datagram(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut s = alloc::vec![0u8; 8];
        put16(&mut s, 0, sport);
        put16(&mut s, 2, dport);
        put16(&mut s, 4, (8 + payload.len()) as u16);
        s.extend_from_slice(payload);
        let c = l4_checksum(src, dst, PROTO_UDP, &s);
        put16(&mut s, 6, if c == 0 { 0xffff } else { c });
        s
    }

    pub fn icmp_echo(kind: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut s = alloc::vec![kind, 0, 0, 0];
        s.extend_from_slice(&id.to_be_bytes());
        s.extend_from_slice(&seq.to_be_bytes());
        s.extend_from_slice(b"pingdata");
        let c = checksum(&s);
        put16(&mut s, 2, c);
        s
    }

    /// Verify every checksum in an IPv4 frame from scratch.
    pub fn checksums_ok(f: &[u8]) -> bool {
        let Some(v) = Ipv4View::parse(f, ETH_HDR) else {
            return false;
        };
        let seg = &f[v.l4..v.l4 + v.l4_len];
        match v.proto {
            PROTO_TCP => l4_checksum(v.src(f), v.dst(f), PROTO_TCP, seg) == 0,
            PROTO_UDP => get16(seg, 6) == 0 || l4_checksum(v.src(f), v.dst(f), PROTO_UDP, seg) == 0,
            PROTO_ICMP => checksum(seg) == 0,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::*;
    use super::*;
    use alloc::vec::Vec;

    const A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
    const B: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const W: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

    #[test]
    fn incremental_checksums_match_full_recompute() {
        for proto in [PROTO_TCP, PROTO_UDP, PROTO_ICMP] {
            let l4 = match proto {
                PROTO_TCP => tcp_segment(A, B, 40000, 80, TCP_SYN, b"hello"),
                PROTO_UDP => udp_datagram(A, B, 5353, 53, b"query"),
                _ => icmp_echo(ICMP_ECHO_REQUEST, 7, 1),
            };
            let mut f = ipv4_frame(A, B, proto, 64, &l4);
            assert!(checksums_ok(&f));
            let v = Ipv4View::parse(&f, ETH_HDR).unwrap();
            v.dec_ttl(&mut f);
            v.set_addr(&mut f, true, W);
            v.set_port(&mut f, true, 12345);
            assert!(
                Ipv4View::parse(&f, ETH_HDR).is_some(),
                "ip header checksum ({proto})"
            );
            assert!(checksums_ok(&f), "l4 checksum ({proto})");
            assert_eq!((v.src(&f), v.ttl(&f)), (W, 63));
        }
    }

    /// Fuzz find (fwd, 2026-11-20): NAT turning an echo reply's identifier
    /// back to 0, with seq 0 and a zero payload, made the message all zero.
    /// Its checksum must then be 0xffff; the incremental update (RFC 1624
    /// eqn. 3) gave 0x0000, which receivers reject.
    #[test]
    fn icmp_identifier_rewrite_to_an_all_zero_message() {
        for payload in [&b""[..], &b"\0"[..], &b"\0\0\0"[..]] {
            let mut l4 = icmp_echo(ICMP_ECHO_REPLY, 0x2a00, 0);
            l4.truncate(8); // no "pingdata"
            l4.extend_from_slice(payload);
            put16(&mut l4, 2, 0);
            let c = checksum(&l4);
            put16(&mut l4, 2, c);
            let mut f = ipv4_frame(B, A, PROTO_ICMP, 64, &l4);
            assert!(checksums_ok(&f));
            let v = Ipv4View::parse(&f, ETH_HDR).unwrap();
            v.set_port(&mut f, false, 0);
            assert_eq!(get16(&f, v.l4 + 2), 0xffff, "payload {payload:?}");
            assert!(checksums_ok(&f));
        }
    }

    fn v6_frame(dmac: Mac, smac: Mac, src: Ipv6Addr, dst: Ipv6Addr, proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&dmac);
        f.extend_from_slice(&smac);
        f.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        f.extend_from_slice(&[0x60, 0, 0, 0]);
        f.extend_from_slice(&(l4.len() as u16).to_be_bytes());
        f.extend_from_slice(&[proto, 255]);
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        f.extend_from_slice(l4);
        f
    }

    const RMAC: Mac = [0x52, 0x54, 0, 0, 0, 2];
    const CMAC: Mac = [0x52, 0x54, 0, 0, 0, 0x10];


    #[test]
    fn echo_frames_are_recognised() {
        let (c, r) = (Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(203, 0, 113, 1));
        let req = test_util::ipv4_frame(c, r, PROTO_ICMP, 64, &[ICMP_ECHO_REQUEST, 0, 0, 0, 0, 1, 0, 1]);
        let rep = test_util::ipv4_frame(r, c, PROTO_ICMP, 64, &[ICMP_ECHO_REPLY, 0, 0, 0, 0, 1, 0, 1]);
        let unreach = test_util::ipv4_frame(r, c, PROTO_ICMP, 64, &[3, 3, 0, 0, 0, 0, 0, 0]);
        let udp = test_util::ipv4_frame(c, r, PROTO_UDP, 64, &[0; 8]);
        assert!(is_echo(&req) && is_echo(&rep));
        assert!(!is_echo(&unreach) && !is_echo(&udp) && !is_echo(&req[..ETH_HDR + 20]));
        // Tagged (a VLAN network's frame in the port queue).
        let mut tagged = req[..12].to_vec();
        tagged.extend_from_slice(&[0x81, 0x00, 0x00, 20]);
        tagged.extend_from_slice(&req[12..]);
        assert!(is_echo(&tagged));
        let a: Ipv6Addr = "fd00::1".parse().unwrap();
        let b: Ipv6Addr = "fd00::2".parse().unwrap();
        assert!(is_echo(&v6_frame(RMAC, CMAC, a, b, PROTO_ICMPV6, &[ICMPV6_ECHO_REPLY, 0, 0, 0, 0, 1, 0, 1])));
        assert!(!is_echo(&v6_frame(RMAC, CMAC, a, b, PROTO_ICMPV6, &[135, 0, 0, 0, 0, 0, 0, 0])));
    }



    #[test]
    fn ns_built_and_nd_parsed() {
        let me: Ipv6Addr = "fe80::5054:ff:fe00:1".parse().unwrap();
        let gw: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
        let mut ns = [0u8; NS_LEN];
        build_ns(&mut ns, RMAC, me, gw);
        assert_eq!(&ns[0..6], &[0x33, 0x33, 0xff, 0, 0, 1]);
        // Our own NS parses as "me at RMAC" (what the gateway learns).
        assert_eq!(parse_nd(&ns), Some((me, RMAC)));
        // The gateway's NA: its target and target link-layer option.
        let mut na = alloc::vec![136u8, 0, 0, 0, 0x60, 0, 0, 0];
        na.extend_from_slice(&gw.octets());
        na.extend_from_slice(&[2, 1, 0x52, 0x54, 0, 0, 0, 0x10]);
        let c = icmpv6_checksum(gw, me, &na);
        put16(&mut na, 2, c);
        let f = v6_frame(RMAC, CMAC, gw, me, PROTO_ICMPV6, &na);
        assert_eq!(parse_nd(&f), Some((gw, CMAC)));
        // Not with a bad checksum, another hop limit, or no option.
        let mut bad = f.clone();
        bad[ETH_HDR + 40 + 2] ^= 1;
        assert_eq!(parse_nd(&bad), None);
        let mut off_link = f.clone();
        off_link[ETH_HDR + 7] = 254;
        assert_eq!(parse_nd(&off_link), None);
        let mut bare = na[..24].to_vec();
        put16(&mut bare, 2, 0);
        let c = icmpv6_checksum(gw, me, &bare);
        put16(&mut bare, 2, c);
        assert_eq!(parse_nd(&v6_frame(RMAC, CMAC, gw, me, PROTO_ICMPV6, &bare)), None);
    }


    #[test]
    fn rs_is_valid() {
        let me: Ipv6Addr = "fe80::5054:ff:fe00:1".parse().unwrap();
        let mut rs = [0u8; RS_LEN];
        assert_eq!(build_rs(&mut rs, RMAC, me, true), RS_LEN);
        let v = Ipv6View::parse(&rs, ETH_HDR).unwrap();
        assert_eq!((v.proto, v.hop_limit(&rs), rs[v.l4]), (PROTO_ICMPV6, 255, 133));
        assert_eq!(icmpv6_checksum(me, v.dst(&rs), &rs[v.l4..]), 0);
        assert_eq!(&rs[0..6], &[0x33, 0x33, 0, 0, 0, 2]);
        // PPP: no link-layer option.
        let n = build_rs(&mut rs, RMAC, me, false);
        assert_eq!(n, RS_LEN - 8);
        let v = Ipv6View::parse(&rs[..n], ETH_HDR).unwrap();
        assert_eq!(v.l4_len, 8);
        assert_eq!(icmpv6_checksum(me, v.dst(&rs), &rs[v.l4..n]), 0);
    }

    #[test]
    fn rejects_bad_headers() {
        let mut f = ipv4_frame(A, B, PROTO_UDP, 64, &udp_datagram(A, B, 1, 2, b""));
        f[ETH_HDR + 10] ^= 0xff; // break checksum
        assert!(Ipv4View::parse(&f, ETH_HDR).is_none());
        let f = ipv4_frame(A, B, PROTO_UDP, 64, &[]);
        assert!(Ipv4View::parse(&f[..30], ETH_HDR).is_none(), "truncated");
    }

    #[test]
    fn arp_roundtrip() {
        let mut buf = [0u8; 64];
        let n = build_arp_request(&mut buf, [2, 0, 0, 0, 0, 1], A, B);
        let a = parse_arp(&buf[..n]).unwrap();
        assert_eq!((a.op, a.sender_ip, a.target_ip), (1, A, B));
        assert_eq!(ethertype(&buf[..n]), Some(ETHERTYPE_ARP));
    }

    /// `frame` with a tag (TPID `tpid`, TCI `tci`) after the MAC addresses.
    fn tagged(frame: &[u8], tpid: u16, tci: u16) -> Vec<u8> {
        let mut t = frame[..12].to_vec();
        t.extend_from_slice(&tpid.to_be_bytes());
        t.extend_from_slice(&tci.to_be_bytes());
        t.extend_from_slice(&frame[12..]);
        t
    }

    #[test]
    fn vlan_ingress_rules() {
        let plain = ipv4_frame(A, B, PROTO_UDP, 64, &udp_datagram(A, B, 1, 2, b"x"));
        let t848 = tagged(&plain, ETHERTYPE_VLAN, vlan_tci_of(848, 5));
        let t849 = tagged(&plain, ETHERTYPE_VLAN, 849);
        let prio = tagged(&plain, ETHERTYPE_VLAN, vlan_tci_of(0, 3));
        let qinq = tagged(&t848, ETHERTYPE_QINQ, 100);
        let double = tagged(&t848, ETHERTYPE_VLAN, 848);
        let accept = VlanRx::Accept { strip: true };
        let keep = VlanRx::Accept { strip: false };
        // Tagged port (VID 848).
        assert_eq!(vlan_rx(&t848, Some(848)), accept);
        assert_eq!(vlan_rx(&t849, Some(848)), VlanRx::Drop);
        assert_eq!(vlan_rx(&prio, Some(848)), VlanRx::Drop);
        assert_eq!(vlan_rx(&plain, Some(848)), VlanRx::Drop);
        assert_eq!(vlan_rx(&qinq, Some(848)), VlanRx::Drop);
        assert_eq!(vlan_rx(&double, Some(848)), VlanRx::Drop);
        // Untagged port.
        assert_eq!(vlan_rx(&plain, None), keep);
        assert_eq!(vlan_rx(&prio, None), accept);
        assert_eq!(vlan_rx(&t848, None), VlanRx::Drop);
        assert_eq!(vlan_rx(&qinq, None), VlanRx::Drop);
        // Short frames never panic.
        for n in 0..20 {
            let _ = vlan_rx(&t848[..n], Some(848));
            let _ = vlan_rx(&t848[..n], None);
        }
        assert_eq!(vlan_rx(&t848[..16], Some(848)), VlanRx::Drop);
        assert_eq!(vlan_tci(&t848), Some(vlan_tci_of(848, 5)));
        assert_eq!(vlan_tci(&plain), None);
    }

    #[test]
    fn vlan_insert_remove_roundtrip() {
        let plain = ipv4_frame(A, B, PROTO_TCP, 64, &tcp_segment(A, B, 1, 2, TCP_SYN, b""));
        let tci = vlan_tci_of(848, 1);
        let mut buf = alloc::vec![0u8; VLAN_HDR];
        buf.extend_from_slice(&plain);
        vlan_insert(&mut buf, tci);
        assert_eq!(buf, tagged(&plain, ETHERTYPE_VLAN, tci));
        vlan_remove(&mut buf);
        assert_eq!(&buf[VLAN_HDR..], &plain[..]);
    }

    // ---- SplitPlan (RFC 791 fragmentation) -------------------------------

    /// Split `f` with `plan` the way the datapath does: pieces 1.. into new
    /// buffers, then piece 0 in place.
    fn split(mut f: Vec<u8>, plan: &SplitPlan) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for i in 1..plan.pieces() {
            let mut b = alloc::vec![0u8; plan.piece_len(i)];
            let n = plan.write_piece(&f, i, &mut b);
            b.truncate(n);
            out.push(b);
        }
        let n = plan.truncate_first(&mut f);
        f.truncate(n);
        out.insert(0, f);
        out
    }

    fn reassemble(pieces: &[Vec<u8>]) -> (Vec<u8>, bool) {
        let mut data = Vec::new();
        let mut more = false;
        for p in pieces {
            let v = Ipv4View::parse(p, ETH_HDR).expect("valid header and checksum");
            assert_eq!(v.frag_offset as usize * 8, data.len(), "contiguous");
            data.extend_from_slice(&p[v.l4..v.l4 + v.l4_len]);
            more = get16(p, ETH_HDR + 6) & 0x2000 != 0;
        }
        (data, more)
    }

    fn no_df(mut f: Vec<u8>) -> Vec<u8> {
        put16(&mut f, ETH_HDR + 6, 0);
        put16(&mut f, ETH_HDR + 10, 0);
        let c = checksum(&f[ETH_HDR..ETH_HDR + 20]);
        put16(&mut f, ETH_HDR + 10, c);
        f
    }

    #[test]
    fn split_a_1500_packet_for_pppoe() {
        let b = Ipv4Addr::new(203, 0, 113, 1);
        let payload: Vec<u8> = (0..1472u32).map(|i| i as u8).collect();
        let udp = udp_datagram(A, b, 5000, 53, &payload);
        let f = no_df(ipv4_frame(A, b, PROTO_UDP, 64, &udp));
        let plan = SplitPlan::new(&f, 1492).unwrap();
        assert_eq!(plan.pieces(), 2);
        let pieces = split(f.clone(), &plan);
        assert_eq!(pieces[0].len(), ETH_HDR + 20 + 1472, "1492 B of IP, 8-byte aligned data");
        assert!(pieces.iter().all(|p| p.len() - ETH_HDR <= 1492));
        let (data, more) = reassemble(&pieces);
        assert_eq!(data, udp, "the UDP datagram, whole again");
        assert!(!more, "the last piece ends the datagram");
        assert_eq!(get16(&pieces[0], ETH_HDR + 6), 0x2000, "first: MF, offset 0");
        // Ethernet header, version/TOS, ID, TTL/protocol and addresses are
        // the original's in every piece.
        let same = |p: &[u8], r: core::ops::Range<usize>| assert_eq!(p[r.clone()], f[r]);
        for p in &pieces {
            same(p, 0..ETH_HDR + 2);
            same(p, ETH_HDR + 4..ETH_HDR + 6);
            same(p, ETH_HDR + 8..ETH_HDR + 10);
            same(p, ETH_HDR + 12..ETH_HDR + 20);
        }
    }

    #[test]
    fn split_a_fragment_keeps_its_place() {
        let b = Ipv4Addr::new(203, 0, 113, 1);
        // A middle fragment: offset 1480 B, MF set, 1480 B of data.
        let data: Vec<u8> = (0..1480u32).map(|i| (i * 3) as u8).collect();
        let mut f = ipv4_frame(A, b, PROTO_UDP, 64, &data);
        put16(&mut f, ETH_HDR + 6, 0x2000 | 185);
        put16(&mut f, ETH_HDR + 10, 0);
        let c = checksum(&f[ETH_HDR..ETH_HDR + 20]);
        put16(&mut f, ETH_HDR + 10, c);
        let plan = SplitPlan::new(&f, 1492).unwrap();
        let pieces = split(f, &plan);
        assert_eq!(pieces.len(), 2);
        let v0 = Ipv4View::parse(&pieces[0], ETH_HDR).unwrap();
        let v1 = Ipv4View::parse(&pieces[1], ETH_HDR).unwrap();
        assert_eq!((v0.frag_offset, v1.frag_offset), (185, 185 + 1472 / 8));
        assert!(get16(&pieces[1], ETH_HDR + 6) & 0x2000 != 0, "MF kept: more of the datagram follows");
        let mut got = pieces[0][v0.l4..v0.l4 + v0.l4_len].to_vec();
        got.extend_from_slice(&pieces[1][v1.l4..v1.l4 + v1.l4_len]);
        assert_eq!(got, data);
    }

    #[test]
    fn split_refusals_and_small_mtus() {
        let b = Ipv4Addr::new(203, 0, 113, 1);
        let udp = udp_datagram(A, b, 1, 2, &[7u8; 1472]);
        let df = ipv4_frame(A, b, PROTO_UDP, 64, &udp); // DF set
        assert_eq!(SplitPlan::new(&df, 1492), None, "DF");
        let f = no_df(df);
        assert_eq!(SplitPlan::new(&f, 1500), None, "fits");
        assert_eq!(SplitPlan::new(&f, 27), None, "no room for 8 bytes");
        // Small MTU: many pieces, all within it, data intact.
        for mtu in [28u16, 576, 1280, 1499] {
            let plan = SplitPlan::new(&f, mtu).unwrap();
            let pieces = split(f.clone(), &plan);
            assert!(pieces.iter().all(|p| p.len() - ETH_HDR <= usize::from(mtu)), "mtu {mtu}");
            assert_eq!(reassemble(&pieces).0, udp, "mtu {mtu}");
        }
        // IP options: not split.
        let mut opt = f.clone();
        opt[ETH_HDR] = 0x46;
        assert_eq!(SplitPlan::new(&opt, 1492), None);
    }
}
