//! Minimal Ethernet / ARP / IPv4 / TCP / UDP / ICMP field access and
//! checksum maintenance for the forwarding path.
//!
//! Frames are `&mut [u8]` starting at the Ethernet header. All accessors
//! are bounds-checked by the parse step ([`Ipv4View::parse`]); after a
//! successful parse, field offsets are known to be in range.
//! Checksums are updated incrementally (RFC 1624) when fields change.

use core::net::Ipv4Addr;

pub const ETH_HDR: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// IEEE 802.1Q VLAN tag (C-tag).
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// IEEE 802.1ad service tag (QinQ outer tag).
pub const ETHERTYPE_QINQ: u16 = 0x88a8;
/// Bytes a VLAN tag adds to a frame (TPID + TCI).
pub const VLAN_HDR: usize = 4;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

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

// ---- IPv4 ------------------------------------------------------------------------

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
    if v.proto != PROTO_TCP || v.l4_len < 20 {
        return false;
    }
    let doff = ((f[v.l4 + 12] >> 4) as usize) * 4;
    if doff < 20 || doff > v.l4_len {
        return false;
    }
    let (mut i, end) = (v.l4 + 20, v.l4 + doff);
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
                    let (o, n) = if (i + 2 - v.l4).is_multiple_of(2) {
                        (old, max)
                    } else {
                        (old.swap_bytes(), max.swap_bytes())
                    };
                    let c = csum_update16(get16(f, v.l4 + 16), o, n);
                    put16(f, v.l4 + 16, c);
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
}
