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

// ---- checksums ------------------------------------------------------------------

/// One's-complement sum of `data` (no final inversion).
fn sum(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
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
}
