//! Helpers shared by the fuzz targets: small value sets that make the
//! generated inputs meet (addresses the router knows, ports a forward
//! covers) and frame builders with correct checksums.

use arbitrary::Arbitrary;
use core::net::Ipv4Addr;
use fwd::wire::{self, ETH_HDR, ETHERTYPE_IPV4, PROTO_ICMP, PROTO_TCP, PROTO_UDP};

/// Flip `n` bytes of `buf` at positions/values taken from `noise`.
pub fn damage(buf: &mut [u8], noise: &[u8]) {
    if buf.is_empty() {
        return;
    }
    for pair in noise.chunks(3) {
        if pair.len() < 3 {
            break;
        }
        let i = u16::from_le_bytes([pair[0], pair[1]]) as usize % buf.len();
        buf[i] = pair[2];
    }
}

/// An address from a set the fuzzed code cares about, or any.
#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum Addr {
    Pick(u8),
    Any(u32),
}

pub const ADDRS: &[Ipv4Addr] = &[
    Ipv4Addr::new(203, 0, 113, 10), // router WAN
    Ipv4Addr::new(203, 0, 113, 1),  // WAN gateway
    Ipv4Addr::new(192, 168, 1, 1),  // router LAN
    Ipv4Addr::new(192, 168, 1, 100),
    Ipv4Addr::new(192, 168, 1, 101),
    Ipv4Addr::new(192, 168, 1, 10), // NAS: forward / redirect target
    Ipv4Addr::new(192, 168, 20, 1), // router guest
    Ipv4Addr::new(192, 168, 20, 50),
    Ipv4Addr::new(10, 30, 0, 5), // behind a static route
    Ipv4Addr::new(198, 51, 100, 7),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(255, 255, 255, 255),
    Ipv4Addr::new(192, 168, 1, 255),
    Ipv4Addr::new(224, 0, 0, 251),
    Ipv4Addr::new(127, 0, 0, 1),
    Ipv4Addr::new(0, 0, 0, 0),
];

impl Addr {
    pub fn get(self) -> Ipv4Addr {
        match self {
            Addr::Pick(i) => ADDRS[i as usize % ADDRS.len()],
            Addr::Any(v) => Ipv4Addr::from(v),
        }
    }
}

/// A port from a set (forwards, router services, NAT range edges), or any.
#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum Port {
    Pick(u8),
    Any(u16),
}

pub const PORTS: &[u16] = &[53, 67, 68, 80, 123, 443, 5353, 8080, 8081, 8443, 10000, 39999, 60000, 61000, 65535, 0];

impl Port {
    pub fn get(self) -> u16 {
        match self {
            Port::Pick(i) => PORTS[i as usize % PORTS.len()],
            Port::Any(v) => v,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum L4Kind {
    Tcp { flags: u8, mss: Option<u16> },
    Udp,
    Icmp { kind: u8, code: u8, id: u16 },
    Other(u8),
}

/// An IPv4 packet described by fields; [`Ipv4Pkt::frame`] builds it with
/// correct checksums (so it gets past the parsers to the logic).
#[derive(Arbitrary, Debug, Clone)]
pub struct Ipv4Pkt {
    pub src: Addr,
    pub dst: Addr,
    pub sport: Port,
    pub dport: Port,
    pub l4: L4Kind,
    pub ttl: u8,
    pub tos: u8,
    pub id: u16,
    pub df: bool,
    pub more_frags: bool,
    /// In 8-byte units; mostly 0.
    pub frag_offset: Option<u16>,
    pub ip_options: Option<[u8; 4]>,
    pub payload: Vec<u8>,
}

impl Ipv4Pkt {
    pub fn frag_offset(&self) -> u16 {
        self.frag_offset.map_or(0, |o| o & 0x1fff)
    }

    pub fn is_fragment(&self) -> bool {
        self.more_frags || self.frag_offset() != 0
    }

    /// Ethernet frame to `dst_mac`, with `tail` bytes of tailroom.
    pub fn frame(&self, dst_mac: [u8; 6], src_mac: [u8; 6], tail: usize) -> Vec<u8> {
        let (src, dst) = (self.src.get(), self.dst.get());
        let payload = &self.payload[..self.payload.len().min(1600)];
        let (proto, l4) = match self.l4 {
            L4Kind::Tcp { flags, mss } => {
                let opt_len = if mss.is_some() { 4 } else { 0 };
                let mut s = vec![0u8; 20 + opt_len];
                wire::put16(&mut s, 0, self.sport.get());
                wire::put16(&mut s, 2, self.dport.get());
                s[4..8].copy_from_slice(&self.id.wrapping_mul(7919).to_be_bytes().repeat(2));
                s[12] = ((20 + opt_len) as u8 / 4) << 4;
                s[13] = flags;
                wire::put16(&mut s, 14, 64240);
                if let Some(m) = mss {
                    s[20] = 2;
                    s[21] = 4;
                    wire::put16(&mut s, 22, m);
                }
                s.extend_from_slice(payload);
                (PROTO_TCP, s)
            }
            L4Kind::Udp => {
                let mut s = vec![0u8; 8];
                wire::put16(&mut s, 0, self.sport.get());
                wire::put16(&mut s, 2, self.dport.get());
                wire::put16(&mut s, 4, (8 + payload.len()) as u16);
                s.extend_from_slice(payload);
                (PROTO_UDP, s)
            }
            L4Kind::Icmp { kind, code, id } => {
                let mut s = vec![kind, code, 0, 0];
                s.extend_from_slice(&id.to_be_bytes());
                s.extend_from_slice(&self.id.to_be_bytes());
                s.extend_from_slice(payload);
                (PROTO_ICMP, s)
            }
            L4Kind::Other(p) => (p, payload.to_vec()),
        };
        ipv4_frame(dst_mac, src_mac, src, dst, proto, self, l4, tail)
    }
}

#[allow(clippy::too_many_arguments)]
fn ipv4_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    p: &Ipv4Pkt,
    mut l4: Vec<u8>,
    tail: usize,
) -> Vec<u8> {
    // L4 checksum over the segment (for a fragment: over this piece only).
    match proto {
        PROTO_TCP if l4.len() >= 20 => {
            let c = wire::l4_checksum(src, dst, PROTO_TCP, &l4);
            wire::put16(&mut l4, 16, c);
        }
        PROTO_UDP if l4.len() >= 8 => {
            let c = wire::l4_checksum(src, dst, PROTO_UDP, &l4);
            wire::put16(&mut l4, 6, if c == 0 { 0xffff } else { c });
        }
        PROTO_ICMP if l4.len() >= 4 => {
            let c = wire::checksum(&l4);
            wire::put16(&mut l4, 2, c);
        }
        _ => {}
    }
    let opts = p.ip_options.map_or(0, |_| 4);
    let ihl = 20 + opts;
    let mut f = vec![0u8; ETH_HDR + ihl];
    f[0..6].copy_from_slice(&dst_mac);
    f[6..12].copy_from_slice(&src_mac);
    wire::put16(&mut f, 12, ETHERTYPE_IPV4);
    let ip = ETH_HDR;
    f[ip] = 0x40 | (ihl / 4) as u8;
    f[ip + 1] = p.tos;
    wire::put16(&mut f, ip + 2, (ihl + l4.len()) as u16);
    wire::put16(&mut f, ip + 4, p.id);
    let flags = (u16::from(p.df) << 14) | (u16::from(p.more_frags) << 13) | p.frag_offset();
    wire::put16(&mut f, ip + 6, flags);
    f[ip + 8] = p.ttl;
    f[ip + 9] = proto;
    wire::put_ip(&mut f, ip + 12, src);
    wire::put_ip(&mut f, ip + 16, dst);
    if let Some(o) = p.ip_options {
        f[ip + 20..ip + 24].copy_from_slice(&o);
    }
    let c = wire::checksum(&f[ip..ip + ihl]);
    wire::put16(&mut f, ip + 10, c);
    f.extend_from_slice(&l4);
    f.resize(f.len() + tail, 0);
    f
}

/// Every checksum of an unfragmented IPv4 frame, verified from scratch.
pub fn checksums_ok(f: &[u8]) -> bool {
    let Some(v) = wire::Ipv4View::parse(f, ETH_HDR) else {
        return false;
    };
    if wire::checksum(&f[ETH_HDR..v.l4]) != 0 {
        return false;
    }
    let seg = &f[v.l4..v.l4 + v.l4_len];
    match v.proto {
        PROTO_TCP => wire::l4_checksum(v.src(f), v.dst(f), PROTO_TCP, seg) == 0,
        PROTO_UDP => wire::get16(seg, 6) == 0 || wire::l4_checksum(v.src(f), v.dst(f), PROTO_UDP, seg) == 0,
        PROTO_ICMP => wire::checksum(seg) == 0,
        _ => true,
    }
}
