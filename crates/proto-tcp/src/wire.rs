//! The TCP header (RFC 9293 §3.1): parse a segment, write one, the
//! checksum with the IPv4 / IPv6 pseudo-header. Options: MSS read and
//! written; the others skipped (window scale, SACK, timestamps are never
//! offered, so a peer does not use them).

use core::net::IpAddr;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// The header without options.
pub const HDR: usize = 20;
/// IP protocol number.
pub const PROTO_TCP: u8 = 6;

/// A parsed segment (the checksum is checked by [`checksum`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// The MSS option (SYN only, RFC 9293 §3.7.1).
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

impl Segment<'_> {
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    /// Sequence space the segment takes: payload, SYN and FIN.
    pub fn seq_len(&self) -> u32 {
        self.payload.len() as u32 + u32::from(self.has(SYN)) + u32::from(self.has(FIN))
    }
}

fn get16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn get32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// The segment in `b` (the TCP header and payload, nothing after it), if
/// its header is well-formed: data offset inside the segment, options
/// that fit. Ports 0 are refused.
pub fn parse(b: &[u8]) -> Option<Segment<'_>> {
    if b.len() < HDR {
        return None;
    }
    let off = usize::from(b[12] >> 4) * 4;
    if off < HDR || off > b.len() {
        return None;
    }
    let (sport, dport) = (get16(b, 0), get16(b, 2));
    if sport == 0 || dport == 0 {
        return None;
    }
    let mut mss = None;
    let mut i = HDR;
    while i < off {
        match b[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let len = usize::from(*b.get(i + 1)?);
                if len < 2 || i + len > off {
                    return None;
                }
                if kind == 2 && len == 4 {
                    mss = Some(get16(b, i + 2));
                }
                i += len;
            }
        }
    }
    Some(Segment {
        sport,
        dport,
        seq: get32(b, 4),
        ack: get32(b, 8),
        flags: b[13] & 0x3f,
        window: get16(b, 14),
        mss,
        payload: &b[off..],
    })
}

fn sum(mut acc: u32, b: &[u8]) -> u32 {
    let (words, rest) = b.as_chunks::<2>();
    for w in words {
        acc += u32::from(u16::from_be_bytes(*w));
    }
    if let [x] = rest {
        acc += u32::from(*x) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The Internet checksum of `seg` with the pseudo-header for `src` → `dst`
/// (RFC 9293 §3.1; RFC 8200 §8.1 for IPv6): 0 over a segment with a valid
/// checksum. `None` when the families differ.
pub fn checksum(src: IpAddr, dst: IpAddr, seg: &[u8]) -> Option<u16> {
    let len = seg.len() as u32;
    let acc = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let a = sum(sum(0, &s.octets()), &d.octets());
            a + u32::from(PROTO_TCP) + len
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let a = sum(sum(0, &s.octets()), &d.octets());
            a + (len >> 16) + (len & 0xffff) + u32::from(PROTO_TCP)
        }
        _ => return None,
    };
    Some(fold(sum(acc, seg)))
}

/// What to write: [`write`]'s input.
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
}

impl Header {
    /// Header length with its options.
    pub fn len(&self) -> usize {
        HDR + if self.mss.is_some() { 4 } else { 0 }
    }

    /// Never empty (for clippy's `len_without_is_empty`).
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Write `h` and the payload (`a` then `b`) into `out` with the checksum
/// for `src` → `dst`; the segment's length, or `None` if `out` is too
/// small or the families differ.
pub fn write(out: &mut [u8], src: IpAddr, dst: IpAddr, h: &Header, a: &[u8], b: &[u8]) -> Option<usize> {
    let hl = h.len();
    let total = hl + a.len() + b.len();
    if out.len() < total || src.is_ipv4() != dst.is_ipv4() {
        return None;
    }
    let o = &mut out[..total];
    o[0..2].copy_from_slice(&h.sport.to_be_bytes());
    o[2..4].copy_from_slice(&h.dport.to_be_bytes());
    o[4..8].copy_from_slice(&h.seq.to_be_bytes());
    o[8..12].copy_from_slice(&h.ack.to_be_bytes());
    o[12] = ((hl / 4) as u8) << 4;
    o[13] = h.flags;
    o[14..16].copy_from_slice(&h.window.to_be_bytes());
    o[16..20].fill(0); // checksum, urgent pointer
    if let Some(m) = h.mss {
        o[20..24].copy_from_slice(&[2, 4, (m >> 8) as u8, m as u8]);
    }
    o[hl..hl + a.len()].copy_from_slice(a);
    o[hl + a.len()..].copy_from_slice(b);
    let c = checksum(src, dst, o)?;
    o[16..18].copy_from_slice(&c.to_be_bytes());
    Some(total)
}
