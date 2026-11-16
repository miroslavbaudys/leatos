//! Minimal DNS wire format (RFC 1035): header, the (single) question,
//! resource-record walking for TTLs and addresses, and building local answers.
//!
//! Every read is bounds-checked; malformed input yields `Err`, never a panic.
//! Name decompression follows at most [`MAX_POINTERS`] pointers (no loops).

use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

pub const HEADER_LEN: usize = 12;
const MAX_POINTERS: usize = 16;
const MAX_NAME_LEN: usize = 255;

pub const TYPE_A: u16 = 1;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_OPT: u16 = 41;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadName,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let w = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
        Ok(Self {
            id: w(0),
            flags: w(2),
            qdcount: w(4),
            ancount: w(6),
            nscount: w(8),
            arcount: w(10),
        })
    }
    pub fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0xf) as u8
    }
    pub fn rcode(&self) -> u8 {
        (self.flags & 0xf) as u8
    }
    pub fn recursion_desired(&self) -> bool {
        self.flags & FLAG_RD != 0
    }
}

/// The question of a message, with the name lowercased (for cache keys).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Read a (possibly compressed) name at `pos`. Returns the dotted, lowercase
/// name (no trailing dot; root = "") and the offset just after the name
/// *at its original position*.
pub fn read_name(msg: &[u8], mut pos: usize) -> Result<(String, usize), Error> {
    let mut name = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos).ok_or(Error::Truncated)? as usize;
        match len & 0xc0 {
            0x00 if len == 0 => {
                return Ok((name, end.unwrap_or(pos + 1)));
            }
            0x00 => {
                let label = msg.get(pos + 1..pos + 1 + len).ok_or(Error::Truncated)?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &c in label {
                    if c == b'.' || !c.is_ascii() {
                        return Err(Error::BadName);
                    }
                    name.push(c.to_ascii_lowercase() as char);
                }
                if name.len() > MAX_NAME_LEN {
                    return Err(Error::BadName);
                }
                pos += 1 + len;
            }
            0xc0 => {
                let lo = *msg.get(pos + 1).ok_or(Error::Truncated)? as usize;
                jumps += 1;
                if jumps > MAX_POINTERS {
                    return Err(Error::BadName);
                }
                end.get_or_insert(pos + 2);
                pos = ((len & 0x3f) << 8) | lo;
            }
            _ => return Err(Error::BadName),
        }
    }
}

/// Encode a dotted name (uncompressed).
pub fn write_name(out: &mut Vec<u8>, name: &str) -> Result<(), Error> {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        if label.len() > 63 {
            return Err(Error::BadName);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Parse the header and the single question. Returns the question and the
/// offset of the first byte after it.
pub fn parse_query(msg: &[u8]) -> Result<(Header, Question, usize), Error> {
    let h = Header::parse(msg)?;
    if h.qdcount != 1 {
        return Err(Error::Unsupported);
    }
    let (name, pos) = read_name(msg, HEADER_LEN)?;
    let f = msg.get(pos..pos + 4).ok_or(Error::Truncated)?;
    let q = Question {
        name,
        qtype: u16::from_be_bytes([f[0], f[1]]),
        qclass: u16::from_be_bytes([f[2], f[3]]),
    };
    Ok((h, q, pos + 4))
}

/// One resource record, located inside a message.
#[derive(Clone, Copy, Debug)]
pub struct RecordInfo {
    pub rtype: u16,
    pub ttl: u32,
    /// Offset of the 4-byte TTL field (for rewriting cached answers).
    pub ttl_offset: usize,
    pub rdata_offset: usize,
    pub rdata_len: usize,
    /// 0 = answer, 1 = authority, 2 = additional.
    pub section: u8,
}

/// Walk all answer/authority/additional records of a response.
pub fn records(msg: &[u8]) -> Result<Vec<RecordInfo>, Error> {
    let (h, _, mut pos) = parse_query(msg)?;
    let mut out = Vec::new();
    for (section, count) in [(0u8, h.ancount), (1, h.nscount), (2, h.arcount)] {
        for _ in 0..count {
            let (_, p) = read_name(msg, pos)?;
            let f = msg.get(p..p + 10).ok_or(Error::Truncated)?;
            let rtype = u16::from_be_bytes([f[0], f[1]]);
            let ttl = u32::from_be_bytes([f[4], f[5], f[6], f[7]]);
            let rdata_len = u16::from_be_bytes([f[8], f[9]]) as usize;
            let rdata_offset = p + 10;
            if msg.len() < rdata_offset + rdata_len {
                return Err(Error::Truncated);
            }
            out.push(RecordInfo {
                rtype,
                ttl,
                ttl_offset: p + 4,
                rdata_offset,
                rdata_len,
                section,
            });
            pos = rdata_offset + rdata_len;
        }
    }
    Ok(out)
}

/// IPv4 addresses in the answer section.
pub fn answer_ipv4s(msg: &[u8], recs: &[RecordInfo]) -> Vec<Ipv4Addr> {
    recs.iter()
        .filter(|r| r.section == 0 && r.rtype == TYPE_A && r.rdata_len == 4)
        .map(|r| {
            let d = &msg[r.rdata_offset..r.rdata_offset + 4];
            Ipv4Addr::new(d[0], d[1], d[2], d[3])
        })
        .collect()
}

pub fn set_id(msg: &mut [u8], id: u16) {
    if msg.len() >= 2 {
        msg[..2].copy_from_slice(&id.to_be_bytes());
    }
}

/// Local answer data.
#[derive(Clone, Debug)]
pub enum Rdata {
    A(Ipv4Addr),
    Ptr(String),
}

/// Build a response to `query` (which has already passed `parse_query`):
/// copies the question, sets QR/AA/RA, the rcode and answers.
/// Answer names point at the question name (offset 12).
pub fn build_response(
    query: &[u8],
    question_end: usize,
    rcode: u8,
    answers: &[(Rdata, u32)],
    authoritative: bool,
) -> Vec<u8> {
    let qh = Header::parse(query).expect("query already parsed");
    let mut out = Vec::with_capacity(question_end + answers.len() * 32);
    out.extend_from_slice(&qh.id.to_be_bytes());
    let mut flags = FLAG_QR | FLAG_RA | (qh.flags & FLAG_RD) | (rcode as u16 & 0xf);
    if authoritative {
        flags |= FLAG_AA;
    }
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]); // NS, AR
    out.extend_from_slice(&query[HEADER_LEN..question_end]);
    for (rdata, ttl) in answers {
        out.extend_from_slice(&[0xc0, HEADER_LEN as u8]); // name = question
        let (rtype, data) = match rdata {
            Rdata::A(a) => (TYPE_A, a.octets().to_vec()),
            Rdata::Ptr(name) => {
                let mut d = Vec::new();
                if write_name(&mut d, name).is_err() {
                    continue;
                }
                (TYPE_PTR, d)
            }
        };
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
    }
    out
}

/// A minimal error response that echoes the question when possible.
pub fn error_response(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    match parse_query(query) {
        Ok((_, _, end)) => Some(build_response(query, end, rcode, &[], false)),
        Err(_) => {
            let h = Header::parse(query).ok()?;
            let mut out = Vec::with_capacity(HEADER_LEN);
            out.extend_from_slice(&h.id.to_be_bytes());
            let flags = FLAG_QR | FLAG_RA | (h.flags & FLAG_RD) | rcode as u16;
            out.extend_from_slice(&flags.to_be_bytes());
            out.extend_from_slice(&[0; 8]);
            Some(out)
        }
    }
}

/// Build a query (used by tests and for health probes).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    let _ = write_name(&mut out, name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

pub fn is_truncated(msg: &[u8]) -> bool {
    Header::parse(msg).is_ok_and(|h| h.flags & FLAG_TC != 0)
}

/// The largest UDP answer `query`'s sender takes: its EDNS buffer size
/// (RFC 6891 §6.2.3), 512 without EDNS, never more than `cap` (what fits
/// in one datagram on the way back).
pub fn udp_limit(query: &[u8], cap: usize) -> usize {
    let edns = records(query).ok().and_then(|recs| {
        recs.iter()
            .find(|r| r.section == 2 && r.rtype == TYPE_OPT)
            .map(|r| u16::from_be_bytes([query[r.ttl_offset - 2], query[r.ttl_offset - 1]]) as usize)
    });
    edns.unwrap_or(512).clamp(512, cap.max(512))
}

/// `msg` for a client that takes at most `limit` bytes: unchanged if it
/// fits, else the header and question with TC set and no records
/// (RFC 2181 §9), so the client knows the answer did not fit.
pub fn fit(msg: &[u8], limit: usize) -> Vec<u8> {
    if msg.len() <= limit {
        return msg.to_vec();
    }
    let end = parse_query(msg).map_or(HEADER_LEN, |(_, _, end)| end).min(msg.len());
    let mut out = msg[..end].to_vec();
    if out.len() >= HEADER_LEN {
        let flags = u16::from_be_bytes([out[2], out[3]]) | FLAG_TC;
        out[2..4].copy_from_slice(&flags.to_be_bytes());
        out[4..6].copy_from_slice(&u16::from(end > HEADER_LEN).to_be_bytes());
        out[6..12].fill(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn query_roundtrip() {
        let q = build_query(7, "Example.COM", TYPE_A);
        let (h, question, end) = parse_query(&q).unwrap();
        assert_eq!(h.id, 7);
        assert!(h.recursion_desired());
        assert_eq!(
            question,
            Question {
                name: "example.com".into(),
                qtype: TYPE_A,
                qclass: CLASS_IN
            }
        );
        assert_eq!(end, q.len());
    }

    #[test]
    fn local_answer_parses_back() {
        let q = build_query(9, "nas.lan", TYPE_A);
        let (_, _, end) = parse_query(&q).unwrap();
        let r = build_response(
            &q,
            end,
            RCODE_NOERROR,
            &[(Rdata::A(Ipv4Addr::new(192, 168, 1, 10)), 60)],
            true,
        );
        let h = Header::parse(&r).unwrap();
        assert!(h.is_response());
        assert_eq!((h.id, h.ancount, h.rcode()), (9, 1, RCODE_NOERROR));
        let recs = records(&r).unwrap();
        assert_eq!(recs[0].ttl, 60);
        assert_eq!(
            answer_ipv4s(&r, &recs),
            vec![Ipv4Addr::new(192, 168, 1, 10)]
        );
    }

    #[test]
    fn udp_limits_and_fitting() {
        let q = build_query(5, "big.example", TYPE_A);
        assert_eq!(udp_limit(&q, 1472), 512, "no EDNS");
        let mut e = q.clone();
        e[11] = 1; // ARCOUNT
        e.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]); // OPT, 4096
        assert_eq!(udp_limit(&e, 1472), 1472, "capped");
        let class = e.len() - 8..e.len() - 6;
        e[class.clone()].copy_from_slice(&1232u16.to_be_bytes());
        assert_eq!(udp_limit(&e, 1472), 1232);
        e[class].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(udp_limit(&e, 1472), 512, "never below 512");

        let (_, _, end) = parse_query(&q).unwrap();
        let answers: Vec<_> = (0..60).map(|i| (Rdata::A(Ipv4Addr::new(10, 0, 0, i)), 60)).collect();
        let r = build_response(&q, end, RCODE_NOERROR, &answers, false);
        assert!(r.len() > 512);
        assert_eq!(fit(&r, 1472), r, "fits");
        let t = fit(&r, 512);
        assert!(is_truncated(&t));
        let h = Header::parse(&t).unwrap();
        assert_eq!((h.id, h.qdcount, h.ancount, h.nscount, h.arcount), (5, 1, 0, 0, 0));
        assert_eq!(parse_query(&t).unwrap().1.name, "big.example");
        assert_eq!(t.len(), end);
    }

    #[test]
    fn pointer_loops_are_rejected() {
        let mut m = build_query(1, "a", TYPE_A);
        // Replace the question name with a pointer to itself.
        m.truncate(HEADER_LEN);
        m.extend_from_slice(&[0xc0, HEADER_LEN as u8, 0, 1, 0, 1]);
        assert_eq!(parse_query(&m).unwrap_err(), Error::BadName);
    }

    #[test]
    fn fuzz_never_panics() {
        let q = build_query(3, "www.example.com", TYPE_A);
        let (_, _, end) = parse_query(&q).unwrap();
        let base = build_response(
            &q,
            end,
            0,
            &[
                (Rdata::A(Ipv4Addr::new(1, 2, 3, 4)), 300),
                (Rdata::Ptr("x.y".into()), 5),
            ],
            false,
        );
        let mut seed = 0x1234_5678_u32;
        for _ in 0..20_000 {
            let mut b = base.clone();
            for _ in 0..6 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let i = seed as usize % b.len();
                b[i] = (seed >> 8) as u8;
            }
            b.truncate((seed as usize >> 3) % (b.len() + 1));
            let _ = parse_query(&b);
            if let Ok(recs) = records(&b) {
                let _ = answer_ipv4s(&b, &recs);
            }
            let _ = error_response(&b, RCODE_FORMERR);
            let _ = udp_limit(&b, 1472);
            let _ = fit(&b, 20);
        }
    }
}
