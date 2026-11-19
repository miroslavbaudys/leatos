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
/// Checking Disabled (RFC 4035 §3.2.2): the client validates itself and
/// wants answers that failed validation upstream too.
const FLAG_CD: u16 = 0x0010;
/// DNSSEC OK (RFC 3225), the top bit of the OPT record's flags.
const EDNS_DO: u8 = 0x80;
/// UDP payload size announced in an OPT record we add (DNS flag day 2020).
const EDNS_UDP_SIZE: u16 = 1232;

/// Extended DNS Errors (RFC 8914): EDNS option code and the INFO-CODEs we
/// send.
pub const EDNS_OPTION_EDE: u16 = 15;
pub const EDE_STALE_ANSWER: u16 = 3;
pub const EDE_BLOCKED: u16 = 15;
pub const EDE_STALE_NXDOMAIN: u16 = 19;
pub const EDE_NO_REACHABLE_AUTHORITY: u16 = 22;

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
    pub fn checking_disabled(&self) -> bool {
        self.flags & FLAG_CD != 0
    }
}

/// Whether `msg` carries an OPT record (EDNS, RFC 6891): only then may an
/// answer to it carry one.
pub fn has_edns(msg: &[u8]) -> bool {
    records(msg).is_ok_and(|recs| recs.iter().any(|r| r.section == 2 && r.rtype == TYPE_OPT))
}

/// Add an Extended DNS Error (RFC 8914) to `msg`: an option in its OPT
/// record, or a new OPT record (with DO when `dnssec_ok`) if it has none.
/// Only where nothing has to move: the OPT record (or, for a new one, the
/// message) must end the message, since compressed names may point into
/// what follows. False if it was left unchanged (malformed, OPT not last,
/// too long).
pub fn add_ede(msg: &mut Vec<u8>, code: u16, text: &str, dnssec_ok: bool) -> bool {
    let Ok((h, _, q_end)) = parse_query(msg) else {
        return false;
    };
    let Ok(recs) = records(msg) else {
        return false;
    };
    let end = recs.last().map_or(q_end, |r| r.rdata_offset + r.rdata_len);
    if end != msg.len() {
        return false; // trailing bytes
    }
    let mut option = Vec::with_capacity(6 + text.len());
    option.extend_from_slice(&EDNS_OPTION_EDE.to_be_bytes());
    option.extend_from_slice(&((2 + text.len()) as u16).to_be_bytes());
    option.extend_from_slice(&code.to_be_bytes());
    option.extend_from_slice(text.as_bytes());
    let opts: Vec<&RecordInfo> = recs.iter().filter(|r| r.section == 2 && r.rtype == TYPE_OPT).collect();
    match opts[..] {
        [] => {
            if h.arcount == u16::MAX {
                return false;
            }
            msg.push(0); // root
            msg.extend_from_slice(&TYPE_OPT.to_be_bytes());
            msg.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes());
            msg.extend_from_slice(&[0, 0, if dnssec_ok { EDNS_DO } else { 0 }, 0]);
            msg.extend_from_slice(&(option.len() as u16).to_be_bytes());
            msg.extend_from_slice(&option);
            msg[10..12].copy_from_slice(&(h.arcount + 1).to_be_bytes());
        }
        [o] if o.rdata_offset + o.rdata_len == msg.len() => {
            let Ok(len) = u16::try_from(o.rdata_len + option.len()) else {
                return false;
            };
            msg[o.rdata_offset - 2..o.rdata_offset].copy_from_slice(&len.to_be_bytes());
            msg.extend_from_slice(&option);
        }
        _ => return false,
    }
    true
}

/// The OPT record of `msg` if it is the last record and its owner is the
/// root (one zero byte, as RFC 6891 §6.1.2 requires): (record start,
/// class offset). Only such a record can be changed in place or cut off
/// without moving anything a compressed name may point to.
fn last_opt(msg: &[u8]) -> Option<(usize, usize)> {
    let recs = records(msg).ok()?;
    let o = recs.last().filter(|r| r.section == 2 && r.rtype == TYPE_OPT)?;
    let start = o.ttl_offset.checked_sub(5)?; // root, type, class
    (o.rdata_offset + o.rdata_len == msg.len() && msg[start] == 0).then_some((start, o.ttl_offset - 2))
}

/// `query` as the forwarder sends it upstream: announcing EDNS with
/// [`EDNS_UDP_SIZE`] bytes, in its own OPT record (size changed, options and
/// DO kept) or a new one (without DO) appended. Unchanged if its OPT record
/// is not the last record, or it cannot be parsed.
pub fn with_edns_size(query: &[u8]) -> Vec<u8> {
    let mut out = query.to_vec();
    let Ok((h, _, q_end)) = parse_query(query) else {
        return out;
    };
    if let Some((_, class)) = last_opt(query) {
        out[class..class + 2].copy_from_slice(&EDNS_UDP_SIZE.to_be_bytes());
        return out;
    }
    let Ok(recs) = records(query) else {
        return out;
    };
    let end = recs.last().map_or(q_end, |r| r.rdata_offset + r.rdata_len);
    if has_edns(query) || end != query.len() || h.arcount == u16::MAX {
        return out;
    }
    out.push(0); // root
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // flags, no options
    out[10..12].copy_from_slice(&(h.arcount + 1).to_be_bytes());
    out
}

/// Remove `msg`'s OPT record (an answer for a client that sent no EDNS,
/// RFC 6891 §7). Only a last record ([`last_opt`]); false if there was
/// none to remove.
pub fn strip_opt(msg: &mut Vec<u8>) -> bool {
    let (Some((start, _)), Ok(h)) = (last_opt(msg), Header::parse(msg)) else {
        return false;
    };
    msg.truncate(start);
    msg[10..12].copy_from_slice(&(h.arcount - 1).to_be_bytes());
    true
}

/// The Extended DNS Error codes in `msg`'s OPT record.
pub fn ede_codes(msg: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    let Ok(recs) = records(msg) else {
        return out;
    };
    for r in recs.iter().filter(|r| r.section == 2 && r.rtype == TYPE_OPT) {
        let mut pos = r.rdata_offset;
        let end = r.rdata_offset + r.rdata_len;
        while pos + 4 <= end {
            let code = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
            let len = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]) as usize;
            let data = pos + 4;
            if data + len > end {
                break;
            }
            if code == EDNS_OPTION_EDE && len >= 2 {
                out.push(u16::from_be_bytes([msg[data], msg[data + 1]]));
            }
            pos = data + len;
        }
    }
    out
}

/// The DO bit of `msg`'s OPT record: the sender wants DNSSEC records
/// (RRSIG, NSEC, …) in the answer. False without EDNS or when malformed.
pub fn dnssec_ok(msg: &[u8]) -> bool {
    records(msg).is_ok_and(|recs| {
        recs.iter()
            .find(|r| r.section == 2 && r.rtype == TYPE_OPT)
            .is_some_and(|r| msg[r.ttl_offset + 2] & EDNS_DO != 0)
    })
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
    fn upstream_queries_announce_1232_bytes_and_answers_lose_opt_for_plain_clients() {
        let q = build_query(5, "x.example", TYPE_A);
        let up = with_edns_size(&q);
        assert!(has_edns(&up) && !dnssec_ok(&up));
        assert_eq!((udp_limit(&up, 4096), Header::parse(&up).unwrap().arcount), (1232, 1));
        assert_eq!(parse_query(&up).unwrap().1, parse_query(&q).unwrap().1);
        // The client's own OPT: size raised, DO and options kept.
        let mut e = q.clone();
        e[11] = 1;
        e.extend_from_slice(&[0, 0, 41, 0x02, 0x00, 0, 0, 0x80, 0, 0, 4, 0, 10, 0, 0]); // 512, DO, empty cookie
        let up = with_edns_size(&e);
        assert_eq!((up.len(), udp_limit(&up, 4096), dnssec_ok(&up)), (e.len(), 1232, true));
        assert_eq!(&up[up.len() - 6..], &e[e.len() - 6..]);

        // An answer with an OPT record, for a client that sent none.
        let (_, _, end) = parse_query(&q).unwrap();
        let mut a = build_response(&q, end, RCODE_NOERROR, &[(Rdata::A(Ipv4Addr::new(1, 2, 3, 4)), 60)], false);
        let plain = a.clone();
        assert!(add_ede(&mut a, EDE_STALE_ANSWER, "", false));
        assert!(strip_opt(&mut a));
        assert_eq!(a, plain);
        assert!(!strip_opt(&mut a), "nothing left to strip");
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
        let mut base = build_response(
            &q,
            end,
            0,
            &[
                (Rdata::A(Ipv4Addr::new(1, 2, 3, 4)), 300),
                (Rdata::Ptr("x.y".into()), 5),
            ],
            false,
        );
        // With an OPT record carrying an EDE, so the EDNS walkers see one.
        assert!(add_ede(&mut base, EDE_STALE_ANSWER, "x", true));
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
            let _ = (dnssec_ok(&b), has_edns(&b), ede_codes(&b));
            let _ = add_ede(&mut b.clone(), EDE_BLOCKED, "fuzz", false);
            let _ = with_edns_size(&b);
            let mut s = b.clone();
            if strip_opt(&mut s) {
                assert!(!has_edns(&s), "an OPT record left after stripping");
            }
        }
    }

    #[test]
    fn extended_dns_errors_are_added_where_nothing_moves() {
        let q = build_query(5, "x.example", TYPE_A);
        let (_, _, end) = parse_query(&q).unwrap();
        // No OPT yet: one is added (DO echoed on request), ARCOUNT + 1.
        let mut m = error_response(&q, RCODE_SERVFAIL).unwrap();
        assert!(add_ede(&mut m, EDE_NO_REACHABLE_AUTHORITY, "no upstream", true));
        assert_eq!(Header::parse(&m).unwrap().arcount, 1);
        assert!(dnssec_ok(&m) && has_edns(&m));
        assert_eq!(ede_codes(&m), vec![EDE_NO_REACHABLE_AUTHORITY]);
        // An OPT at the end: the option is appended to it.
        assert!(add_ede(&mut m, EDE_STALE_ANSWER, "", true));
        assert_eq!(ede_codes(&m), vec![EDE_NO_REACHABLE_AUTHORITY, EDE_STALE_ANSWER]);
        assert_eq!(Header::parse(&m).unwrap().arcount, 1);
        // An answer with records keeps them intact.
        let mut a = build_response(&q, end, RCODE_NOERROR, &[(Rdata::A(Ipv4Addr::new(1, 2, 3, 4)), 60)], false);
        assert!(add_ede(&mut a, EDE_STALE_ANSWER, "", false));
        assert_eq!(answer_ipv4s(&a, &records(&a).unwrap()), vec![Ipv4Addr::new(1, 2, 3, 4)]);
        assert!(!dnssec_ok(&a));
        // OPT not last, trailing bytes, garbage: unchanged.
        let mut not_last = m.clone();
        not_last.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]); // root A
        not_last[11] += 1;
        let before = not_last.clone();
        assert!(!add_ede(&mut not_last, EDE_STALE_ANSWER, "", false));
        assert_eq!(not_last, before);
        let mut trailing = error_response(&q, RCODE_SERVFAIL).unwrap();
        trailing.push(0);
        assert!(!add_ede(&mut trailing, EDE_STALE_ANSWER, "", false));
        let mut junk = vec![1, 2, 3];
        assert!(!add_ede(&mut junk, EDE_STALE_ANSWER, "", false));
        assert!(ede_codes(&junk).is_empty());
    }
}
