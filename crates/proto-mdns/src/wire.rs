//! mDNS message format: RFC 1035 wire format with the mDNS twists
//! (RFC 6762 §18): the top bit of a question's class asks for a unicast
//! reply (QU), the top bit of a record's class is cache-flush.
//!
//! A message is parsed whole into owned parts and written back with name
//! compression, so a filter can drop questions and records freely. Names
//! are kept as raw labels: DNS-SD instance names are UTF-8 and may contain
//! spaces and dots. Every read is bounds-checked; compression pointers must
//! point strictly backwards, so decompression always ends.

use alloc::vec::Vec;
use core::net::Ipv4Addr;

pub const PORT: u16 = 5353;
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const GROUP_V6: core::net::Ipv6Addr = core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
pub const HEADER_LEN: usize = 12;
/// RFC 6762 §17: messages up to 9000 bytes.
pub const MAX_MESSAGE: usize = 9000;
const MAX_NAME_WIRE: usize = 255;
const MAX_LABEL: usize = 63;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_ANY: u16 = 255;
pub const CLASS_IN: u16 = 1;
/// QU in a question's class, cache-flush in a record's class.
pub const CLASS_TOP_BIT: u16 = 0x8000;

pub const FLAG_QR: u16 = 0x8000;
pub const FLAG_AA: u16 = 0x0400;
const OPCODE_MASK: u16 = 0x7800;
const RCODE_MASK: u16 = 0x000f;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadName,
    TooLarge,
}

/// A domain name as raw labels (case kept; compare with the `_ignore_case`
/// methods).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    pub fn new(labels: Vec<Vec<u8>>) -> Result<Self, Error> {
        let n = Self { labels };
        if n.labels.iter().any(|l| l.is_empty() || l.len() > MAX_LABEL) || n.wire_len() > MAX_NAME_WIRE {
            return Err(Error::BadName);
        }
        Ok(n)
    }

    /// From dotted text (no escapes; a label cannot contain a dot here).
    pub fn from_dotted(s: &str) -> Result<Self, Error> {
        Self::new(s.split('.').filter(|l| !l.is_empty()).map(|l| l.as_bytes().to_vec()).collect())
    }

    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// Length on the wire, uncompressed.
    pub fn wire_len(&self) -> usize {
        self.labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1
    }

    pub fn eq_ignore_case(&self, other: &Name) -> bool {
        self.labels.len() == other.labels.len()
            && self.labels.iter().zip(&other.labels).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// Whether the last labels equal `suffix` (ASCII case-insensitive).
    pub fn ends_with_ignore_case(&self, suffix: &[&[u8]]) -> bool {
        self.labels.len() >= suffix.len()
            && self.labels[self.labels.len() - suffix.len()..]
                .iter()
                .zip(suffix)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    /// With the QU bit ([`CLASS_TOP_BIT`]).
    pub qclass: u16,
}

/// Record data. For types that carry a name (PTR, CNAME, NS, MX, SRV, NSEC)
/// the name is decompressed into `name`, with the fixed bytes before it in
/// `pre` (SRV: priority, weight, port) and the rest after it in `post`
/// (NSEC: the type bitmap). Other types: everything in `pre`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rdata {
    pub pre: Vec<u8>,
    pub name: Option<Name>,
    pub post: Vec<u8>,
}

impl Rdata {
    pub fn raw(b: &[u8]) -> Self {
        Self { pre: b.to_vec(), name: None, post: Vec::new() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: u16,
    /// With the cache-flush bit ([`CLASS_TOP_BIT`]).
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Rdata,
}

impl Record {
    /// The IPv4 address of an A record.
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        let d: [u8; 4] = (self.rtype == TYPE_A).then(|| self.rdata.pre.as_slice().try_into().ok()).flatten()?;
        Some(Ipv4Addr::from(d))
    }

    /// Whether an A/AAAA record holds a link-local address (169.254/16,
    /// fe80::/10): useless on another network.
    pub fn is_link_local_address(&self) -> bool {
        let d = &self.rdata.pre;
        match self.rtype {
            TYPE_A => self.ipv4().is_some_and(|a| a.is_link_local()),
            TYPE_AAAA => d.len() == 16 && d[0] == 0xfe && d[1] & 0xc0 == 0x80,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

impl Message {
    pub fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }

    pub fn opcode(&self) -> u8 {
        ((self.flags & OPCODE_MASK) >> 11) as u8
    }

    pub fn rcode(&self) -> u8 {
        (self.flags & RCODE_MASK) as u8
    }

    /// Parse a whole message. Bytes after the last record are ignored.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLarge);
        }
        if b.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let w = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
        let (qd, an, ns, ar) = (w(4) as usize, w(6) as usize, w(8) as usize, w(10) as usize);
        // A question takes ≥ 5 bytes, a record ≥ 11: refuse counts the
        // message cannot hold before allocating for them.
        if qd * 5 + (an + ns + ar) * 11 > b.len() - HEADER_LEN {
            return Err(Error::Truncated);
        }
        let mut m = Message { id: w(0), flags: w(2), ..Default::default() };
        let mut pos = HEADER_LEN;
        for _ in 0..qd {
            let (name, p) = read_name(b, pos)?;
            let f = b.get(p..p + 4).ok_or(Error::Truncated)?;
            m.questions.push(Question {
                name,
                qtype: u16::from_be_bytes([f[0], f[1]]),
                qclass: u16::from_be_bytes([f[2], f[3]]),
            });
            pos = p + 4;
        }
        for (count, section) in [(an, &mut m.answers), (ns, &mut m.authority), (ar, &mut m.additional)] {
            for _ in 0..count {
                let (r, p) = read_record(b, pos)?;
                section.push(r);
                pos = p;
            }
        }
        Ok(m)
    }

    /// Write the message, compressing names where RFC 6762 §18.14 allows.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let count = |n: usize| u16::try_from(n).map_err(|_| Error::TooLarge);
        let mut w = Writer::default();
        for v in [
            self.id,
            self.flags,
            count(self.questions.len())?,
            count(self.answers.len())?,
            count(self.authority.len())?,
            count(self.additional.len())?,
        ] {
            w.u16(v);
        }
        for q in &self.questions {
            w.name(&q.name, true);
            w.u16(q.qtype);
            w.u16(q.qclass);
        }
        for r in self.answers.iter().chain(&self.authority).chain(&self.additional) {
            w.record(r)?;
        }
        Ok(w.out)
    }
}

/// Read a (possibly compressed) name at `start`. Returns it and the offset
/// just after the name at its original position.
fn read_name(msg: &[u8], start: usize) -> Result<(Name, usize), Error> {
    let mut labels = Vec::new();
    let mut pos = start;
    // A pointer must point before the run of labels it ends: each jump
    // goes strictly backwards, so there are no loops.
    let mut limit = start;
    let mut end = None;
    let mut wire = 1;
    loop {
        let len = *msg.get(pos).ok_or(Error::Truncated)? as usize;
        match len & 0xc0 {
            0x00 if len == 0 => return Ok((Name { labels }, end.unwrap_or(pos + 1))),
            0x00 => {
                let label = msg.get(pos + 1..pos + 1 + len).ok_or(Error::Truncated)?;
                wire += 1 + len;
                if wire > MAX_NAME_WIRE {
                    return Err(Error::BadName);
                }
                labels.push(label.to_vec());
                pos += 1 + len;
            }
            0xc0 => {
                let lo = *msg.get(pos + 1).ok_or(Error::Truncated)? as usize;
                let target = ((len & 0x3f) << 8) | lo;
                if target >= limit {
                    return Err(Error::BadName);
                }
                end.get_or_insert(pos + 2);
                limit = target;
                pos = target;
            }
            _ => return Err(Error::BadName),
        }
    }
}

fn read_record(msg: &[u8], pos: usize) -> Result<(Record, usize), Error> {
    let (name, p) = read_name(msg, pos)?;
    let f = msg.get(p..p + 10).ok_or(Error::Truncated)?;
    let rtype = u16::from_be_bytes([f[0], f[1]]);
    let rclass = u16::from_be_bytes([f[2], f[3]]);
    let ttl = u32::from_be_bytes([f[4], f[5], f[6], f[7]]);
    let len = u16::from_be_bytes([f[8], f[9]]) as usize;
    let (off, end) = (p + 10, p + 10 + len);
    let raw = msg.get(off..end).ok_or(Error::Truncated)?;
    let pre_len = match rtype {
        TYPE_NS | TYPE_CNAME | TYPE_PTR | TYPE_NSEC => 0,
        TYPE_MX => 2,
        TYPE_SRV => 6,
        _ => return Ok((Record { name, rtype, rclass, ttl, rdata: Rdata::raw(raw) }, end)),
    };
    if len <= pre_len {
        return Err(Error::Truncated);
    }
    // The name must end inside the rdata.
    let (target, after) = read_name(&msg[..end], off + pre_len)?;
    let rdata = Rdata { pre: raw[..pre_len].to_vec(), name: Some(target), post: msg[after..end].to_vec() };
    Ok((Record { name, rtype, rclass, ttl, rdata }, end))
}

/// Writes a message; remembers where name suffixes were written so later
/// names can point at them.
#[derive(Default)]
struct Writer {
    out: Vec<u8>,
    suffixes: Vec<(Vec<Vec<u8>>, u16)>,
}

impl Writer {
    fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    fn name(&mut self, n: &Name, compress: bool) {
        for i in 0..n.labels.len() {
            let suffix = &n.labels[i..];
            if compress {
                if let Some(&(_, off)) = self.suffixes.iter().find(|(s, _)| s.as_slice() == suffix) {
                    self.u16(0xc000 | off);
                    return;
                }
                if self.out.len() < 0x4000 {
                    self.suffixes.push((suffix.to_vec(), self.out.len() as u16));
                }
            }
            self.out.push(n.labels[i].len() as u8);
            self.out.extend_from_slice(&n.labels[i]);
        }
        self.out.push(0);
    }

    fn record(&mut self, r: &Record) -> Result<(), Error> {
        self.name(&r.name, true);
        self.u16(r.rtype);
        self.u16(r.rclass);
        self.out.extend_from_slice(&r.ttl.to_be_bytes());
        let len_at = self.out.len();
        self.u16(0);
        self.out.extend_from_slice(&r.rdata.pre);
        if let Some(n) = &r.rdata.name {
            // NSEC's next domain name is never compressed (RFC 4034 §4.1.1).
            self.name(n, r.rtype != TYPE_NSEC);
        }
        self.out.extend_from_slice(&r.rdata.post);
        let len = u16::try_from(self.out.len() - len_at - 2).map_err(|_| Error::TooLarge)?;
        self.out[len_at..len_at + 2].copy_from_slice(&len.to_be_bytes());
        Ok(())
    }
}
