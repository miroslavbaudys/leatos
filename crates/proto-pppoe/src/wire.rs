//! PPPoE (RFC 2516) and PPP (RFC 1661) wire formats.
//!
//! Two kinds of users:
//! - the datapath, per packet and without allocating: [`classify_session`],
//!   [`decap_ipv4`], [`encap_ipv4`], [`write_padt`] work on frames in place;
//! - the [`crate::Client`] (control plane): builders that return a new
//!   `Vec` per frame, and parsers.
//!
//! All frames here are Ethernet frames without an 802.1Q tag (the kernel
//! removes and adds the tag at the datapath's ends).

use alloc::vec::Vec;

pub type Mac = [u8; 6];

pub const ETH_HDR: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_DISCOVERY: u16 = 0x8863;
pub const ETHERTYPE_SESSION: u16 = 0x8864;
/// Version/type byte: version 1, type 1.
pub const VER_TYPE: u8 = 0x11;
pub const PPPOE_HDR: usize = 6;
/// What session encapsulation adds to an IPv4 packet: the PPPoE header and
/// the PPP protocol field (the Ethernet header is there either way).
pub const SESSION_OVERHEAD: usize = PPPOE_HDR + 2;
/// Ethernet frames shorter than this are padded (the PPPoE length field
/// says where the payload ends).
pub const MIN_FRAME: usize = 60;
pub const BROADCAST: Mac = [0xff; 6];

// Discovery codes.
pub const PADI: u8 = 0x09;
pub const PADO: u8 = 0x07;
pub const PADR: u8 = 0x19;
pub const PADS: u8 = 0x65;
pub const PADT: u8 = 0xa7;

// Discovery tags.
pub const TAG_END_OF_LIST: u16 = 0x0000;
pub const TAG_SERVICE_NAME: u16 = 0x0101;
pub const TAG_AC_NAME: u16 = 0x0102;
pub const TAG_HOST_UNIQ: u16 = 0x0103;
pub const TAG_AC_COOKIE: u16 = 0x0104;
pub const TAG_RELAY_SESSION_ID: u16 = 0x0110;
pub const TAG_SERVICE_NAME_ERROR: u16 = 0x0201;
pub const TAG_AC_SYSTEM_ERROR: u16 = 0x0202;
pub const TAG_GENERIC_ERROR: u16 = 0x0203;

// PPP protocols.
pub const PPP_IPV4: u16 = 0x0021;
pub const PPP_IPV6: u16 = 0x0057;
pub const PPP_IPCP: u16 = 0x8021;
pub const PPP_IPV6CP: u16 = 0x8057;
pub const PPP_LCP: u16 = 0xc021;
pub const PPP_PAP: u16 = 0xc023;
pub const PPP_CHAP: u16 = 0xc223;

// LCP / NCP codes (RFC 1661 §5).
pub const CONF_REQ: u8 = 1;
pub const CONF_ACK: u8 = 2;
pub const CONF_NAK: u8 = 3;
pub const CONF_REJ: u8 = 4;
pub const TERM_REQ: u8 = 5;
pub const TERM_ACK: u8 = 6;
pub const CODE_REJ: u8 = 7;
pub const PROTO_REJ: u8 = 8;
pub const ECHO_REQ: u8 = 9;
pub const ECHO_REPLY: u8 = 10;
pub const DISCARD_REQ: u8 = 11;

pub fn get16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_be_bytes());
}

/// An established session: what the datapath needs to encapsulate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    /// Never 0 (RFC 2516: 0 is reserved for discovery).
    pub id: u16,
    /// The access concentrator's MAC.
    pub peer: Mac,
}

impl Session {
    /// Session ID and peer MAC in one `u64` (0 = no session), so the
    /// datapath can read it from one atomic.
    pub fn pack(self) -> u64 {
        let mut b = [0u8; 8];
        b[..2].copy_from_slice(&self.id.to_be_bytes());
        b[2..].copy_from_slice(&self.peer);
        u64::from_be_bytes(b)
    }

    pub fn unpack(v: u64) -> Option<Self> {
        let b = v.to_be_bytes();
        let id = u16::from_be_bytes([b[0], b[1]]);
        let mut peer = [0; 6];
        peer.copy_from_slice(&b[2..]);
        (id != 0).then_some(Session { id, peer })
    }
}

/// A parsed PPPoE frame (discovery or session stage).
#[derive(Clone, Copy, Debug)]
pub struct Pppoe<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
    pub code: u8,
    pub session: u16,
    /// The payload as long as the PPPoE length field says (Ethernet
    /// padding cut off).
    pub payload: &'a [u8],
}

fn mac_at(f: &[u8], off: usize) -> Mac {
    let mut m = [0; 6];
    m.copy_from_slice(&f[off..off + 6]);
    m
}

/// Parse the Ethernet + PPPoE headers. `None`: not PPPoE, wrong
/// version/type, or the length field points past the frame.
pub fn parse(frame: &[u8]) -> Option<Pppoe<'_>> {
    if frame.len() < ETH_HDR + PPPOE_HDR {
        return None;
    }
    let ethertype = get16(frame, 12);
    if ethertype != ETHERTYPE_DISCOVERY && ethertype != ETHERTYPE_SESSION {
        return None;
    }
    let h = &frame[ETH_HDR..];
    if h[0] != VER_TYPE {
        return None;
    }
    let len = get16(h, 4) as usize;
    let payload = h.get(PPPOE_HDR..PPPOE_HDR + len)?;
    Some(Pppoe {
        dst: mac_at(frame, 0),
        src: mac_at(frame, 6),
        ethertype,
        code: h[1],
        session: get16(h, 2),
        payload,
    })
}

/// What the datapath does with a received session-stage frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRx {
    /// IPv4 in the current session: `len` bytes of IP packet after the
    /// 22 bytes of headers ([`decap_ipv4`]).
    Ipv4 { len: usize },
    /// Anything else (LCP, authentication, NCPs, another session, a
    /// malformed frame): for the control plane, which checks it.
    Control,
}

/// Classify a frame with EtherType `0x8864` for the datapath.
pub fn classify_session(frame: &[u8], session: Option<Session>) -> SessionRx {
    let Some(s) = session else {
        return SessionRx::Control;
    };
    match parse(frame) {
        Some(p)
            if p.ethertype == ETHERTYPE_SESSION
                && p.code == 0
                && p.session == s.id
                && p.src == s.peer
                && p.payload.len() >= 2
                && get16(p.payload, 0) == PPP_IPV4 =>
        {
            SessionRx::Ipv4 {
                len: p.payload.len() - 2,
            }
        }
        _ => SessionRx::Control,
    }
}

/// Turn a PPPoE session frame carrying IPv4 ([`SessionRx::Ipv4`]) into
/// an Ethernet/IPv4 frame in place: the MAC addresses move 8 bytes
/// forward and EtherType 0x0800 replaces the PPP protocol field. The new
/// frame starts at offset [`SESSION_OVERHEAD`] and is `ETH_HDR + len`
/// bytes long.
pub fn decap_ipv4(frame: &mut [u8]) {
    frame.copy_within(0..12, SESSION_OVERHEAD);
    put16(frame, SESSION_OVERHEAD + 12, ETHERTYPE_IPV4);
}

/// Encapsulate an Ethernet/IPv4 frame for session `s`: `frame` is the
/// frame with [`SESSION_OVERHEAD`] bytes prepended (from headroom), so
/// `frame.len() == SESSION_OVERHEAD + ETH_HDR + ip_len`. Writes the
/// Ethernet header (to the peer, from `src`), the PPPoE header and the
/// PPP protocol field over the first 22 bytes; the old EtherType's place
/// becomes the protocol field.
pub fn encap_ipv4(frame: &mut [u8], s: Session, src: Mac) {
    let ip_len = frame.len() - SESSION_OVERHEAD - ETH_HDR;
    frame[0..6].copy_from_slice(&s.peer);
    frame[6..12].copy_from_slice(&src);
    put16(frame, 12, ETHERTYPE_SESSION);
    frame[14] = VER_TYPE;
    frame[15] = 0;
    put16(frame, 16, s.id);
    put16(frame, 18, (ip_len + 2) as u16);
    put16(frame, 20, PPP_IPV4);
}

/// A PADT for session `s` into `buf` (at least [`MIN_FRAME`] bytes, zeroed
/// padding); returns the frame length. For the datapath at shutdown.
pub fn write_padt(buf: &mut [u8], s: Session, src: Mac) -> usize {
    buf[..MIN_FRAME].fill(0);
    buf[0..6].copy_from_slice(&s.peer);
    buf[6..12].copy_from_slice(&src);
    put16(buf, 12, ETHERTYPE_DISCOVERY);
    buf[14] = VER_TYPE;
    buf[15] = PADT;
    put16(buf, 16, s.id);
    put16(buf, 18, 0);
    MIN_FRAME
}

fn frame(dst: Mac, src: Mac, ethertype: u16, code: u8, session: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity((ETH_HDR + PPPOE_HDR + payload.len()).max(MIN_FRAME));
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.push(VER_TYPE);
    f.push(code);
    f.extend_from_slice(&session.to_be_bytes());
    f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    f.extend_from_slice(payload);
    if f.len() < MIN_FRAME {
        f.resize(MIN_FRAME, 0);
    }
    f
}

/// A discovery frame with the given tags (in order).
pub fn discovery(dst: Mac, src: Mac, code: u8, session: u16, tags: &[(u16, &[u8])]) -> Vec<u8> {
    let mut p = Vec::new();
    for (t, v) in tags {
        p.extend_from_slice(&t.to_be_bytes());
        p.extend_from_slice(&(v.len() as u16).to_be_bytes());
        p.extend_from_slice(v);
    }
    frame(dst, src, ETHERTYPE_DISCOVERY, code, session, &p)
}

/// A session frame: PPP protocol `proto` with `body`.
pub fn session_frame(dst: Mac, src: Mac, session: u16, proto: u16, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(2 + body.len());
    p.extend_from_slice(&proto.to_be_bytes());
    p.extend_from_slice(body);
    frame(dst, src, ETHERTYPE_SESSION, 0, session, &p)
}

/// Discovery tags: `(type, value)` up to End-Of-List or a truncated tag.
pub fn tags(payload: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut rest = payload;
    core::iter::from_fn(move || {
        if rest.len() < 4 {
            return None;
        }
        let t = get16(rest, 0);
        let len = get16(rest, 2) as usize;
        let v = rest.get(4..4 + len)?;
        rest = &rest[4 + len..];
        (t != TAG_END_OF_LIST).then_some((t, v))
    })
}

pub fn find_tag(payload: &[u8], tag: u16) -> Option<&[u8]> {
    tags(payload).find(|(t, _)| *t == tag).map(|(_, v)| v)
}

/// A PPP control packet (LCP, NCP, PAP, CHAP share the layout).
#[derive(Clone, Copy, Debug)]
pub struct Ctrl<'a> {
    pub code: u8,
    pub id: u8,
    /// After the 4-byte header, as long as the length field says.
    pub data: &'a [u8],
}

pub fn parse_ctrl(body: &[u8]) -> Option<Ctrl<'_>> {
    if body.len() < 4 {
        return None;
    }
    let len = get16(body, 2) as usize;
    if len < 4 {
        return None;
    }
    Some(Ctrl {
        code: body[0],
        id: body[1],
        data: body.get(4..len)?,
    })
}

pub fn ctrl(code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + data.len());
    b.push(code);
    b.push(id);
    b.extend_from_slice(&((4 + data.len()) as u16).to_be_bytes());
    b.extend_from_slice(data);
    b
}

/// Configuration options `(type, value)`; `None` if one is malformed
/// (length below 2 or past the end): the whole packet is then invalid.
pub fn options(data: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut v = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        if rest.len() < 2 {
            return None;
        }
        let len = rest[1] as usize;
        if len < 2 || len > rest.len() {
            return None;
        }
        v.push((rest[0], &rest[2..len]));
        rest = &rest[len..];
    }
    Some(v)
}

pub fn put_option(out: &mut Vec<u8>, kind: u8, value: &[u8]) {
    out.push(kind);
    out.push((2 + value.len()) as u8);
    out.extend_from_slice(value);
}
