//! DHCPv4 / BOOTP message codec (RFC 2131, RFC 2132).
//!
//! Parsing never panics on malformed input: every length is checked.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;

const BOOTP_FIXED_LEN: usize = 236;
const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// BOOTP minimum message size (some clients reject shorter replies).
const MIN_LEN: usize = 300;

pub const OP_REQUEST: u8 = 1;
pub const OP_REPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
pub const FLAG_BROADCAST: u16 = 0x8000;

// Option codes
const OPT_PAD: u8 = 0;
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_HOSTNAME: u8 = 12;
const OPT_DOMAIN: u8 = 15;
const OPT_BROADCAST: u8 = 28;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_REQUEST: u8 = 55;
const OPT_MESSAGE: u8 = 56;
const OPT_RENEWAL_T1: u8 = 58;
const OPT_REBINDING_T2: u8 = 59;
const OPT_CLIENT_ID: u8 = 61;
/// Classless static routes (RFC 3442).
pub const OPT_CLASSLESS_ROUTES: u8 = 121;
/// The same, under Microsoft's private code (Windows XP/2003 ask for it).
pub const OPT_MS_CLASSLESS_ROUTES: u8 = 249;
const OPT_END: u8 = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl MessageType {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            _ => return None,
        })
    }

    fn to_u8(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
        }
    }
}

/// Decoded options we care about. Unknown options are skipped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub msg_type: Option<MessageType>,
    pub requested_ip: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub client_id: Option<Vec<u8>>,
    pub param_request: Vec<u8>,
    pub lease_time: Option<u32>,
    pub renewal_t1: Option<u32>,
    pub rebinding_t2: Option<u32>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    pub broadcast: Option<Ipv4Addr>,
    pub message: Option<String>,
    /// Option 121 (RFC 3442): (destination, prefix length, router). A
    /// client that takes it ignores option 3, so the default route goes
    /// in here too.
    pub classless_routes: Vec<Route>,
    /// Option 249: the same routes for clients asking under that code.
    pub ms_classless_routes: Vec<Route>,
}

/// A classless static route: (destination, prefix length, router).
pub type Route = (Ipv4Addr, u8, Ipv4Addr);

/// RFC 3442 §3: per route its width, the significant octets of the
/// destination, then the router.
pub fn encode_routes(routes: &[Route]) -> Vec<u8> {
    let mut b = Vec::new();
    for &(dst, len, via) in routes {
        let len = len.min(32);
        b.push(len);
        b.extend_from_slice(&dst.octets()[..len.div_ceil(8) as usize]);
        b.extend_from_slice(&via.octets());
    }
    b
}

/// The routes of option 121/249; `None` if malformed (RFC 3442: then the
/// whole option is ignored).
pub fn decode_routes(mut data: &[u8]) -> Option<Vec<Route>> {
    let mut out = Vec::new();
    while let Some((&len, rest)) = data.split_first() {
        if len > 32 {
            return None;
        }
        let n = len.div_ceil(8) as usize;
        if rest.len() < n + 4 {
            return None;
        }
        let mut dst = [0; 4];
        dst[..n].copy_from_slice(&rest[..n]);
        out.push((Ipv4Addr::from(dst), len, ip(&rest[n..n + 4])));
        data = &rest[n + 4..];
    }
    Some(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub op: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    /// Client hardware (MAC) address; only Ethernet (6 bytes) is supported.
    pub chaddr: [u8; 6],
    pub options: Options,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadMagic,
    NotEthernet,
}

fn ip(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

fn ips(data: &[u8]) -> Vec<Ipv4Addr> {
    data.as_chunks::<4>().0.iter().map(|c| ip(c)).collect()
}

fn u32_be(data: &[u8]) -> Option<u32> {
    (data.len() == 4).then(|| u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

fn text(data: &[u8]) -> String {
    data.iter()
        .take_while(|&&b| b != 0)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '?'
            }
        })
        .collect()
}

impl Message {
    pub fn parse(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < BOOTP_FIXED_LEN + MAGIC.len() {
            return Err(Error::Truncated);
        }
        if buf[BOOTP_FIXED_LEN..BOOTP_FIXED_LEN + 4] != MAGIC {
            return Err(Error::BadMagic);
        }
        if buf[1] != HTYPE_ETHERNET || buf[2] != 6 {
            return Err(Error::NotEthernet);
        }
        let mut chaddr = [0u8; 6];
        chaddr.copy_from_slice(&buf[28..34]);
        let mut msg = Message {
            op: buf[0],
            xid: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            secs: u16::from_be_bytes([buf[8], buf[9]]),
            flags: u16::from_be_bytes([buf[10], buf[11]]),
            ciaddr: ip(&buf[12..16]),
            yiaddr: ip(&buf[16..20]),
            siaddr: ip(&buf[20..24]),
            giaddr: ip(&buf[24..28]),
            chaddr,
            options: Options::default(),
        };

        let mut rest = &buf[BOOTP_FIXED_LEN + 4..];
        while let Some((&code, tail)) = rest.split_first() {
            match code {
                OPT_PAD => {
                    rest = tail;
                    continue;
                }
                OPT_END => break,
                _ => {}
            }
            let Some((&len, tail)) = tail.split_first() else {
                break;
            };
            let len = len as usize;
            if tail.len() < len {
                return Err(Error::Truncated);
            }
            let (data, tail) = tail.split_at(len);
            rest = tail;
            let o = &mut msg.options;
            match code {
                OPT_MSG_TYPE if len == 1 => o.msg_type = MessageType::from_u8(data[0]),
                OPT_REQUESTED_IP if len == 4 => o.requested_ip = Some(ip(data)),
                OPT_SERVER_ID if len == 4 => o.server_id = Some(ip(data)),
                OPT_SUBNET_MASK if len == 4 => o.subnet_mask = Some(ip(data)),
                OPT_BROADCAST if len == 4 => o.broadcast = Some(ip(data)),
                OPT_ROUTER => o.routers = ips(data),
                OPT_DNS => o.dns = ips(data),
                OPT_HOSTNAME if len > 0 => o.hostname = Some(text(data)),
                OPT_DOMAIN if len > 0 => o.domain = Some(text(data)),
                OPT_MESSAGE if len > 0 => o.message = Some(text(data)),
                OPT_CLIENT_ID if len > 0 => o.client_id = Some(data.to_vec()),
                OPT_PARAM_REQUEST => o.param_request = data.to_vec(),
                OPT_CLASSLESS_ROUTES => o.classless_routes = decode_routes(data).unwrap_or_default(),
                OPT_MS_CLASSLESS_ROUTES => o.ms_classless_routes = decode_routes(data).unwrap_or_default(),
                OPT_LEASE_TIME => o.lease_time = u32_be(data),
                OPT_RENEWAL_T1 => o.renewal_t1 = u32_be(data),
                OPT_REBINDING_T2 => o.rebinding_t2 = u32_be(data),
                _ => {} // unknown/unsupported: skipped
            }
        }
        Ok(msg)
    }

    /// Encode, padded to the BOOTP minimum size.
    pub fn emit(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(MIN_LEN + 64);
        b.push(self.op);
        b.push(HTYPE_ETHERNET);
        b.push(6);
        b.push(0); // hops
        b.extend_from_slice(&self.xid.to_be_bytes());
        b.extend_from_slice(&self.secs.to_be_bytes());
        b.extend_from_slice(&self.flags.to_be_bytes());
        for a in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            b.extend_from_slice(&a.octets());
        }
        b.extend_from_slice(&self.chaddr);
        b.resize(BOOTP_FIXED_LEN, 0); // rest of chaddr, sname, file
        b.extend_from_slice(&MAGIC);

        let o = &self.options;
        let mut opt = |code: u8, data: &[u8]| {
            // Options longer than 255 bytes are truncated (never needed here).
            let data = &data[..data.len().min(255)];
            b.push(code);
            b.push(data.len() as u8);
            b.extend_from_slice(data);
        };
        if let Some(t) = o.msg_type {
            opt(OPT_MSG_TYPE, &[t.to_u8()]);
        }
        if let Some(a) = o.server_id {
            opt(OPT_SERVER_ID, &a.octets());
        }
        if let Some(a) = o.requested_ip {
            opt(OPT_REQUESTED_IP, &a.octets());
        }
        for (code, v) in [
            (OPT_LEASE_TIME, o.lease_time),
            (OPT_RENEWAL_T1, o.renewal_t1),
            (OPT_REBINDING_T2, o.rebinding_t2),
        ] {
            if let Some(v) = v {
                opt(code, &v.to_be_bytes());
            }
        }
        if let Some(a) = o.subnet_mask {
            opt(OPT_SUBNET_MASK, &a.octets());
        }
        if let Some(a) = o.broadcast {
            opt(OPT_BROADCAST, &a.octets());
        }
        for (code, list) in [(OPT_ROUTER, &o.routers), (OPT_DNS, &o.dns)] {
            if !list.is_empty() {
                let bytes: Vec<u8> = list.iter().flat_map(|a| a.octets()).collect();
                opt(code, &bytes);
            }
        }
        if let Some(d) = &o.domain {
            opt(OPT_DOMAIN, d.as_bytes());
        }
        for (code, routes) in [
            (OPT_CLASSLESS_ROUTES, &o.classless_routes),
            (OPT_MS_CLASSLESS_ROUTES, &o.ms_classless_routes),
        ] {
            if !routes.is_empty() {
                opt(code, &encode_routes(routes));
            }
        }
        if let Some(h) = &o.hostname {
            opt(OPT_HOSTNAME, h.as_bytes());
        }
        if let Some(m) = &o.message {
            opt(OPT_MESSAGE, m.as_bytes());
        }
        if let Some(c) = &o.client_id {
            opt(OPT_CLIENT_ID, c);
        }
        if !o.param_request.is_empty() {
            opt(OPT_PARAM_REQUEST, &o.param_request);
        }
        b.push(OPT_END);
        if b.len() < MIN_LEN {
            b.resize(MIN_LEN, OPT_PAD);
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn sample() -> Message {
        Message {
            op: OP_REQUEST,
            xid: 0x1234_5678,
            secs: 3,
            flags: FLAG_BROADCAST,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0x52, 0x54, 0, 0, 0, 0x10],
            options: Options {
                msg_type: Some(MessageType::Discover),
                requested_ip: Some(Ipv4Addr::new(192, 168, 1, 150)),
                hostname: Some("laptop".to_string()),
                param_request: vec![1, 3, 6, 15],
                client_id: Some(vec![1, 0x52, 0x54, 0, 0, 0, 0x10]),
                ..Default::default()
            },
        }
    }

    #[test]
    fn roundtrip() {
        let m = sample();
        let bytes = m.emit();
        assert!(bytes.len() >= MIN_LEN);
        assert_eq!(Message::parse(&bytes).unwrap(), m);
    }

    #[test]
    fn classless_routes_rfc3442_examples() {
        let routes = vec![
            (Ipv4Addr::new(10, 17, 0, 0), 16, Ipv4Addr::new(10, 27, 129, 1)),
            (Ipv4Addr::new(10, 229, 0, 128), 25, Ipv4Addr::new(10, 229, 0, 1)),
            (Ipv4Addr::new(10, 198, 122, 47), 32, Ipv4Addr::new(10, 198, 122, 1)),
            (Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::new(192, 168, 1, 1)),
        ];
        let b = encode_routes(&routes);
        // RFC 3442 §3: 10.17/16 → 16.10.17, /25 → 25.10.229.0.128, /0 → 0.
        assert_eq!(&b[..7], &[16, 10, 17, 10, 27, 129, 1]);
        assert_eq!(&b[7..16], &[25, 10, 229, 0, 128, 10, 229, 0, 1]);
        assert_eq!(&b[b.len() - 5..], &[0, 192, 168, 1, 1]);
        assert_eq!(decode_routes(&b), Some(routes.clone()));
        assert_eq!(decode_routes(&[33, 0, 0, 0, 0, 0, 0, 0, 0]), None, "width above 32");
        assert_eq!(decode_routes(&b[..b.len() - 1]), None, "truncated");
        let mut m = sample();
        m.options.classless_routes = routes.clone();
        m.options.ms_classless_routes = routes;
        assert_eq!(Message::parse(&m.emit()).unwrap(), m);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(Message::parse(&[0; 10]), Err(Error::Truncated));
        let mut b = sample().emit();
        b[BOOTP_FIXED_LEN] = 0;
        assert_eq!(Message::parse(&b), Err(Error::BadMagic));
    }

    #[test]
    fn truncated_option_is_an_error_not_a_panic() {
        let mut b = sample().emit();
        let end = b.iter().rposition(|&x| x == OPT_END).unwrap();
        b.truncate(end);
        b.extend_from_slice(&[OPT_HOSTNAME, 50, b'x']); // claims 50 bytes, has 1
        assert_eq!(Message::parse(&b), Err(Error::Truncated));
    }

    #[test]
    fn fuzz_never_panics() {
        // Deterministic pseudo-random mutations of a valid message.
        let base = sample().emit();
        let mut seed = 0x9e37_79b9_u32;
        for _ in 0..20_000 {
            let mut b = base.clone();
            for _ in 0..8 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let i = (seed as usize) % b.len();
                b[i] = (seed >> 8) as u8;
            }
            b.truncate((seed as usize >> 4) % (b.len() + 1));
            let _ = Message::parse(&b);
        }
    }
}
