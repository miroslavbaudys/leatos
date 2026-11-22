//! Minimal HTTP/1.1, server side, for the router's management interface.
//!
//! - [`Parser`]: incremental request parser. The head (request line +
//!   headers) is buffered up to a limit; the **body streams through** in
//!   the caller's chunks, so a multi-megabyte upload never needs a second
//!   copy. `Content-Length` bodies only (no chunked encoding), one request
//!   per connection (every response says `Connection: close`).
//! - [`response`]: a complete response with `Content-Length`.
//! - [`basic_auth`], [`ct_eq`]: HTTP Basic credentials, constant-time compare.
//! - [`check_browser_origin`]: refuse DNS-rebound `Host`s and cross-site
//!   requests (CSRF) that only a browser sends.
//! - [`json_str`]: JSON string escaping for status output.
//!
//! `#![no_std]` + `alloc`, sans-IO: bytes in, events and bytes out.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub method: Method,
    /// Path without the query string.
    pub path: String,
    pub content_length: usize,
    /// Header (lower-case name, value) pairs.
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A request error and the status to answer with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadRequest,
    HeadTooLarge,
    LengthRequired,
    BodyTooLarge,
}

impl Error {
    pub fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::HeadTooLarge => 431,
            Self::LengthRequired => 411,
            Self::BodyTooLarge => 413,
        }
    }
}

/// What one [`Parser::push`] produced.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Step<'a> {
    /// The head, the moment it is complete (once per request).
    pub head: Option<Head>,
    /// Body bytes contained in this chunk.
    pub body: &'a [u8],
    /// The whole body has been delivered.
    pub done: bool,
}

#[derive(Debug)]
enum State {
    Head,
    Body { remaining: usize },
    Done,
}

#[derive(Debug)]
pub struct Parser {
    state: State,
    buf: Vec<u8>,
    max_head: usize,
    max_body: usize,
}

impl Parser {
    pub fn new(max_head: usize, max_body: usize) -> Self {
        Self {
            state: State::Head,
            buf: Vec::new(),
            max_head,
            max_body,
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Feed received bytes. Bytes after the end of the body are ignored.
    pub fn push<'a>(&mut self, data: &'a [u8]) -> Result<Step<'a>, Error> {
        let mut step = Step::default();
        let mut rest = data;
        if let State::Head = self.state {
            let before = self.buf.len();
            let take = data.len().min(self.max_head + 4 - before.min(self.max_head + 4));
            self.buf.extend_from_slice(&data[..take]);
            // Search from slightly before the new bytes: the terminator may straddle chunks.
            let from = before.saturating_sub(3);
            let Some(pos) = self.buf[from..].windows(4).position(|w| w == b"\r\n\r\n") else {
                if self.buf.len() > self.max_head {
                    return Err(Error::HeadTooLarge);
                }
                return Ok(step);
            };
            let end = from + pos + 4;
            if end > self.max_head {
                return Err(Error::HeadTooLarge);
            }
            let head = parse_head(&self.buf[..end - 4])?;
            if head.content_length > self.max_body {
                return Err(Error::BodyTooLarge);
            }
            // Bytes of `data` after the terminator are body.
            rest = &data[end - before..];
            self.buf = Vec::new();
            self.state = State::Body {
                remaining: head.content_length,
            };
            step.head = Some(head);
        }
        if let State::Body { remaining } = &mut self.state {
            let n = rest.len().min(*remaining);
            step.body = &rest[..n];
            *remaining -= n;
            if *remaining == 0 {
                self.state = State::Done;
            }
        }
        step.done = self.is_done();
        Ok(step)
    }
}

fn parse_head(raw: &[u8]) -> Result<Head, Error> {
    let text = core::str::from_utf8(raw).map_err(|_| Error::BadRequest)?;
    let mut lines = text.split("\r\n");
    let mut parts = lines.next().ok_or(Error::BadRequest)?.split(' ');
    let (Some(m), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::BadRequest);
    };
    if parts.next().is_some() || !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return Err(Error::BadRequest);
    }
    let method = match m {
        "GET" => Method::Get,
        "POST" => Method::Post,
        _ => Method::Other,
    };
    let path = String::from(target.split('?').next().unwrap_or("/"));
    let mut headers = Vec::new();
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(Error::BadRequest)?;
        if name.is_empty() || name.contains(' ') {
            return Err(Error::BadRequest);
        }
        let (name, value) = (name.to_ascii_lowercase(), value.trim());
        if name == "transfer-encoding" {
            return Err(Error::LengthRequired); // chunked uploads unsupported
        }
        if name == "content-length" {
            let n: usize = value.parse().map_err(|_| Error::BadRequest)?;
            if content_length.is_some_and(|c| c != n) {
                return Err(Error::BadRequest);
            }
            content_length = Some(n);
        }
        headers.push((name, String::from(value)));
    }
    Ok(Head {
        method,
        path,
        content_length: content_length.unwrap_or(0),
        headers,
    })
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// A complete response. `extra` headers are emitted as given.
pub fn response(status: u16, content_type: &str, extra: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n",
        reason(status),
        body.len()
    );
    for (n, v) in extra {
        head.push_str(n);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// (user, password) from `Authorization: Basic …`.
pub fn basic_auth(head: &Head) -> Option<(String, String)> {
    let v = head.header("authorization")?;
    let (scheme, b64) = v.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64_decode(b64.trim())?;
    let s = String::from_utf8(raw).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((String::from(u), String::from(p)))
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// A request a browser may have been made to send by another site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Foreign {
    /// `Host` names neither an IP address nor one of the router's own
    /// names: a page whose name was rebound to the router (DNS rebinding).
    Host,
    /// A request other than `GET` from another site: `Origin` is not the
    /// `Host` it was sent to (or `null`), or, without `Origin`,
    /// `Sec-Fetch-Site` says `cross-site`/`same-site` (CSRF).
    CrossSite,
}

/// Refuse what only a browser tricked by another site sends (security
/// audit, docs/security-audit.md §5 items 1–2). Scripts (no `Origin`, no
/// `Sec-Fetch-Site`, any `Host` that is an address) pass.
///
/// `Host` must be an IP address literal (an origin that is an address
/// cannot be rebound), `localhost`, a single label (`router`), or a name in
/// one of `local_domains` (the router's DNS domains, e.g. `lan`). A missing
/// `Host` passes (HTTP/1.0; browsers always send one).
///
/// For methods other than `GET`, `Origin` (sent by browsers on every POST)
/// must be the same origin as `Host`: `http://<host>[:port]` (or https
/// with its port), compared without case, default ports filled in.
pub fn check_browser_origin(head: &Head, local_domains: &[&str]) -> Result<(), Foreign> {
    let host = match head.header("host") {
        None => None,
        Some(h) => {
            let a = Authority::parse(h, 80).ok_or(Foreign::Host)?;
            if !a.is_local(local_domains) {
                return Err(Foreign::Host);
            }
            Some(a)
        }
    };
    if head.method == Method::Get {
        return Ok(());
    }
    if let Some(origin) = head.header("origin") {
        let origin = origin.trim();
        let (default, rest) = if let Some(r) = strip_prefix_ci(origin, "http://") {
            (80, r)
        } else if let Some(r) = strip_prefix_ci(origin, "https://") {
            (443, r)
        } else {
            return Err(Foreign::CrossSite); // "null", other schemes
        };
        let o = Authority::parse(rest, default).ok_or(Foreign::CrossSite)?;
        return match host {
            Some(h) if h == o => Ok(()),
            _ => Err(Foreign::CrossSite),
        };
    }
    match head.header("sec-fetch-site").map(str::trim) {
        Some(s) if s.eq_ignore_ascii_case("cross-site") || s.eq_ignore_ascii_case("same-site") => {
            Err(Foreign::CrossSite)
        }
        _ => Ok(()),
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

/// `host[:port]` of a `Host` header or an origin, normalised.
#[derive(Debug, PartialEq, Eq)]
struct Authority {
    /// Lower case, no trailing dot; IPv6 without brackets or zone.
    name: String,
    ip: bool,
    port: u16,
}

impl Authority {
    fn parse(s: &str, default_port: u16) -> Option<Self> {
        let s = s.trim();
        let (name, port, ip) = if let Some(rest) = s.strip_prefix('[') {
            let (inner, after) = rest.split_once(']')?;
            let addr = inner.split_once('%').map_or(inner, |(a, _)| a);
            let addr: core::net::Ipv6Addr = addr.parse().ok()?;
            (format!("{addr}"), after, true)
        } else {
            let (name, port) = s.find(':').map_or((s, ""), |i| s.split_at(i));
            if port.len() > 1 && port[1..].contains(':') {
                return None; // an IPv6 address without brackets
            }
            let name = name.strip_suffix('.').unwrap_or(name);
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
            {
                return None;
            }
            let ip = name.parse::<core::net::Ipv4Addr>().is_ok();
            (name.to_ascii_lowercase(), port, ip)
        };
        let port = match port {
            "" => default_port,
            p => p.strip_prefix(':')?.parse().ok()?,
        };
        Some(Self { name, ip, port })
    }

    fn is_local(&self, local_domains: &[&str]) -> bool {
        self.ip
            || self.name == "localhost"
            || !self.name.contains('.')
            || local_domains.iter().any(|d| {
                let d = d.trim_end_matches('.');
                !d.is_empty()
                    && (self.name.eq_ignore_ascii_case(d)
                        || self.name.len() > d.len()
                            && self.name.as_bytes()[self.name.len() - d.len() - 1] == b'.'
                            && self.name[self.name.len() - d.len()..].eq_ignore_ascii_case(d))
            })
    }
}

/// Compare without an early exit on the first differing byte.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `s` as a quoted JSON string.
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            // `<` too: the status JSON may be shown inside HTML.
            '<' => out.push_str("\\u003c"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const UPLOAD: &[u8] = b"POST /api/upgrade?x=1 HTTP/1.1\r\nHost: r\r\nContent-Length: 10\r\nAuthorization: Basic YWRtaW46czNjcmV0\r\n\r\n0123456789TRAILING";

    #[test]
    fn whole_request_in_one_chunk() {
        let mut p = Parser::new(1024, 100);
        let s = p.push(UPLOAD).unwrap();
        let h = s.head.unwrap();
        assert_eq!((h.method, h.path.as_str(), h.content_length), (Method::Post, "/api/upgrade", 10));
        assert_eq!(s.body, b"0123456789", "trailing bytes ignored");
        assert!(s.done);
        assert_eq!(basic_auth(&h), Some(("admin".into(), "s3cret".into())));
    }

    fn req(method: Method, headers: &[(&str, &str)]) -> Head {
        Head {
            method,
            path: "/api/config".into(),
            content_length: 0,
            headers: headers.iter().map(|(n, v)| (n.to_ascii_lowercase(), String::from(*v))).collect(),
        }
    }

    const DOMAINS: &[&str] = &["lan", "guest.lan"];

    #[test]
    fn host_must_be_an_address_or_a_local_name() {
        for ok in [
            "192.168.1.1",
            "192.168.1.1:80",
            "127.0.0.1:18081",
            "[fd13:34ac:fcc9::1]",
            "[FE80::1%25eth0]:8080",
            "localhost:8080",
            "router",
            "router.lan",
            "ROUTER.LAN.",
            "router.guest.lan",
            "lan",
        ] {
            let h = req(Method::Get, &[("Host", ok)]);
            assert_eq!(check_browser_origin(&h, DOMAINS), Ok(()), "{ok}");
        }
        for bad in [
            "rebind.evil.example",
            "evil.example:80",
            "routerlan.evil",
            "lan.evil.example",
            "1.2.3.4.evil.example",
            "fd13::1",
            "[fd13::1",
            "[nonsense]",
            "router.lan:99999",
            "router.lan:",
            "",
            "a b",
        ] {
            let h = req(Method::Get, &[("Host", bad)]);
            assert_eq!(check_browser_origin(&h, DOMAINS), Err(Foreign::Host), "{bad:?}");
        }
        // `xlan` is a single label: allowed; `evil.xlan` is not under `lan`.
        assert_eq!(check_browser_origin(&req(Method::Get, &[("Host", "evil.xlan")]), DOMAINS), Err(Foreign::Host));
        // No domains configured: addresses and single labels only.
        assert_eq!(check_browser_origin(&req(Method::Get, &[("Host", "router.lan")]), &[]), Err(Foreign::Host));
        // No Host at all (HTTP/1.0 scripts).
        assert_eq!(check_browser_origin(&req(Method::Post, &[]), DOMAINS), Ok(()));
    }

    #[test]
    fn post_from_another_origin_is_refused() {
        let post = |h: &[(&str, &str)]| check_browser_origin(&req(Method::Post, h), DOMAINS);
        // The page's own requests.
        assert_eq!(post(&[("Host", "192.168.1.1"), ("Origin", "http://192.168.1.1")]), Ok(()));
        assert_eq!(post(&[("Host", "192.168.1.1:80"), ("Origin", "http://192.168.1.1")]), Ok(()));
        assert_eq!(post(&[("Host", "Router.lan"), ("Origin", "http://router.LAN:80")]), Ok(()));
        assert_eq!(post(&[("Host", "localhost:8080"), ("Origin", "http://localhost:8080")]), Ok(()));
        assert_eq!(post(&[("Host", "[fd00::1]"), ("Origin", "http://[fd00::1]")]), Ok(()));
        // Scripts: no Origin, no Sec-Fetch-Site.
        assert_eq!(post(&[("Host", "192.168.1.1")]), Ok(()));
        assert_eq!(post(&[("Host", "192.168.1.1"), ("Sec-Fetch-Site", "same-origin")]), Ok(()));
        assert_eq!(post(&[("Host", "192.168.1.1"), ("Sec-Fetch-Site", "none")]), Ok(()));
        // Other sites.
        for (o, why) in [
            ("http://evil.example", "another name"),
            ("http://203.0.113.9", "another address"),
            ("http://192.168.1.1:8080", "another port"),
            ("https://192.168.1.1", "another scheme (port 443)"),
            ("null", "opaque origin"),
            ("file://", "other scheme"),
            ("http://", "empty"),
        ] {
            assert_eq!(post(&[("Host", "192.168.1.1"), ("Origin", o)]), Err(Foreign::CrossSite), "{why}");
        }
        assert_eq!(post(&[("Origin", "http://192.168.1.1")]), Err(Foreign::CrossSite), "Origin without Host");
        assert_eq!(post(&[("Host", "192.168.1.1"), ("Sec-Fetch-Site", "cross-site")]), Err(Foreign::CrossSite));
        assert_eq!(post(&[("Host", "192.168.1.1"), ("Sec-Fetch-Site", "same-site")]), Err(Foreign::CrossSite));
        // A foreign Host is reported as such, before the origin.
        assert_eq!(post(&[("Host", "evil.example"), ("Origin", "http://evil.example")]), Err(Foreign::Host));
        // GET is not checked for the origin (responses are not readable cross-site).
        let get = req(Method::Get, &[("Host", "192.168.1.1"), ("Origin", "http://evil.example")]);
        assert_eq!(check_browser_origin(&get, DOMAINS), Ok(()));
    }

    #[test]
    fn byte_by_byte_gives_same_result() {
        let mut p = Parser::new(1024, 100);
        let (mut head, mut body, mut done) = (None, vec![], false);
        for b in UPLOAD.chunks(1) {
            let s = p.push(b).unwrap();
            head = head.or(s.head);
            body.extend_from_slice(s.body);
            done |= s.done;
        }
        assert_eq!(head.unwrap().path, "/api/upgrade");
        assert_eq!(body, b"0123456789");
        assert!(done);
    }

    #[test]
    fn get_without_body_is_done_at_head() {
        let mut p = Parser::new(1024, 0);
        let s = p.push(b"GET /api/status HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(s.head.unwrap().method, Method::Get);
        assert!(s.done);
    }

    #[test]
    fn errors() {
        let e = |req: &[u8], max_head, max_body| Parser::new(max_head, max_body).push(req).unwrap_err();
        assert_eq!(e(b"GARBAGE\r\n\r\n", 100, 0), Error::BadRequest);
        assert_eq!(e(b"GET http://x/ HTTP/1.1\r\n\r\n", 100, 0), Error::BadRequest);
        assert_eq!(e(b"POST / HTTP/1.1\r\nContent-Length: 11\r\n\r\n", 100, 10), Error::BodyTooLarge);
        assert_eq!(e(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", 100, 10), Error::LengthRequired);
        assert_eq!(e(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", 100, 10), Error::BadRequest);
        let mut p = Parser::new(16, 0);
        assert_eq!(p.push(b"GET / HTTP/1.1\r\nX-Long: aaaaaaaaaaaaaaaa").unwrap_err(), Error::HeadTooLarge);
    }

    #[test]
    fn auth_and_helpers() {
        let h = |v: &str| Head {
            method: Method::Get,
            path: "/".into(),
            content_length: 0,
            headers: vec![("authorization".into(), v.into())],
        };
        assert_eq!(basic_auth(&h("Basic YTpi")), Some(("a".into(), "b".into())));
        assert_eq!(basic_auth(&h("Bearer xyz")), None);
        assert_eq!(basic_auth(&h("Basic !!!")), None);
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"ab", b"abc"));
        assert_eq!(json_str("a\"b\\<\n\u{1}"), "\"a\\\"b\\\\\\u003c\\n\\u0001\"");
        let r = response(200, "text/plain", &[("X-A", "1")], b"hi");
        assert_eq!(
            r,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\nCache-Control: no-store\r\nX-A: 1\r\n\r\nhi"
        );
    }
}
