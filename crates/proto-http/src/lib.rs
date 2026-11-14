//! Minimal HTTP/1.1, server side, for the router's management interface.
//!
//! - [`Parser`]: incremental request parser. The head (request line +
//!   headers) is buffered up to a limit; the **body streams through** in
//!   the caller's chunks, so a multi-megabyte upload never needs a second
//!   copy. `Content-Length` bodies only (no chunked encoding), one request
//!   per connection (every response says `Connection: close`).
//! - [`response`]: a complete response with `Content-Length`.
//! - [`basic_auth`], [`ct_eq`]: HTTP Basic credentials, constant-time compare.
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
