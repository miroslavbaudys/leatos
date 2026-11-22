//! The management web server's HTTP/1.1 parser (`crates/proto-http`),
//! reachable from the LAN before authentication. The same bytes are fed
//! whole and in fuzzer-chosen pieces. Checks: the body never exceeds the
//! limit or Content-Length; when both feeds complete, they agree on the
//! head and the body. Also `basic_auth`, `json_str` and
//! `check_browser_origin` on what was parsed (the Host/Origin parsers run
//! before auth): a GET with a foreign `Origin` is never refused as cross-site.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_http::{Foreign, Head, Method, Parser, basic_auth, check_browser_origin, json_str};

const MAX_HEAD: usize = 4096;
const MAX_BODY: usize = 8192;

/// Feed `pieces`; Ok((head, body)) once done, Err on an error, None if not
/// finished.
fn feed<'a>(pieces: impl Iterator<Item = &'a [u8]>) -> Option<Result<(Head, Vec<u8>), proto_http::Error>> {
    let mut p = Parser::new(MAX_HEAD, MAX_BODY);
    let mut head = None;
    let mut body = Vec::new();
    for chunk in pieces {
        match p.push(chunk) {
            Err(e) => return Some(Err(e)),
            Ok(step) => {
                if let Some(h) = step.head {
                    assert!(head.is_none(), "head delivered twice");
                    assert!(h.content_length <= MAX_BODY);
                    head = Some(h);
                }
                body.extend_from_slice(step.body);
                assert!(body.len() <= MAX_BODY);
                if let Some(h) = &head {
                    assert!(body.len() <= h.content_length, "more body than Content-Length");
                }
                if step.done {
                    assert!(p.is_done());
                    let h = head.expect("done without a head");
                    assert_eq!(body.len(), h.content_length);
                    // Bytes after the end are ignored.
                    let after = p.push(b"GET / HTTP/1.1\r\n\r\n");
                    assert!(after.is_ok_and(|s| s.body.is_empty() && s.head.is_none()));
                    return Some(Ok((h, body)));
                }
            }
        }
    }
    None
}

fuzz_target!(|input: (Vec<u8>, Vec<u8>)| {
    let (cuts, data) = input;
    let whole = feed(core::iter::once(&data[..]));
    // Pieces at the fuzzer's cut lengths.
    let mut pieces = Vec::new();
    let mut rest = &data[..];
    for &c in &cuts {
        if rest.is_empty() {
            break;
        }
        let n = (c as usize % 64 + 1).min(rest.len());
        pieces.push(&rest[..n]);
        rest = &rest[n..];
    }
    pieces.push(rest);
    let split = feed(pieces.into_iter());
    if let (Some(Ok(a)), Some(Ok(b))) = (&whole, &split) {
        assert_eq!(a, b, "whole and split feeds disagree");
    }
    for r in [whole, split].into_iter().flatten().flatten() {
        let _ = basic_auth(&r.0);
        let _ = json_str(&r.0.path);
        let _ = r.0.header("authorization");
        let v = check_browser_origin(&r.0, &["lan", "guest.lan"]);
        if r.0.method == Method::Get {
            assert_ne!(v, Err(Foreign::CrossSite), "GET checked for its origin");
        }
    }
});
