//! DNS over TCP framing (`proto_dns::tcp`), reachable from every LAN
//! client on port 53: arbitrary bytes pushed in arbitrary pieces, answers
//! and partial sends interleaved. Checks: every query handed out is
//! 12..=MAX_QUERY bytes and matches a reference parse of the same stream;
//! never more than MAX_OUTSTANDING unanswered; buffers stay bounded;
//! what goes out is exactly the framed answers in order.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use proto_dns::tcp::{Framing, MAX_OUT, MAX_OUTSTANDING, MAX_QUERY};

#[derive(Arbitrary, Debug)]
enum Op {
    Push(Vec<u8>),
    Answer(u16),
    Send(u16),
}

fuzz_target!(|ops: Vec<Op>| {
    let mut f = Framing::new();
    let mut stream = Vec::new(); // everything pushed since the last abort
    let mut seen = 0usize; // bytes of `stream` the queries so far covered
    let mut handed = 0u32; // queries handed out, minus answers
    let mut expect_out: Vec<u8> = Vec::new();
    for op in ops.into_iter().take(256) {
        match op {
            Op::Push(b) => {
                stream.extend_from_slice(&b);
                match f.push(&b) {
                    Ok(qs) => {
                        for q in qs {
                            assert!((12..=MAX_QUERY).contains(&q.len()));
                            let len = usize::from(u16::from_be_bytes([stream[seen], stream[seen + 1]]));
                            assert_eq!(&stream[seen + 2..seen + 2 + len], &q[..], "not the next message");
                            seen += 2 + len;
                            handed += 1;
                        }
                    }
                    Err(_) => {
                        assert_eq!(f.buffered(), 0);
                        (stream, seen, handed, expect_out) = (Vec::new(), 0, 0, Vec::new());
                    }
                }
            }
            Op::Answer(len) => {
                let data = vec![0xab; usize::from(len)];
                match f.answer(&data) {
                    Ok(()) => {
                        expect_out.extend_from_slice(&len.to_be_bytes());
                        expect_out.extend_from_slice(&data);
                        handed = handed.saturating_sub(1);
                    }
                    Err(_) => {
                        assert_eq!(f.buffered(), 0);
                        (stream, seen, handed, expect_out) = (Vec::new(), 0, 0, Vec::new());
                    }
                }
            }
            Op::Send(n) => {
                let n = usize::from(n).min(f.pending_out().len());
                assert_eq!(f.pending_out(), &expect_out[..], "out of order or damaged");
                f.consume_out(n);
                expect_out.drain(..n);
            }
        }
        assert!(u32::from(f.outstanding()) <= u32::from(MAX_OUTSTANDING));
        assert_eq!(u32::from(f.outstanding()), handed);
        assert!(f.pending_out().len() <= MAX_OUT);
        assert_eq!(f.pending_out(), &expect_out[..]);
    }
});
