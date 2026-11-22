//! DNS over TCP framing for one client connection (RFC 7766, RFC 1035
//! §4.2.2): each message is preceded by its length (two bytes); a
//! connection may carry several queries, answered in any order
//! (pipelining). Sans-IO: received bytes in, whole queries out; answers in,
//! framed bytes out. The kernel's `net::dns_tcp` moves the bytes.
//!
//! Bounded: queries up to [`MAX_QUERY`] bytes (a length outside
//! 12..=`MAX_QUERY` is not DNS, or more than a query: [`Abort::BadLength`]),
//! at most [`MAX_OUTSTANDING`] unanswered queries (then [`Framing::wants_input`]
//! is false and the caller stops reading: TCP's window holds the client
//! back), at most [`MAX_OUT`] bytes of answers waiting for the client to
//! read ([`Abort::TooMuchOut`]).

use alloc::vec::Vec;

/// Largest query accepted (a query is one question, maybe an OPT record).
pub const MAX_QUERY: usize = 1024;
/// Unanswered queries per connection before reading pauses.
pub const MAX_OUTSTANDING: u16 = 16;
/// Answers queued for the client, framed.
pub const MAX_OUT: usize = 128 * 1024;

/// Why the connection must be aborted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abort {
    /// A length outside 12..=[`MAX_QUERY`].
    BadLength,
    /// The client does not read its answers.
    TooMuchOut,
}

#[derive(Debug, Default)]
pub struct Framing {
    /// Bytes received but not yet a whole message.
    inbuf: Vec<u8>,
    /// Framed answers not yet taken by the caller ([`Self::pending_out`]).
    out: Vec<u8>,
    /// Queries handed out and not answered yet.
    outstanding: u16,
}

impl Framing {
    pub fn new() -> Self {
        Self::default()
    }

    /// The caller may read more from the connection: queries may be
    /// handed out, and at most one query plus a read chunk is buffered.
    pub fn wants_input(&self) -> bool {
        self.outstanding < MAX_OUTSTANDING && self.inbuf.len() < 2 + MAX_QUERY
    }

    /// Received bytes in (none: just take what is buffered); the whole
    /// queries out (without their length), at most up to
    /// [`MAX_OUTSTANDING`] unanswered; the rest stays buffered until
    /// [`Self::answer`]s make room and the next `push`. `Err`: abort the
    /// connection (the framing is cleared).
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, Abort> {
        self.inbuf.extend_from_slice(bytes);
        self.take()
    }

    fn take(&mut self) -> Result<Vec<Vec<u8>>, Abort> {
        let mut queries = Vec::new();
        while self.inbuf.len() >= 2 && self.outstanding < MAX_OUTSTANDING {
            let len = usize::from(u16::from_be_bytes([self.inbuf[0], self.inbuf[1]]));
            if !(12..=MAX_QUERY).contains(&len) {
                self.reset();
                return Err(Abort::BadLength);
            }
            let Some(q) = self.inbuf.get(2..2 + len) else { break };
            queries.push(q.to_vec());
            self.inbuf.drain(..2 + len);
            self.outstanding += 1;
        }
        Ok(queries)
    }

    /// An answer to one of the handed-out queries: framed and queued.
    /// Answers that cannot be framed (over 65535 bytes, which the resolver
    /// never makes) are dropped. `Err`: abort.
    pub fn answer(&mut self, data: &[u8]) -> Result<(), Abort> {
        self.outstanding = self.outstanding.saturating_sub(1);
        if let Ok(len) = u16::try_from(data.len()) {
            if self.out.len() + 2 + data.len() > MAX_OUT {
                self.reset();
                return Err(Abort::TooMuchOut);
            }
            self.out.extend_from_slice(&len.to_be_bytes());
            self.out.extend_from_slice(data);
        }
        Ok(())
    }

    /// Framed answers for the client.
    pub fn pending_out(&self) -> &[u8] {
        &self.out
    }

    /// The caller sent `n` bytes of [`Self::pending_out`].
    pub fn consume_out(&mut self, n: usize) {
        self.out.drain(..n.min(self.out.len()));
    }

    pub fn outstanding(&self) -> u16 {
        self.outstanding
    }

    /// Nothing unanswered and nothing left to send.
    pub fn idle(&self) -> bool {
        self.outstanding == 0 && self.out.is_empty()
    }

    /// Bytes buffered (both directions): bounded by the limits.
    pub fn buffered(&self) -> usize {
        self.inbuf.len() + self.out.len()
    }

    pub fn reset(&mut self) {
        self.inbuf.clear();
        self.out.clear();
        self.outstanding = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn framed(msg: &[u8]) -> Vec<u8> {
        let mut f = (msg.len() as u16).to_be_bytes().to_vec();
        f.extend_from_slice(msg);
        f
    }

    #[test]
    fn queries_split_and_pipelined() {
        let (a, b) = (vec![1u8; 20], vec![2u8; 30]);
        let mut stream = framed(&a);
        stream.extend(framed(&b));
        let mut f = Framing::new();
        let mut got = Vec::new();
        for byte in &stream {
            got.extend(f.push(core::slice::from_ref(byte)).unwrap());
        }
        assert_eq!(got, [a, b]);
        assert_eq!(f.outstanding(), 2);
        f.answer(&[9; 40]).unwrap();
        assert_eq!(f.pending_out(), &framed(&[9; 40])[..]);
        f.consume_out(10);
        assert_eq!(f.pending_out().len(), 32);
        f.consume_out(1000);
        assert!(f.pending_out().is_empty());
        assert!(!f.idle(), "one still outstanding");
        f.answer(&[8; 12]).unwrap();
        f.consume_out(14);
        assert!(f.idle());
    }

    #[test]
    fn bad_lengths_abort() {
        for len in [0u16, 11, MAX_QUERY as u16 + 1, u16::MAX] {
            let mut f = Framing::new();
            assert_eq!(f.push(&len.to_be_bytes()), Err(Abort::BadLength), "{len}");
            assert_eq!(f.buffered(), 0);
        }
        let mut f = Framing::new();
        assert_eq!(f.push(&framed(&[0; MAX_QUERY])).unwrap().len(), 1, "MAX_QUERY itself is fine");
    }

    #[test]
    fn at_most_max_outstanding_then_reading_pauses() {
        let mut f = Framing::new();
        let one = framed(&[0; 12]);
        let stream: Vec<u8> = (0..MAX_OUTSTANDING + 3).flat_map(|_| one.clone()).collect();
        assert_eq!(f.push(&stream).unwrap().len(), usize::from(MAX_OUTSTANDING));
        assert!(!f.wants_input());
        // Each answer makes room for one more buffered query.
        f.answer(&[1; 12]).unwrap();
        assert_eq!(f.push(&[]).unwrap().len(), 1);
        assert_eq!(f.outstanding(), MAX_OUTSTANDING);
        for _ in 0..3 {
            f.answer(&[1; 12]).unwrap();
        }
        assert_eq!(f.push(&[]).unwrap().len(), 2, "the last two");
        assert!(f.wants_input());
    }

    #[test]
    fn a_client_that_does_not_read_is_aborted() {
        let mut f = Framing::new();
        f.push(&framed(&[0; 12])).unwrap();
        let big = vec![0u8; 60_000];
        f.answer(&big).unwrap();
        f.push(&framed(&[0; 12])).unwrap();
        f.answer(&big).unwrap();
        f.push(&framed(&[0; 12])).unwrap();
        assert_eq!(f.answer(&big), Err(Abort::TooMuchOut));
        assert_eq!(f.buffered(), 0);
        // Too big to frame: dropped, not queued.
        let mut f = Framing::new();
        f.push(&framed(&[0; 12])).unwrap();
        f.answer(&vec![0; 70_000]).unwrap();
        assert!(f.idle());
    }
}
