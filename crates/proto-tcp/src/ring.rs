//! A fixed byte ring: the send buffer (bytes not yet acknowledged, the
//! front is `snd_una`) and the receive buffer (bytes not yet read; data
//! that arrived out of order sits past the readable end, uncommitted).

use alloc::vec;
use alloc::vec::Vec;

pub(crate) struct Ring {
    buf: Vec<u8>,
    head: usize,
    len: usize,
}

impl Ring {
    pub fn new(cap: usize) -> Self {
        Self { buf: vec![0; cap], head: 0, len: 0 }
    }

    pub fn cap(&self) -> usize {
        self.buf.len()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn free(&self) -> usize {
        self.cap() - self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    fn at(&self, i: usize) -> usize {
        (self.head + i) % self.cap().max(1)
    }

    /// Write `data` at `off` bytes past the readable end, without making it
    /// readable; as much as fits. Returns the bytes written.
    pub fn write_at(&mut self, off: usize, data: &[u8]) -> usize {
        let room = self.free().saturating_sub(off);
        let n = data.len().min(room);
        let start = self.at(self.len + off);
        let first = n.min(self.cap() - start);
        self.buf[start..start + first].copy_from_slice(&data[..first]);
        self.buf[..n - first].copy_from_slice(&data[first..n]);
        n
    }

    /// Make `n` written bytes readable (`n <= free`).
    pub fn commit(&mut self, n: usize) {
        self.len += n.min(self.free());
    }

    /// Append as much of `data` as fits.
    pub fn push(&mut self, data: &[u8]) -> usize {
        let n = self.write_at(0, data);
        self.commit(n);
        n
    }

    /// Drop `n` bytes from the front.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.len);
        self.head = self.at(n);
        // The head stays where it is even when nothing is left to read:
        // out-of-order bytes past the end are placed relative to it.
        self.len -= n;
    }

    /// The readable bytes `[off, off + n)` as up to two slices.
    pub fn slices(&self, off: usize, n: usize) -> (&[u8], &[u8]) {
        let n = n.min(self.len.saturating_sub(off));
        if n == 0 {
            return (&[], &[]);
        }
        let start = self.at(off);
        let first = n.min(self.cap() - start);
        (&self.buf[start..start + first], &self.buf[..n - first])
    }

    /// Copy out and drop up to `out.len()` bytes.
    pub fn pop(&mut self, out: &mut [u8]) -> usize {
        let (a, b) = self.slices(0, out.len());
        let n = a.len() + b.len();
        out[..a.len()].copy_from_slice(a);
        out[a.len()..n].copy_from_slice(b);
        self.consume(n);
        n
    }
}
