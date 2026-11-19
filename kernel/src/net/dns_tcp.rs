//! DNS over TCP from clients (RFC 7766, RFC 1035 §4.2.2): port 53 on each
//! network's address, next to the UDP socket (`net::services`).
//!
//! A client asks over TCP when a UDP answer came back truncated (TC: too
//! big for 512 bytes, or for its EDNS size), or always (some resolvers,
//! `dig +tcp`). Each message is preceded by its length (two bytes); a
//! connection may carry several queries, and answers may come back in any
//! order (pipelining, RFC 7766 §6.2.1.1), each as soon as the resolver has
//! it.
//!
//! Bounded: [`CONNS`] connections per network (more are refused with a
//! RST by smoltcp: no socket listens), queries up to [`MAX_QUERY`] bytes
//! (larger: the connection is aborted), at most [`MAX_OUTSTANDING`]
//! unanswered queries per connection (then reading stops and TCP's window
//! holds the client back), [`MAX_OUT`] bytes of answers waiting for the
//! client to read (more: aborted). A connection with nothing to answer is
//! closed after [`IDLE_MS`] without traffic; one still waiting after
//! [`HARD_MS`] is aborted.
//!
//! The boot argument `dns_tcp=0` opens no listeners (`config::dns_tcp`).

use alloc::vec;
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicU64, Ordering};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;

const PORT: u16 = 53;
/// Connections per network.
pub const CONNS: usize = 4;
const RX_BUF: usize = 2048;
const TX_BUF: usize = 16 * 1024;
/// Largest query accepted (a query is one question, maybe an OPT record).
pub const MAX_QUERY: usize = 1024;
/// Unanswered queries per connection before reading pauses.
pub const MAX_OUTSTANDING: u16 = 16;
/// Answers queued beyond the socket's send buffer, per connection.
pub const MAX_OUT: usize = 128 * 1024;
/// A connection with nothing outstanding is closed after this long
/// without traffic.
pub const IDLE_MS: u64 = 10_000;
/// Any connection is aborted after this long without traffic (the
/// resolver answers or fails every query well before).
pub const HARD_MS: u64 = 30_000;

/// Connections accepted since boot (all networks; `/api/status`).
static ACCEPTED: AtomicU64 = AtomicU64::new(0);

pub fn accepted() -> u64 {
    ACCEPTED.load(Ordering::Relaxed)
}

struct Conn {
    sock: SocketHandle,
    /// The client, once connected (answers are routed by it).
    remote: Option<SocketAddr>,
    /// Bytes received but not yet a whole message.
    inbuf: Vec<u8>,
    /// Framed answers the socket had no room for yet.
    out: Vec<u8>,
    /// Queries handed to the resolver and not answered yet.
    outstanding: u16,
    /// Last traffic (ms since boot).
    last_ms: u64,
    /// We sent our FIN: smoltcp finishes the connection.
    closing: bool,
}

impl Conn {
    fn reset(&mut self) {
        self.remote = None;
        self.inbuf.clear();
        self.out.clear();
        self.outstanding = 0;
        self.closing = false;
    }

    /// Move queued answers into the socket.
    fn flush(&mut self, s: &mut tcp::Socket) {
        if self.out.is_empty() || !s.may_send() {
            return;
        }
        if let Ok(n) = s.send_slice(&self.out) {
            self.out.drain(..n);
        }
    }
}

/// One network's TCP port 53.
pub struct Listener {
    conns: Vec<Conn>,
}

fn socket() -> tcp::Socket<'static> {
    let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; RX_BUF]), tcp::SocketBuffer::new(vec![0; TX_BUF]));
    s.set_timeout(Some(smoltcp::time::Duration::from_secs(10))); // unacknowledged data
    s.listen(PORT).expect("dns: listen :53/tcp");
    s
}

impl Listener {
    pub fn open(sockets: &mut SocketSet<'static>) -> Self {
        let conns = (0..CONNS)
            .map(|_| Conn {
                sock: sockets.add(socket()),
                remote: None,
                inbuf: Vec::new(),
                out: Vec::new(),
                outstanding: 0,
                last_ms: 0,
                closing: false,
            })
            .collect();
        Self { conns }
    }

    /// The network went away: its sockets too (open connections end
    /// without a FIN; the interface is gone or readdressed anyway).
    pub fn close(self, sockets: &mut SocketSet<'static>) {
        for c in self.conns {
            sockets.remove(c.sock);
        }
    }

    /// Whole queries received since the last call: (client, message
    /// without its length).
    pub fn recv(&mut self, sockets: &mut SocketSet<'static>, now_ms: u64) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut queries = Vec::new();
        let mut buf = [0u8; 512];
        for c in &mut self.conns {
            let s = sockets.get_mut::<tcp::Socket>(c.sock);
            let connected = matches!(
                s.state(),
                tcp::State::Established | tcp::State::FinWait1 | tcp::State::FinWait2 | tcp::State::CloseWait
            );
            if c.remote.is_none() && connected {
                let Some(ep) = s.remote_endpoint() else { continue };
                c.remote = Some(SocketAddr::new(ep.addr.into(), ep.port));
                c.last_ms = now_ms;
                ACCEPTED.fetch_add(1, Ordering::Relaxed);
            }
            let Some(client) = c.remote else { continue };
            while c.outstanding < MAX_OUTSTANDING && c.inbuf.len() < 2 + MAX_QUERY && s.can_recv() {
                let Ok(n) = s.recv_slice(&mut buf) else { break };
                if n == 0 {
                    break;
                }
                c.inbuf.extend_from_slice(&buf[..n]);
                c.last_ms = now_ms;
                // Whole messages out of the buffer.
                while c.inbuf.len() >= 2 && c.outstanding < MAX_OUTSTANDING {
                    let len = usize::from(u16::from_be_bytes([c.inbuf[0], c.inbuf[1]]));
                    if !(12..=MAX_QUERY).contains(&len) {
                        s.abort(); // not DNS, or more than a query
                        c.inbuf.clear();
                        break;
                    }
                    if c.inbuf.len() < 2 + len {
                        break;
                    }
                    queries.push((client, c.inbuf[2..2 + len].to_vec()));
                    c.inbuf.drain(..2 + len);
                    c.outstanding += 1;
                }
            }
        }
        queries
    }

    /// An answer for `to`: framed and sent on its connection. False if no
    /// connection of this network has that client (it went away).
    pub fn send(&mut self, sockets: &mut SocketSet<'static>, to: SocketAddr, data: &[u8], now_ms: u64) -> bool {
        let Some(c) = self.conns.iter_mut().find(|c| c.remote == Some(to)) else {
            return false;
        };
        let s = sockets.get_mut::<tcp::Socket>(c.sock);
        c.outstanding = c.outstanding.saturating_sub(1);
        c.last_ms = now_ms;
        let Ok(len) = u16::try_from(data.len()) else {
            return true; // cannot be framed (the resolver never makes one)
        };
        if c.out.len() + 2 + data.len() > MAX_OUT {
            s.abort(); // the client does not read its answers
            c.out.clear();
            return true;
        }
        c.out.extend_from_slice(&len.to_be_bytes());
        c.out.extend_from_slice(data);
        c.flush(s);
        true
    }

    /// Queued answers out, finished connections closed, closed sockets
    /// listening again. Pending queries of a remaining message are read on
    /// the next [`Self::recv`].
    pub fn step(&mut self, sockets: &mut SocketSet<'static>, now_ms: u64) {
        for c in &mut self.conns {
            let s = sockets.get_mut::<tcp::Socket>(c.sock);
            if !s.is_open() {
                c.reset();
                let _ = s.listen(PORT);
                continue;
            }
            if c.remote.is_none() {
                continue; // listening, or a handshake under way
            }
            c.flush(s);
            let idle = now_ms.saturating_sub(c.last_ms);
            let done = c.outstanding == 0 && c.out.is_empty() && s.send_queue() == 0;
            let peer_closed = s.state() == tcp::State::CloseWait;
            if idle > HARD_MS {
                s.abort();
            } else if !c.closing && done && (peer_closed || idle > IDLE_MS) {
                // The client closed its side and has every answer, or it
                // has been quiet too long: our FIN.
                s.close();
                c.closing = true;
            }
        }
    }

    /// When [`Self::step`] must run without traffic (a timeout).
    pub fn next_deadline(&self) -> Option<u64> {
        self.conns
            .iter()
            .filter(|c| c.remote.is_some())
            .map(|c| {
                let busy = c.closing || c.outstanding > 0 || !c.out.is_empty();
                c.last_ms + if busy { HARD_MS } else { IDLE_MS } + 1
            })
            .min()
    }

    /// Connections open now.
    pub fn open_conns(&self) -> usize {
        self.conns.iter().filter(|c| c.remote.is_some()).count()
    }
}
