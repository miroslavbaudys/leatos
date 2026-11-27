//! The sockets of one link: demultiplexing, the RSTs nobody's socket sends,
//! initial sequence numbers, challenge-ACK budget, counters.

use crate::siphash::siphash24;
use crate::socket::{Socket, TIME_WAIT_MS, TimeWait};
use crate::wire::{self, ACK, FIN, Header, RST, SYN};
use crate::{State, Tuple};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};

/// RSTs for segments no socket takes, waiting for the next poll; more are
/// dropped (counted).
const MAX_RESETS: usize = 16;
/// TIME-WAITs kept for sockets that listen or connect again; the oldest
/// goes first when full.
const MAX_TIME_WAIT: usize = 64;
/// Segments kept in [`Tcp::recent`] per kind.
const RECENT: usize = 32;
/// RFC 5961 §7: challenge ACKs per second for the whole link.
const CHALLENGE_PER_SEC: u32 = 10;

/// A socket in a [`Tcp`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle(usize);

/// Counters since the stack was made (`/api/status`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Segments taken (checksum and header good).
    pub segments_in: u64,
    pub segments_out: u64,
    pub bad_checksum: u64,
    pub malformed: u64,
    /// Segments no socket took (a RST answered unless it was one).
    pub no_socket: u64,
    pub resets_sent: u64,
    pub resets_dropped: u64,
    pub resets_received: u64,
    /// Our SYN answered with a RST.
    pub refused: u64,
    pub challenge_acks: u64,
    pub retransmits: u64,
    pub fast_retransmits: u64,
    pub window_probes: u64,
    /// Connections given up (user timeout or retry limit).
    pub timeouts: u64,
    /// Segments for a connection in the stack's TIME-WAIT table (the
    /// peer's repeated FIN: answered with an ACK, not a RST).
    pub time_wait: u64,
}

/// A segment the stack answered itself (diagnostics, `/api/status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen {
    pub at: u64,
    pub remote: SocketAddr,
    pub local_port: u16,
    pub flags: u8,
    /// Payload bytes.
    pub len: u16,
}

/// What a socket needs from its stack while it handles a segment or a
/// timer.
pub(crate) struct Ctx<'a> {
    pub now: u64,
    secret: &'a [u8; 16],
    mtu: u16,
    resets: &'a mut VecDeque<(Tuple, u32, Option<u32>)>,
    challenge: &'a mut (u64, u32),
    pub stats: &'a mut Stats,
}

impl Ctx<'_> {
    /// RFC 6528: a keyed hash of the connection plus a 4 µs clock.
    pub fn isn(&self, t: &Tuple) -> u32 {
        let mut b = [0u8; 36];
        let ip = |a: IpAddr| match a {
            IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
            IpAddr::V6(a) => a.octets(),
        };
        b[..16].copy_from_slice(&ip(t.local.ip()));
        b[16..32].copy_from_slice(&ip(t.remote.ip()));
        b[32..34].copy_from_slice(&t.local.port().to_be_bytes());
        b[34..36].copy_from_slice(&t.remote.port().to_be_bytes());
        let f = siphash24(self.secret, &b) as u32;
        f.wrapping_add(self.now.wrapping_mul(250) as u32)
    }

    /// The MSS our link carries (RFC 9293 §3.7.1: MTU less the headers).
    pub fn mss(&self, v6: bool) -> usize {
        usize::from(self.mtu).saturating_sub(if v6 { 60 } else { 40 })
    }

    /// A RST for `t`: `seq`, and `ack` with the ACK flag.
    pub fn reset(&mut self, t: Tuple, seq: u32, ack: Option<u32>) {
        if self.resets.len() < MAX_RESETS {
            self.resets.push_back((t, seq, ack));
        } else {
            self.stats.resets_dropped += 1;
        }
    }

    pub fn challenge_allowed(&mut self) -> bool {
        let (start, n) = self.challenge;
        if self.now >= *start + 1000 {
            *start = self.now;
            *n = 0;
        }
        if *n < CHALLENGE_PER_SEC {
            *n += 1;
            true
        } else {
            false
        }
    }
}

/// A segment to send: [`Emit::write`] puts it into the caller's buffer.
pub struct Emit<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub header: Header,
    a: &'a [u8],
    b: &'a [u8],
}

impl<'a> Emit<'a> {
    pub(crate) fn new(t: &Tuple, header: Header, a: &'a [u8], b: &'a [u8]) -> Self {
        Self { src: t.local, dst: t.remote, header, a, b }
    }

    /// The TCP segment's length (header, options, payload).
    pub fn len(&self) -> usize {
        self.header.len() + self.a.len() + self.b.len()
    }

    /// Never empty (a header at least).
    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn payload_len(&self) -> usize {
        self.a.len() + self.b.len()
    }

    /// Write the segment with its checksum into `out`; its length, or
    /// `None` if `out` is too small.
    pub fn write(&self, out: &mut [u8]) -> Option<usize> {
        wire::write(out, self.src.ip(), self.dst.ip(), &self.header, self.a, self.b)
    }
}

/// The TCP of one link.
pub struct Tcp {
    sockets: Vec<Option<Socket>>,
    secret: [u8; 16],
    mtu: u16,
    resets: VecDeque<(Tuple, u32, Option<u32>)>,
    challenge: (u64, u32),
    stats: Stats,
    /// Connections in TIME-WAIT whose socket moved on (RFC 9293 §3.10.7.4:
    /// a repeated FIN is acknowledged and restarts the timer).
    time_wait: VecDeque<TimeWait>,
    /// The last segments no socket took, and the last ones the TIME-WAIT
    /// table took.
    recent_no_socket: VecDeque<Seen>,
    recent_time_wait: VecDeque<Seen>,
    /// Segments no socket takes get a RST (RFC 9293); off: dropped
    /// silently (`set_rst_closed`).
    rst_closed: bool,
}

impl Tcp {
    /// `secret`: random, for RFC 6528 sequence numbers.
    pub fn new(secret: [u8; 16]) -> Self {
        Self {
            sockets: Vec::new(),
            secret,
            mtu: 1500,
            resets: VecDeque::new(),
            challenge: (0, 0),
            stats: Stats::default(),
            time_wait: VecDeque::new(),
            recent_no_socket: VecDeque::new(),
            recent_time_wait: VecDeque::new(),
            rst_closed: true,
        }
    }

    /// Whether a segment no socket takes (a closed port, a stale
    /// connection) is answered with a RST (the default, RFC 9293
    /// §3.10.7.1) or dropped silently.
    pub fn set_rst_closed(&mut self, on: bool) {
        self.rst_closed = on;
    }

    /// The link's MTU: the MSS of new connections (PPPoE 1492).
    pub fn set_mtu(&mut self, mtu: u16) {
        self.mtu = mtu.max(576);
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    pub fn add(&mut self, s: Socket) -> Handle {
        match self.sockets.iter().position(Option::is_none) {
            Some(i) => {
                self.sockets[i] = Some(s);
                Handle(i)
            }
            None => {
                self.sockets.push(Some(s));
                Handle(self.sockets.len() - 1)
            }
        }
    }

    /// The socket goes, as it is (no FIN, no RST: abort it first for one;
    /// a TIME-WAIT stays with the stack).
    pub fn remove(&mut self, h: Handle) -> Option<Socket> {
        let mut s = self.sockets.get_mut(h.0)?.take()?;
        s.hand_off_time_wait();
        if let Some(tw) = s.take_time_wait() {
            self.keep_time_wait(tw);
        }
        Some(s)
    }

    /// The last segments no socket took (`false`) or the TIME-WAIT table
    /// took (`true`), oldest first.
    pub fn recent(&self, time_wait: bool) -> impl Iterator<Item = &Seen> {
        if time_wait { self.recent_time_wait.iter() } else { self.recent_no_socket.iter() }
    }

    fn note(q: &mut VecDeque<Seen>, seen: Seen) {
        if q.len() >= RECENT {
            q.pop_front();
        }
        q.push_back(seen);
    }

    /// TIME-WAITs in the stack's table.
    pub fn time_waits(&self) -> usize {
        self.time_wait.len()
    }

    fn keep_time_wait(&mut self, tw: TimeWait) {
        self.time_wait.retain(|k| k.tuple != tw.tuple);
        if self.time_wait.len() >= MAX_TIME_WAIT {
            self.time_wait.pop_front();
        }
        self.time_wait.push_back(tw);
    }

    /// Take the TIME-WAITs sockets left since the last call, and forget
    /// the expired ones.
    fn collect_time_waits(&mut self, now: u64) {
        for i in 0..self.sockets.len() {
            if let Some(tw) = self.sockets[i].as_mut().and_then(Socket::take_time_wait) {
                self.keep_time_wait(tw);
            }
        }
        self.time_wait.retain(|k| k.until > now);
    }

    /// Panics on a handle that was removed (a bug in the caller).
    pub fn get(&self, h: Handle) -> &Socket {
        self.sockets[h.0].as_ref().expect("tcp: stale socket handle")
    }

    pub fn get_mut(&mut self, h: Handle) -> &mut Socket {
        self.sockets[h.0].as_mut().expect("tcp: stale socket handle")
    }

    /// Sockets held.
    pub fn len(&self) -> usize {
        self.sockets.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn split(&mut self, now: u64) -> (&mut Vec<Option<Socket>>, Ctx<'_>) {
        (
            &mut self.sockets,
            Ctx {
                now,
                secret: &self.secret,
                mtu: self.mtu,
                resets: &mut self.resets,
                challenge: &mut self.challenge,
                stats: &mut self.stats,
            },
        )
    }

    /// A TCP segment (`seg`: header and payload) from `src` to `dst`, one
    /// of the router's addresses on this link. Bad checksums and malformed
    /// headers are dropped and counted.
    pub fn receive(&mut self, now: u64, src: IpAddr, dst: IpAddr, seg: &[u8]) {
        if wire::checksum(src, dst, seg) != Some(0) {
            self.stats.bad_checksum += 1;
            return;
        }
        let Some(s) = wire::parse(seg) else {
            self.stats.malformed += 1;
            return;
        };
        self.stats.segments_in += 1;
        self.collect_time_waits(now);
        let t = Tuple { local: SocketAddr::new(dst, s.dport), remote: SocketAddr::new(src, s.sport) };
        let seen = Seen {
            at: now,
            remote: t.remote,
            local_port: s.dport,
            flags: s.flags,
            len: s.payload.len().min(usize::from(u16::MAX)) as u16,
        };
        let live = self
            .sockets
            .iter()
            .flatten()
            .any(|k| k.tuple() == Some(t) && !matches!(k.state(), State::Closed | State::Listen));
        if !live && let Some(i) = self.time_wait.iter().position(|k| k.tuple == t) {
            let tw = &mut self.time_wait[i];
            if s.has(SYN) && !s.has(ACK) && !s.has(RST) && crate::seq::gt(s.seq, tw.rcv_nxt) {
                // RFC 9293 §3.10.7.4: a new connection may reuse the pair.
                self.time_wait.remove(i);
            } else {
                self.stats.time_wait += 1;
                Self::note(&mut self.recent_time_wait, seen);
                // RFC 1337: RSTs ignored; a repeated FIN (or anything
                // taking sequence space) is acknowledged and restarts the
                // timer; a bare ACK needs nothing.
                if !s.has(RST) && (s.has(FIN) || s.has(SYN) || !s.payload.is_empty()) {
                    tw.ack_due = true;
                    if s.has(FIN) {
                        tw.until = now + TIME_WAIT_MS;
                    }
                }
                return;
            }
        }
        let rst_closed = self.rst_closed;
        let (sockets, mut cx) = self.split(now);
        let conn = sockets
            .iter_mut()
            .flatten()
            .find(|k| k.tuple() == Some(t) && !matches!(k.state(), State::Closed | State::Listen));
        if let Some(k) = conn {
            k.process(&mut cx, t, &s);
            return;
        }
        if s.has(SYN) && !s.has(ACK) && !s.has(RST) {
            let l = sockets.iter_mut().flatten().find(|k| k.is_listening() && k.listen_port() == s.dport);
            if let Some(k) = l {
                k.process(&mut cx, t, &s);
                return;
            }
        }
        cx.stats.no_socket += 1;
        // RFC 9293 §3.10.7.1: a RST for anything but a RST.
        if !s.has(RST) && rst_closed {
            if s.has(ACK) {
                cx.reset(t, s.ack, None);
            } else {
                cx.reset(t, 0, Some(s.seq.wrapping_add(s.seq_len())));
            }
        }
        Self::note(&mut self.recent_no_socket, seen);
    }

    /// Run the timers due at `now` and hand every segment due to `emit`,
    /// which returns false when it could not send it (no buffer, queue
    /// full): the rest waits for the next poll.
    pub fn poll(&mut self, now: u64, mut emit: impl FnMut(&Emit) -> bool) {
        self.collect_time_waits(now);
        for tw in self.time_wait.iter_mut().filter(|k| k.ack_due) {
            let h = Header {
                sport: tw.tuple.local.port(),
                dport: tw.tuple.remote.port(),
                seq: tw.snd_nxt,
                ack: tw.rcv_nxt,
                flags: ACK,
                window: tw.window,
                mss: None,
            };
            if !emit(&Emit::new(&tw.tuple, h, &[], &[])) {
                return;
            }
            tw.ack_due = false;
            self.stats.segments_out += 1;
        }
        let (sockets, mut cx) = self.split(now);
        while let Some(&(t, sq, ack)) = cx.resets.front() {
            let h = Header {
                sport: t.local.port(),
                dport: t.remote.port(),
                seq: sq,
                ack: ack.unwrap_or(0),
                flags: RST | if ack.is_some() { ACK } else { 0 },
                window: 0,
                mss: None,
            };
            if !emit(&Emit::new(&t, h, &[], &[])) {
                return;
            }
            cx.stats.resets_sent += 1;
            cx.stats.segments_out += 1;
            cx.resets.pop_front();
        }
        let out = &mut 0u64;
        let mut counted = |e: &Emit| {
            let ok = emit(e);
            *out += u64::from(ok);
            ok
        };
        for k in sockets.iter_mut().flatten() {
            k.on_time(&mut cx);
            if !k.dispatch(&mut cx, &mut counted) {
                break;
            }
        }
        cx.stats.segments_out += *out;
    }

    /// When [`Self::poll`] must run next without a segment arriving
    /// (`Some(t)` with `t <= now`: at once).
    pub fn next_deadline(&self, now: u64) -> Option<u64> {
        let handed_off = self.sockets.iter().flatten().any(Socket::time_wait_ack_due);
        if !self.resets.is_empty() || handed_off || self.time_wait.iter().any(|k| k.ack_due) {
            return Some(now);
        }
        self.sockets.iter().flatten().filter_map(|k| k.poll_at(now)).min().map(|t| t.max(now.min(t)))
    }
}
