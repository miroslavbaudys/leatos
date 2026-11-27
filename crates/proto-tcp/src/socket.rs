//! One connection: the RFC 9293 state machine, its rings and timers.
//!
//! The model is smoltcp's (what the kernel's users were written against):
//! a socket listens on a port and becomes the connection of the first SYN
//! that arrives; when it is closed again (`!is_open`) the user lets it
//! listen once more. No backlog: a SYN that finds no listening socket gets
//! a RST ([`crate::Tcp`]).

use crate::ring::Ring;
use crate::stack::{Ctx, Emit};
use crate::wire::{ACK, FIN, Header, PSH, RST, SYN, Segment};
use crate::{Error, State, Tuple, seq};
use alloc::vec::Vec;
use core::net::SocketAddr;

/// A delayed ACK waits at most this long (or until two full segments).
pub const ACK_DELAY_MS: u64 = 10;
/// RFC 6298 §2: the first timeout, and the bounds (the minimum is Linux's
/// 200 ms rather than RFC 6298's 1 s: the router's peers are close).
pub const RTO_INIT_MS: u64 = 1000;
pub const RTO_MIN_MS: u64 = 200;
pub const RTO_MAX_MS: u64 = 60_000;
/// TIME-WAIT (short: the router's connections are few). A socket that
/// listens or connects again hands its TIME-WAIT to the stack
/// ([`crate::Tcp`]), which keeps answering the peer's FIN.
pub const TIME_WAIT_MS: u64 = 10_000;
/// SYN or SYN-ACK sent this many times more, then the open fails.
const SYN_RETRIES: u32 = 5;
/// Retransmissions of data before the connection is given up (without
/// a [`Socket::set_timeout`]).
const MAX_RETRIES: u32 = 12;
/// Ranges received out of order that are kept.
const OOO_RANGES: usize = 4;
/// No window scaling: the advertised window is at most this.
const MAX_WINDOW: usize = 0xffff;

pub struct Socket {
    state: State,
    /// The port a listening socket was given (also kept while it is the
    /// connection of a passive open).
    listen_port: u16,
    /// The connection came from a listen (RST / timeout in SYN-RECEIVED
    /// returns to LISTEN, RFC 9293 §3.10.7.4).
    passive: bool,
    tuple: Option<Tuple>,
    rx: Ring,
    tx: Ring,
    timeout_ms: Option<u64>,

    iss: u32,
    /// `connect` before the first poll: the ISS comes from the stack.
    iss_pending: bool,
    snd_una: u32,
    snd_nxt: u32,
    /// Highest sequence number sent (after a retransmission `snd_nxt` goes
    /// back; ACKs up to here are still valid).
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    max_snd_wnd: u32,
    snd_mss: usize,
    /// `close` was called: a FIN follows the send buffer.
    fin_queued: bool,
    /// Sequence number our FIN took, once sent.
    fin_seq: Option<u32>,

    irs: u32,
    rcv_nxt: u32,
    /// The right edge of the window we advertised last.
    rcv_adv: u32,
    /// `rcv_nxt` when we last sent an ACK.
    ack_sent: u32,
    /// Received out of order: `[start, end)` in sequence space, the bytes
    /// already in the receive ring past its readable end.
    ooo: Vec<(u32, u32)>,

    srtt: Option<u64>,
    rttvar: u64,
    rto: u64,
    /// Round-trip sample under way: (sequence number whose ACK ends it,
    /// time sent). Karn: never on a retransmitted segment.
    rtt_sample: Option<(u32, u64)>,
    rtx_at: Option<u64>,
    retries: u32,
    persist_at: Option<u64>,
    persist_ivl: u64,
    ack_at: Option<u64>,
    time_wait_until: Option<u64>,
    /// Last sign of life from the peer (an acceptable ACK), or when data
    /// became outstanding: the user timeout counts from here.
    alive_at: u64,
    dupacks: u32,
    /// A RST to send for an aborted connection (kept across `listen`).
    pending_rst: Option<(Tuple, u32, u32)>,
    /// The TIME-WAIT this socket left by listening or connecting again,
    /// for the stack to take over.
    time_wait_out: Option<TimeWait>,
}

/// A connection in TIME-WAIT without its socket (the stack keeps it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TimeWait {
    pub tuple: Tuple,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub window: u16,
    pub until: u64,
    /// An ACK is owed (the peer's FIN, not acknowledged yet).
    pub ack_due: bool,
}

impl Socket {
    /// A closed socket with receive and send buffers of these sizes.
    pub fn new(rx: usize, tx: usize) -> Self {
        Self {
            state: State::Closed,
            listen_port: 0,
            passive: false,
            tuple: None,
            rx: Ring::new(rx),
            tx: Ring::new(tx),
            timeout_ms: None,
            iss: 0,
            iss_pending: false,
            snd_una: 0,
            snd_nxt: 0,
            snd_max: 0,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            max_snd_wnd: 0,
            snd_mss: 536,
            fin_queued: false,
            fin_seq: None,
            irs: 0,
            rcv_nxt: 0,
            rcv_adv: 0,
            ack_sent: 0,
            ooo: Vec::with_capacity(OOO_RANGES + 1),
            srtt: None,
            rttvar: 0,
            rto: RTO_INIT_MS,
            rtt_sample: None,
            rtx_at: None,
            retries: 0,
            persist_at: None,
            persist_ivl: 0,
            ack_at: None,
            time_wait_until: None,
            alive_at: 0,
            dupacks: 0,
            pending_rst: None,
            time_wait_out: None,
        }
    }

    /// Unacknowledged data for this long without any ACK from the peer
    /// ends the connection (with a RST). `None`: only the retry limit.
    pub fn set_timeout(&mut self, ms: Option<u64>) {
        self.timeout_ms = ms;
    }

    /// Forget the connection; buffers, timeout, a pending RST and a
    /// TIME-WAIT handed off stay.
    fn reset_conn(&mut self) {
        let (rx, tx, timeout, rst, tw) = (
            core::mem::replace(&mut self.rx, Ring::new(0)),
            core::mem::replace(&mut self.tx, Ring::new(0)),
            self.timeout_ms,
            self.pending_rst.take(),
            self.time_wait_out.take(),
        );
        let mut ooo = core::mem::take(&mut self.ooo);
        ooo.clear();
        *self = Self { rx, tx, timeout_ms: timeout, pending_rst: rst, time_wait_out: tw, ooo, ..Self::new(0, 0) };
        self.rx.clear();
        self.tx.clear();
    }

    /// Listen on `port` (any of the link's addresses).
    pub fn listen(&mut self, port: u16) -> Result<(), Error> {
        if port == 0 {
            return Err(Error::Unaddressable);
        }
        if self.is_open() {
            return if self.state == State::Listen && self.listen_port == port { Ok(()) } else { Err(Error::InvalidState) };
        }
        self.hand_off_time_wait();
        self.reset_conn();
        self.state = State::Listen;
        self.listen_port = port;
        Ok(())
    }

    /// Open a connection from `local` (the caller picks the address and a
    /// port) to `remote`.
    pub fn connect(&mut self, local: SocketAddr, remote: SocketAddr) -> Result<(), Error> {
        if self.is_open() {
            return Err(Error::InvalidState);
        }
        if local.port() == 0
            || remote.port() == 0
            || local.ip().is_unspecified()
            || remote.ip().is_unspecified()
            || local.is_ipv4() != remote.is_ipv4()
        {
            return Err(Error::Unaddressable);
        }
        self.hand_off_time_wait();
        self.reset_conn();
        self.tuple = Some(Tuple { local, remote });
        self.state = State::SynSent;
        self.iss_pending = true;
        Ok(())
    }

    /// Close our side: a FIN after what is queued (a listening or
    /// connecting socket closes at once).
    pub fn close(&mut self) {
        match self.state {
            State::Listen | State::SynSent => {
                self.reset_conn();
            }
            State::SynReceived | State::Established => {
                self.fin_queued = true;
                self.state = State::FinWait1;
            }
            State::CloseWait => {
                self.fin_queued = true;
                self.state = State::LastAck;
            }
            _ => {}
        }
    }

    /// End the connection at once; the peer gets a RST.
    pub fn abort(&mut self) {
        let synced = !matches!(self.state, State::Closed | State::Listen | State::SynSent | State::TimeWait);
        if let (true, Some(t)) = (synced, self.tuple) {
            self.pending_rst = Some((t, self.snd_nxt, self.rcv_nxt));
        }
        self.reset_conn();
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Neither closed nor in TIME-WAIT (`listen` and `connect` refuse).
    pub fn is_open(&self) -> bool {
        !matches!(self.state, State::Closed | State::TimeWait)
    }

    /// A connection exists or is being made (not closed, not listening).
    pub fn is_active(&self) -> bool {
        !matches!(self.state, State::Closed | State::TimeWait | State::Listen)
    }

    pub fn is_listening(&self) -> bool {
        self.state == State::Listen
    }

    /// Data may be queued: the connection is up and our side not closed.
    pub fn may_send(&self) -> bool {
        matches!(self.state, State::Established | State::CloseWait)
    }

    pub fn can_send(&self) -> bool {
        self.may_send() && self.tx.free() > 0
    }

    /// The peer may still send (its FIN has not come).
    pub fn may_recv(&self) -> bool {
        matches!(self.state, State::Established | State::FinWait1 | State::FinWait2)
    }

    pub fn can_recv(&self) -> bool {
        !self.rx.is_empty()
    }

    /// Bytes queued and not yet acknowledged.
    pub fn send_queue(&self) -> usize {
        self.tx.len()
    }

    /// Bytes received and not yet read.
    pub fn recv_queue(&self) -> usize {
        self.rx.len()
    }

    pub fn remote_endpoint(&self) -> Option<SocketAddr> {
        self.tuple.filter(|_| self.is_active()).map(|t| t.remote)
    }

    pub fn local_endpoint(&self) -> Option<SocketAddr> {
        self.tuple.filter(|_| self.is_active()).map(|t| t.local)
    }

    pub(crate) fn tuple(&self) -> Option<Tuple> {
        self.tuple
    }

    pub(crate) fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Queue `data` (as much as fits).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize, Error> {
        if !self.may_send() {
            return Err(Error::InvalidState);
        }
        Ok(self.tx.push(data))
    }

    fn recv_empty(&self) -> Result<(), Error> {
        if !self.rx.is_empty() || self.may_recv() {
            Ok(())
        } else if matches!(self.state, State::CloseWait | State::LastAck | State::Closing | State::TimeWait) {
            Err(Error::Finished)
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Read into `out`.
    pub fn recv_slice(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        self.recv_empty()?;
        Ok(self.rx.pop(out))
    }

    /// `f` gets the first contiguous received bytes and returns how many it
    /// took and a result.
    pub fn recv<R>(&mut self, f: impl FnOnce(&[u8]) -> (usize, R)) -> Result<R, Error> {
        self.recv_empty()?;
        let (a, _) = self.rx.slices(0, self.rx.len());
        let (n, r) = f(a);
        let n = n.min(a.len());
        self.rx.consume(n);
        Ok(r)
    }

    fn rcv_wnd(&self) -> u32 {
        self.rx.free().min(MAX_WINDOW) as u32
    }

    /// Leaving TIME-WAIT early (listen / connect): the stack takes it over.
    pub(crate) fn hand_off_time_wait(&mut self) {
        if self.state != State::TimeWait {
            return;
        }
        let (Some(tuple), Some(until)) = (self.tuple, self.time_wait_until) else { return };
        self.time_wait_out = Some(TimeWait {
            tuple,
            snd_nxt: self.snd_nxt,
            rcv_nxt: self.rcv_nxt,
            window: self.rcv_wnd() as u16,
            until,
            ack_due: self.ack_at.is_some(),
        });
    }

    pub(crate) fn take_time_wait(&mut self) -> Option<TimeWait> {
        self.time_wait_out.take()
    }

    /// A TIME-WAIT handed off owes an ACK (the stack must poll).
    pub(crate) fn time_wait_ack_due(&self) -> bool {
        self.time_wait_out.as_ref().is_some_and(|k| k.ack_due)
    }

    fn back_to_listen(&mut self) {
        let port = self.listen_port;
        self.reset_conn();
        self.state = State::Listen;
        self.listen_port = port;
    }

    fn ack_now(&mut self, now: u64) {
        self.ack_at = Some(now);
    }

    fn rtt_update(&mut self, r: u64) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(s) => {
                self.rttvar = (3 * self.rttvar + s.abs_diff(r)) / 4;
                self.srtt = Some((7 * s + r) / 8);
            }
        }
        let s = self.srtt.unwrap_or(r);
        self.rto = (s + (4 * self.rttvar).max(1)).clamp(RTO_MIN_MS, RTO_MAX_MS);
    }

    /// The MSS we may send: the peer's option (RFC 9293 §3.7.1 defaults
    /// without one), at most what our link carries.
    fn peer_mss(seg: &Segment, ours: usize, v6: bool) -> usize {
        let default = if v6 { 1220 } else { 536 };
        usize::from(seg.mss.unwrap_or(default)).clamp(64, ours.max(64))
    }

    /// A segment for this socket (its tuple, or a SYN for a listening one).
    pub(crate) fn process(&mut self, cx: &mut Ctx, t: Tuple, s: &Segment) {
        let now = cx.now;
        match self.state {
            State::Closed => {}
            State::Listen => {
                if s.has(RST) {
                    return;
                }
                if s.has(ACK) {
                    cx.reset(t, s.ack, None);
                    return;
                }
                if !s.has(SYN) {
                    return;
                }
                let iss = cx.isn(&t);
                self.tuple = Some(t);
                self.passive = true;
                self.irs = s.seq;
                self.rcv_nxt = s.seq.wrapping_add(1);
                self.ack_sent = self.rcv_nxt;
                self.rcv_adv = self.rcv_nxt;
                self.iss = iss;
                self.snd_una = iss;
                self.snd_nxt = iss;
                self.snd_max = iss;
                self.snd_wnd = u32::from(s.window);
                self.max_snd_wnd = self.snd_wnd;
                self.snd_wl1 = s.seq;
                self.snd_wl2 = 0;
                self.snd_mss = Self::peer_mss(s, cx.mss(t.local.is_ipv6()), t.local.is_ipv6());
                self.alive_at = now;
                self.state = State::SynReceived;
            }
            State::SynSent => self.process_syn_sent(cx, t, s),
            _ => self.process_synced(cx, t, s),
        }
    }

    fn process_syn_sent(&mut self, cx: &mut Ctx, t: Tuple, s: &Segment) {
        let now = cx.now;
        if self.iss_pending {
            return; // nothing sent yet: nothing can be an answer
        }
        if s.has(ACK) && s.ack != self.iss.wrapping_add(1) {
            if !s.has(RST) {
                cx.reset(t, s.ack, None);
            }
            return;
        }
        if s.has(RST) {
            if s.has(ACK) {
                cx.stats.refused += 1;
                self.reset_conn();
            }
            return;
        }
        if !s.has(SYN) {
            return;
        }
        self.irs = s.seq;
        self.rcv_nxt = s.seq.wrapping_add(1);
        self.ack_sent = self.rcv_nxt;
        self.rcv_adv = self.rcv_nxt;
        self.snd_wnd = u32::from(s.window);
        self.max_snd_wnd = self.snd_wnd;
        self.snd_wl1 = s.seq;
        self.snd_wl2 = s.ack;
        self.snd_mss = Self::peer_mss(s, cx.mss(t.local.is_ipv6()), t.local.is_ipv6());
        self.alive_at = now;
        if s.has(ACK) {
            self.snd_una = s.ack;
            if let Some((end, at)) = self.rtt_sample.take()
                && seq::ge(s.ack, end)
            {
                self.rtt_update(now.saturating_sub(at));
            }
            self.rtx_at = None;
            self.retries = 0;
            self.state = State::Established;
            self.ack_now(now);
        } else {
            // Simultaneous open: our SYN again, with the ACK.
            self.state = State::SynReceived;
            self.snd_nxt = self.iss;
        }
    }

    fn process_synced(&mut self, cx: &mut Ctx, t: Tuple, s: &Segment) {
        let now = cx.now;
        // The peer did not get our SYN-ACK and sends its SYN again.
        if self.state == State::SynReceived && s.has(SYN) && !s.has(ACK) && !s.has(RST) && s.seq == self.irs {
            self.snd_nxt = self.iss;
            return;
        }
        let wnd = self.rcv_wnd();
        let len = s.seq_len();
        let rn = self.rcv_nxt;
        let acceptable = match (len, wnd) {
            (0, 0) => s.seq == rn,
            (0, _) => seq::in_range(s.seq, rn, rn.wrapping_add(wnd)),
            (_, 0) => false,
            _ => {
                let end = rn.wrapping_add(wnd);
                seq::in_range(s.seq, rn, end) || seq::in_range(s.seq.wrapping_add(len - 1), rn, end)
            }
        };
        // A full receive buffer still takes ACKs (RFC 9293 §3.10.7.4).
        let ack_only = !acceptable && wnd == 0 && s.seq == rn && s.has(ACK) && !s.has(RST) && !s.has(SYN);
        if !acceptable && !ack_only {
            if !s.has(RST) {
                self.ack_now(now);
            }
            return;
        }
        // RFC 5961 §3: a RST ends the connection only at the exact number;
        // anywhere else in the window it gets a challenge ACK.
        if s.has(RST) {
            if s.seq == rn {
                cx.stats.resets_received += 1;
                if self.state == State::SynReceived && self.passive {
                    self.back_to_listen();
                } else {
                    self.reset_conn();
                }
            } else {
                self.challenge(cx);
            }
            return;
        }
        // RFC 5961 §4: a SYN in a synchronized state.
        if s.has(SYN) {
            self.challenge(cx);
            return;
        }
        if !s.has(ACK) {
            return;
        }
        if self.state == State::SynReceived {
            if seq::gt(s.ack, self.snd_una) && seq::le(s.ack, self.snd_max) {
                self.state = State::Established;
            } else {
                cx.reset(t, s.ack, None);
                return;
            }
        }
        if !self.process_ack(cx, s) {
            return;
        }
        if self.state == State::Closed {
            return;
        }
        if ack_only {
            self.ack_now(now);
            return;
        }
        let data_state = matches!(self.state, State::Established | State::FinWait1 | State::FinWait2);
        if data_state && !s.payload.is_empty() {
            self.take_data(now, s.seq, s.payload);
        }
        if s.has(FIN) && data_state && s.seq.wrapping_add(s.payload.len() as u32) == self.rcv_nxt {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.ack_now(now);
            self.state = match self.state {
                State::Established => State::CloseWait,
                State::FinWait1 => State::Closing,
                _ => {
                    self.enter_time_wait(now);
                    State::TimeWait
                }
            };
        }
    }

    fn enter_time_wait(&mut self, now: u64) {
        self.time_wait_until = Some(now + TIME_WAIT_MS);
        self.rtx_at = None;
        self.persist_at = None;
    }

    fn challenge(&mut self, cx: &mut Ctx) {
        if cx.challenge_allowed() {
            cx.stats.challenge_acks += 1;
            self.ack_now(cx.now);
        }
    }

    /// The ACK field (RFC 9293 §3.10.7.4 fifth check, RFC 5961 §5). False:
    /// the segment is dropped.
    fn process_ack(&mut self, cx: &mut Ctx, s: &Segment) -> bool {
        let now = cx.now;
        if seq::gt(s.ack, self.snd_max) {
            self.ack_now(now); // acknowledges something we never sent
            return false;
        }
        let oldest = self.snd_una.wrapping_sub(self.max_snd_wnd.max(1));
        if seq::lt(s.ack, oldest) {
            self.challenge(cx);
            return false;
        }
        self.alive_at = now;
        if seq::gt(s.ack, self.snd_una) {
            let mut acked = s.ack.wrapping_sub(self.snd_una) as usize;
            if self.snd_una == self.iss {
                acked -= 1; // our SYN
            }
            self.tx.consume(acked.min(self.tx.len()));
            if let Some((end, at)) = self.rtt_sample
                && seq::ge(s.ack, end)
            {
                self.rtt_sample = None;
                self.rtt_update(now.saturating_sub(at));
            }
            self.snd_una = s.ack;
            if seq::lt(self.snd_nxt, self.snd_una) {
                self.snd_nxt = self.snd_una;
            }
            self.retries = 0;
            self.dupacks = 0;
            self.rtx_at = (self.snd_una != self.snd_max).then_some(now + self.rto);
        } else if s.ack == self.snd_una
            && s.payload.is_empty()
            && !s.has(FIN)
            && u32::from(s.window) == self.snd_wnd
            && s.window != 0
            && self.snd_una != self.snd_max
        {
            self.dupacks += 1;
            if self.dupacks == 3 {
                // Fast retransmit: from the first unacknowledged byte.
                cx.stats.fast_retransmits += 1;
                self.snd_nxt = self.snd_una;
                self.rtt_sample = None;
            }
        }
        if seq::lt(self.snd_wl1, s.seq) || (self.snd_wl1 == s.seq && seq::le(self.snd_wl2, s.ack)) {
            self.snd_wnd = u32::from(s.window);
            self.snd_wl1 = s.seq;
            self.snd_wl2 = s.ack;
            self.max_snd_wnd = self.max_snd_wnd.max(self.snd_wnd);
        }
        if self.snd_wnd > 0 {
            self.persist_at = None;
        } else if self.snd_max.wrapping_sub(self.snd_una) <= 1 {
            // A window probe answered with a zero window: the persist timer
            // sends the next one, not the retransmission timer.
            self.rtx_at = None;
            self.snd_nxt = self.snd_una;
            self.retries = 0;
        }
        let fin_acked = self.fin_seq.is_some_and(|f| seq::gt(self.snd_una, f));
        if fin_acked {
            match self.state {
                State::FinWait1 => self.state = State::FinWait2,
                State::Closing => {
                    self.enter_time_wait(now);
                    self.state = State::TimeWait;
                }
                State::LastAck => {
                    self.reset_conn();
                    return false;
                }
                _ => {}
            }
        }
        true
    }

    /// Payload at `seq_no`: into the receive ring, in order or as an
    /// out-of-order range.
    fn take_data(&mut self, now: u64, seq_no: u32, data: &[u8]) {
        let (mut sq, mut data) = (seq_no, data);
        if seq::lt(sq, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(sq) as usize;
            if skip >= data.len() {
                self.ack_now(now); // all of it seen before
                return;
            }
            data = &data[skip..];
            sq = self.rcv_nxt;
        }
        let off = sq.wrapping_sub(self.rcv_nxt) as usize;
        if off >= self.rcv_wnd() as usize {
            self.ack_now(now);
            return;
        }
        let n = self.rx.write_at(off, data).min(self.rcv_wnd() as usize - off);
        if n == 0 {
            self.ack_now(now);
            return;
        }
        if off == 0 {
            self.rx.commit(n);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(n as u32);
            self.merge_ooo();
            let unacked = self.rcv_nxt.wrapping_sub(self.ack_sent) as usize;
            if !self.ooo.is_empty() || unacked >= 2 * self.snd_mss {
                self.ack_now(now);
            } else {
                let at = now + ACK_DELAY_MS;
                self.ack_at = Some(self.ack_at.map_or(at, |a| a.min(at)));
            }
        } else {
            self.add_ooo(sq, sq.wrapping_add(n as u32));
            self.ack_now(now); // a duplicate ACK tells the peer of the gap
        }
    }

    fn add_ooo(&mut self, mut a: u32, mut b: u32) {
        // Merge with every range it touches.
        let mut i = 0;
        while i < self.ooo.len() {
            let (x, y) = self.ooo[i];
            if seq::le(x, b) && seq::le(a, y) {
                if seq::lt(x, a) {
                    a = x;
                }
                if seq::gt(y, b) {
                    b = y;
                }
                self.ooo.swap_remove(i);
            } else {
                i += 1;
            }
        }
        if self.ooo.len() < OOO_RANGES {
            self.ooo.push((a, b));
        }
    }

    fn merge_ooo(&mut self) {
        loop {
            let Some(i) = self.ooo.iter().position(|&(a, _)| seq::le(a, self.rcv_nxt)) else { return };
            let (_, b) = self.ooo.swap_remove(i);
            if seq::gt(b, self.rcv_nxt) {
                let n = b.wrapping_sub(self.rcv_nxt) as usize;
                self.rx.commit(n);
                self.rcv_nxt = b;
            }
        }
    }

    /// Timers due at `now`: TIME-WAIT over, retransmission, user timeout.
    pub(crate) fn on_time(&mut self, cx: &mut Ctx) {
        let now = cx.now;
        if self.iss_pending
            && let Some(t) = self.tuple
        {
            let iss = cx.isn(&t);
            self.iss_pending = false;
            self.iss = iss;
            self.snd_una = iss;
            self.snd_nxt = iss;
            self.snd_max = iss;
            self.alive_at = now;
        }
        if self.state == State::TimeWait && self.time_wait_until.is_some_and(|t| t <= now) {
            self.reset_conn();
            return;
        }
        if let Some(to) = self.timeout_ms
            && self.awaiting_ack()
            && now >= self.alive_at + to
        {
            cx.stats.timeouts += 1;
            if self.state == State::SynReceived && self.passive {
                self.back_to_listen();
            } else {
                self.abort();
            }
            return;
        }
        if self.rtx_at.is_some_and(|t| t <= now) {
            self.rtx_at = None;
            self.retries += 1;
            let opening = matches!(self.state, State::SynSent | State::SynReceived);
            if self.retries > if opening { SYN_RETRIES } else { MAX_RETRIES } {
                cx.stats.timeouts += 1;
                if self.state == State::SynReceived && self.passive {
                    self.back_to_listen();
                } else {
                    self.abort();
                }
                return;
            }
            cx.stats.retransmits += 1;
            self.snd_nxt = if opening { self.iss } else { self.snd_una };
            self.rtt_sample = None;
            self.rto = (self.rto * 2).min(RTO_MAX_MS);
        }
    }

    /// Sequence space sent and not acknowledged, other than a window probe
    /// the peer answered (it lives; the persist timer goes on).
    fn awaiting_ack(&self) -> bool {
        self.snd_una != self.snd_max && !(self.snd_wnd == 0 && self.snd_nxt == self.snd_una)
    }

    /// What the next segment would carry: payload bytes, whether it is a
    /// window probe, whether the FIN goes with it.
    fn next_send(&self, now: u64) -> (usize, bool, bool) {
        let off = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
        let unsent = self.tx.len().saturating_sub(off);
        let wnd = self.snd_wnd as usize;
        let room = wnd.saturating_sub(off);
        let probe = off == 0 && wnd == 0 && unsent > 0 && self.persist_at.is_some_and(|p| p <= now);
        let n = if probe { 1 } else { unsent.min(room).min(self.snd_mss) };
        let data_end = self.snd_una.wrapping_add(self.tx.len() as u32);
        let fin = self.fin_queued && !probe && self.snd_nxt.wrapping_add(n as u32) == data_end;
        (n, probe, fin)
    }

    /// The receive window grew enough to tell the peer (RFC 9293 §3.8.6.2.2:
    /// by a segment or half the buffer, after the window had shrunk).
    fn window_update_due(&self) -> bool {
        if !self.may_recv() {
            return false;
        }
        let edge = self.rcv_nxt.wrapping_add(self.rcv_wnd());
        let grow = edge.wrapping_sub(self.rcv_adv) as i32;
        let half = self.rx.cap() / 2;
        let left = self.rcv_adv.wrapping_sub(self.rcv_nxt) as usize;
        grow > 0 && grow as usize >= half.min(self.snd_mss) && left < half
    }

    /// When this socket must be polled (`Some(0)`: now).
    pub(crate) fn poll_at(&self, now: u64) -> Option<u64> {
        if self.pending_rst.is_some() || self.iss_pending {
            return Some(0);
        }
        // The persist timer only while nothing is in flight (a probe that
        // is out has the retransmission timer).
        let persist = self.persist_at.filter(|_| self.snd_nxt == self.snd_una);
        let timers = [self.rtx_at, persist, self.ack_at, self.time_wait_until]
            .into_iter()
            .flatten()
            .chain(
                self.timeout_ms
                    .filter(|_| self.awaiting_ack())
                    .map(|to| self.alive_at + to),
            )
            .min();
        match self.state {
            State::Closed | State::Listen => None,
            State::SynSent | State::SynReceived if self.snd_nxt == self.iss => Some(0),
            State::SynSent | State::SynReceived => [self.rtx_at, self.timeout_ms.filter(|_| self.awaiting_ack()).map(|to| self.alive_at + to)]
                .into_iter()
                .flatten()
                .min(),
            State::TimeWait => timers,
            _ => {
                let (n, _, fin) = self.next_send(now);
                if n > 0 || fin || self.window_update_due() {
                    return Some(0);
                }
                // Data waits for a zero window: the persist timer starts
                // at the next poll.
                let off = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
                if self.persist_at.is_none() && self.snd_wnd == 0 && off == 0 && self.tx.len() > off {
                    return Some(0);
                }
                timers
            }
        }
    }

    fn header(&self, t: &Tuple, seq_no: u32, flags: u8, mss: Option<u16>) -> Header {
        Header {
            sport: t.local.port(),
            dport: t.remote.port(),
            seq: seq_no,
            ack: if flags & ACK != 0 { self.rcv_nxt } else { 0 },
            flags,
            window: self.rcv_wnd() as u16,
            mss,
        }
    }

    /// A segment that carries our ACK went out.
    fn acked(&mut self) {
        self.ack_at = None;
        self.ack_sent = self.rcv_nxt;
        let edge = self.rcv_nxt.wrapping_add(self.rcv_wnd());
        if seq::gt(edge, self.rcv_adv) {
            self.rcv_adv = edge;
        }
    }

    /// A segment taking sequence space went out.
    fn sent(&mut self, now: u64, len: u32) {
        if len == 0 {
            return;
        }
        if self.snd_una == self.snd_max {
            self.alive_at = now; // the user timeout starts
        }
        if self.rtt_sample.is_none() && self.snd_nxt == self.snd_max {
            self.rtt_sample = Some((self.snd_nxt.wrapping_add(len), now));
        }
        self.snd_nxt = self.snd_nxt.wrapping_add(len);
        if seq::gt(self.snd_nxt, self.snd_max) {
            self.snd_max = self.snd_nxt;
        }
        if self.rtx_at.is_none() {
            self.rtx_at = Some(now + self.rto);
        }
    }

    /// Send what is due through `emit` (false: it took nothing, stop).
    pub(crate) fn dispatch(&mut self, cx: &mut Ctx, emit: &mut dyn FnMut(&Emit) -> bool) -> bool {
        let now = cx.now;
        if let Some((t, sq, ack)) = self.pending_rst {
            let h = Header {
                sport: t.local.port(),
                dport: t.remote.port(),
                seq: sq,
                ack,
                flags: RST | ACK,
                window: 0,
                mss: None,
            };
            if !emit(&Emit::new(&t, h, &[], &[])) {
                return false;
            }
            cx.stats.resets_sent += 1;
            self.pending_rst = None;
        }
        let Some(t) = self.tuple else { return true };
        for _ in 0..64 {
            match self.state {
                State::Closed | State::Listen => return true,
                State::SynSent | State::SynReceived if self.snd_nxt == self.iss && !self.iss_pending => {
                    let flags = if self.state == State::SynSent { SYN } else { SYN | ACK };
                    let mss = cx.mss(t.local.is_ipv6()) as u16;
                    let h = self.header(&t, self.iss, flags, Some(mss));
                    if !emit(&Emit::new(&t, h, &[], &[])) {
                        return false;
                    }
                    if flags & ACK != 0 {
                        self.acked();
                    }
                    self.sent(now, 1);
                    return true;
                }
                State::SynSent | State::SynReceived => {
                    // Only the SYN (-ACK) goes out while opening: its
                    // retransmission answers anything unacceptable.
                    self.ack_at = None;
                    return true;
                }
                State::TimeWait => {
                    if self.ack_at.is_some_and(|a| a <= now) {
                        let h = self.header(&t, self.snd_nxt, ACK, None);
                        if !emit(&Emit::new(&t, h, &[], &[])) {
                            return false;
                        }
                        self.acked();
                    }
                    return true;
                }
                _ => {}
            }
            let (n, probe, fin) = self.next_send(now);
            if n == 0 && !fin {
                let off = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
                if self.persist_at.is_none() && self.snd_wnd == 0 && off == 0 && !self.tx.is_empty() {
                    self.persist_ivl = self.rto;
                    self.persist_at = Some(now + self.persist_ivl);
                }
                if self.ack_at.is_some_and(|a| a <= now) || self.window_update_due() {
                    let h = self.header(&t, self.snd_nxt, ACK, None);
                    if !emit(&Emit::new(&t, h, &[], &[])) {
                        return false;
                    }
                    self.acked();
                }
                return true;
            }
            let off = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
            let mut flags = ACK;
            if n > 0 && off + n == self.tx.len() {
                flags |= PSH;
            }
            if fin {
                flags |= FIN;
            }
            let (a, b) = self.tx.slices(off, n);
            let h = self.header(&t, self.snd_nxt, flags, None);
            if !emit(&Emit::new(&t, h, a, b)) {
                return false;
            }
            self.acked();
            if fin {
                self.fin_seq = Some(self.snd_nxt.wrapping_add(n as u32));
            }
            self.sent(now, n as u32 + u32::from(fin));
            if probe {
                // The user timeout counts from each probe: an answer
                // shows the peer lives (RFC 9293 §3.8.6.1).
                self.alive_at = now;
                cx.stats.window_probes += 1;
                self.persist_ivl = (self.persist_ivl * 2).clamp(RTO_MIN_MS, RTO_MAX_MS);
                self.persist_at = Some(now + self.persist_ivl);
            }
        }
        true
    }
}

impl core::fmt::Debug for Socket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Socket")
            .field("state", &self.state)
            .field("tuple", &self.tuple)
            .field("snd", &(self.snd_una, self.snd_nxt, self.snd_max, self.snd_wnd, self.snd_mss))
            .field("tx", &self.tx.len())
            .field("fin", &(self.fin_queued, self.fin_seq))
            .field("rcv", &(self.rcv_nxt, self.rcv_adv, self.rx.len(), self.ooo.len()))
            .field("timers", &(self.rtx_at, self.persist_at, self.ack_at, self.time_wait_until, self.alive_at))
            .field("pending_rst", &self.pending_rst.is_some())
            .finish()
    }
}
