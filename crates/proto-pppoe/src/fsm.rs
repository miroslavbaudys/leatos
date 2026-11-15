//! The option negotiation automaton of RFC 1661 §4, shared by LCP and
//! IPCP. The lower layer (the PPPoE session) is up whenever an automaton
//! exists, so only the states from Req-Sent on are needed:
//!
//! ```text
//!            RCA                  RCR+ (we ack)
//!  ReqSent ───────► AckRcvd ─────────────────────┐
//!     │ RCR+                                     ▼
//!     └──────► AckSent ──── RCA ──────────────► Opened
//! ```
//!
//! Naks and rejects of our request adjust it ([`Options::on_nak`],
//! [`Options::on_reject`]) and send it again. The restart timer resends
//! the request; after [`MAX_CONFIGURE`] unanswered requests or
//! [`MAX_NAKS`] naks the negotiation fails. Terminate-Request is handled
//! by the caller (it ends the session).

use crate::wire::{self, CONF_ACK, CONF_NAK, CONF_REJ, CONF_REQ, Ctrl};
use alloc::vec::Vec;

pub const RESTART_MS: u64 = 3_000;
pub const MAX_CONFIGURE: u32 = 10;
pub const MAX_NAKS: u32 = 10;

/// The answer to the peer's Configure-Request.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Ack,
    /// Options with the values we want instead.
    Nak(Vec<u8>),
    /// The options we do not accept, as received.
    Reject(Vec<u8>),
}

/// Protocol-specific option handling (LCP, IPCP).
pub trait Options {
    /// Our Configure-Request options.
    fn request(&self) -> Vec<u8>;
    /// The peer naked these of our options (with values it wants).
    fn on_nak(&mut self, opts: &[(u8, &[u8])]);
    /// The peer rejected these of our options.
    fn on_reject(&mut self, opts: &[(u8, &[u8])]);
    /// Check the peer's request.
    fn check(&mut self, opts: &[(u8, &[u8])]) -> Verdict;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    ReqSent,
    AckRcvd,
    AckSent,
    Opened,
}

/// What a step did besides sending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    None,
    /// Entered Opened.
    Up,
    /// Left Opened (the peer renegotiates).
    Down,
    /// Gave up: no answer, or a nak loop.
    Failed,
}

pub struct Fsm {
    pub state: State,
    next_id: u8,
    /// Identifier and options of our outstanding request.
    req_id: u8,
    req: Vec<u8>,
    restart_at: u64,
    sent: u32,
    naks: u32,
    /// Control packets to send (`wire::ctrl` bodies).
    pub out: Vec<Vec<u8>>,
}

impl Fsm {
    /// Lower layer up and administratively open: send our request.
    pub fn start(now: u64, opts: &impl Options, first_id: u8) -> Self {
        let mut f = Fsm {
            state: State::ReqSent,
            next_id: first_id,
            req_id: 0,
            req: Vec::new(),
            restart_at: 0,
            sent: 0,
            naks: 0,
            out: Vec::new(),
        };
        f.send_request(now, opts);
        f
    }

    pub fn is_open(&self) -> bool {
        self.state == State::Opened
    }

    fn send_request(&mut self, now: u64, opts: &impl Options) {
        self.req = opts.request();
        self.req_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.out.push(wire::ctrl(CONF_REQ, self.req_id, &self.req));
        self.restart_at = now + RESTART_MS;
        self.sent += 1;
    }

    /// The restart timer, while not Opened.
    pub fn deadline(&self) -> Option<u64> {
        (self.state != State::Opened).then_some(self.restart_at)
    }

    pub fn poll(&mut self, now: u64, opts: &impl Options) -> Change {
        if self.state == State::Opened || now < self.restart_at {
            return Change::None;
        }
        if self.sent >= MAX_CONFIGURE {
            return Change::Failed;
        }
        if self.state == State::AckRcvd {
            self.state = State::ReqSent;
        }
        self.send_request(now, opts);
        Change::None
    }

    /// A Configure-Request/Ack/Nak/Reject from the peer. Other codes are
    /// the caller's.
    pub fn input(&mut self, now: u64, p: &Ctrl, opts: &mut impl Options) -> Change {
        let Some(list) = wire::options(p.data) else {
            return Change::None; // malformed: silently discarded
        };
        match p.code {
            CONF_REQ => {
                let verdict = opts.check(&list);
                let was_open = self.state == State::Opened;
                if was_open {
                    // Renegotiation: start over with our request too.
                    self.send_request(now, opts);
                }
                match verdict {
                    Verdict::Ack => {
                        self.out.push(wire::ctrl(CONF_ACK, p.id, p.data));
                        self.state = match self.state {
                            State::AckRcvd => State::Opened,
                            _ => State::AckSent,
                        };
                    }
                    Verdict::Nak(o) | Verdict::Reject(o) if o.is_empty() => {}
                    v => {
                        let (code, o) = match v {
                            Verdict::Nak(o) => (CONF_NAK, o),
                            Verdict::Reject(o) => (CONF_REJ, o),
                            Verdict::Ack => unreachable!(),
                        };
                        self.out.push(wire::ctrl(code, p.id, &o));
                        if matches!(self.state, State::AckSent | State::Opened) {
                            self.state = State::ReqSent;
                        }
                    }
                }
                match (was_open, self.state == State::Opened) {
                    (false, true) => Change::Up,
                    (true, false) => Change::Down,
                    _ => Change::None,
                }
            }
            CONF_ACK if p.id == self.req_id && p.data == self.req.as_slice() => {
                self.sent = 0;
                match self.state {
                    State::ReqSent => {
                        self.state = State::AckRcvd;
                        Change::None
                    }
                    State::AckSent => {
                        self.state = State::Opened;
                        Change::Up
                    }
                    // Crossed or repeated: renegotiate.
                    State::AckRcvd | State::Opened => {
                        let was_open = self.state == State::Opened;
                        self.state = State::ReqSent;
                        self.send_request(now, opts);
                        if was_open { Change::Down } else { Change::None }
                    }
                }
            }
            CONF_NAK | CONF_REJ if p.id == self.req_id => {
                if p.code == CONF_NAK {
                    self.naks += 1;
                    if self.naks > MAX_NAKS {
                        return Change::Failed;
                    }
                    opts.on_nak(&list);
                } else {
                    opts.on_reject(&list);
                }
                let was_open = self.state == State::Opened;
                if matches!(self.state, State::AckRcvd | State::Opened) {
                    self.state = State::ReqSent;
                }
                self.sent = 0;
                self.send_request(now, opts);
                if was_open { Change::Down } else { Change::None }
            }
            _ => Change::None, // stale identifier
        }
    }
}

/// Split the peer's options into the verdict: reject wins over nak,
/// nak over ack (RFC 1661 §5.2–5.4).
#[derive(Default)]
pub struct Judge {
    nak: Vec<u8>,
    rej: Vec<u8>,
}

impl Judge {
    pub fn nak(&mut self, kind: u8, value: &[u8]) {
        wire::put_option(&mut self.nak, kind, value);
    }

    pub fn reject(&mut self, kind: u8, value: &[u8]) {
        wire::put_option(&mut self.rej, kind, value);
    }

    pub fn verdict(self) -> Verdict {
        if !self.rej.is_empty() {
            Verdict::Reject(self.rej)
        } else if !self.nak.is_empty() {
            Verdict::Nak(self.nak)
        } else {
            Verdict::Ack
        }
    }
}
