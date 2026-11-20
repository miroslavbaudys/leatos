//! PPPoE client (RFC 2516) with the PPP it carries (RFC 1661): discovery
//! (PADI/PADO/PADR/PADS/PADT), LCP with echo keepalive, PAP (RFC 1334) or
//! CHAP-MD5 (RFC 1994), and IPCP with DNS servers (RFC 1332, RFC 1877).
//! See `docs/soho-features.md#pppoe`.
//!
//! ```text
//!  Idle ─start─► Padi ─PADO─► Padr ─PADS─► Lcp ─► Auth ─► Ipcp ─► Up
//!                  ▲                                               │
//!                  └──── Wait (exponential backoff) ◄── any failure, PADT,
//!                                                       echo timeout
//! ```
//!
//! [`Client`] is sans-IO: the caller feeds received frames
//! ([`Client::handle_frame`], EtherTypes 0x8863/0x8864) and the time
//! ([`Client::poll`]), and takes frames to send
//! ([`Client::poll_transmit`]) and [`Event`]s. IPv4 data never passes
//! through it: the datapath encapsulates and decapsulates that itself
//! ([`wire::encap_ipv4`], [`wire::decap_ipv4`]) for the [`Session`] the
//! client reports.
//!
//! RFC 4638 (MTU above 1492, "baby jumbo" frames): with [`Config::mtu`]
//! above 1492 the PADI and PADR carry PPP-Max-Payload; only if the AC echoes
//! it in both PADO and PADS does LCP ask for the larger MRU. Before the link
//! counts as up, a full-size LCP Echo-Request must come back full size (the
//! modem and the NICs carry the frames both ways); otherwise the session is
//! ended and every later one uses 1492 ([`Reason::JumboFailed`]).
//! [`Client::rfc4638_trace`] says what each step answered.
//!
//! Not supported (rejected in negotiation): IPv6CP, compression, multilink.
//!
//! `#![no_std]` + `alloc`, sans-IO, no unsafe; time is milliseconds.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod fsm;
pub mod wire;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::net::Ipv4Addr;
use fsm::{Change, Fsm, Judge, Options, Verdict};
use wire::*;
pub use wire::{Mac, Session};

/// Largest payload of a PPPoE session on Ethernet (1500 − 8).
pub const MAX_MTU: u16 = 1492;
/// Largest MTU asked for with RFC 4638 (1508 B PPPoE payload on the wire).
pub const MAX_MTU_RFC4638: u16 = 1500;
/// RFC 4638 path check: a full-size LCP echo, retried this often.
const JUMBO_CHECK_MS: u64 = 1_000;
const JUMBO_CHECK_TRIES: u32 = 3;
const PADI_FIRST_MS: u64 = 1_000;
const PADI_MAX_MS: u64 = 32_000;
const PADR_MS: u64 = 2_000;
const PADR_TRIES: u32 = 3;
const AUTH_RESTART_MS: u64 = 3_000;
const AUTH_TRIES: u32 = 10;
/// CHAP: how long to wait for the peer's challenge.
const CHAP_WAIT_MS: u64 = 30_000;
const BACKOFF_FIRST_MS: u64 = 1_000;
const BACKOFF_MAX_MS: u64 = 64_000;
/// An authentication failure waits at least this long (ISPs lock out
/// accounts that retry wrong credentials too often).
const AUTH_FAIL_MIN_MS: u64 = 10_000;
const TX_QUEUE_MAX: usize = 32;
/// Used as the peer's address when IPCP does not tell it (pppd does the
/// same): over PPP the next hop needs no address.
pub const DEFAULT_REMOTE: Ipv4Addr = Ipv4Addr::new(10, 64, 64, 64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub username: String,
    pub password: String,
    /// Service-Name to ask for; empty = any.
    pub service: String,
    /// Only accept offers from this access concentrator; empty = the first.
    pub ac_name: String,
    /// MRU we ask for and largest packet we send: ≤ [`MAX_MTU`], or up to
    /// [`MAX_MTU_RFC4638`] if the AC and the path carry it (RFC 4638; else
    /// [`MAX_MTU`]).
    pub mtu: u16,
    /// LCP echo request interval in seconds; 0 = no keepalive.
    pub echo_interval_secs: u32,
    /// Unanswered echo requests before the link counts as dead.
    pub echo_failures: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            username: String::new(),
            password: String::new(),
            service: String::new(),
            ac_name: String::new(),
            mtu: MAX_MTU,
            echo_interval_secs: 10,
            echo_failures: 5,
        }
    }
}

/// An established link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub session: Session,
    pub local: Ipv4Addr,
    pub remote: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    /// Largest IP packet to send: our MTU, capped by the peer's MRU.
    pub mtu: u16,
    pub ac_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The access concentrator ended the session (PADT).
    Padt,
    /// LCP Terminate-Request from the peer.
    Terminated,
    /// No answer to `echo_failures` echo requests.
    EchoTimeout,
    /// PAP Nak / CHAP Failure, with the peer's message.
    AuthFailed(String),
    /// The peer did not authenticate us in time, or asked for a method we
    /// do not support and would not take another.
    AuthTimeout,
    /// LCP or IPCP gave up (no answer, nak loop, no address assigned).
    Negotiation(&'static str),
    /// RFC 4638: the full-size echo did not come back full size, so frames
    /// above 1492 B of payload do not pass; the next sessions use 1492.
    JumboFailed,
    /// PADS with an error tag or session 0.
    Refused(String),
    /// [`Client::stop`].
    Stopped,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Padt => f.write_str("PADT from the access concentrator"),
            Reason::Terminated => f.write_str("terminated by the peer (LCP)"),
            Reason::EchoTimeout => f.write_str("no answer to LCP echo"),
            Reason::AuthFailed(m) if m.is_empty() => f.write_str("authentication failed"),
            Reason::AuthFailed(m) => write!(f, "authentication failed: {m}"),
            Reason::AuthTimeout => f.write_str("authentication timed out"),
            Reason::Negotiation(m) => write!(f, "negotiation failed: {m}"),
            Reason::JumboFailed => f.write_str("frames above 1492 B do not pass (RFC 4638): falling back to 1492"),
            Reason::Refused(m) => write!(f, "session refused: {m}"),
            Reason::Stopped => f.write_str("stopped"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// PADS: the session exists (LCP starts). The datapath may start
    /// decapsulating it.
    Session(Session),
    /// IPCP opened: IPv4 can flow.
    Up(Link),
    /// The session attempt or the session ended; `was_up` = after [`Event::Up`].
    Down { reason: Reason, was_up: bool },
    /// The peer's first IPv6CP Configure-Request in this session: it
    /// offers IPv6. We still answer with a Protocol-Reject (IPv6 is M7);
    /// `options` are the request's raw options (RFC 5072: type 1 =
    /// Interface-Identifier), for the log.
    PeerOffersIpv6 { options: Vec<u8> },
}

/// Where the client is, for status output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Idle,
    /// Waiting before the next attempt, until (ms).
    Waiting(u64),
    /// PADI sent (attempts).
    Discovery(u32),
    Requesting,
    Lcp,
    Auth,
    Ipcp,
    Up,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Idle => f.write_str("idle"),
            State::Waiting(_) => f.write_str("waiting to retry"),
            State::Discovery(n) => write!(f, "discovery (PADI {n})"),
            State::Requesting => f.write_str("discovery (PADR)"),
            State::Lcp => f.write_str("LCP"),
            State::Auth => f.write_str("authentication"),
            State::Ipcp => f.write_str("IPCP"),
            State::Up => f.write_str("up"),
        }
    }
}

/// xorshift64*: magic numbers and Host-Uniq (not secrets).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn nonzero32(&mut self) -> u32 {
        loop {
            let v = self.next() as u32;
            if v != 0 {
                return v;
            }
        }
    }
}

const LCP_MRU: u8 = 1;
const LCP_ACCM: u8 = 2;
const LCP_AUTH: u8 = 3;
const LCP_MAGIC: u8 = 5;
const CHAP_MD5: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Auth {
    Pap,
    Chap,
}

struct Lcp {
    /// MRU we request; `None` once rejected.
    mru: Option<u16>,
    max_mru: u16,
    magic: u32,
    rng: Rng,
    /// The peer's MRU (what we may send), default 1492 on PPPoE.
    peer_mru: u16,
    /// The peer sent an MRU option.
    peer_mru_sent: bool,
    /// RFC 4638: a peer MRU below ours was nak'd once (suggesting ours);
    /// the second time it is taken as it is.
    peer_mru_nakked: bool,
    peer_magic: u32,
    /// What the peer requires from us.
    auth: Option<Auth>,
}

impl Options for Lcp {
    fn request(&self) -> Vec<u8> {
        let mut o = Vec::new();
        if let Some(m) = self.mru {
            put_option(&mut o, LCP_MRU, &m.to_be_bytes());
        }
        if self.magic != 0 {
            put_option(&mut o, LCP_MAGIC, &self.magic.to_be_bytes());
        }
        o
    }

    fn on_nak(&mut self, opts: &[(u8, &[u8])]) {
        for &(k, v) in opts {
            match (k, v.len()) {
                (LCP_MRU, 2) => {
                    let m = get16(v, 0);
                    // Larger than we can take: leave the default to the peer.
                    self.mru = (m <= self.max_mru && m >= 576).then_some(m);
                }
                (LCP_MAGIC, 4) => self.magic = self.rng.nonzero32(),
                _ => {}
            }
        }
    }

    fn on_reject(&mut self, opts: &[(u8, &[u8])]) {
        for &(k, _) in opts {
            match k {
                LCP_MRU => self.mru = None,
                LCP_MAGIC => self.magic = 0,
                _ => {}
            }
        }
    }

    fn check(&mut self, opts: &[(u8, &[u8])]) -> Verdict {
        let mut j = Judge::default();
        let mut auth = None;
        for &(k, v) in opts {
            match (k, v.len()) {
                // RFC 4638: suggest the larger MRU once, then take theirs.
                (LCP_MRU, 2) if self.max_mru > MAX_MTU && get16(v, 0) < self.max_mru && !self.peer_mru_nakked => {
                    self.peer_mru_nakked = true;
                    j.nak(LCP_MRU, &self.max_mru.to_be_bytes());
                }
                (LCP_MRU, 2) => {
                    self.peer_mru = get16(v, 0);
                    self.peer_mru_sent = true;
                }
                // Meaningless on PPPoE (no async framing), harmless to ack.
                (LCP_ACCM, 4) => {}
                (LCP_AUTH, 2) if get16(v, 0) == PPP_PAP => auth = Some(Auth::Pap),
                (LCP_AUTH, 3) if get16(v, 0) == PPP_CHAP && v[2] == CHAP_MD5 => {
                    auth = Some(Auth::Chap)
                }
                // EAP, MS-CHAP, …: propose CHAP-MD5 instead.
                (LCP_AUTH, _) => j.nak(LCP_AUTH, &[0xc2, 0x23, CHAP_MD5]),
                (LCP_MAGIC, 4) => {
                    let m = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                    if m != 0 && m == self.magic {
                        // Looped back (or a collision): suggest another.
                        j.nak(LCP_MAGIC, &self.rng.nonzero32().to_be_bytes());
                    } else {
                        self.peer_magic = m;
                    }
                }
                // PFC/ACFC (forbidden on PPPoE), callbacks, multilink, …
                _ => j.reject(k, v),
            }
        }
        let v = j.verdict();
        if v == Verdict::Ack {
            self.auth = auth;
        }
        v
    }
}

const IPCP_ADDR: u8 = 3;
const IPCP_DNS1: u8 = 129;
const IPCP_DNS2: u8 = 131;

struct Ipcp {
    addr: Ipv4Addr,
    dns1: Option<Ipv4Addr>,
    dns2: Option<Ipv4Addr>,
    addr_rejected: bool,
    remote: Option<Ipv4Addr>,
}

fn ip(v: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(v[0], v[1], v[2], v[3])
}

impl Options for Ipcp {
    fn request(&self) -> Vec<u8> {
        let mut o = Vec::new();
        if !self.addr_rejected {
            put_option(&mut o, IPCP_ADDR, &self.addr.octets());
        }
        for (k, d) in [(IPCP_DNS1, self.dns1), (IPCP_DNS2, self.dns2)] {
            if let Some(d) = d {
                put_option(&mut o, k, &d.octets());
            }
        }
        o
    }

    fn on_nak(&mut self, opts: &[(u8, &[u8])]) {
        for &(k, v) in opts {
            if v.len() != 4 {
                continue;
            }
            match k {
                IPCP_ADDR => self.addr = ip(v),
                IPCP_DNS1 => self.dns1 = Some(ip(v)),
                IPCP_DNS2 => self.dns2 = Some(ip(v)),
                _ => {}
            }
        }
    }

    fn on_reject(&mut self, opts: &[(u8, &[u8])]) {
        for &(k, _) in opts {
            match k {
                IPCP_ADDR => self.addr_rejected = true,
                IPCP_DNS1 => self.dns1 = None,
                IPCP_DNS2 => self.dns2 = None,
                _ => {}
            }
        }
    }

    fn check(&mut self, opts: &[(u8, &[u8])]) -> Verdict {
        let mut j = Judge::default();
        for &(k, v) in opts {
            match (k, v.len()) {
                (IPCP_ADDR, 4) if ip(v) != Ipv4Addr::UNSPECIFIED => self.remote = Some(ip(v)),
                // 0.0.0.0 asks us to assign one: we cannot. VJ compression,
                // anything else: not supported.
                _ => j.reject(k, v),
            }
        }
        j.verdict()
    }
}

enum AuthPhase {
    Pap { id: u8, next: u64, tries: u32 },
    Chap { deadline: u64 },
}

struct Sess {
    s: Session,
    ac_name: String,
    lcp_opts: Lcp,
    lcp: Fsm,
    auth: Option<AuthPhase>,
    /// Auth done (or not required): IPCP runs.
    ipcp: Option<(Fsm, Ipcp)>,
    up: bool,
    next_echo: u64,
    echo_id: u8,
    echo_outstanding: u32,
    /// Identifiers for LCP packets outside the negotiation.
    lcp_id: u8,
    /// RFC 4638: IPCP is up, waiting for the full-size echo to come back
    /// before reporting `link`.
    jumbo_check: Option<JumboCheck>,
    /// An IPv6CP Configure-Request came in this session
    /// ([`Event::PeerOffersIpv6`] once).
    ipv6cp_seen: bool,
}

struct JumboCheck {
    id: u8,
    tries: u32,
    next: u64,
    /// The echo's size: our MRU (what the AC may now send us).
    size: u16,
    link: Link,
}

enum Phase {
    Idle,
    Wait(u64),
    Padi {
        tries: u32,
        next: u64,
        interval: u64,
    },
    Padr {
        ac: Mac,
        tags: Vec<(u16, Vec<u8>)>,
        ac_name: String,
        tries: u32,
        next: u64,
    },
    Session(alloc::boxed::Box<Sess>),
}

pub struct Client {
    cfg: Config,
    mac: Mac,
    rng: Rng,
    host_uniq: [u8; 8],
    phase: Phase,
    backoff: u64,
    tx: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    /// RFC 4638: the last accepted PADO's PPP-Max-Payload.
    pado_max_payload: Option<u16>,
    /// RFC 4638 failed its path check: no more asking (this client).
    jumbo_failed: bool,
    /// The last PADS's PPP-Max-Payload (RFC 4638 trace).
    pads_max_payload: Option<u16>,
    /// The last RFC 4638 path check's echo reply: LCP length, and what
    /// was sent.
    jumbo_reply: Option<(usize, u16)>,
    /// IPv6CP Configure-Requests from peers (all sessions).
    ipv6cp_requests: u32,
}

/// What each RFC 4638 step said, for the log ([`Client::rfc4638_trace`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rfc4638Trace {
    /// PPP-Max-Payload in the PADO / the PADS (`None`: no tag).
    pub pado: Option<u16>,
    pub pads: Option<u16>,
    /// The MRU we asked for in LCP (`None`: rejected).
    pub our_mru: Option<u16>,
    /// The MRU the peer asked for (`None`: it sent no MRU option).
    pub peer_mru: Option<u16>,
    /// The path check's echo: (reply length, request length).
    pub echo: Option<(usize, u16)>,
}

impl Client {
    /// A client for the WAN port with MAC `mac`; `seed` varies magic
    /// numbers and Host-Uniq. Starts [`State::Idle`].
    pub fn new(mut cfg: Config, mac: Mac, seed: u64) -> Self {
        cfg.mtu = cfg.mtu.clamp(576, MAX_MTU_RFC4638);
        let mut rng = Rng(seed | 1);
        let host_uniq = rng.next().to_be_bytes();
        Client {
            cfg,
            mac,
            rng,
            host_uniq,
            phase: Phase::Idle,
            backoff: BACKOFF_FIRST_MS,
            tx: VecDeque::new(),
            events: VecDeque::new(),
            pado_max_payload: None,
            jumbo_failed: false,
            pads_max_payload: None,
            jumbo_reply: None,
            ipv6cp_requests: 0,
        }
    }

    /// With an MTU above 1492: what the PADO, PADS and LCP said, during or
    /// after a session's negotiation.
    pub fn rfc4638_trace(&self) -> Option<Rfc4638Trace> {
        if self.cfg.mtu <= MAX_MTU {
            return None;
        }
        let Phase::Session(s) = &self.phase else { return None };
        Some(Rfc4638Trace {
            pado: self.pado_max_payload,
            pads: self.pads_max_payload,
            our_mru: s.lcp_opts.mru,
            peer_mru: s.lcp_opts.peer_mru_sent.then_some(s.lcp_opts.peer_mru),
            echo: self.jumbo_reply,
        })
    }

    /// The trace of the attempt that just failed (no session any more):
    /// what the last path check got.
    pub fn last_jumbo_reply(&self) -> Option<(usize, u16)> {
        self.jumbo_reply
    }

    /// RFC 4638 is asked for: an MTU above 1492 that has not failed.
    fn wants_jumbo(&self) -> bool {
        self.cfg.mtu > MAX_MTU && !self.jumbo_failed
    }

    /// The path check of an RFC 4638 session failed earlier: sessions use
    /// 1492 now.
    pub fn jumbo_failed(&self) -> bool {
        self.jumbo_failed
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Begin discovery now (from Idle or Waiting).
    pub fn start(&mut self, now: u64) {
        if matches!(self.phase, Phase::Idle | Phase::Wait(_)) {
            self.send_padi(now, 1, PADI_FIRST_MS);
        }
    }

    /// End the session (LCP Terminate-Request and PADT) and stay idle.
    pub fn stop(&mut self) {
        if let Phase::Session(s) = &mut self.phase {
            let id = s.lcp_id;
            s.lcp_id = id.wrapping_add(1);
            let (sess, up) = (s.s, s.up);
            self.send_ppp(sess, PPP_LCP, &ctrl(TERM_REQ, id, b"stopped"));
            self.send_padt(sess);
            self.events.push_back(Event::Down {
                reason: Reason::Stopped,
                was_up: up,
            });
        }
        self.phase = Phase::Idle;
    }

    pub fn state(&self) -> State {
        match &self.phase {
            Phase::Idle => State::Idle,
            Phase::Wait(t) => State::Waiting(*t),
            Phase::Padi { tries, .. } => State::Discovery(*tries),
            Phase::Padr { .. } => State::Requesting,
            Phase::Session(s) if s.up => State::Up,
            Phase::Session(s) if s.ipcp.is_some() => State::Ipcp,
            Phase::Session(s) if s.lcp.is_open() => State::Auth,
            Phase::Session(_) => State::Lcp,
        }
    }

    /// The session, from PADS on.
    pub fn session(&self) -> Option<Session> {
        match &self.phase {
            Phase::Session(s) => Some(s.s),
            _ => None,
        }
    }

    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When [`Self::poll`] next has work.
    pub fn next_deadline(&self) -> Option<u64> {
        match &self.phase {
            Phase::Idle => None,
            Phase::Wait(t) => Some(*t),
            Phase::Padi { next, .. } | Phase::Padr { next, .. } => Some(*next),
            Phase::Session(s) => {
                let mut d = s.lcp.deadline();
                let mut min = |t: Option<u64>| {
                    if let Some(t) = t {
                        d = Some(d.map_or(t, |x: u64| x.min(t)));
                    }
                };
                min(match &s.auth {
                    Some(AuthPhase::Pap { next, .. }) => Some(*next),
                    Some(AuthPhase::Chap { deadline }) => Some(*deadline),
                    None => None,
                });
                min(s.ipcp.as_ref().and_then(|(f, _)| f.deadline()));
                if s.up && self.cfg.echo_interval_secs > 0 {
                    min(Some(s.next_echo));
                }
                d
            }
        }
    }

    fn push_tx(&mut self, f: Vec<u8>) {
        if self.tx.len() >= TX_QUEUE_MAX {
            self.tx.pop_front();
        }
        self.tx.push_back(f);
    }

    fn send_ppp(&mut self, s: Session, proto: u16, body: &[u8]) {
        let f = session_frame(s.peer, self.mac, s.id, proto, body);
        self.push_tx(f);
    }

    fn send_padt(&mut self, s: Session) {
        let f = discovery(
            s.peer,
            self.mac,
            PADT,
            s.id,
            &[(TAG_HOST_UNIQ, &self.host_uniq)],
        );
        self.push_tx(f);
    }

    fn send_padi(&mut self, now: u64, tries: u32, interval: u64) {
        let ask = self.wants_jumbo().then_some(self.cfg.mtu.to_be_bytes());
        let mut t: Vec<(u16, &[u8])> = alloc::vec![
            (TAG_SERVICE_NAME, self.cfg.service.as_bytes()),
            (TAG_HOST_UNIQ, &self.host_uniq),
        ];
        if let Some(a) = &ask {
            t.push((TAG_PPP_MAX_PAYLOAD, a));
        }
        let f = discovery(BROADCAST, self.mac, PADI, 0, &t);
        self.push_tx(f);
        self.phase = Phase::Padi {
            tries,
            next: now + interval,
            interval,
        };
    }

    fn send_padr(&mut self, ac: Mac, tags: &[(u16, Vec<u8>)]) {
        let t: Vec<(u16, &[u8])> = tags.iter().map(|(k, v)| (*k, v.as_slice())).collect();
        let f = discovery(ac, self.mac, PADR, 0, &t);
        self.push_tx(f);
    }

    /// Give up on this attempt (or session): wait, then discover again.
    fn fail(&mut self, now: u64, reason: Reason, padt: bool) {
        let was_up = match &self.phase {
            Phase::Session(s) => {
                let (sess, up) = (s.s, s.up);
                if padt {
                    self.send_padt(sess);
                }
                up
            }
            _ => false,
        };
        let mut wait = self.backoff;
        if matches!(reason, Reason::AuthFailed(_) | Reason::AuthTimeout) {
            wait = wait.max(AUTH_FAIL_MIN_MS);
        }
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX_MS);
        self.phase = Phase::Wait(now + wait);
        self.events.push_back(Event::Down { reason, was_up });
    }

    /// Timers: retransmissions, keepalive, the backoff wait.
    pub fn poll(&mut self, now: u64) {
        match &mut self.phase {
            Phase::Idle => {}
            Phase::Wait(t) => {
                if now >= *t {
                    self.send_padi(now, 1, PADI_FIRST_MS);
                }
            }
            Phase::Padi {
                tries,
                next,
                interval,
            } => {
                if now >= *next {
                    let (t, i) = (*tries + 1, (*interval * 2).min(PADI_MAX_MS));
                    self.send_padi(now, t, i);
                }
            }
            Phase::Padr {
                ac,
                tags,
                tries,
                next,
                ..
            } => {
                if now >= *next {
                    if *tries >= PADR_TRIES {
                        self.send_padi(now, 1, PADI_FIRST_MS);
                    } else {
                        *tries += 1;
                        *next = now + PADR_MS;
                        let (ac, tags) = (*ac, tags.clone());
                        self.send_padr(ac, &tags);
                    }
                }
            }
            Phase::Session(_) => self.poll_session(now),
        }
    }

    fn poll_session(&mut self, now: u64) {
        let Phase::Session(s) = &mut self.phase else {
            return;
        };
        let sess = s.s;
        let mut out: Vec<(u16, Vec<u8>)> = Vec::new();
        let mut failed: Option<Reason> = None;
        if s.lcp.poll(now, &s.lcp_opts) == Change::Failed {
            failed = Some(Reason::Negotiation("LCP: no answer"));
        }
        out.extend(s.lcp.out.drain(..).map(|b| (PPP_LCP, b)));
        match &mut s.auth {
            Some(AuthPhase::Pap { id, next, tries }) if now >= *next => {
                if *tries >= AUTH_TRIES {
                    failed = failed.or(Some(Reason::AuthTimeout));
                } else {
                    *tries += 1;
                    *id = id.wrapping_add(1);
                    *next = now + AUTH_RESTART_MS;
                    out.push((PPP_PAP, pap_request(*id, &self.cfg)));
                }
            }
            Some(AuthPhase::Chap { deadline }) if now >= *deadline => {
                failed = failed.or(Some(Reason::AuthTimeout));
            }
            _ => {}
        }
        if let Some((f, o)) = &mut s.ipcp {
            if f.poll(now, o) == Change::Failed {
                failed = failed.or(Some(Reason::Negotiation("IPCP: no answer")));
            }
            out.extend(f.out.drain(..).map(|b| (PPP_IPCP, b)));
        }
        if let Some(j) = &mut s.jumbo_check
            && now >= j.next
        {
            if j.tries >= JUMBO_CHECK_TRIES {
                self.jumbo_failed = true;
                failed = failed.or(Some(Reason::JumboFailed));
            } else {
                j.tries += 1;
                j.next = now + JUMBO_CHECK_MS;
                out.push((PPP_LCP, jumbo_echo(j.id, s.lcp_opts.magic, j.size)));
            }
        }
        if s.up && self.cfg.echo_interval_secs > 0 && now >= s.next_echo {
            if s.echo_outstanding >= self.cfg.echo_failures.max(1) {
                failed = failed.or(Some(Reason::EchoTimeout));
            } else {
                s.echo_outstanding += 1;
                s.echo_id = s.echo_id.wrapping_add(1);
                s.next_echo = now + u64::from(self.cfg.echo_interval_secs) * 1000;
                let magic = s.lcp_opts.magic.to_be_bytes();
                out.push((PPP_LCP, ctrl(ECHO_REQ, s.echo_id, &magic)));
            }
        }
        for (p, b) in out {
            self.send_ppp(sess, p, &b);
        }
        if let Some(r) = failed {
            self.fail(now, r, true);
        }
    }

    /// A received frame (EtherType 0x8863 or 0x8864, untagged). Anything
    /// not for this client is ignored.
    pub fn handle_frame(&mut self, now: u64, frame: &[u8]) {
        let Some(p) = parse(frame) else { return };
        if p.dst != self.mac && p.dst != BROADCAST {
            return;
        }
        if p.ethertype == ETHERTYPE_DISCOVERY {
            self.discovery(now, &p);
        } else if p.code == 0
            && let Phase::Session(s) = &self.phase
            && p.session == s.s.id
            && p.src == s.s.peer
            && p.payload.len() >= 2
        {
            let proto = get16(p.payload, 0);
            self.session_input(now, proto, &p.payload[2..]);
        }
    }

    fn uniq_ok(&self, payload: &[u8]) -> bool {
        find_tag(payload, TAG_HOST_UNIQ) == Some(&self.host_uniq[..])
    }

    fn discovery(&mut self, now: u64, p: &Pppoe) {
        match (p.code, &self.phase) {
            (PADO, Phase::Padi { .. }) if p.session == 0 && self.uniq_ok(p.payload) => {
                let ac_name = find_tag(p.payload, TAG_AC_NAME).unwrap_or(b"");
                let errors = tags(p.payload).any(|(t, _)| {
                    matches!(
                        t,
                        TAG_SERVICE_NAME_ERROR | TAG_AC_SYSTEM_ERROR | TAG_GENERIC_ERROR
                    )
                });
                let service_ok = self.cfg.service.is_empty()
                    || tags(p.payload)
                        .any(|(t, v)| t == TAG_SERVICE_NAME && v == self.cfg.service.as_bytes());
                let ac_ok = self.cfg.ac_name.is_empty() || ac_name == self.cfg.ac_name.as_bytes();
                if errors || !service_ok || !ac_ok || p.src[0] & 1 != 0 {
                    return;
                }
                let mut t = alloc::vec![
                    (TAG_SERVICE_NAME, Vec::from(self.cfg.service.as_bytes())),
                    (TAG_HOST_UNIQ, Vec::from(&self.host_uniq[..])),
                ];
                for tag in [TAG_AC_COOKIE, TAG_RELAY_SESSION_ID] {
                    if let Some(v) = find_tag(p.payload, tag) {
                        t.push((tag, Vec::from(v)));
                    }
                }
                let echo = max_payload(p.payload);
                self.pado_max_payload = echo;
                // RFC 4638: ask again in the PADR only if the AC echoed it.
                if self.wants_jumbo()
                    && let Some(m) = echo.filter(|&m| m > MAX_MTU)
                {
                    t.push((TAG_PPP_MAX_PAYLOAD, Vec::from(m.min(self.cfg.mtu).to_be_bytes())));
                }
                let ac_name = String::from_utf8_lossy(ac_name).into();
                self.send_padr(p.src, &t);
                self.phase = Phase::Padr {
                    ac: p.src,
                    tags: t,
                    ac_name,
                    tries: 1,
                    next: now + PADR_MS,
                };
            }
            (PADS, Phase::Padr { ac, ac_name, tags: asked, .. }) if p.src == *ac && self.uniq_ok(p.payload) => {
                let err = tags(p.payload).find(|(t, _)| {
                    matches!(
                        *t,
                        TAG_SERVICE_NAME_ERROR | TAG_AC_SYSTEM_ERROR | TAG_GENERIC_ERROR
                    )
                });
                if p.session == 0 || err.is_some() {
                    let msg = err
                        .map(|(_, v)| String::from_utf8_lossy(v).into())
                        .unwrap_or_else(|| String::from("session 0"));
                    self.fail(now, Reason::Refused(msg), false);
                    return;
                }
                let s = Session {
                    id: p.session,
                    peer: *ac,
                };
                // RFC 4638: the larger MRU once PADR asked and PADS echoed.
                let asked = asked
                    .iter()
                    .find(|(t, _)| *t == TAG_PPP_MAX_PAYLOAD)
                    .and_then(|(_, v)| max_payload_value(v));
                self.pads_max_payload = max_payload(p.payload);
                let mru = match (asked, max_payload(p.payload)) {
                    (Some(a), Some(e)) if e > MAX_MTU => a.min(e),
                    _ => self.cfg.mtu.min(MAX_MTU),
                };
                let ac_name = ac_name.clone();
                self.open_session(now, s, ac_name, mru);
            }
            (PADT, Phase::Session(s)) if p.session == s.s.id && p.src == s.s.peer => {
                self.fail(now, Reason::Padt, false);
            }
            _ => {}
        }
    }

    fn open_session(&mut self, now: u64, s: Session, ac_name: String, mru: u16) {
        let lcp_opts = Lcp {
            mru: Some(mru),
            max_mru: mru,
            magic: self.rng.nonzero32(),
            rng: Rng(self.rng.next() | 1),
            // Unless the peer says more (RFC 4638 §7: above 1492 only when
            // negotiated).
            peer_mru: MAX_MTU,
            peer_mru_sent: false,
            peer_mru_nakked: false,
            peer_magic: 0,
            auth: None,
        };
        let first_id = self.rng.next() as u8;
        let lcp = Fsm::start(now, &lcp_opts, first_id);
        self.phase = Phase::Session(alloc::boxed::Box::new(Sess {
            s,
            ac_name,
            lcp_opts,
            lcp,
            auth: None,
            ipcp: None,
            up: false,
            next_echo: 0,
            echo_id: 0,
            echo_outstanding: 0,
            lcp_id: first_id.wrapping_add(128),
            jumbo_check: None,
            ipv6cp_seen: false,
        }));
        self.events.push_back(Event::Session(s));
        self.flush_session_out();
    }

    /// Send what the automata queued.
    fn flush_session_out(&mut self) {
        let Phase::Session(s) = &mut self.phase else {
            return;
        };
        let sess = s.s;
        let mut out: Vec<(u16, Vec<u8>)> = s.lcp.out.drain(..).map(|b| (PPP_LCP, b)).collect();
        if let Some((f, _)) = &mut s.ipcp {
            out.extend(f.out.drain(..).map(|b| (PPP_IPCP, b)));
        }
        for (p, b) in out {
            self.send_ppp(sess, p, &b);
        }
    }

    fn session_input(&mut self, now: u64, proto: u16, body: &[u8]) {
        match proto {
            PPP_LCP => self.lcp_input(now, body),
            PPP_PAP => self.pap_input(now, body),
            PPP_CHAP => self.chap_input(now, body),
            PPP_IPCP => self.ipcp_input(now, body),
            PPP_IPV6CP => {
                self.note_ipv6cp(body);
                self.protocol_reject(proto, body);
            }
            _ => self.protocol_reject(proto, body),
        }
        self.flush_session_out();
    }

    /// Count an IPv6CP Configure-Request; the first one of a session
    /// becomes [`Event::PeerOffersIpv6`].
    fn note_ipv6cp(&mut self, body: &[u8]) {
        let Some(p) = parse_ctrl(body) else { return };
        let Phase::Session(s) = &mut self.phase else {
            return;
        };
        if p.code != CONF_REQ || !s.lcp.is_open() {
            return;
        }
        self.ipv6cp_requests = self.ipv6cp_requests.saturating_add(1);
        if !core::mem::replace(&mut s.ipv6cp_seen, true) {
            let options = p.data[..p.data.len().min(64)].to_vec();
            self.events.push_back(Event::PeerOffersIpv6 { options });
        }
    }

    /// IPv6CP Configure-Requests peers sent (all sessions): whether the
    /// ISP offers IPv6.
    pub fn ipv6cp_requests(&self) -> u32 {
        self.ipv6cp_requests
    }

    /// LCP Protocol-Reject for protocols we do not run (IPv6CP, CCP, …),
    /// once LCP is open (RFC 1661 §5.7).
    fn protocol_reject(&mut self, proto: u16, body: &[u8]) {
        let Phase::Session(s) = &mut self.phase else {
            return;
        };
        if !s.lcp.is_open() {
            return;
        }
        let id = s.lcp_id;
        s.lcp_id = id.wrapping_add(1);
        let sess = s.s;
        let mut data = Vec::from(proto.to_be_bytes());
        // Fits the peer's MRU with room for the headers.
        data.extend_from_slice(&body[..body.len().min(1400)]);
        self.send_ppp(sess, PPP_LCP, &ctrl(PROTO_REJ, id, &data));
    }

    fn lcp_input(&mut self, now: u64, body: &[u8]) {
        let Some(p) = parse_ctrl(body) else { return };
        let Phase::Session(s) = &mut self.phase else {
            return;
        };
        let sess = s.s;
        match p.code {
            CONF_REQ | CONF_ACK | CONF_NAK | CONF_REJ => {
                let change = s.lcp.input(now, &p, &mut s.lcp_opts);
                match change {
                    Change::Up => {
                        // Authentication phase: what the peer asked for.
                        s.auth = match s.lcp_opts.auth {
                            Some(Auth::Pap) => Some(AuthPhase::Pap {
                                id: 0,
                                next: now,
                                tries: 0,
                            }),
                            Some(Auth::Chap) => Some(AuthPhase::Chap {
                                deadline: now + CHAP_WAIT_MS,
                            }),
                            None => None,
                        };
                        if s.auth.is_none() {
                            Self::start_ipcp(s, now);
                        } else {
                            self.poll_session(now);
                        }
                    }
                    Change::Down => {
                        self.flush_session_out();
                        self.fail(now, Reason::Negotiation("LCP renegotiated"), true);
                    }
                    Change::Failed => {
                        self.fail(now, Reason::Negotiation("LCP: nak loop"), true);
                    }
                    Change::None => {}
                }
            }
            TERM_REQ => {
                self.send_ppp(sess, PPP_LCP, &ctrl(TERM_ACK, p.id, b""));
                self.fail(now, Reason::Terminated, true);
            }
            ECHO_REQ if s.lcp.is_open() => {
                let mut d = Vec::from(s.lcp_opts.magic.to_be_bytes());
                d.extend_from_slice(p.data.get(4..).unwrap_or(b""));
                self.send_ppp(sess, PPP_LCP, &ctrl(ECHO_REPLY, p.id, &d));
            }
            ECHO_REPLY => {
                // Any reply shows the peer is alive (a late one too), unless
                // it carries our own magic number: a looped-back link.
                let magic = p
                    .data
                    .get(..4)
                    .map(|m| u32::from_be_bytes([m[0], m[1], m[2], m[3]]));
                let looped = magic == Some(s.lcp_opts.magic) && s.lcp_opts.magic != 0;
                if !looped {
                    s.echo_outstanding = 0;
                }
                // RFC 4638 path check: the full-size echo came back full
                // size (both directions carry the frames), or it did not.
                if !looped
                    && let Some(j) = s.jumbo_check.take_if(|j| j.id == p.id)
                {
                    let got = 4 + p.data.len();
                    self.jumbo_reply = Some((got, j.size));
                    // A short reply (an AC that does not copy the data, as
                    // RFC 1661 allows) proves only the upstream direction:
                    // not enough.
                    if got >= usize::from(j.size) {
                        self.go_up(now, j.link);
                    } else {
                        self.jumbo_failed = true;
                        self.fail(now, Reason::JumboFailed, true);
                    }
                }
            }
            PROTO_REJ => {
                if p.data.len() >= 2 && get16(p.data, 0) == PPP_IPCP {
                    self.fail(now, Reason::Negotiation("peer rejected IPCP"), true);
                }
            }
            TERM_ACK | CODE_REJ | DISCARD_REQ | ECHO_REQ => {}
            _ => {
                let id = s.lcp_id;
                s.lcp_id = id.wrapping_add(1);
                let rej = &body[..body.len().min(1400)];
                self.send_ppp(sess, PPP_LCP, &ctrl(CODE_REJ, id, rej));
            }
        }
    }

    fn start_ipcp(s: &mut Sess, now: u64) {
        let o = Ipcp {
            addr: Ipv4Addr::UNSPECIFIED,
            dns1: Some(Ipv4Addr::UNSPECIFIED),
            dns2: Some(Ipv4Addr::UNSPECIFIED),
            addr_rejected: false,
            remote: None,
        };
        let f = Fsm::start(now, &o, 1);
        s.auth = None;
        s.ipcp = Some((f, o));
    }

    fn auth_done(&mut self, now: u64, ok: Result<(), String>) {
        let Phase::Session(s) = &mut self.phase else {
            return;
        };
        if s.auth.is_none() {
            return; // repeated answer (CHAP re-challenge)
        }
        match ok {
            Ok(()) => Self::start_ipcp(s, now),
            Err(m) => self.fail(now, Reason::AuthFailed(m), true),
        }
    }

    fn pap_input(&mut self, now: u64, body: &[u8]) {
        let Some(p) = parse_ctrl(body) else { return };
        let Phase::Session(s) = &self.phase else {
            return;
        };
        let Some(AuthPhase::Pap { id, .. }) = s.auth else {
            return;
        };
        if p.id != id {
            return;
        }
        // Ack/Nak: a length-prefixed message.
        let msg = p
            .data
            .first()
            .and_then(|&n| p.data.get(1..1 + n as usize))
            .map(|m| String::from_utf8_lossy(m).into())
            .unwrap_or_default();
        match p.code {
            2 => self.auth_done(now, Ok(())),
            3 => self.auth_done(now, Err(msg)),
            _ => {}
        }
    }

    fn chap_input(&mut self, now: u64, body: &[u8]) {
        let Some(p) = parse_ctrl(body) else { return };
        let Phase::Session(s) = &self.phase else {
            return;
        };
        let sess = s.s;
        // Challenges also come later (re-authentication) while up.
        let waiting = matches!(s.auth, Some(AuthPhase::Chap { .. }));
        let chap = waiting || (s.lcp_opts.auth == Some(Auth::Chap) && s.ipcp.is_some());
        if !chap {
            return;
        }
        match p.code {
            1 => {
                let Some(&n) = p.data.first() else { return };
                let Some(value) = p.data.get(1..1 + n as usize) else {
                    return;
                };
                let resp = chap_response(p.id, &self.cfg, value);
                self.send_ppp(sess, PPP_CHAP, &resp);
            }
            3 if waiting => self.auth_done(now, Ok(())),
            4 if waiting => {
                let m = String::from_utf8_lossy(p.data).into();
                self.auth_done(now, Err(m));
            }
            _ => {}
        }
    }

    fn ipcp_input(&mut self, now: u64, body: &[u8]) {
        let Some(p) = parse_ctrl(body) else { return };
        let Phase::Session(s) = &mut self.phase else {
            return;
        };
        let sess = s.s;
        let Some((f, o)) = &mut s.ipcp else { return };
        match p.code {
            CONF_REQ | CONF_ACK | CONF_NAK | CONF_REJ => match f.input(now, &p, o) {
                Change::Up => {
                    if o.addr_rejected || o.addr == Ipv4Addr::UNSPECIFIED {
                        self.flush_session_out();
                        self.fail(now, Reason::Negotiation("IPCP: no address assigned"), true);
                        return;
                    }
                    let mut dns: Vec<Ipv4Addr> = Vec::new();
                    for d in [o.dns1, o.dns2].into_iter().flatten() {
                        if !d.is_unspecified() && !dns.contains(&d) {
                            dns.push(d);
                        }
                    }
                    let our_mru = s.lcp_opts.mru.unwrap_or(MAX_MTU);
                    let mtu = our_mru.min(s.lcp_opts.peer_mru);
                    let link = Link {
                        session: sess,
                        local: o.addr,
                        remote: o.remote.unwrap_or(DEFAULT_REMOTE),
                        dns,
                        mtu,
                        ac_name: s.ac_name.clone(),
                    };
                    if our_mru > MAX_MTU {
                        // RFC 4638: the AC may send us frames this large
                        // (whatever it takes from us): prove the path first.
                        let id = s.lcp_id;
                        s.lcp_id = id.wrapping_add(1);
                        let echo = jumbo_echo(id, s.lcp_opts.magic, our_mru);
                        s.jumbo_check = Some(JumboCheck {
                            id,
                            tries: 1,
                            next: now + JUMBO_CHECK_MS,
                            size: our_mru,
                            link,
                        });
                        self.send_ppp(sess, PPP_LCP, &echo);
                    } else {
                        self.go_up(now, link);
                    }
                }
                Change::Down => {
                    self.flush_session_out();
                    self.fail(now, Reason::Negotiation("IPCP renegotiated"), true);
                }
                Change::Failed => self.fail(now, Reason::Negotiation("IPCP: nak loop"), true),
                Change::None => {}
            },
            TERM_REQ => {
                self.send_ppp(sess, PPP_IPCP, &ctrl(TERM_ACK, p.id, b""));
                self.fail(now, Reason::Terminated, true);
            }
            _ => {}
        }
    }
}

impl Client {
    /// The link is up: keepalive starts, [`Event::Up`].
    fn go_up(&mut self, now: u64, link: Link) {
        let Phase::Session(s) = &mut self.phase else {
            return;
        };
        s.up = true;
        s.echo_outstanding = 0;
        s.next_echo = now + u64::from(self.cfg.echo_interval_secs) * 1000;
        self.backoff = BACKOFF_FIRST_MS;
        self.events.push_back(Event::Up(link));
    }
}

/// A PPP-Max-Payload tag's value (2 bytes).
fn max_payload_value(v: &[u8]) -> Option<u16> {
    (v.len() == 2).then(|| u16::from_be_bytes([v[0], v[1]]))
}

/// The PPP-Max-Payload tag of a discovery payload.
fn max_payload(payload: &[u8]) -> Option<u16> {
    find_tag(payload, TAG_PPP_MAX_PAYLOAD).and_then(max_payload_value)
}

/// An LCP Echo-Request exactly `mtu` bytes long (the PPP payload of a
/// full-size frame): magic number, then zeros.
fn jumbo_echo(id: u8, magic: u32, mtu: u16) -> Vec<u8> {
    let mut d = Vec::from(magic.to_be_bytes());
    d.resize(usize::from(mtu).saturating_sub(4), 0);
    ctrl(ECHO_REQ, id, &d)
}

fn pap_request(id: u8, cfg: &Config) -> Vec<u8> {
    let (u, p) = (cfg.username.as_bytes(), cfg.password.as_bytes());
    let (u, p) = (&u[..u.len().min(255)], &p[..p.len().min(255)]);
    let mut d = Vec::with_capacity(2 + u.len() + p.len());
    d.push(u.len() as u8);
    d.extend_from_slice(u);
    d.push(p.len() as u8);
    d.extend_from_slice(p);
    ctrl(1, id, &d)
}

/// CHAP-MD5 response: MD5(identifier ‖ secret ‖ challenge), then our name.
fn chap_response(id: u8, cfg: &Config, challenge: &[u8]) -> Vec<u8> {
    let digest = chap_md5(id, cfg.password.as_bytes(), challenge);
    let mut d = Vec::with_capacity(17 + cfg.username.len());
    d.push(16);
    d.extend_from_slice(&digest);
    d.extend_from_slice(cfg.username.as_bytes());
    ctrl(2, id, &d)
}

pub fn chap_md5(id: u8, secret: &[u8], challenge: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update([id]);
    h.update(secret);
    h.update(challenge);
    h.finalize().into()
}

#[cfg(test)]
mod tests;
