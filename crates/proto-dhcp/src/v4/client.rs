//! DHCPv4 client (RFC 2131, sans-IO): the WAN's address on a DHCP line
//! (docs/local-stack.md step 1; replaces smoltcp's `dhcpv4::Socket`, which
//! panics on `Medium::Ip`).
//!
//! INIT → DISCOVER → OFFER → REQUEST → ACK (bound), then RENEW at T1
//! (unicast to the server), REBIND at T2 (broadcast), and the lease is lost
//! when it ends (back to DISCOVER). A NAK in any state also starts over.
//! With an address from before ([`Config::last`]) the client starts in
//! INIT-REBOOT (§3.2: REQUEST for it, no server identifier) and falls back
//! to DISCOVER, still asking for that address, when nobody answers.
//!
//! Retransmission (§4.1): 4, 8, 16, 32, 64 s ±1 s for DISCOVER, REQUEST
//! and INIT-REBOOT; while renewing / rebinding, half the time left until
//! T2 / the lease's end, at least 60 s (§4.4.5). Consecutive NAKs delay
//! the next DISCOVER (doubling up to 64 s), so a server that NAKs every
//! REQUEST is not hammered.
//!
//! Not done: the ARP probe of an offered address and DECLINE (§4.4.1
//! SHOULD; smoltcp did not either), RELEASE (a reboot or upgrade should
//! get the same address back), option overload (option 52: `sname` /
//! `file` carrying options), BOOTP replies without a message type.
//!
//! Times are ms on the caller's clock. [`Client::poll`] returns a
//! [`Transmit`] (from port 68 to port 67, with the source and destination
//! address to use); [`Client::handle`] takes a datagram that came to port
//! 68; [`Client::poll_event`] reports [`Event::Bound`] (first lease, or
//! one whose settings changed) and [`Event::Lost`].

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use super::packet::{FLAG_BROADCAST, Message, MessageType, OP_REPLY, OP_REQUEST, Options};

pub use super::packet::{CLIENT_PORT, SERVER_PORT};

/// DISCOVER / REQUEST / INIT-REBOOT: first timeout, doubled up to the
/// maximum, each ±`JITTER_MS` (§4.1).
const FIRST_RT_MS: u64 = 4_000;
const MAX_RT_MS: u64 = 64_000;
const JITTER_MS: u64 = 1_000;
/// REQUESTs (after an OFFER) before starting over with DISCOVER.
const REQUEST_TRIES: u32 = 5;
/// INIT-REBOOT REQUESTs before DISCOVER (asking for the same address).
const REBOOT_TRIES: u32 = 2;
/// Renewing / rebinding retransmit no sooner than this (§4.4.5).
const MIN_RENEW_RT_MS: u64 = 60_000;
/// The first message waits up to this long (desynchronises routers after
/// a power cut; RFC 2131 suggests 1–10 s, too long for an upgrade).
const START_DELAY_MS: u64 = 1_000;
/// An ACK without a lease time (RFC 2131 requires one): smoltcp's default.
const DEFAULT_LEASE_SECS: u32 = 120;
/// Leases shorter than this are treated as this long, so a server cannot
/// make the client renew in a tight loop.
const MIN_LEASE_SECS: u32 = 60;
/// Option 51 = 0xffff_ffff: an infinite lease (no renewal).
const INFINITE: u32 = u32::MAX;
/// DNS servers kept from a reply.
const MAX_DNS: usize = 4;
/// Parameter request list (option 55): subnet mask, router, DNS, domain,
/// interface MTU, lease time, T1, T2.
const PARAMS: [u8; 8] = [1, 3, 6, 15, 26, 51, 58, 59];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The WAN MAC: `chaddr` and the client identifier (type 1 + MAC).
    pub mac: [u8; 6],
    /// Sent as option 12 when set (some ISPs want one).
    pub hostname: Option<String>,
    /// The address held before (kept across a restart): asked for again
    /// with INIT-REBOOT.
    pub last: Option<Ipv4Addr>,
    /// Ask servers to broadcast their replies (§4.1 `flags`), for a stack
    /// that cannot receive unicast to an address it does not have yet.
    pub broadcast: bool,
}

/// A datagram for the caller to send from port 68 to port 67.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// 0.0.0.0, or the leased address while renewing / rebinding.
    pub src: Ipv4Addr,
    /// 255.255.255.255, or the server while renewing.
    pub dst: Ipv4Addr,
    pub payload: Vec<u8>,
}

/// What the server gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    /// Option 26, if the server sent a sane one (≥ 576).
    pub mtu: Option<u16>,
    /// The server identifier (option 54).
    pub server: Ipv4Addr,
    /// As given (option 51); [`INFINITE`] = never ends.
    pub lease_secs: u32,
}

impl Lease {
    /// The same settings, apart from the lease time (a renewal).
    fn same_settings(&self, o: &Lease) -> bool {
        (self.address, self.prefix_len, self.router, &self.dns, &self.domain, self.mtu)
            == (o.address, o.prefix_len, o.router, &o.dns, &o.domain, o.mtu)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A lease, or a renewal that changed its settings (address, router,
    /// DNS, …). A renewal with the same settings reports nothing.
    Bound(Lease),
    /// The address is gone (lease over, NAK, [`Client::reset`]).
    Lost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// INIT-REBOOT: REQUEST for [`Config::last`].
    Rebooting,
    /// INIT / SELECTING: DISCOVER, waiting for an OFFER.
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Rebooting => "rebooting",
            State::Selecting => "selecting",
            State::Requesting => "requesting",
            State::Bound => "bound",
            State::Renewing => "renewing",
            State::Rebinding => "rebinding",
        }
    }
}

/// Counters for status pages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub sent: u64,
    /// Replies that moved the state machine (OFFER taken, ACK, NAK).
    pub received: u64,
    pub naks: u64,
    /// Datagrams dropped: malformed, not for us, not expected now, or a
    /// lease that fails the checks ([`Client::handle`]).
    pub ignored: u64,
}

/// The held lease, times in ms on the caller's clock (`u64::MAX` = never).
#[derive(Clone, Debug)]
struct Held {
    lease: Lease,
    t1: u64,
    t2: u64,
    end: u64,
}

pub struct Client {
    cfg: Config,
    state: State,
    xid: u32,
    rng: u64,
    /// The OFFER taken: (address, server identifier).
    offer: Option<(Ipv4Addr, Ipv4Addr)>,
    held: Option<Held>,
    /// Asked for in DISCOVER: the last address held.
    hint: Option<Ipv4Addr>,
    /// When the current exchange began (`secs`), the next transmission,
    /// its timeout and how many went out.
    started: u64,
    next_tx: u64,
    rt: u64,
    tries: u32,
    /// NAKs since the last lease.
    naks_in_row: u32,
    events: VecDeque<Event>,
    stats: Stats,
}

impl Client {
    pub fn new(cfg: Config, now: u64, seed: u64) -> Self {
        let mut c = Client {
            hint: cfg.last.filter(|&a| usable(a)),
            cfg,
            state: State::Selecting,
            xid: 0,
            rng: seed | 1,
            offer: None,
            held: None,
            started: now,
            next_tx: now,
            rt: 0,
            tries: 0,
            naks_in_row: 0,
            events: VecDeque::new(),
            stats: Stats::default(),
        };
        let first = if c.cfg.last.is_some_and(usable) { State::Rebooting } else { State::Selecting };
        let delay = c.random(START_DELAY_MS);
        c.begin(first, now + delay);
        c
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The lease held now.
    pub fn lease(&self) -> Option<&Lease> {
        self.held.as_ref().map(|h| &h.lease)
    }

    /// When the held lease ends (ms, `u64::MAX` = never).
    pub fn lease_end(&self) -> Option<u64> {
        self.held.as_ref().map(|h| h.end)
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When [`Self::poll`] has something to do (`u64::MAX`: nothing).
    pub fn next_deadline(&self) -> u64 {
        let mut t = if self.state == State::Bound { u64::MAX } else { self.next_tx };
        if let Some(h) = &self.held {
            t = t.min(h.end);
            match self.state {
                State::Bound => t = t.min(h.t1),
                State::Renewing => t = t.min(h.t2),
                _ => {}
            }
        }
        t
    }

    /// The link changed (another VLAN, back from PPPoE): drop the lease
    /// and ask again, still for the same address.
    pub fn reset(&mut self, now: u64) {
        self.lose();
        self.naks_in_row = 0;
        self.begin(State::Selecting, now);
    }

    /// Timers, and the message due at `now`.
    pub fn poll(&mut self, now: u64) -> Option<Transmit> {
        // Every transition that is due (T1 = T2 goes straight to
        // REBINDING, not a RENEW and a REBIND at the same instant).
        if let Some(h) = &self.held {
            let (t1, t2, end) = (h.t1, h.t2, h.end);
            if now >= end {
                self.lose();
                self.begin(State::Selecting, now);
            } else {
                if self.state == State::Bound && now >= t1 {
                    self.begin(State::Renewing, now);
                }
                if self.state == State::Renewing && now >= t2 {
                    self.begin(State::Rebinding, now);
                }
            }
        }
        if self.state == State::Bound || now < self.next_tx {
            return None;
        }
        match self.state {
            State::Requesting if self.tries >= REQUEST_TRIES => {
                self.offer = None;
                self.begin(State::Selecting, now);
            }
            State::Rebooting if self.tries >= REBOOT_TRIES => self.begin(State::Selecting, now),
            _ => {}
        }
        self.rt = match (self.state, &self.held) {
            (State::Renewing, Some(h)) => (h.t2.saturating_sub(now) / 2).max(MIN_RENEW_RT_MS),
            (State::Rebinding, Some(h)) => (h.end.saturating_sub(now) / 2).max(MIN_RENEW_RT_MS),
            _ => {
                let base = (FIRST_RT_MS << self.tries.min(4)).min(MAX_RT_MS);
                base - JITTER_MS + self.random(2 * JITTER_MS)
            }
        };
        self.tries += 1;
        self.next_tx = now.saturating_add(self.rt);
        self.stats.sent += 1;
        Some(self.message(now))
    }

    /// A datagram that came to port 68.
    pub fn handle(&mut self, now: u64, datagram: &[u8]) {
        if !self.take(now, datagram) {
            self.stats.ignored += 1;
        }
    }

    /// Whether the datagram moved the state machine.
    fn take(&mut self, now: u64, datagram: &[u8]) -> bool {
        let Ok(m) = Message::parse(datagram) else { return false };
        if m.op != OP_REPLY || m.xid != self.xid || m.chaddr != self.cfg.mac {
            return false; // not an answer to our last message
        }
        let sid = m.options.server_id;
        match (self.state, m.options.msg_type) {
            (State::Selecting, Some(MessageType::Offer)) => {
                let Some(sid) = sid.filter(|&s| usable(s)) else { return false };
                if !usable(m.yiaddr) {
                    return false;
                }
                self.stats.received += 1;
                self.offer = Some((m.yiaddr, sid));
                self.begin(State::Requesting, now);
                true
            }
            (State::Requesting | State::Rebooting | State::Renewing | State::Rebinding, Some(MessageType::Ack)) => {
                // REQUESTING: only the server we chose (another one's ACK
                // answers somebody else's choice). Otherwise any server
                // identifier, else the one we hold.
                let sid = match (self.state, self.offer, &self.held) {
                    (State::Requesting, Some((_, chosen)), _) => {
                        if sid.is_some_and(|s| s != chosen) {
                            return false;
                        }
                        chosen
                    }
                    (_, _, Some(h)) => sid.unwrap_or(h.lease.server),
                    _ => match sid {
                        Some(s) => s,
                        None => return false,
                    },
                };
                let Some(lease) = lease_of(&m.yiaddr, &m.options, sid) else { return false };
                self.stats.received += 1;
                self.bind(now, lease, &m.options);
                true
            }
            (State::Requesting | State::Rebooting | State::Renewing | State::Rebinding, Some(MessageType::Nak)) => {
                let from = match (self.state, self.offer, &self.held) {
                    (State::Requesting, Some((_, chosen)), _) => Some(chosen),
                    (State::Renewing, _, Some(h)) => Some(h.lease.server),
                    _ => None, // INIT-REBOOT, REBINDING: any server may NAK
                };
                if from.is_some() && sid.is_some() && sid != from {
                    return false;
                }
                self.stats.received += 1;
                self.stats.naks += 1;
                self.lose();
                self.hint = None; // the server said no to it
                self.offer = None;
                self.naks_in_row = self.naks_in_row.saturating_add(1);
                let delay = match self.naks_in_row {
                    1 => 0,
                    n => (1_000u64 << (n - 1).min(6)).min(MAX_RT_MS),
                };
                self.begin(State::Selecting, now + delay);
                true
            }
            _ => false,
        }
    }

    fn bind(&mut self, now: u64, lease: Lease, o: &Options) {
        let (t1, t2, end) = if lease.lease_secs == INFINITE {
            (u64::MAX, u64::MAX, u64::MAX)
        } else {
            let len = lease.lease_secs.max(MIN_LEASE_SECS);
            let t2 = o.rebinding_t2.filter(|&t| t > 0 && t < len).unwrap_or(len / 8 * 7);
            let t1 = o.renewal_t1.filter(|&t| t > 0 && t <= t2).unwrap_or((len / 2).min(t2));
            let at = |s: u32| now.saturating_add(u64::from(s) * 1000);
            (at(t1), at(t2), at(len))
        };
        let changed = self.held.as_ref().is_none_or(|h| !h.lease.same_settings(&lease));
        if changed {
            self.events.push_back(Event::Bound(lease.clone()));
        }
        self.hint = Some(lease.address);
        self.offer = None;
        self.naks_in_row = 0;
        self.held = Some(Held { lease, t1, t2, end });
        self.state = State::Bound;
    }

    fn lose(&mut self) {
        if self.held.take().is_some() {
            self.events.push_back(Event::Lost);
        }
    }

    fn begin(&mut self, state: State, at: u64) {
        self.state = state;
        self.tries = 0;
        self.started = at;
        self.next_tx = at;
        self.xid = self.next_random() as u32;
    }

    fn message(&self, now: u64) -> Transmit {
        let renewing = matches!(self.state, State::Renewing | State::Rebinding);
        let held = self.held.as_ref().filter(|_| renewing).map(|h| &h.lease);
        let (kind, requested, server_id) = match self.state {
            State::Selecting => (MessageType::Discover, self.hint, None),
            State::Requesting => (MessageType::Request, self.offer.map(|o| o.0), self.offer.map(|o| o.1)),
            State::Rebooting => (MessageType::Request, self.cfg.last, None),
            // §4.3.2: RENEWING / REBINDING name the address in ciaddr only.
            State::Renewing | State::Rebinding => (MessageType::Request, None, None),
            State::Bound => unreachable!("nothing is sent while bound"),
        };
        let mut client_id = Vec::with_capacity(7);
        client_id.push(1);
        client_id.extend_from_slice(&self.cfg.mac);
        let msg = Message {
            op: OP_REQUEST,
            xid: self.xid,
            secs: (now.saturating_sub(self.started) / 1000).min(0xffff) as u16,
            flags: if self.cfg.broadcast && held.is_none() { FLAG_BROADCAST } else { 0 },
            ciaddr: held.map_or(Ipv4Addr::UNSPECIFIED, |l| l.address),
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: self.cfg.mac,
            options: Options {
                msg_type: Some(kind),
                requested_ip: requested,
                server_id,
                hostname: self.cfg.hostname.clone(),
                client_id: Some(client_id),
                param_request: PARAMS.to_vec(),
                ..Default::default()
            },
        };
        let (src, dst) = match (self.state, held) {
            (State::Renewing, Some(l)) => (l.address, l.server),
            (State::Rebinding, Some(l)) => (l.address, Ipv4Addr::BROADCAST),
            _ => (Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST),
        };
        Transmit { src, dst, payload: msg.emit() }
    }

    fn next_random(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// 0 ..= `max`.
    fn random(&mut self, max: u64) -> u64 {
        self.next_random() % (max + 1)
    }
}

/// A unicast host address: not 0/8, loopback, multicast, 240/4 or the
/// limited broadcast.
fn usable(a: Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] != 0 && !a.is_loopback() && o[0] < 224
}

/// The lease an ACK describes, or `None` if it cannot be used: no or a
/// non-contiguous subnet mask, an address that is no host address (or
/// its subnet's network / broadcast address). A router that is no usable
/// unicast address (or ours) is left out; so are such DNS servers.
fn lease_of(yiaddr: &Ipv4Addr, o: &Options, server: Ipv4Addr) -> Option<Lease> {
    let address = *yiaddr;
    let mask = u32::from(o.subnet_mask?);
    let prefix_len = mask.leading_ones() as u8;
    if mask.count_ones() != u32::from(prefix_len) || prefix_len == 0 || !usable(address) {
        return None;
    }
    if prefix_len < 31 {
        let host = u32::from(address) & !mask;
        if host == 0 || host == !mask {
            return None;
        }
    }
    let router = o.routers.iter().copied().find(|&r| usable(r) && r != address);
    let mut dns: Vec<Ipv4Addr> = Vec::new();
    for &d in &o.dns {
        if usable(d) && !dns.contains(&d) && dns.len() < MAX_DNS {
            dns.push(d);
        }
    }
    Some(Lease {
        address,
        prefix_len,
        router,
        dns,
        domain: o.domain.clone().filter(|d| !d.is_empty()),
        mtu: o.mtu.filter(|&m| m >= 576),
        server,
        lease_secs: o.lease_time.unwrap_or(DEFAULT_LEASE_SECS),
    })
}

#[cfg(test)]
mod tests;
