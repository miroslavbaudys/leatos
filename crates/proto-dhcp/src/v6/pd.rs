//! DHCPv6 prefix delegation client (RFC 8415, sans-IO): the WAN asks the
//! ISP for a prefix (IA_PD) to number the networks from.
//!
//! Solicit → Advertise → Request → Reply, then Renew at T1, Rebind at T2,
//! and the prefix is lost when its valid lifetime ends (back to Solicit).
//! Retransmission follows §15 (initial and maximum times, ±10 % jitter).
//! The client identifier is a DUID-LL of the WAN MAC, so a reboot asks for
//! (and usually gets) the same prefix again. Reconfigure is ignored; IA_NA
//! (a WAN address) is not asked for.
//!
//! [`Client::poll`] returns a message for `ff02::1:2` port 547 (sent from
//! port 546 and the link-local address); [`Client::handle`] takes a
//! datagram that came to port 546; [`Client::poll_event`] reports
//! [`Event::Bound`] (also after each renewal) and [`Event::Lost`].

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::Ipv6Addr;

pub const CLIENT_PORT: u16 = 546;
pub const SERVER_PORT: u16 = 547;
/// All_DHCP_Relay_Agents_and_Servers.
pub const SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

const SOLICIT: u8 = 1;
const ADVERTISE: u8 = 2;
const REQUEST: u8 = 3;
const RENEW: u8 = 5;
const REBIND: u8 = 6;
const REPLY: u8 = 7;

const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_ORO: u16 = 6;
const OPT_ELAPSED: u16 = 8;
const OPT_STATUS: u16 = 13;
const OPT_DNS: u16 = 23;
const OPT_IA_PD: u16 = 25;
const OPT_IAPREFIX: u16 = 26;

/// Status codes that send the client back to Solicit (RFC 8415 §21.13).
const NO_BINDING: u16 = 3;
const NO_PREFIX_AVAIL: u16 = 6;

/// Retransmission parameters (ms): (initial, maximum, maximum tries; 0 =
/// unlimited). RFC 8415 §7.6.
const SOL: (u64, u64, u32) = (1_000, 3_600_000, 0);
const REQ: (u64, u64, u32) = (1_000, 30_000, 10);
const REN: (u64, u64, u32) = (10_000, 600_000, 0);
const REB: (u64, u64, u32) = (10_000, 600_000, 0);
/// The first Solicit waits up to this long (SOL_MAX_DELAY).
const SOL_MAX_DELAY_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PdConfig {
    /// The WAN MAC: the DUID-LL.
    pub mac: [u8; 6],
    pub iaid: u32,
    /// The prefix length asked for (a hint; the server decides).
    pub hint_len: u8,
}

/// A delegated prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegation {
    pub prefix: Ipv6Addr,
    pub len: u8,
    pub preferred_secs: u32,
    pub valid_secs: u32,
    /// DNS servers the reply named.
    pub dns: Vec<Ipv6Addr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Bound or renewed (the prefix may have changed).
    Bound(Delegation),
    /// The prefix is gone (valid lifetime over, or withdrawn).
    Lost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Solicit,
    Request,
    Bound,
    Renew,
    Rebind,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Solicit => "soliciting",
            State::Request => "requesting",
            State::Bound => "bound",
            State::Renew => "renewing",
            State::Rebind => "rebinding",
        }
    }
}

/// The bound lease: times in ms since the client's clock started.
#[derive(Clone, Debug)]
struct Lease {
    d: Delegation,
    t1: u64,
    t2: u64,
    end: u64,
}

pub struct Client {
    cfg: PdConfig,
    state: State,
    xid: [u8; 3],
    rng: u64,
    server_id: Option<Vec<u8>>,
    /// The prefix offered (Advertise) or held.
    offer: Option<(Ipv6Addr, u8)>,
    lease: Option<Lease>,
    /// When the current exchange began (elapsed time), the next
    /// transmission, its timeout and how many went out.
    started: u64,
    next_tx: u64,
    rt: u64,
    tries: u32,
    events: VecDeque<Event>,
    /// Messages sent / replies taken (status).
    pub sent: u64,
    pub received: u64,
}

impl Client {
    pub fn new(cfg: PdConfig, now: u64, seed: u64) -> Self {
        let mut c = Client {
            cfg,
            state: State::Solicit,
            xid: [0; 3],
            rng: seed | 1,
            server_id: None,
            offer: None,
            lease: None,
            started: now,
            next_tx: now,
            rt: 0,
            tries: 0,
            events: VecDeque::new(),
            sent: 0,
            received: 0,
        };
        let delay = c.random(SOL_MAX_DELAY_MS);
        c.begin(State::Solicit, now + delay);
        c
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// The prefix held now.
    pub fn delegation(&self) -> Option<&Delegation> {
        self.lease.as_ref().map(|l| &l.d)
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When [`Self::poll`] has something to do.
    pub fn next_deadline(&self) -> u64 {
        // Bound: no transmission is due, only T1 and the end.
        let mut t = if self.state == State::Bound { u64::MAX } else { self.next_tx };
        if let Some(l) = &self.lease {
            t = t.min(l.end);
            if self.state == State::Bound {
                t = t.min(l.t1);
            }
            if self.state == State::Renew {
                t = t.min(l.t2);
            }
        }
        t
    }

    /// Timers, and the message due at `now` (to [`SERVERS`]:547).
    pub fn poll(&mut self, now: u64) -> Option<Vec<u8>> {
        if let Some(l) = &self.lease {
            if now >= l.end {
                self.lease = None;
                self.events.push_back(Event::Lost);
                self.begin(State::Solicit, now);
            } else if self.state == State::Bound && now >= l.t1 {
                self.begin(State::Renew, now);
            } else if self.state == State::Renew && now >= l.t2 {
                self.begin(State::Rebind, now);
            }
        }
        if self.state == State::Bound || now < self.next_tx {
            return None;
        }
        let (irt, mrt, mrc) = params(self.state);
        if mrc != 0 && self.tries >= mrc {
            // Request ran out: start over.
            self.begin(State::Solicit, now);
            return self.poll(now);
        }
        self.rt = if self.tries == 0 {
            // The first Solicit's timeout is above IRT (§18.2.1: RAND > 0).
            if self.state == State::Solicit { irt + 1 + self.random(irt / 10) } else { self.jittered(irt) }
        } else {
            let r = self.jittered(2 * self.rt);
            if r > mrt { self.jittered(mrt) } else { r }
        };
        self.tries += 1;
        self.next_tx = now + self.rt;
        self.sent += 1;
        Some(self.message(now))
    }

    /// A datagram that came to port 546.
    pub fn handle(&mut self, now: u64, msg: &[u8]) {
        let Some(m) = Msg::parse(msg) else { return };
        if m.xid != self.xid || m.client_id != Some(&self.duid()[..]) {
            return; // not an answer to us
        }
        let Some(server) = m.server_id else { return };
        match (self.state, m.kind) {
            (State::Solicit, ADVERTISE) => {
                if m.status_stops() {
                    return;
                }
                let Some(ia) = m.ia_pd(self.cfg.iaid) else { return };
                let Some(p) = ia.prefix.filter(|p| p.valid > 0) else { return };
                self.received += 1;
                self.server_id = Some(server.to_vec());
                self.offer = Some((p.prefix, p.len));
                self.begin(State::Request, now);
            }
            (State::Request | State::Renew | State::Rebind, REPLY) => {
                self.received += 1;
                let ia = m.ia_pd(self.cfg.iaid);
                let gone = m.status_stops() || ia.as_ref().is_none_or(|ia| ia.status_stops);
                match ia.and_then(|ia| ia.prefix.map(|p| (ia, p))) {
                    Some((ia, p)) if !gone && p.valid > 0 => {
                        if self.state == State::Rebind {
                            self.server_id = Some(server.to_vec());
                        }
                        let d = Delegation {
                            prefix: p.prefix,
                            len: p.len,
                            preferred_secs: p.preferred,
                            valid_secs: p.valid,
                            dns: m.dns.clone(),
                        };
                        // T1/T2 0: the client picks (0.5 and 0.8 of preferred).
                        let pref = u64::from(p.preferred.max(1)) * 1000;
                        let t1 = if ia.t1 > 0 { u64::from(ia.t1) * 1000 } else { pref / 2 };
                        let t2 = if ia.t2 > 0 { u64::from(ia.t2) * 1000 } else { pref * 4 / 5 };
                        self.lease = Some(Lease {
                            d: d.clone(),
                            t1: now + t1,
                            t2: now + t2.max(t1),
                            end: now + u64::from(p.valid) * 1000,
                        });
                        self.offer = Some((p.prefix, p.len));
                        self.state = State::Bound;
                        self.events.push_back(Event::Bound(d));
                    }
                    _ => {
                        // No binding (any more): the prefix is gone, ask again.
                        if self.lease.take().is_some() {
                            self.events.push_back(Event::Lost);
                        }
                        self.offer = None;
                        self.begin(State::Solicit, now);
                    }
                }
            }
            _ => {}
        }
    }

    fn begin(&mut self, state: State, at: u64) {
        self.state = state;
        self.tries = 0;
        self.started = at;
        self.next_tx = at;
        let x = self.next_random();
        self.xid = [(x >> 16) as u8, (x >> 8) as u8, x as u8];
        if state == State::Solicit {
            self.server_id = None;
        }
    }

    fn duid(&self) -> [u8; 10] {
        let m = self.cfg.mac;
        [0, 3, 0, 1, m[0], m[1], m[2], m[3], m[4], m[5]]
    }

    fn message(&self, now: u64) -> Vec<u8> {
        let kind = match self.state {
            State::Solicit => SOLICIT,
            State::Request => REQUEST,
            State::Renew => RENEW,
            State::Rebind => REBIND,
            State::Bound => unreachable!("nothing is sent while bound"),
        };
        let mut b = Vec::with_capacity(96);
        b.push(kind);
        b.extend_from_slice(&self.xid);
        opt(&mut b, OPT_CLIENTID, &self.duid());
        if matches!(self.state, State::Request | State::Renew)
            && let Some(s) = &self.server_id
        {
            opt(&mut b, OPT_SERVERID, s);
        }
        let elapsed = ((now - self.started) / 10).min(0xffff) as u16;
        opt(&mut b, OPT_ELAPSED, &elapsed.to_be_bytes());
        opt(&mut b, OPT_ORO, &OPT_DNS.to_be_bytes());
        // IA_PD: our IAID, T1/T2 0 (the server decides), one IAPREFIX: the
        // hint (::/len) or the prefix asked for / held.
        let (prefix, len) = match (self.state, self.offer) {
            (State::Solicit, _) | (_, None) => (Ipv6Addr::UNSPECIFIED, self.cfg.hint_len),
            (_, Some(o)) => o,
        };
        let mut iap = Vec::with_capacity(25);
        iap.extend_from_slice(&[0; 8]); // preferred, valid: 0
        iap.push(len);
        iap.extend_from_slice(&prefix.octets());
        let mut ia = Vec::with_capacity(41);
        ia.extend_from_slice(&self.cfg.iaid.to_be_bytes());
        ia.extend_from_slice(&[0; 8]);
        opt(&mut ia, OPT_IAPREFIX, &iap);
        opt(&mut b, OPT_IA_PD, &ia);
        b
    }

    fn next_random(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// 0 ..= `below`.
    fn random(&mut self, below: u64) -> u64 {
        self.next_random() % (below + 1)
    }

    /// `t` ±10 % (RAND in −0.1 … 0.1, §15).
    fn jittered(&mut self, t: u64) -> u64 {
        t - t / 10 + self.random(t / 5)
    }
}

fn params(s: State) -> (u64, u64, u32) {
    match s {
        State::Solicit | State::Bound => SOL,
        State::Request => REQ,
        State::Renew => REN,
        State::Rebind => REB,
    }
}

fn opt(b: &mut Vec<u8>, code: u16, data: &[u8]) {
    b.extend_from_slice(&code.to_be_bytes());
    b.extend_from_slice(&(data.len() as u16).to_be_bytes());
    b.extend_from_slice(data);
}

fn options(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    core::iter::from_fn(move || {
        if b.len() < 4 {
            return None;
        }
        let code = u16::from_be_bytes([b[0], b[1]]);
        let len = usize::from(u16::from_be_bytes([b[2], b[3]]));
        let data = b.get(4..4 + len)?;
        b = &b[4 + len..];
        Some((code, data))
    })
}

fn stops(status: &[u8]) -> bool {
    status.len() >= 2 && matches!(u16::from_be_bytes([status[0], status[1]]), NO_BINDING | NO_PREFIX_AVAIL)
}

#[derive(Clone, Copy, Debug)]
struct IaPrefix {
    preferred: u32,
    valid: u32,
    len: u8,
    prefix: Ipv6Addr,
}

#[derive(Clone, Copy, Debug)]
struct IaPd {
    t1: u32,
    t2: u32,
    prefix: Option<IaPrefix>,
    status_stops: bool,
}

/// A server message, as far as the client needs it.
struct Msg<'a> {
    kind: u8,
    xid: [u8; 3],
    client_id: Option<&'a [u8]>,
    server_id: Option<&'a [u8]>,
    status: Option<&'a [u8]>,
    ia_pds: Vec<(u32, IaPd)>,
    dns: Vec<Ipv6Addr>,
}

impl<'a> Msg<'a> {
    fn parse(b: &'a [u8]) -> Option<Self> {
        if b.len() < 4 {
            return None;
        }
        let mut m = Msg {
            kind: b[0],
            xid: [b[1], b[2], b[3]],
            client_id: None,
            server_id: None,
            status: None,
            ia_pds: Vec::new(),
            dns: Vec::new(),
        };
        for (code, d) in options(&b[4..]) {
            match code {
                OPT_CLIENTID => m.client_id = Some(d),
                OPT_SERVERID if !d.is_empty() => m.server_id = Some(d),
                OPT_STATUS => m.status = Some(d),
                OPT_DNS => {
                    for a in d.as_chunks::<16>().0.iter().take(4) {
                        m.dns.push(Ipv6Addr::from(*a));
                    }
                }
                OPT_IA_PD if d.len() >= 12 && m.ia_pds.len() < 4 => {
                    let be32 = |i: usize| u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
                    let mut ia = IaPd { t1: be32(4), t2: be32(8), prefix: None, status_stops: false };
                    for (c, x) in options(&d[12..]) {
                        match c {
                            OPT_IAPREFIX if x.len() >= 25 && ia.prefix.is_none() => {
                                let len = x[8];
                                let a: [u8; 16] = x[9..25].try_into().ok()?;
                                let be = |i: usize| u32::from_be_bytes([x[i], x[i + 1], x[i + 2], x[i + 3]]);
                                let (preferred, valid) = (be(0), be(4));
                                // RFC 8415 §21.22: preferred above valid is invalid.
                                if (1..=64).contains(&len) && preferred <= valid {
                                    ia.prefix = Some(IaPrefix { preferred, valid, len, prefix: Ipv6Addr::from(a) });
                                }
                                if options(&x[25..]).any(|(c, s)| c == OPT_STATUS && stops(s)) {
                                    ia.prefix = None;
                                    ia.status_stops = true;
                                }
                            }
                            OPT_STATUS if stops(x) => ia.status_stops = true,
                            _ => {}
                        }
                    }
                    m.ia_pds.push((be32(0), ia));
                }
                _ => {}
            }
        }
        Some(m)
    }

    fn ia_pd(&self, iaid: u32) -> Option<IaPd> {
        self.ia_pds.iter().find(|(id, _)| *id == iaid).map(|&(_, ia)| ia)
    }

    fn status_stops(&self) -> bool {
        self.status.is_some_and(stops)
    }
}

#[cfg(test)]
mod tests;
