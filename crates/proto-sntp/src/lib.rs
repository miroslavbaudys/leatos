//! SNTP client (RFC 4330; RFC 5905 client mode): sets a wall clock from
//! NTP servers. No clock discipline: the router has no use for slewing,
//! it only needs to know the time (status page, logs, later TLS/DNSSEC).
//!
//! - [`packet`]: the 48-byte request and the checks on a reply
//! - [`Client`]: when to ask whom, and which answer to believe
//!
//! Sans-IO: the caller passes in monotonic time (`now`, ns since boot),
//! sends the [`Request`]s that [`Client::poll`] returns, feeds replies to
//! [`Client::handle`], and applies what [`Client::take_update`] returns:
//! the Unix time (ns) at monotonic 0, so `unix = offset + now`.
//!
//! `#![no_std]` + `alloc`, no unsafe.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod packet;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;

const SEC: u64 = 1_000_000_000;

/// Requests in one burst (the best of them is taken).
pub const BURST: u32 = 4;
/// Spacing of the requests in a burst.
pub const BURST_SPACING: u64 = 2 * SEC;
/// A request without a reply after this counts as lost.
pub const TIMEOUT: u64 = 3 * SEC;
/// Poll interval after a sync, doubled up to [`MAX_INTERVAL`] while the
/// samples agree.
pub const MIN_INTERVAL: u64 = 64 * SEC;
pub const MAX_INTERVAL: u64 = 1024 * SEC;
/// A sample further than this from the current estimate starts a new burst.
pub const STEP_THRESHOLD: u64 = 128_000_000;
/// After a burst without any answer: wait this long, doubling up to
/// [`MIN_INTERVAL`].
pub const RETRY_MIN: u64 = 8 * SEC;
/// Lost or rejected replies in a row before moving to the next server.
pub const FAILS_PER_SERVER: u32 = 2;

/// One datagram to send to `server` (UDP port [`packet::PORT`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<A> {
    pub server: A,
    pub data: [u8; packet::LEN],
}

/// One measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// Unix time in ns at monotonic 0.
    pub offset: i64,
    /// Round-trip delay through the network, ns.
    pub delay: u64,
    pub stratum: u8,
    /// Monotonic time of the reply.
    pub at: u64,
}

impl Sample {
    /// From the four timestamps: `t1`/`t4` local monotonic ns (sent,
    /// received), `t2`/`t3` server Unix ns (received, sent).
    pub fn from_times(t1: u64, t2: i64, t3: i64, t4: u64, stratum: u8) -> Self {
        let (t1, t4) = (t1 as i128, t4 as i128);
        let (t2, t3) = (t2 as i128, t3 as i128);
        let offset = ((t2 - t1) + (t3 - t4)) / 2;
        let delay = ((t4 - t1) - (t3 - t2)).max(0);
        Sample {
            offset: offset as i64,
            delay: delay as u64,
            stratum,
            at: t4 as u64,
        }
    }
}

/// What the client reports for the status page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status<A> {
    /// The last sample applied, if any.
    pub synced: Option<Sample>,
    /// The server that sample came from.
    pub server: Option<A>,
    /// Current poll interval (ns).
    pub interval: u64,
    pub sent: u64,
    pub received: u64,
    pub rejected: u64,
    pub lost: u64,
}

#[derive(Clone, Copy, Debug)]
struct Pending<A> {
    server: A,
    cookie: u64,
    sent: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Collecting `BURST` attempts; `left` still to send.
    Burst { left: u32 },
    /// Synced: one request per interval.
    Steady,
}

pub struct Client<A> {
    servers: Vec<A>,
    cur: usize,
    fails: u32,
    pending: Option<Pending<A>>,
    phase: Phase,
    best: Option<(Sample, A)>,
    next_at: u64,
    interval: u64,
    retry: u64,
    rng: u64,
    synced: Option<(Sample, A)>,
    update: Option<Sample>,
    sent: u64,
    received: u64,
    rejected: u64,
    lost: u64,
}

impl<A: Copy + PartialEq> Client<A> {
    /// A client without servers; `seed` varies the request cookies.
    pub fn new(seed: u64) -> Self {
        Client {
            servers: Vec::new(),
            cur: 0,
            fails: 0,
            pending: None,
            phase: Phase::Burst { left: BURST },
            best: None,
            next_at: 0,
            interval: MIN_INTERVAL,
            retry: RETRY_MIN,
            rng: seed | 1,
            synced: None,
            update: None,
            sent: 0,
            received: 0,
            rejected: 0,
            lost: 0,
        }
    }

    /// Replace the server list (resolved addresses, in preference order).
    /// A request in flight to a server no longer listed is forgotten.
    /// The sync state is kept.
    pub fn set_servers(&mut self, servers: &[A]) {
        if self.servers.as_slice() == servers {
            return;
        }
        let current = self.servers.get(self.cur).copied();
        self.servers = servers.to_vec();
        self.cur = current
            .and_then(|c| servers.iter().position(|&s| s == c))
            .unwrap_or(0);
        if self
            .pending
            .is_some_and(|p| !servers.contains(&p.server))
        {
            self.pending = None;
        }
    }

    pub fn servers(&self) -> &[A] {
        &self.servers
    }

    /// Forget the sync and start over with a burst (new config).
    pub fn restart(&mut self, now: u64) {
        let (servers, rng) = (core::mem::take(&mut self.servers), self.rng);
        *self = Self::new(rng);
        self.servers = servers;
        self.next_at = now;
    }

    fn cookie(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        // Never 0: a zero origin timestamp means "none" in the protocol.
        self.rng | 1
    }

    /// A request that failed (lost, rejected, kiss-o'-death).
    fn failed(&mut self) {
        self.fails += 1;
        if self.fails >= FAILS_PER_SERVER && !self.servers.is_empty() {
            self.fails = 0;
            self.cur = (self.cur + 1) % self.servers.len();
        }
    }

    /// One attempt of the current round is over (answered or not).
    fn attempt_done(&mut self, now: u64) {
        match self.phase {
            Phase::Burst { left: 0 } => self.finish_burst(now),
            Phase::Burst { .. } => {}
            Phase::Steady => self.next_at = now.saturating_add(self.interval),
        }
    }

    fn finish_burst(&mut self, now: u64) {
        match self.best.take() {
            Some((s, a)) => {
                self.synced = Some((s, a));
                self.update = Some(s);
                self.phase = Phase::Steady;
                self.interval = MIN_INTERVAL;
                self.retry = RETRY_MIN;
                self.next_at = now.saturating_add(self.interval);
            }
            None => {
                // Nobody answered: try again later, then with longer waits.
                self.phase = Phase::Burst { left: BURST };
                self.next_at = now.saturating_add(self.retry);
                self.retry = (self.retry * 2).min(MIN_INTERVAL);
            }
        }
    }

    /// Time has passed: a request to send, if one is due. Call again
    /// until it returns `None`.
    pub fn poll(&mut self, now: u64) -> Option<Request<A>> {
        if let Some(p) = self.pending
            && now >= p.sent.saturating_add(TIMEOUT)
        {
            self.pending = None;
            self.lost += 1;
            self.failed();
            self.attempt_done(now);
        }
        if self.pending.is_some() || self.servers.is_empty() || now < self.next_at {
            return None;
        }
        if let Phase::Burst { left } = &mut self.phase {
            *left = left.saturating_sub(1);
            self.next_at = now.saturating_add(BURST_SPACING);
        }
        let server = self.servers[self.cur % self.servers.len()];
        let cookie = self.cookie();
        self.pending = Some(Pending {
            server,
            cookie,
            sent: now,
        });
        self.sent += 1;
        Some(Request {
            server,
            data: packet::request(cookie),
        })
    }

    /// A datagram from `from` (source port [`packet::PORT`]) arrived.
    /// Anything that is not the reply to the request in flight is ignored.
    pub fn handle(&mut self, from: A, data: &[u8], now: u64) {
        let Some(p) = self.pending else { return };
        if from != p.server {
            return;
        }
        let reply = match packet::parse_reply(data, p.cookie) {
            Ok(r) => r,
            // Not an answer to our request (spoofed or stale): keep waiting.
            Err(packet::Reject::Short | packet::Reject::Mode | packet::Reject::Origin) => return,
            Err(_) => {
                self.pending = None;
                self.rejected += 1;
                self.failed();
                self.attempt_done(now);
                return;
            }
        };
        self.pending = None;
        self.received += 1;
        self.fails = 0;
        let s = Sample::from_times(p.sent, reply.receive, reply.transmit, now, reply.stratum);
        match self.phase {
            Phase::Burst { .. } => {
                if self.best.is_none_or(|(b, _)| s.delay < b.delay) {
                    self.best = Some((s, from));
                }
            }
            Phase::Steady => {
                let cur = self.synced.map_or(s.offset, |(c, _)| c.offset);
                if s.offset.abs_diff(cur) <= STEP_THRESHOLD {
                    self.synced = Some((s, from));
                    self.update = Some(s);
                    self.interval = (self.interval * 2).min(MAX_INTERVAL);
                } else {
                    // A jump: measure again carefully before believing it.
                    self.phase = Phase::Burst { left: BURST };
                    self.interval = MIN_INTERVAL;
                    self.next_at = now;
                    return;
                }
            }
        }
        self.attempt_done(now);
    }

    /// A new estimate to apply (Unix ns at monotonic 0), once per change.
    pub fn take_update(&mut self) -> Option<Sample> {
        self.update.take()
    }

    /// When [`Self::poll`] must run next (monotonic ns), if ever.
    pub fn next_deadline(&self) -> Option<u64> {
        if let Some(p) = self.pending {
            return Some(p.sent.saturating_add(TIMEOUT));
        }
        (!self.servers.is_empty()).then_some(self.next_at)
    }

    pub fn status(&self) -> Status<A> {
        Status {
            synced: self.synced.map(|(s, _)| s),
            server: self.synced.map(|(_, a)| a),
            interval: self.interval,
            sent: self.sent,
            received: self.received,
            rejected: self.rejected,
            lost: self.lost,
        }
    }
}
