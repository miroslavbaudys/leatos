//! Sans-IO DHCPv4 server (RFC 2131) for one LAN segment.
//!
//! Feed it received datagrams with [`Server::handle`] and the current time
//! in seconds; it returns the reply to send (always as a broadcast to
//! `255.255.255.255:68`, which every client accepts before it has an
//! address) plus [`Event`]s for the DNS zone. Call [`Server::expire`]
//! periodically.
//!
//! Policy (SOHO-oriented):
//! - Static reservations by MAC always win; their IPs are never given to others.
//! - A returning client gets its previous address if it's still free.
//! - INIT-REBOOT requests for a free in-range address are ACKed even if no
//!   lease is on record, so clients keep working after a router restart
//!   without a store (with one, [`Server::restore`] brings the leases back:
//!   [`super::persist`]).
//! - Relayed requests (giaddr != 0) are ignored.
//!
//! Against a client exhausting the pool (docs/security-audit.md §5 item 5):
//! a DECLINE counts only for the address the declining MAC was offered or
//! holds; a DISCOVER that finds the pool full takes over the oldest offer
//! nobody requested; leases are indexed by address (one lease per
//! address), so checking an address is O(log n) and picking one at most a
//! pass over the pool (whose size the config caps). Counters: [`Stats`].

use super::packet::{
    FLAG_BROADCAST, Message, MessageType, OPT_CLASSLESS_ROUTES, OPT_MS_CLASSLESS_ROUTES, OP_REPLY, OP_REQUEST, Options,
    Route,
};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

pub type Mac = [u8; 6];

/// How long an OFFER reserves an address for the client.
const OFFER_HOLD_SECS: u64 = 60;
/// How long a DECLINEd (conflicting) address stays out of the pool.
const DECLINE_HOLD_SECS: u64 = 600;

#[derive(Clone, Debug)]
pub struct StaticLease {
    pub mac: Mac,
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub server_ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    /// Inclusive dynamic range.
    pub range: (Ipv4Addr, Ipv4Addr),
    pub lease_secs: u32,
    pub statics: Vec<StaticLease>,
    /// Static routes through other routers on this network (option 121,
    /// and 249 for clients asking for that one; with the default route
    /// via `router` appended, since such clients ignore option 3).
    pub routes: Vec<Route>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState {
    Offered,
    Bound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub mac: Mac,
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub state: LeaseState,
    /// Absolute expiry (seconds, same clock as `now`).
    pub expires: u64,
    /// Restored after a restart ([`Server::restore`]) and not renewed
    /// since: `expires` is then an upper bound (a full lease time from the
    /// restore), the client's own lease ends earlier.
    pub restored: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A client is bound to `ip` (new lease, renewal or hostname change).
    Bound {
        mac: Mac,
        ip: Ipv4Addr,
        hostname: Option<String>,
    },
    /// A lease ended (release, expiry, decline).
    Released {
        mac: Mac,
        ip: Ipv4Addr,
        hostname: Option<String>,
    },
}

#[derive(Debug, Default)]
pub struct Output {
    /// Reply datagram to broadcast to port 68, if any.
    pub reply: Option<Vec<u8>>,
    pub events: Vec<Event>,
}

pub struct Server {
    cfg: Config,
    leases: BTreeMap<Mac, Lease>,
    /// The lease holding each address: at most one per address (a new
    /// lease replaces an expired one of another MAC, [`Self::put_lease`]).
    by_ip: BTreeMap<u32, Mac>,
    /// Reserved addresses and their MACs (from `cfg.statics`).
    static_ips: BTreeMap<u32, Mac>,
    /// Addresses a client declined (a conflict), until when. Only ones it
    /// was offered or held, so at most the pool and the reservations.
    declined: BTreeMap<Ipv4Addr, u64>,
    stats: Stats,
}

/// What the server refused or reclaimed (`/api/status` per network).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// DISCOVERs left unanswered: no free address and no offer to take over.
    pub pool_full: u64,
    /// Offers taken over by a DISCOVER while the pool was full.
    pub offers_reclaimed: u64,
    /// DECLINEs for an address the client was not offered and does not hold.
    pub declines_refused: u64,
}

fn u32_of(a: Ipv4Addr) -> u32 {
    u32::from(a)
}

/// Lowercase, keep `[a-z0-9-]`, max 63 chars; `None` if nothing usable remains.
pub fn sanitize_hostname(raw: &str) -> Option<String> {
    let label = raw.split('.').next().unwrap_or("");
    let s: String = label
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(63)
        .collect();
    let s = s.trim_matches('-');
    (!s.is_empty()).then(|| String::from(s))
}

impl Server {
    pub fn new(cfg: Config) -> Self {
        let static_ips = Self::static_index(&cfg);
        Self {
            cfg,
            leases: BTreeMap::new(),
            by_ip: BTreeMap::new(),
            static_ips,
            declined: BTreeMap::new(),
            stats: Stats::default(),
        }
    }

    fn static_index(cfg: &Config) -> BTreeMap<u32, Mac> {
        cfg.statics.iter().map(|s| (u32_of(s.ip), s.mac)).collect()
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Store `lease` (replacing its MAC's) and index it by address. Another
    /// MAC's lease of the same address (expired: callers checked
    /// [`Self::available_for`]) goes first, with its `Released` event.
    /// Returns the MAC's previous lease.
    fn put_lease(&mut self, lease: Lease, out: &mut Output) -> Option<Lease> {
        let (mac, ip) = (lease.mac, u32_of(lease.ip));
        if let Some(&other) = self.by_ip.get(&ip)
            && other != mac
        {
            self.drop_lease(&other, out);
        }
        let prev = self.leases.insert(mac, lease);
        if let Some(p) = &prev
            && u32_of(p.ip) != ip
            && self.by_ip.get(&u32_of(p.ip)) == Some(&mac)
        {
            self.by_ip.remove(&u32_of(p.ip));
        }
        self.by_ip.insert(ip, mac);
        prev
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// All current leases (offered and bound).
    pub fn leases(&self) -> impl Iterator<Item = &Lease> {
        self.leases.values()
    }

    fn static_for_mac(&self, mac: &Mac) -> Option<&StaticLease> {
        self.cfg.statics.iter().find(|s| &s.mac == mac)
    }

    fn in_range(&self, ip: Ipv4Addr) -> bool {
        let (lo, hi) = self.cfg.range;
        (u32_of(lo)..=u32_of(hi)).contains(&u32_of(ip))
    }

    fn in_subnet(&self, ip: Ipv4Addr) -> bool {
        let m = u32_of(self.cfg.netmask);
        u32_of(ip) & m == u32_of(self.cfg.server_ip) & m
    }

    /// Is `ip` usable by `mac` right now?
    fn available_for(&self, ip: Ipv4Addr, mac: &Mac, now: u64) -> bool {
        // The server's own address and the router address are never leased.
        if ip == self.cfg.server_ip || Some(ip) == self.cfg.router {
            return false;
        }
        if let Some(owner) = self.static_ips.get(&u32_of(ip)) {
            return owner == mac;
        }
        if !self.in_range(ip) || self.declined.get(&ip).is_some_and(|&until| until > now) {
            return false;
        }
        self.by_ip
            .get(&u32_of(ip))
            .and_then(|m| self.leases.get(m))
            .is_none_or(|l| &l.mac == mac || l.expires <= now)
    }

    /// Choose an address for `mac`: static → previous → requested → first free.
    fn pick_address(&self, mac: &Mac, requested: Option<Ipv4Addr>, now: u64) -> Option<Ipv4Addr> {
        if let Some(s) = self.static_for_mac(mac) {
            return Some(s.ip);
        }
        if let Some(l) = self.leases.get(mac)
            && self.available_for(l.ip, mac, now)
        {
            return Some(l.ip);
        }
        if let Some(r) = requested
            && self.available_for(r, mac, now)
        {
            return Some(r);
        }
        let (lo, hi) = self.cfg.range;
        (u32_of(lo)..=u32_of(hi))
            .map(Ipv4Addr::from)
            .find(|&ip| self.available_for(ip, mac, now))
    }

    /// The pool is full: take over the oldest offer of another MAC that was
    /// never requested (a client that went elsewhere, or someone sending
    /// DISCOVERs only). Oldest first, so a flood of DISCOVERs takes its own
    /// offers back before a real client's, which it requests at once.
    fn reclaim_offer(&mut self, mac: &Mac, now: u64, out: &mut Output) -> Option<Ipv4Addr> {
        let (other, ip) = self
            .leases
            .values()
            .filter(|l| l.state == LeaseState::Offered && &l.mac != mac && l.expires > now)
            .filter(|l| !self.static_ips.contains_key(&u32_of(l.ip)))
            .min_by_key(|l| l.expires)
            .map(|l| (l.mac, l.ip))?;
        self.drop_lease(&other, out);
        self.stats.offers_reclaimed += 1;
        Some(ip)
    }

    fn hostname_for(&self, mac: &Mac, msg: &Message) -> Option<String> {
        self.static_for_mac(mac)
            .and_then(|s| s.hostname.clone())
            .or_else(|| msg.options.hostname.as_deref().and_then(sanitize_hostname))
    }

    fn reply(
        &self,
        req: &Message,
        kind: MessageType,
        yiaddr: Ipv4Addr,
        with_lease: bool,
    ) -> Vec<u8> {
        let c = &self.cfg;
        let mut o = Options {
            msg_type: Some(kind),
            server_id: Some(c.server_ip),
            ..Default::default()
        };
        if kind != MessageType::Nak {
            o.subnet_mask = Some(c.netmask);
            o.broadcast = Some(Ipv4Addr::from(u32_of(c.server_ip) | !u32_of(c.netmask)));
            o.routers = c.router.into_iter().collect();
            o.dns = c.dns.clone();
            o.domain = c.domain.clone();
            if !c.routes.is_empty() {
                let mut routes = c.routes.clone();
                routes.extend(c.router.map(|r| (Ipv4Addr::UNSPECIFIED, 0, r)));
                let asks = |code| req.options.param_request.contains(&code);
                if asks(OPT_CLASSLESS_ROUTES) {
                    o.classless_routes = routes;
                } else if asks(OPT_MS_CLASSLESS_ROUTES) {
                    o.ms_classless_routes = routes;
                }
            }
            if with_lease {
                o.lease_time = Some(c.lease_secs);
                o.renewal_t1 = Some(c.lease_secs / 2);
                o.rebinding_t2 = Some(c.lease_secs / 8 * 7);
            }
        }
        Message {
            op: OP_REPLY,
            xid: req.xid,
            secs: 0,
            flags: req.flags | FLAG_BROADCAST,
            ciaddr: if kind == MessageType::Ack {
                req.ciaddr
            } else {
                Ipv4Addr::UNSPECIFIED
            },
            yiaddr,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: req.giaddr,
            chaddr: req.chaddr,
            options: o,
        }
        .emit()
    }

    fn bind(
        &mut self,
        mac: Mac,
        ip: Ipv4Addr,
        hostname: Option<String>,
        now: u64,
        out: &mut Output,
    ) {
        let expires = now + self.cfg.lease_secs as u64;
        let lease = Lease {
            mac,
            ip,
            hostname: hostname.clone(),
            state: LeaseState::Bound,
            expires,
            restored: false,
        };
        let prev = self.put_lease(lease, out);
        // Report changes only: a renewal with the same address and name is silent.
        let changed = !matches!(&prev, Some(p) if p.state == LeaseState::Bound && p.ip == ip && p.hostname == hostname);
        if let Some(p) = prev
            && p.state == LeaseState::Bound
            && changed
        {
            out.events.push(Event::Released {
                mac,
                ip: p.ip,
                hostname: p.hostname,
            });
        }
        if changed {
            out.events.push(Event::Bound { mac, ip, hostname });
        }
    }

    fn drop_lease(&mut self, mac: &Mac, out: &mut Output) {
        let Some(l) = self.leases.remove(mac) else { return };
        if self.by_ip.get(&u32_of(l.ip)) == Some(mac) {
            self.by_ip.remove(&u32_of(l.ip));
        }
        if l.state == LeaseState::Bound {
            out.events.push(Event::Released {
                mac: l.mac,
                ip: l.ip,
                hostname: l.hostname,
            });
        }
    }

    /// Process one datagram received on port 67.
    pub fn handle(&mut self, now: u64, datagram: &[u8]) -> Output {
        let mut out = Output::default();
        let Ok(msg) = Message::parse(datagram) else {
            return out;
        };
        if msg.op != OP_REQUEST || msg.giaddr != Ipv4Addr::UNSPECIFIED {
            return out;
        }
        let mac = msg.chaddr;
        match msg.options.msg_type {
            Some(MessageType::Discover) => {
                let Some(ip) = self
                    .pick_address(&mac, msg.options.requested_ip, now)
                    .or_else(|| self.reclaim_offer(&mac, now, &mut out))
                else {
                    self.stats.pool_full += 1;
                    return out; // pool exhausted: stay silent
                };
                let hostname = self.hostname_for(&mac, &msg);
                let keep_bound = self
                    .leases
                    .get(&mac)
                    .is_some_and(|l| l.state == LeaseState::Bound && l.ip == ip);
                if !keep_bound {
                    let offer = Lease {
                        mac,
                        ip,
                        hostname,
                        state: LeaseState::Offered,
                        expires: now + OFFER_HOLD_SECS,
                        restored: false,
                    };
                    self.put_lease(offer, &mut out);
                }
                out.reply = Some(self.reply(&msg, MessageType::Offer, ip, true));
            }
            Some(MessageType::Request) => self.handle_request(now, &msg, &mut out),
            Some(MessageType::Release) => {
                if self.leases.get(&mac).is_some_and(|l| l.ip == msg.ciaddr) {
                    self.drop_lease(&mac, &mut out);
                }
            }
            // Only for the address this client was offered or holds (RFC
            // 2131 §4.3.3: a client declines what the server gave it), so
            // no client can take others' addresses out of the pool or grow
            // the table.
            Some(MessageType::Decline) => match msg.options.requested_ip {
                Some(ip) if self.leases.get(&mac).is_some_and(|l| l.ip == ip) => {
                    self.declined.insert(ip, now + DECLINE_HOLD_SECS);
                    self.drop_lease(&mac, &mut out);
                }
                _ => self.stats.declines_refused += 1,
            },
            Some(MessageType::Inform) => {
                out.reply = Some(self.reply(&msg, MessageType::Ack, Ipv4Addr::UNSPECIFIED, false));
            }
            _ => {}
        }
        out
    }

    fn handle_request(&mut self, now: u64, msg: &Message, out: &mut Output) {
        let mac = msg.chaddr;
        let nak = |s: &Self| s.reply(msg, MessageType::Nak, Ipv4Addr::UNSPECIFIED, false);

        // SELECTING: the client answers an OFFER and names the chosen server.
        if let Some(sid) = msg.options.server_id {
            if sid != self.cfg.server_ip {
                // It picked another server: forget our offer.
                if self
                    .leases
                    .get(&mac)
                    .is_some_and(|l| l.state == LeaseState::Offered)
                {
                    self.leases.remove(&mac);
                }
                return;
            }
            let wanted = msg.options.requested_ip;
            match (self.leases.get(&mac), wanted) {
                (Some(l), Some(ip)) if l.ip == ip && self.available_for(ip, &mac, now) => {
                    let hostname = self.hostname_for(&mac, msg);
                    self.bind(mac, ip, hostname, now, out);
                    out.reply = Some(self.reply(msg, MessageType::Ack, ip, true));
                }
                _ => out.reply = Some(nak(self)),
            }
            return;
        }

        // INIT-REBOOT (requested IP option) or RENEWING/REBINDING (ciaddr).
        let Some(ip) = msg
            .options
            .requested_ip
            .or(Some(msg.ciaddr))
            .filter(|a| !a.is_unspecified())
        else {
            return;
        };
        if !self.in_subnet(ip) {
            out.reply = Some(nak(self)); // client moved networks
            return;
        }
        let own_static = self.static_for_mac(&mac).map(|s| s.ip);
        if own_static.is_some_and(|s| s != ip) || !self.available_for(ip, &mac, now) {
            out.reply = Some(nak(self));
            return;
        }
        let hostname = self.hostname_for(&mac, msg);
        self.bind(mac, ip, hostname, now, out);
        out.reply = Some(self.reply(msg, MessageType::Ack, ip, true));
    }

    /// Change the configuration without a restart (the web interface's
    /// Save). Leases that are still valid under `cfg` are kept, with their
    /// expiry; a lease is dropped (a `Released` event for a bound one) when
    /// its MAC now has a reservation for another address, or its address is
    /// reserved for someone else, outside the new pool and not reserved, or
    /// the server's own. Such a client keeps its address until it renews,
    /// then gets a NAK and asks again. A reservation's new hostname is
    /// reported as `Released` + `Bound`, so the DNS zone follows.
    pub fn reconfigure(&mut self, now: u64, cfg: Config) -> Vec<Event> {
        self.static_ips = Self::static_index(&cfg);
        self.cfg = cfg;
        let mut out = Output::default();
        let macs: Vec<Mac> = self.leases.keys().copied().collect();
        for mac in macs {
            let l = &self.leases[&mac];
            let keep = match self.static_for_mac(&mac) {
                Some(st) => st.ip == l.ip,
                None => self.in_subnet(l.ip) && self.available_for(l.ip, &mac, now),
            };
            if !keep {
                self.drop_lease(&mac, &mut out);
                continue;
            }
            let new_name = self.static_for_mac(&mac).and_then(|st| st.hostname.clone());
            let l = &self.leases[&mac];
            if new_name.is_some() && new_name != l.hostname && l.state == LeaseState::Bound {
                let (ip, old) = (l.ip, l.hostname.clone());
                if let Some(l) = self.leases.get_mut(&mac) {
                    l.hostname = new_name.clone();
                }
                out.events.push(Event::Released {
                    mac,
                    ip,
                    hostname: old,
                });
                out.events.push(Event::Bound {
                    mac,
                    ip,
                    hostname: new_name,
                });
            }
        }
        out.events
    }

    /// Drop expired leases and offers. Call every few seconds.
    pub fn expire(&mut self, now: u64) -> Vec<Event> {
        let expired: Vec<Mac> = self
            .leases
            .values()
            .filter(|l| l.expires <= now)
            .map(|l| l.mac)
            .collect();
        let mut out = Output::default();
        for mac in expired {
            self.drop_lease(&mac, &mut out);
        }
        self.declined.retain(|_, until| *until > now);
        out.events
    }

    /// The bound leases, for a snapshot ([`super::persist`]), by MAC.
    pub fn snapshot(&self) -> Vec<super::persist::Saved> {
        self.leases
            .values()
            .filter(|l| l.state == LeaseState::Bound)
            .map(|l| super::persist::Saved {
                mac: l.mac,
                ip: l.ip,
                hostname: l.hostname.clone(),
            })
            .collect()
    }

    /// Bring back leases from a snapshot (router restart), each bound for a
    /// full lease time from `now` ([`super::persist`] says why). A lease is
    /// skipped when the current config no longer allows it (as in
    /// [`Server::reconfigure`]: a reservation of the MAC elsewhere, the
    /// address out of the pool, reserved for another MAC or already taken)
    /// or when its MAC already has a lease. A reservation's hostname wins
    /// over the saved one. Returns `Bound` events for the DNS zone.
    pub fn restore(&mut self, now: u64, saved: &[super::persist::Saved]) -> Vec<Event> {
        let mut out = Output::default();
        for s in saved {
            if self.leases.contains_key(&s.mac) {
                continue;
            }
            let ok = match self.static_for_mac(&s.mac) {
                Some(st) => st.ip == s.ip,
                None => self.in_subnet(s.ip) && self.available_for(s.ip, &s.mac, now),
            };
            if !ok {
                continue;
            }
            let hostname = self
                .static_for_mac(&s.mac)
                .and_then(|st| st.hostname.clone())
                .or_else(|| s.hostname.clone());
            let lease = Lease {
                mac: s.mac,
                ip: s.ip,
                hostname: hostname.clone(),
                state: LeaseState::Bound,
                expires: now + u64::from(self.cfg.lease_secs),
                restored: true,
            };
            self.put_lease(lease, &mut out);
            out.events.push(Event::Bound {
                mac: s.mac,
                ip: s.ip,
                hostname,
            });
        }
        out.events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4::packet::{CLIENT_PORT, SERVER_PORT};
    use alloc::string::ToString;
    use alloc::vec;

    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const A: Mac = [0x52, 0x54, 0, 0, 0, 0xa];
    const B: Mac = [0x52, 0x54, 0, 0, 0, 0xb];
    const NAS: Mac = [0x52, 0x54, 0, 0, 0, 0x5];

    fn cfg() -> Config {
        Config {
            server_ip: SERVER,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            router: Some(SERVER),
            dns: vec![SERVER],
            domain: Some("lan".to_string()),
            range: (
                Ipv4Addr::new(192, 168, 1, 100),
                Ipv4Addr::new(192, 168, 1, 101),
            ),
            lease_secs: 3600,
            statics: vec![StaticLease {
                mac: NAS,
                ip: Ipv4Addr::new(192, 168, 1, 10),
                hostname: Some("nas".to_string()),
            }],
            routes: Vec::new(),
        }
    }

    fn client_msg(mac: Mac, kind: MessageType) -> Message {
        Message {
            op: OP_REQUEST,
            xid: 42,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: mac,
            options: Options {
                msg_type: Some(kind),
                ..Default::default()
            },
        }
    }

    fn reply_of(out: &Output) -> Message {
        Message::parse(out.reply.as_ref().expect("expected a reply")).unwrap()
    }

    /// Full DORA exchange; returns the bound address.
    fn dora(s: &mut Server, mac: Mac, hostname: Option<&str>, now: u64) -> Ipv4Addr {
        let mut d = client_msg(mac, MessageType::Discover);
        d.options.hostname = hostname.map(|h| h.to_string());
        let offer = reply_of(&s.handle(now, &d.emit()));
        assert_eq!(offer.options.msg_type, Some(MessageType::Offer));
        let mut r = client_msg(mac, MessageType::Request);
        r.options.server_id = Some(SERVER);
        r.options.requested_ip = Some(offer.yiaddr);
        r.options.hostname = d.options.hostname.clone();
        let ack = reply_of(&s.handle(now, &r.emit()));
        assert_eq!(ack.options.msg_type, Some(MessageType::Ack));
        ack.yiaddr
    }

    #[test]
    fn snapshot_and_restore_across_a_restart() {
        use crate::v4::persist::{self, Saved};
        let mut s = Server::new(cfg());
        let ip_a = dora(&mut s, A, Some("laptop"), 0);
        dora(&mut s, NAS, None, 0);
        // An offer only: not saved.
        let c: Mac = [2, 0, 0, 0, 0, 0xc];
        s.handle(0, &client_msg(c, MessageType::Discover).emit());
        let snap = s.snapshot();
        assert_eq!(snap.len(), 2, "{snap:?}");
        let bytes = persist::encode(&[persist::Network { name: "lan".into(), leases: snap.clone() }]);

        // Restart: a new server, restored long after the old clock.
        let saved = persist::decode(&bytes).unwrap().remove(0).leases;
        let mut s = Server::new(cfg());
        let ev = s.restore(5, &saved);
        assert_eq!(ev.len(), 2);
        assert!(ev.contains(&Event::Bound { mac: A, ip: ip_a, hostname: Some("laptop".into()) }));
        let a = s.leases().find(|l| l.mac == A).unwrap();
        assert_eq!((a.ip, a.state, a.expires), (ip_a, LeaseState::Bound, 5 + 3600), "a full lease time again");
        assert!(a.restored, "an upper bound until the client renews");
        // The address stays the client's: B gets the other one.
        assert_ne!(dora(&mut s, B, None, 6), ip_a);
        // Restoring twice changes nothing.
        assert!(s.restore(7, &saved).is_empty());

        // The config changed meanwhile: what no longer fits is skipped.
        let mut s = Server::new(cfg());
        let other: Mac = [2, 0, 0, 0, 0, 0xd];
        let stale = [
            Saved { mac: NAS, ip: Ipv4Addr::new(192, 168, 1, 11), hostname: None }, // reservation moved
            Saved { mac: other, ip: Ipv4Addr::new(192, 168, 1, 10), hostname: None }, // reserved for NAS
            Saved { mac: other, ip: Ipv4Addr::new(10, 0, 0, 100), hostname: None }, // other subnet
            Saved { mac: other, ip: Ipv4Addr::new(192, 168, 1, 150), hostname: None }, // out of the pool
            Saved { mac: other, ip: SERVER, hostname: None }, // the router
            Saved { mac: A, ip: Ipv4Addr::new(192, 168, 1, 100), hostname: Some("a".into()) },
            Saved { mac: B, ip: Ipv4Addr::new(192, 168, 1, 100), hostname: None }, // taken by A
        ];
        let ev = s.restore(0, &stale);
        assert_eq!(ev, [Event::Bound { mac: A, ip: Ipv4Addr::new(192, 168, 1, 100), hostname: Some("a".into()) }]);
        // A reservation's hostname wins over the saved one.
        let mut s = Server::new(cfg());
        let ev = s.restore(0, &[Saved { mac: NAS, ip: Ipv4Addr::new(192, 168, 1, 10), hostname: Some("old".into()) }]);
        assert_eq!(ev, [Event::Bound { mac: NAS, ip: Ipv4Addr::new(192, 168, 1, 10), hostname: Some("nas".into()) }]);
    }

    #[test]
    fn classless_routes_go_to_clients_that_ask() {
        let lab = (Ipv4Addr::new(10, 20, 0, 0), 24, Ipv4Addr::new(192, 168, 1, 2));
        let mut c = cfg();
        c.routes = vec![lab];
        let mut s = Server::new(c);
        let mut d = client_msg(A, MessageType::Discover);
        d.options.param_request = vec![1, 3, 6, 121];
        let offer = reply_of(&s.handle(0, &d.emit()));
        // The default route too: such clients ignore option 3.
        assert_eq!(offer.options.classless_routes, vec![lab, (Ipv4Addr::UNSPECIFIED, 0, SERVER)]);
        assert!(offer.options.ms_classless_routes.is_empty());
        assert_eq!(offer.options.routers, vec![SERVER], "option 3 for the others");
        let mut r = client_msg(A, MessageType::Request);
        r.options.server_id = Some(SERVER);
        r.options.requested_ip = Some(offer.yiaddr);
        r.options.param_request = vec![1, 3, 121];
        assert_eq!(reply_of(&s.handle(1, &r.emit())).options.classless_routes.len(), 2, "in the ACK");
        // Option 249 only for clients asking for it (and not for 121).
        d.chaddr = B;
        d.options.param_request = vec![1, 3, 249];
        let offer = reply_of(&s.handle(2, &d.emit()));
        assert!(offer.options.classless_routes.is_empty());
        assert_eq!(offer.options.ms_classless_routes.len(), 2);
        // Not asked: neither (negative control).
        d.options.param_request = vec![1, 3, 6];
        let offer = reply_of(&s.handle(3, &d.emit()));
        assert!(offer.options.classless_routes.is_empty() && offer.options.ms_classless_routes.is_empty());
        // No routes: nothing, even when asked.
        let mut s = Server::new(cfg());
        d.options.param_request = vec![121];
        assert!(reply_of(&s.handle(0, &d.emit())).options.classless_routes.is_empty());
    }

    #[test]
    fn ports_are_standard() {
        assert_eq!((SERVER_PORT, CLIENT_PORT), (67, 68));
    }

    #[test]
    fn dora_assigns_first_free_address_with_options() {
        let mut s = Server::new(cfg());
        let mut d = client_msg(A, MessageType::Discover);
        d.options.hostname = Some("Laptop.local".to_string());
        let offer = reply_of(&s.handle(0, &d.emit()));
        assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(offer.options.routers, vec![SERVER]);
        assert_eq!(offer.options.dns, vec![SERVER]);
        assert_eq!(offer.options.lease_time, Some(3600));
        assert_eq!(offer.options.domain.as_deref(), Some("lan"));
        assert_eq!(offer.flags & FLAG_BROADCAST, FLAG_BROADCAST);

        let mut r = client_msg(A, MessageType::Request);
        r.options.server_id = Some(SERVER);
        r.options.requested_ip = Some(offer.yiaddr);
        r.options.hostname = Some("Laptop.local".to_string());
        let out = s.handle(1, &r.emit());
        assert_eq!(reply_of(&out).options.msg_type, Some(MessageType::Ack));
        assert_eq!(
            out.events,
            vec![Event::Bound {
                mac: A,
                ip: offer.yiaddr,
                hostname: Some("laptop".to_string())
            }]
        );
    }

    #[test]
    fn static_lease_wins_and_is_reserved() {
        let mut s = Server::new(cfg());
        assert_eq!(
            dora(&mut s, NAS, Some("whatever"), 0),
            Ipv4Addr::new(192, 168, 1, 10)
        );
        // Static hostname overrides the client's.
        assert_eq!(
            s.leases()
                .find(|l| l.mac == NAS)
                .unwrap()
                .hostname
                .as_deref(),
            Some("nas")
        );
        // Another client may not take the static address.
        let mut d = client_msg(A, MessageType::Discover);
        d.options.requested_ip = Some(Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(
            reply_of(&s.handle(0, &d.emit())).yiaddr,
            Ipv4Addr::new(192, 168, 1, 100)
        );
    }

    #[test]
    fn pool_exhaustion_is_silent() {
        let mut s = Server::new(cfg());
        dora(&mut s, A, None, 0);
        dora(&mut s, B, None, 0);
        let c: Mac = [2, 0, 0, 0, 0, 0xc];
        assert!(
            s.handle(0, &client_msg(c, MessageType::Discover).emit())
                .reply
                .is_none()
        );
    }

    #[test]
    fn returning_client_gets_same_address() {
        let mut s = Server::new(cfg());
        let first = dora(&mut s, B, None, 0);
        assert_eq!(dora(&mut s, B, None, 100), first);
    }

    #[test]
    fn renew_is_acked_and_silent() {
        let mut s = Server::new(cfg());
        let ip = dora(&mut s, A, Some("pc"), 0);
        let mut r = client_msg(A, MessageType::Request);
        r.ciaddr = ip;
        r.options.hostname = Some("pc".to_string());
        let out = s.handle(1800, &r.emit());
        assert_eq!(reply_of(&out).options.msg_type, Some(MessageType::Ack));
        assert!(out.events.is_empty(), "renewal must not re-announce");
        assert_eq!(s.leases().next().unwrap().expires, 1800 + 3600);
    }

    #[test]
    fn renewal_after_a_restore_gives_the_real_expiry() {
        use crate::v4::persist::Saved;
        let mut s = Server::new(cfg());
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        s.restore(0, &[Saved { mac: A, ip, hostname: Some("pc".into()) }]);
        assert!(s.leases().next().unwrap().restored);
        let mut r = client_msg(A, MessageType::Request);
        r.ciaddr = ip;
        r.options.hostname = Some("pc".to_string());
        let out = s.handle(600, &r.emit());
        assert_eq!(reply_of(&out).options.msg_type, Some(MessageType::Ack));
        let l = s.leases().next().unwrap();
        assert_eq!((l.restored, l.expires), (false, 600 + 3600));
    }

    #[test]
    fn request_for_foreign_subnet_or_taken_ip_is_naked() {
        let mut s = Server::new(cfg());
        let ip_a = dora(&mut s, A, None, 0);
        let mut r = client_msg(B, MessageType::Request);
        r.options.requested_ip = Some(ip_a);
        assert_eq!(
            reply_of(&s.handle(0, &r.emit())).options.msg_type,
            Some(MessageType::Nak)
        );
        r.options.requested_ip = Some(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(
            reply_of(&s.handle(0, &r.emit())).options.msg_type,
            Some(MessageType::Nak)
        );
    }

    #[test]
    fn init_reboot_without_record_is_acked_when_free() {
        let mut s = Server::new(cfg());
        let mut r = client_msg(A, MessageType::Request);
        r.options.requested_ip = Some(Ipv4Addr::new(192, 168, 1, 101));
        let out = s.handle(0, &r.emit());
        assert_eq!(reply_of(&out).options.msg_type, Some(MessageType::Ack));
        assert_eq!(out.events.len(), 1);
    }

    #[test]
    fn client_choosing_other_server_frees_offer() {
        let mut s = Server::new(cfg());
        s.handle(0, &client_msg(A, MessageType::Discover).emit());
        let mut r = client_msg(A, MessageType::Request);
        r.options.server_id = Some(Ipv4Addr::new(192, 168, 1, 254));
        r.options.requested_ip = Some(Ipv4Addr::new(192, 168, 1, 100));
        assert!(s.handle(0, &r.emit()).reply.is_none());
        assert_eq!(s.leases().count(), 0);
    }

    #[test]
    fn release_and_decline() {
        let mut s = Server::new(cfg());
        let ip = dora(&mut s, A, Some("pc"), 0);
        let mut rel = client_msg(A, MessageType::Release);
        rel.ciaddr = ip;
        let out = s.handle(5, &rel.emit());
        assert_eq!(
            out.events,
            vec![Event::Released {
                mac: A,
                ip,
                hostname: Some("pc".to_string())
            }]
        );

        // Decline puts the address on hold; the next client gets another one.
        let ip = dora(&mut s, A, None, 10);
        let mut dec = client_msg(A, MessageType::Decline);
        dec.options.requested_ip = Some(ip);
        s.handle(11, &dec.emit());
        assert_ne!(
            reply_of(&s.handle(12, &client_msg(B, MessageType::Discover).emit())).yiaddr,
            ip
        );
    }

    #[test]
    fn leases_and_offers_expire() {
        let mut s = Server::new(cfg());
        let ip = dora(&mut s, A, Some("pc"), 0);
        s.handle(0, &client_msg(B, MessageType::Discover).emit()); // offer only
        assert!(s.expire(59).is_empty());
        assert!(s.expire(60).is_empty(), "offers expire silently");
        assert_eq!(s.leases().count(), 1);
        assert_eq!(
            s.expire(3600),
            vec![Event::Released {
                mac: A,
                ip,
                hostname: Some("pc".to_string())
            }]
        );
    }

    #[test]
    fn hostname_sanitizing() {
        assert_eq!(
            sanitize_hostname("My_Laptop.local").as_deref(),
            Some("mylaptop")
        );
        assert_eq!(sanitize_hostname("--x--").as_deref(), Some("x"));
        assert_eq!(sanitize_hostname("!!!"), None);
    }

    #[test]
    fn ignores_replies_relays_and_garbage() {
        let mut s = Server::new(cfg());
        let mut m = client_msg(A, MessageType::Discover);
        m.op = OP_REPLY;
        assert!(s.handle(0, &m.emit()).reply.is_none());
        let mut m = client_msg(A, MessageType::Discover);
        m.giaddr = Ipv4Addr::new(10, 1, 1, 1);
        assert!(s.handle(0, &m.emit()).reply.is_none());
        assert!(s.handle(0, b"junk").reply.is_none());
    }

    // ---- pool exhaustion (docs/security-audit.md §5 item 5) ----------------

    fn decline(s: &mut Server, mac: Mac, ip: Ipv4Addr, now: u64) -> Output {
        let mut m = client_msg(mac, MessageType::Decline);
        m.options.requested_ip = Some(ip);
        s.handle(now, &m.emit())
    }

    fn offered(s: &mut Server, mac: Mac, now: u64) -> Option<Ipv4Addr> {
        let out = s.handle(now, &client_msg(mac, MessageType::Discover).emit());
        out.reply.map(|r| Message::parse(&r).unwrap().yiaddr)
    }

    #[test]
    fn decline_only_for_the_clients_own_address() {
        let mut s = Server::new(cfg());
        let (a100, a101) = (Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(192, 168, 1, 101));
        // B declines both pool addresses, holding neither: refused.
        decline(&mut s, B, a100, 0);
        decline(&mut s, B, a101, 0);
        assert_eq!(s.stats().declines_refused, 2);
        assert!(s.declined.is_empty());
        assert_eq!(dora(&mut s, A, None, 1), a100, "the pool stays usable");
        // A declines the address it holds: it leaves the pool for a while.
        let out = decline(&mut s, A, a100, 2);
        assert!(matches!(out.events[..], [Event::Released { ip, .. }] if ip == a100));
        assert_eq!(s.declined.len(), 1);
        assert_eq!(offered(&mut s, B, 3), Some(a101));
        assert_eq!(s.stats().declines_refused, 2);
    }

    #[test]
    fn declines_for_foreign_addresses_do_not_grow_the_table() {
        let mut s = Server::new(cfg());
        for i in 0..10_000u32 {
            decline(&mut s, B, Ipv4Addr::from(0x0a00_0000 + i), 0);
        }
        assert!(s.declined.is_empty());
        assert_eq!(s.stats().declines_refused, 10_000);
    }

    #[test]
    fn a_discover_flood_cannot_hold_the_pool() {
        let mut s = Server::new(cfg());
        let (x, y): (Mac, Mac) = ([2, 0, 0, 0, 0, 0x1], [2, 0, 0, 0, 0, 0x2]);
        assert!(offered(&mut s, x, 0).is_some());
        assert!(offered(&mut s, y, 1).is_some());
        // Pool of two, both offered: a real client takes over the oldest
        // offer (x's) and gets it bound.
        let got = dora(&mut s, A, None, 2);
        assert_eq!(got, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(s.stats().offers_reclaimed, 1);
        // x's late REQUEST for it is refused.
        let mut r = client_msg(x, MessageType::Request);
        r.options.server_id = Some(SERVER);
        r.options.requested_ip = Some(got);
        assert_eq!(reply_of(&s.handle(3, &r.emit())).options.msg_type, Some(MessageType::Nak));
        // Bound leases are never taken over: with A and B bound, a third
        // client gets nothing and the counter says why.
        assert_eq!(dora(&mut s, B, None, 4), Ipv4Addr::new(192, 168, 1, 101));
        assert_eq!(offered(&mut s, [2, 0, 0, 0, 0, 0x3], 5), None);
        assert_eq!(s.stats().pool_full, 1);
        assert_eq!(s.stats().offers_reclaimed, 2, "y's offer was the one left to take");
    }

    #[test]
    fn a_reservations_offer_is_not_taken_over() {
        let mut s = Server::new(cfg());
        assert_eq!(offered(&mut s, NAS, 0), Some(Ipv4Addr::new(192, 168, 1, 10)));
        dora(&mut s, A, None, 1);
        dora(&mut s, B, None, 1);
        assert_eq!(offered(&mut s, [2, 0, 0, 0, 0, 0x3], 2), None);
        assert!(s.leases.get(&NAS).is_some_and(|l| l.state == LeaseState::Offered));
    }

    #[test]
    fn an_expired_lease_is_replaced_with_its_release_event() {
        let mut s = Server::new(cfg());
        let first = dora(&mut s, A, Some("old"), 0);
        dora(&mut s, B, None, 0);
        // A's lease ran out, no expire() pass yet: C may take the address,
        // A's lease goes with it (its DNS name too).
        let c: Mac = [2, 0, 0, 0, 0, 0xc];
        let mut d = client_msg(c, MessageType::Discover);
        d.options.requested_ip = Some(first);
        let out = s.handle(3601, &d.emit());
        assert_eq!(reply_of(&out).yiaddr, first);
        assert!(matches!(&out.events[..], [Event::Released { mac, .. }] if *mac == A));
        assert!(!s.leases.contains_key(&A));
        assert_eq!(s.by_ip.get(&u32_of(first)), Some(&c));
        assert_eq!(s.by_ip.len(), s.leases.len(), "one index entry per lease");
    }

    #[test]
    fn the_address_index_follows_every_change() {
        let mut s = Server::new(cfg());
        let check = |s: &Server| {
            assert_eq!(s.by_ip.len(), s.leases.len());
            for (ip, mac) in &s.by_ip {
                assert_eq!(u32_of(s.leases[mac].ip), *ip);
            }
        };
        dora(&mut s, A, None, 0);
        check(&s);
        // A moves to the other address (INIT-REBOOT for .101).
        let mut r = client_msg(A, MessageType::Request);
        r.options.requested_ip = Some(Ipv4Addr::new(192, 168, 1, 101));
        s.handle(1, &r.emit());
        check(&s);
        assert!(!s.by_ip.contains_key(&u32_of(Ipv4Addr::new(192, 168, 1, 100))));
        dora(&mut s, B, None, 2);
        check(&s);
        let mut rel = client_msg(B, MessageType::Release);
        rel.ciaddr = Ipv4Addr::new(192, 168, 1, 100);
        s.handle(3, &rel.emit());
        check(&s);
        s.expire(10_000);
        check(&s);
        assert!(s.by_ip.is_empty());
        let saved = [crate::v4::persist::Saved { mac: A, ip: Ipv4Addr::new(192, 168, 1, 100), hostname: None }];
        s.restore(10_001, &saved);
        check(&s);
        let mut c = cfg();
        c.range = (Ipv4Addr::new(192, 168, 1, 101), Ipv4Addr::new(192, 168, 1, 101));
        s.reconfigure(10_002, c);
        check(&s);
        assert!(s.by_ip.is_empty(), "outside the new pool");
    }
}

#[cfg(test)]
mod reconfigure_tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    fn cfg(lo: u8, hi: u8, statics: Vec<StaticLease>) -> Config {
        Config {
            server_ip: SERVER,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            router: Some(SERVER),
            dns: vec![SERVER],
            domain: Some("lan".to_string()),
            range: (
                Ipv4Addr::new(192, 168, 1, lo),
                Ipv4Addr::new(192, 168, 1, hi),
            ),
            lease_secs: 3600,
            statics,
            routes: Vec::new(),
        }
    }

    fn ip(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, d)
    }

    fn bound(s: &mut Server, mac: Mac, d: u8, host: &str) {
        s.leases.insert(
            mac,
            Lease {
                mac,
                ip: ip(d),
                hostname: Some(host.to_string()),
                state: LeaseState::Bound,
                expires: 1000,
                restored: false,
            },
        );
    }

    fn st(mac: Mac, d: u8, host: Option<&str>) -> StaticLease {
        StaticLease {
            mac,
            ip: ip(d),
            hostname: host.map(|h| h.to_string()),
        }
    }

    #[test]
    fn keeps_valid_leases_and_drops_the_rest() {
        let (a, b, c, d, e) = ([1u8; 6], [2u8; 6], [3u8; 6], [4u8; 6], [5u8; 6]);
        let mut s = Server::new(cfg(100, 199, vec![st(d, 20, Some("nas"))]));
        bound(&mut s, a, 100, "a"); // stays in the pool
        bound(&mut s, b, 150, "b"); // pool shrinks below it
        bound(&mut s, c, 101, "c"); // its address becomes reserved for another MAC
        bound(&mut s, d, 20, "nas"); // reservation kept, renamed
        bound(&mut s, e, 102, "e"); // gets a reservation elsewhere
        let ev = s.reconfigure(
            10,
            cfg(
                100,
                120,
                vec![
                    st(d, 20, Some("storage")),
                    st(e, 30, None),
                    st([9; 6], 101, None),
                ],
            ),
        );
        let left: Vec<_> = s.leases().map(|l| (l.mac, l.ip)).collect();
        assert_eq!(left, vec![(a, ip(100)), (d, ip(20))]);
        // Expiry untouched.
        assert!(s.leases().all(|l| l.expires == 1000));
        let released: Vec<_> = ev
            .iter()
            .filter_map(|e| match e {
                Event::Released { mac, .. } => Some(*mac),
                _ => None,
            })
            .collect();
        assert_eq!(released, vec![b, c, d, e]);
        assert!(ev.contains(&Event::Bound {
            mac: d,
            ip: ip(20),
            hostname: Some("storage".to_string())
        }));
        assert_eq!(s.config().range.1, ip(120));
    }

    #[test]
    fn unchanged_config_changes_nothing() {
        let mut s = Server::new(cfg(100, 199, vec![]));
        bound(&mut s, [1; 6], 100, "a");
        assert!(s.reconfigure(10, cfg(100, 199, vec![])).is_empty());
        assert_eq!(s.leases().count(), 1);
    }
}
