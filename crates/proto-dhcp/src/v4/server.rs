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
//!   (until lease persistence lands).
//! - Relayed requests (giaddr != 0) are ignored.

use super::packet::{FLAG_BROADCAST, Message, MessageType, OP_REPLY, OP_REQUEST, Options};
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
    declined: BTreeMap<Ipv4Addr, u64>,
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
        Self {
            cfg,
            leases: BTreeMap::new(),
            declined: BTreeMap::new(),
        }
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
        if let Some(s) = self.cfg.statics.iter().find(|s| s.ip == ip) {
            return &s.mac == mac;
        }
        if !self.in_range(ip) || self.declined.get(&ip).is_some_and(|&until| until > now) {
            return false;
        }
        !self
            .leases
            .values()
            .any(|l| l.ip == ip && &l.mac != mac && l.expires > now)
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
        let prev = self.leases.insert(
            mac,
            Lease {
                mac,
                ip,
                hostname: hostname.clone(),
                state: LeaseState::Bound,
                expires,
            },
        );
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
        if let Some(l) = self.leases.remove(mac)
            && l.state == LeaseState::Bound
        {
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
                let Some(ip) = self.pick_address(&mac, msg.options.requested_ip, now) else {
                    return out; // pool exhausted: stay silent
                };
                let hostname = self.hostname_for(&mac, &msg);
                let keep_bound = self
                    .leases
                    .get(&mac)
                    .is_some_and(|l| l.state == LeaseState::Bound && l.ip == ip);
                if !keep_bound {
                    self.leases.insert(
                        mac,
                        Lease {
                            mac,
                            ip,
                            hostname,
                            state: LeaseState::Offered,
                            expires: now + OFFER_HOLD_SECS,
                        },
                    );
                }
                out.reply = Some(self.reply(&msg, MessageType::Offer, ip, true));
            }
            Some(MessageType::Request) => self.handle_request(now, &msg, &mut out),
            Some(MessageType::Release) => {
                if self.leases.get(&mac).is_some_and(|l| l.ip == msg.ciaddr) {
                    self.drop_lease(&mac, &mut out);
                }
            }
            Some(MessageType::Decline) => {
                if let Some(ip) = msg.options.requested_ip {
                    self.declined.insert(ip, now + DECLINE_HOLD_SECS);
                    if self.leases.get(&mac).is_some_and(|l| l.ip == ip) {
                        self.drop_lease(&mac, &mut out);
                    }
                }
            }
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
}
