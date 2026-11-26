//! The WAN's IPv6 (docs/ipv6.md step 3), in the services task: the
//! default router from the ISP's Router Advertisements, the networks'
//! prefix by DHCPv6 prefix delegation (`proto_dhcp::v6::pd`).
//!
//! - RAs: `net::device` keeps the last one the WAN received
//!   (`RxTap::take_ra`); `v6::ra::parse_frame` reads it. Its link-local
//!   source is the default route while its router lifetime lasts. Until one
//!   comes, up to three Router Solicitations, 4 s apart.
//! - DHCPv6: a UDP socket on the WAN's :546, messages to ff02::1:2:547
//!   from the WAN's link-local address (smoltcp picks it for the
//!   link-scope destination).
//! - The result is [`State`], read by `config::wan6` and
//!   `config::gua_router` (the datapath's default route, the networks'
//!   global /64s, the RAs' router lifetime, status). [`Wan6::step`] says
//!   when it changed; the services task then applies the networks again.
//!
//! On PPPoE (step 4) it runs while IPv6CP is up ([`set_ppp_link`], from
//! `net::pppoe`): from IPv6CP's link-local address, solicitations without
//! a link-layer option; frames go through the session like IPv4. Not with
//! the development boot arguments `wan6_*` / `lan6_prefix` (they win), not
//! with `ipv6.dhcpv6_pd = false`.

use crate::net::shared::Shared;
use crate::net::svc::HostIf;
use crate::println;
use alloc::vec;
use alloc::vec::Vec;
use core::net::Ipv6Addr;
use proto_dhcp::v6::pd::{self, Client, Event, PdConfig};
use proto_dhcp::v6::ra;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp;
use smoltcp::wire::IpEndpoint;

/// What the WAN has learned (none: not running).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    /// The ISP router (link-local) while its RA's lifetime lasts.
    pub gateway: Option<Ipv6Addr>,
    /// The delegated prefix.
    pub prefix: Option<(Ipv6Addr, u8)>,
    pub preferred_secs: u32,
    pub valid_secs: u32,
    /// The ISP's DNS servers from the delegation's reply.
    pub dns: Vec<Ipv6Addr>,
    /// The default router came from an RA (else, on PPPoE, the IPv6CP
    /// peer).
    pub from_ra: bool,
    /// The DHCPv6 client's state (status).
    pub pd_state: &'static str,
}

static STATE: spin::Mutex<Option<State>> = spin::Mutex::new(None);

/// The last delegated prefix (this boot, or from the store's lease
/// record): asked for again, kept across restarts.
static LAST: spin::Mutex<Option<(Ipv6Addr, u8)>> = spin::Mutex::new(None);

/// The prefix from the store at boot (`svc::LeaseStore`).
pub fn set_last(p: Option<(Ipv6Addr, u8)>) {
    *LAST.lock() = p;
}

/// The last delegated prefix, for the store.
pub fn last() -> Option<(Ipv6Addr, u8)> {
    *LAST.lock()
}

/// PPPoE: IPv6CP's link-local addresses (ours, the peer's) while IPv6 is
/// up on the session.
static PPP_LINK: spin::Mutex<Option<(Ipv6Addr, Option<Ipv6Addr>)>> = spin::Mutex::new(None);

/// IPv6CP up (`Some`) or down, from `net::pppoe`.
pub fn set_ppp_link(l: Option<(Ipv6Addr, Option<Ipv6Addr>)>) {
    *PPP_LINK.lock() = l;
}

/// IPv6 on the PPPoE session: (our link-local address, the peer's).
pub fn ppp_link() -> Option<(Ipv6Addr, Option<Ipv6Addr>)> {
    *PPP_LINK.lock()
}

/// The WAN's link-local address: IPv6CP's on PPPoE, else the MAC's.
pub fn wan_link_local(sh: &Shared) -> Option<Ipv6Addr> {
    if sh.ports[0].is_pppoe() { ppp_link().map(|l| l.0) } else { Some(fwd::wire::link_local(sh.ports[0].mac)) }
}

/// The ISP's IPv6 DNS servers (none while prefix delegation is not bound).
pub fn dns() -> Vec<Ipv6Addr> {
    state().map(|s| s.dns).unwrap_or_default()
}

/// The WAN's learned IPv6, if prefix delegation runs.
pub fn state() -> Option<State> {
    STATE.lock().clone()
}

const RS_TRIES: u8 = 3;
const RS_INTERVAL_MS: u64 = 4_000;

pub struct Wan6 {
    pd: Client,
    sock: SocketHandle,
    mac: [u8; 6],
    /// Our link-local address (the RS source).
    ll: Ipv6Addr,
    /// Ethernet: solicitations carry the source link-layer option.
    lla: bool,
    rs_sent: u8,
    next_rs: u64,
    /// The router and when its lifetime ends (ms).
    router: Option<(Ipv6Addr, u64)>,
    shown: State,
}

impl Wan6 {
    /// Prefix delegation on the WAN, if it should run (IPv6 on, PD on, no
    /// development override; on PPPoE while IPv6CP is up).
    pub fn new(wan: &mut HostIf, sh: &Shared, now: u64) -> Option<Self> {
        let ll = wan_link_local(sh);
        let Some(ll) = ll.filter(|_| crate::config::pd_wanted()) else {
            *STATE.lock() = None;
            return None;
        };
        let lla = !sh.ports[0].is_pppoe();
        let mac = sh.ports[0].mac;
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4 * 1024]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4 * 1024]);
        let mut s = udp::Socket::new(rx, tx);
        s.bind(pd::CLIENT_PORT).expect("bind :546");
        let sock = wan.sockets.add(s);
        let hint = crate::config::get_ipv6().prefix_hint;
        let pd = Client::new(PdConfig { mac, iaid: 1, hint_len: hint, last: last().filter(|_| crate::config::pd_keep()) }, now, crate::timer::ticks());
        println!("  wan6            : DHCPv6 prefix delegation (asking for a /{hint}), router solicitations");
        let shown = State { pd_state: pd.state().name(), ..State::default() };
        *STATE.lock() = Some(shown.clone());
        Some(Wan6 { pd, sock, mac, ll, lla, rs_sent: 0, next_rs: now, router: None, shown })
    }

    /// Stop (the WAN changes mode): its socket goes, nothing is learned.
    pub fn stop(self, wan: &mut HostIf) {
        wan.sockets.remove(self.sock);
        *STATE.lock() = None;
    }

    /// RAs, solicitations, DHCPv6. True when [`state`] changed in a way
    /// the networks must follow (router or prefix).
    pub fn step(&mut self, wan: &mut HostIf, sh: &Shared, now: u64) -> bool {
        // The ISP's RA.
        if let Some(f) = wan.tap.take_ra()
            && let Some(r) = ra::parse_frame(&f)
        {
            self.router = (r.lifetime_secs > 0).then(|| (r.router, now + u64::from(r.lifetime_secs) * 1000));
        }
        if self.router.is_some_and(|(_, until)| until <= now) {
            self.router = None;
        }
        if self.router.is_none() && self.rs_sent < RS_TRIES && now >= self.next_rs {
            let mut rs = [0u8; fwd::wire::RS_LEN];
            let n = fwd::wire::build_rs(&mut rs, self.mac, self.ll, self.lla);
            crate::net::services::send_frame(sh, 0, &rs[..n]);
            self.rs_sent += 1;
            self.next_rs = now + RS_INTERVAL_MS;
        }
        // DHCPv6.
        let mut buf = [0u8; 1500];
        while let Ok((n, _)) = wan.sockets.get_mut::<udp::Socket>(self.sock).recv_slice(&mut buf) {
            self.pd.handle(now, &buf[..n]);
        }
        while let Some(m) = self.pd.poll(now) {
            let ep = IpEndpoint::new(pd::SERVERS.into(), pd::SERVER_PORT);
            let _ = wan.sockets.get_mut::<udp::Socket>(self.sock).send_slice(&m, ep);
        }
        while let Some(e) = self.pd.poll_event() {
            match e {
                // Renewals of the same prefix are quiet.
                Event::Bound(d) if self.shown.prefix == Some((d.prefix, d.len)) => {}
                Event::Bound(d) => println!(
                    "  wan6            : delegated {}/{} (preferred {} s, valid {} s){}",
                    d.prefix,
                    d.len,
                    d.preferred_secs,
                    d.valid_secs,
                    if d.dns.is_empty() { alloc::string::String::new() } else { alloc::format!(", dns {:?}", d.dns) }
                ),
                Event::Lost => println!("  wan6            : prefix lost"),
            }
        }
        let d = self.pd.delegation();
        if let Some(d) = d {
            *LAST.lock() = Some((d.prefix, d.len));
        }
        let now_state = State {
            // PPPoE: the RA's router, else the IPv6CP peer (point to point:
            // the session is the route).
            gateway: self.router.map(|(g, _)| g).or_else(|| if self.lla { None } else { ppp_gateway() }),
            prefix: d.map(|d| (d.prefix, d.len)),
            preferred_secs: d.map_or(0, |d| d.preferred_secs),
            valid_secs: d.map_or(0, |d| d.valid_secs),
            dns: d.map(|d| d.dns.clone()).unwrap_or_default(),
            from_ra: self.router.is_some(),
            pd_state: self.pd.state().name(),
        };
        let changed = now_state.gateway != self.shown.gateway || now_state.prefix != self.shown.prefix || now_state.dns != self.shown.dns;
        if changed && now_state.gateway != self.shown.gateway {
            match now_state.gateway {
                Some(g) => println!("  wan6            : default router {g}"),
                None => println!("  wan6            : no default router"),
            }
        }
        if now_state != self.shown {
            self.shown = now_state.clone();
            *STATE.lock() = Some(now_state);
        }
        changed
    }

    /// When [`Self::step`] must run again (ms).
    pub fn next_deadline(&self) -> u64 {
        let mut t = self.pd.next_deadline();
        if let Some((_, until)) = self.router {
            t = t.min(until);
        } else if self.rs_sent < RS_TRIES {
            t = t.min(self.next_rs);
        }
        t
    }
}

/// PPPoE: the default router while IPv6CP is up when no RA names one:
/// the peer's link-local address (`fe80::1` if it sent no identifier; the
/// datapath sends to the access concentrator either way).
pub fn ppp_gateway() -> Option<Ipv6Addr> {
    ppp_link().map(|(_, peer)| peer.unwrap_or(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))
}

/// The `/api/status` `wan_ipv6` object for prefix delegation.
pub fn status_json() -> Option<Vec<u8>> {
    let s = state()?;
    let q = |v: Option<alloc::string::String>| v.map_or_else(|| alloc::string::String::from("null"), |s| alloc::format!("\"{s}\""));
    Some(
        alloc::format!(
            "{{\"source\":\"dhcpv6-pd\",\"state\":\"{}\",\"gateway\":{},\"router_from\":{},\"prefix\":{},\"preferred\":{},\"valid\":{},\"addr\":{},\"dns\":[{}]}}",
            s.pd_state,
            q(s.gateway.map(|g| alloc::format!("{g}"))),
            match (s.gateway, s.from_ra) {
                (None, _) => "null",
                (Some(_), true) => "\"ra\"",
                (Some(_), false) => "\"ipv6cp\"",
            },
            q(s.prefix.map(|(p, l)| alloc::format!("{p}/{l}"))),
            s.preferred_secs,
            s.valid_secs,
            q(s.prefix.and_then(|(p, l)| crate::config::wan_address6(p, l)).map(|a| alloc::format!("{a}"))),
            s.dns.iter().map(|d| alloc::format!("\"{d}\"")).collect::<Vec<_>>().join(",")
        )
        .into_bytes(),
    )
}
