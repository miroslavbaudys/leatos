//! The router's multicast group memberships per link (docs/local-stack.md
//! step 4): what snooping switches learn from its IGMP / MLD reports, so
//! they keep forwarding the groups to it. smoltcp's `multicast` feature
//! did this before.
//!
//! - IPv6 on a link with addresses (not the WAN): all-routers ff02::2 and
//!   the solicited-node group of each address (neighbor solicitations for
//!   the router reach it); on the WAN only the solicited-node groups (the
//!   router is a host there). Not on PPPoE (no link layer).
//! - mDNS: 224.0.0.251 and ff02::fb where the reflector takes part
//!   (`net::mdns`, which waits until the datapath runs the link's VLAN).
//!
//! A change sends reports at once and once more a second later (RFC 3810
//! robustness), a group gone an IGMP leave / MLD "left" record; a query
//! (`net::local` takes IGMP and MLD queries) is answered within its
//! maximum response time, at most 1 s, with every group of the link.
//! Sources: the link's IPv4 address, its link-local IPv6 address.

use crate::net::datapath::WAN;
use crate::net::local;
use crate::net::shared::Shared;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};
use fwd::IfIndex;
use fwd::mcast::{self, Record};

/// The second report after a change (ms).
const REPEAT_MS: u64 = 1_000;
/// The longest the router waits before answering a query (ms).
const MAX_ANSWER_MS: u64 = 1_000;

/// What one link should be a member of, and from which addresses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Want {
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
    pub src4: Option<Ipv4Addr>,
    pub src6: Option<Ipv6Addr>,
}

#[derive(Default)]
struct Link {
    have: Want,
    /// When to send the current state (a repeat or a query's answer).
    report_at: Option<u64>,
}

#[derive(Default)]
pub struct Groups {
    links: Vec<Link>,
    rng: u64,
    /// `groups=0`: track, never send (the lab's negative control).
    on: bool,
}

/// The groups link `ifx` wants: from the datapath's view of the link
/// (`fwd::local::LocalLink`) and the mDNS members (`(link, v6)`).
pub fn wanted(sh: &Shared, ifx: usize, mdns: &[(usize, bool)]) -> Want {
    let mut w = Want::default();
    let Some(dp) = crate::net::stack::datapath() else { return w };
    if sh.links.get(ifx).is_none_or(|l| sh.ports[l.port()].is_pppoe()) {
        return w;
    }
    let (v4, v6) = dp.local_addrs(ifx as IfIndex);
    w.src4 = v4;
    w.src6 = v6.iter().copied().find(|a| a.is_unicast_link_local());
    if w.src6.is_some() {
        if ifx != WAN as usize {
            w.v6.push(mcast::ALL_ROUTERS6);
        }
        for a in &v6 {
            let g = fwd::wire::solicited_node(*a);
            if !w.v6.contains(&g) {
                w.v6.push(g);
            }
        }
    }
    for &(link, v6) in mdns {
        if link == ifx {
            if !w.v4.contains(&proto_mdns::GROUP_V4) {
                w.v4.push(proto_mdns::GROUP_V4);
            }
            if v6 && w.src6.is_some() && !w.v6.contains(&proto_mdns::GROUP_V6) {
                w.v6.push(proto_mdns::GROUP_V6);
            }
        }
    }
    w
}

impl Groups {
    pub fn new() -> Self {
        Groups { links: Vec::new(), rng: crate::entropy::u64() | 1, on: crate::config::groups_on() }
    }

    /// Link `ifx` should now be a member of `want`'s groups: joins and
    /// leaves reported at once, the state again in [`REPEAT_MS`].
    pub fn set(&mut self, sh: &Shared, ifx: usize, want: Want, now: u64) {
        if self.links.len() <= ifx {
            self.links.resize_with(ifx + 1, Link::default);
        }
        let l = &mut self.links[ifx];
        if l.have == want {
            return;
        }
        if !self.on {
            l.have = want;
            return;
        }
        let link = ifx as IfIndex;
        let mut buf = [0u8; 1024];
        // Left: from the old sources (still the link's a moment ago).
        if let Some(src) = l.have.src4 {
            for &g in l.have.v4.iter().filter(|g| !want.v4.contains(g) || want.src4 != Some(src)) {
                if let Some(n) = mcast::igmp2_leave(&mut buf, src, g) {
                    local::send_raw(sh, link, &buf[..n]);
                }
            }
        }
        if let Some(src) = l.have.src6 {
            let gone: Vec<Ipv6Addr> = l.have.v6.iter().copied().filter(|g| !want.v6.contains(g) || want.src6 != Some(src)).collect();
            send_mld(sh, link, src, Record::Left, &gone, &mut buf);
        }
        // Joined: from the new ones.
        if let Some(src) = want.src4 {
            for &g in want.v4.iter().filter(|g| !l.have.v4.contains(g) || l.have.src4 != Some(src)) {
                if let Some(n) = mcast::igmp2_report(&mut buf, src, g) {
                    local::send_raw(sh, link, &buf[..n]);
                }
            }
        }
        if let Some(src) = want.src6 {
            let new: Vec<Ipv6Addr> = want.v6.iter().copied().filter(|g| !l.have.v6.contains(g) || l.have.src6 != Some(src)).collect();
            send_mld(sh, link, src, Record::Joined, &new, &mut buf);
        }
        l.have = want;
        l.report_at = Some(now + REPEAT_MS);
    }

    /// A query heard on link `ifx` (`net::local`): answer within its time.
    pub fn query(&mut self, ifx: usize, q: mcast::Query, now: u64) {
        let Some(l) = self.links.get_mut(ifx) else { return };
        let wait = (q.max_resp_ms as u64).min(MAX_ANSWER_MS);
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        let at = now + x % (wait + 1);
        l.report_at = Some(l.report_at.map_or(at, |t| t.min(at)));
    }

    /// Reports that are due: every group of the link, current state.
    pub fn step(&mut self, sh: &Shared, now: u64) {
        let mut buf = [0u8; 1024];
        for (ifx, l) in self.links.iter_mut().enumerate() {
            if l.report_at.is_none_or(|t| t > now) {
                continue;
            }
            l.report_at = None;
            let link = ifx as IfIndex;
            if let Some(src) = l.have.src4 {
                for &g in &l.have.v4 {
                    if let Some(n) = mcast::igmp2_report(&mut buf, src, g) {
                        local::send_raw(sh, link, &buf[..n]);
                    }
                }
            }
            if let Some(src) = l.have.src6 {
                send_mld(sh, link, src, Record::IsMember, &l.have.v6, &mut buf);
            }
        }
    }

    /// When [`Self::step`] has something to do (ms, `u64::MAX`: nothing).
    pub fn next_deadline(&self) -> u64 {
        self.links.iter().filter_map(|l| l.report_at).min().unwrap_or(u64::MAX)
    }
}

fn send_mld(sh: &Shared, link: IfIndex, src: Ipv6Addr, kind: Record, groups: &[Ipv6Addr], buf: &mut [u8]) {
    for chunk in groups.chunks(mcast::MAX_RECORDS) {
        if let Some(n) = mcast::mld2_report(buf, src, kind, chunk) {
            local::send_raw(sh, link, &buf[..n]);
        }
    }
}
