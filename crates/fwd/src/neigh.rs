//! Neighbor (ARP) cache for forwarding, generic over the packet type.
//!
//! Entries are learned by snooping ARP on each interface. A packet to an
//! unresolved neighbor waits in a **tiny bounded** queue (at most
//! [`MAX_PENDING`] per neighbor, oldest dropped) while an ARP request is
//! retried; this is the only buffering outside the qdisc and is bounded by
//! design (docs/bufferbloat-cake.md §3.1).

use crate::IfIndex;
use crate::wire::Mac;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::net::Ipv4Addr;

pub const MAX_PENDING: usize = 3;
const REACHABLE_MS: u64 = 300_000;
const RETRY_MS: u64 = 1_000;
const MAX_TRIES: u8 = 3;

enum Entry<P> {
    Reachable {
        mac: Mac,
        learned: u64,
    },
    Incomplete {
        pending: VecDeque<P>,
        last_try: u64,
        tries: u8,
    },
}

pub enum Resolve<P> {
    /// Known neighbor: send `P` to `Mac`.
    Ready(Mac, P),
    /// Packet queued; send an ARP request now if `send_arp`.
    Queued { send_arp: bool },
}

pub struct NeighTable<P> {
    entries: BTreeMap<(IfIndex, Ipv4Addr), Entry<P>>,
    pub dropped: u64,
}

impl<P> Default for NeighTable<P> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            dropped: 0,
        }
    }
}

impl<P> NeighTable<P> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookup(&self, ifx: IfIndex, ip: Ipv4Addr, now: u64) -> Option<Mac> {
        match self.entries.get(&(ifx, ip)) {
            Some(Entry::Reachable { mac, learned }) if now < learned + REACHABLE_MS => Some(*mac),
            _ => None,
        }
    }

    /// Learn `ip → mac`; returns packets that were waiting for it.
    pub fn learn(&mut self, ifx: IfIndex, ip: Ipv4Addr, mac: Mac, now: u64) -> Vec<P> {
        let old = self
            .entries
            .insert((ifx, ip), Entry::Reachable { mac, learned: now });
        match old {
            Some(Entry::Incomplete { pending, .. }) => pending.into_iter().collect(),
            _ => Vec::new(),
        }
    }

    /// Resolve the next hop for `pkt`.
    pub fn resolve(&mut self, ifx: IfIndex, ip: Ipv4Addr, pkt: P, now: u64) -> Resolve<P> {
        if let Some(mac) = self.lookup(ifx, ip, now) {
            return Resolve::Ready(mac, pkt);
        }
        match self.entries.get_mut(&(ifx, ip)) {
            Some(Entry::Incomplete { pending, .. }) => {
                if pending.len() >= MAX_PENDING {
                    pending.pop_front();
                    self.dropped += 1;
                }
                pending.push_back(pkt);
                Resolve::Queued { send_arp: false }
            }
            _ => {
                let mut pending = VecDeque::with_capacity(MAX_PENDING);
                pending.push_back(pkt);
                self.entries.insert(
                    (ifx, ip),
                    Entry::Incomplete {
                        pending,
                        last_try: now,
                        tries: 1,
                    },
                );
                Resolve::Queued { send_arp: true }
            }
        }
    }

    /// Retry or give up on unresolved neighbors and age out stale entries.
    /// Returns the (interface, address) pairs to send ARP requests for.
    pub fn poll(&mut self, now: u64) -> Vec<(IfIndex, Ipv4Addr)> {
        let mut retry = Vec::new();
        let mut dead = Vec::new();
        for (&k, e) in self.entries.iter_mut() {
            match e {
                Entry::Incomplete {
                    last_try,
                    tries,
                    pending,
                } if now >= *last_try + RETRY_MS => {
                    if *tries >= MAX_TRIES {
                        self.dropped += pending.len() as u64;
                        dead.push(k);
                    } else {
                        *tries += 1;
                        *last_try = now;
                        retry.push(k);
                    }
                }
                Entry::Reachable { learned, .. } if now >= *learned + REACHABLE_MS => dead.push(k),
                _ => {}
            }
        }
        for k in dead {
            self.entries.remove(&k);
        }
        retry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
    const MAC: Mac = [2, 0, 0, 0, 0, 9];

    #[test]
    fn queue_then_release_on_learn() {
        let mut n: NeighTable<u32> = NeighTable::new();
        assert!(matches!(
            n.resolve(1, IP, 10, 0),
            Resolve::Queued { send_arp: true }
        ));
        assert!(matches!(
            n.resolve(1, IP, 11, 0),
            Resolve::Queued { send_arp: false }
        ));
        assert_eq!(n.learn(1, IP, MAC, 5), [10, 11]);
        assert!(matches!(n.resolve(1, IP, 12, 6), Resolve::Ready(m, 12) if m == MAC));
    }

    #[test]
    fn pending_is_bounded_and_retries_give_up() {
        let mut n: NeighTable<u32> = NeighTable::new();
        for i in 0..5 {
            n.resolve(0, IP, i, 0);
        }
        assert_eq!(n.dropped, 2);
        assert_eq!(n.poll(999), []);
        assert_eq!(n.poll(1000), [(0, IP)]);
        assert_eq!(n.poll(2000), [(0, IP)]);
        assert!(n.poll(3000).is_empty(), "third try failed: give up");
        assert_eq!(n.dropped, 5);
        assert!(matches!(
            n.resolve(0, IP, 9, 3001),
            Resolve::Queued { send_arp: true }
        ));
    }

    #[test]
    fn entries_age_out() {
        let mut n: NeighTable<u32> = NeighTable::new();
        n.learn(0, IP, MAC, 0);
        assert!(n.lookup(0, IP, REACHABLE_MS - 1).is_some());
        assert!(n.lookup(0, IP, REACHABLE_MS).is_none());
    }
}
