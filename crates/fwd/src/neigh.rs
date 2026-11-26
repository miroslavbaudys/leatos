//! Neighbor cache for forwarding (ARP for IPv4, neighbor discovery for
//! IPv6), generic over the packet type and the address family.
//!
//! Entries are learned by snooping ARP on each interface. A packet to an
//! unresolved neighbor waits in a **tiny bounded** queue (at most
//! [`MAX_PENDING`] per neighbor, oldest dropped) while an ARP request is
//! retried; this is the only buffering outside the qdisc and is bounded by
//! design (docs/bufferbloat-cake.md §3.1). With
//! [`NeighTable::with_incomplete_cap`] at most that many neighbors are
//! being resolved at once (RFC 6583: a scan of an IPv6 /64 must not fill
//! the table); a packet to another unknown one is dropped.
//!
//! An entry lives [`REACHABLE_MS`] from when it was learned. One that was
//! used in that time is not dropped then: it is **probed** (RFC 4861 §7.3
//! PROBE, Linux's STALE → PROBE) and packets keep going to the known MAC
//! while up to [`MAX_TRIES`] requests ask for it again; an answer makes it
//! reachable anew, none removes it. Hosts that never ARP for the router
//! (wired ones whose own entry for us stays fresh) would otherwise lose a
//! burst of packets every [`REACHABLE_MS`] while being resolved again.
//! Unused entries age out as before.

use crate::IfIndex;
use crate::wire::Mac;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::net::Ipv4Addr;

pub const MAX_PENDING: usize = 3;
pub const REACHABLE_MS: u64 = 300_000;
const RETRY_MS: u64 = 1_000;
const MAX_TRIES: u8 = 3;

enum Entry<P> {
    Reachable {
        mac: Mac,
        learned: u64,
        /// A packet went to it since it was learned.
        used: bool,
    },
    /// Past its lifetime while in use: still sent to while asked again.
    Probe { mac: Mac, last_try: u64, tries: u8 },
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

pub struct NeighTable<P, A = Ipv4Addr> {
    entries: BTreeMap<(IfIndex, A), Entry<P>>,
    pub dropped: u64,
    /// Entries being resolved, and the most allowed at once.
    incomplete: usize,
    max_incomplete: usize,
    /// Packets dropped because [`Self::max_incomplete`] was reached (also
    /// in `dropped`).
    pub incomplete_drops: u64,
    /// Requests sent to entries in use past their lifetime (probes).
    pub probes: u64,
    reachable_ms: u64,
    probe: bool,
    /// Packets held per neighbor being resolved (default [`MAX_PENDING`];
    /// 0 drops them: the lab's negative control `neigh_pending=0`).
    max_pending: usize,
}

impl<P, A> Default for NeighTable<P, A> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            dropped: 0,
            incomplete: 0,
            max_incomplete: usize::MAX,
            incomplete_drops: 0,
            probes: 0,
            reachable_ms: REACHABLE_MS,
            probe: true,
            max_pending: MAX_PENDING,
        }
    }
}

impl<P, A: Copy + Ord> NeighTable<P, A> {
    pub fn new() -> Self {
        Self::default()
    }

    /// At most `max` neighbors being resolved at once.
    pub fn with_incomplete_cap(max: usize) -> Self {
        Self {
            max_incomplete: max,
            ..Self::default()
        }
    }

    /// An entry's lifetime (default [`REACHABLE_MS`]), and whether entries
    /// in use are probed at its end (default) or dropped.
    pub fn with_timing(self, reachable_ms: u64, probe: bool) -> Self {
        Self {
            reachable_ms: reachable_ms.max(1),
            probe,
            ..self
        }
    }

    /// At most `n` packets wait per neighbor being resolved (capped at
    /// [`MAX_PENDING`]; 0: none, the packet that starts a resolution is
    /// dropped).
    pub fn with_pending(self, n: usize) -> Self {
        Self { max_pending: n.min(MAX_PENDING), ..self }
    }

    pub fn lookup(&self, ifx: IfIndex, ip: A, now: u64) -> Option<Mac> {
        match self.entries.get(&(ifx, ip)) {
            Some(Entry::Reachable { mac, learned, used }) if self.usable(*learned, *used, now) => Some(*mac),
            Some(Entry::Probe { mac, .. }) => Some(*mac),
            _ => None,
        }
    }

    /// A reachable entry still sent to: in its lifetime, or past it in use
    /// until [`Self::poll`] starts the probe.
    fn usable(&self, learned: u64, used: bool, now: u64) -> bool {
        now < learned + self.reachable_ms || (self.probe && used)
    }

    /// Learn `ip → mac`; returns packets that were waiting for it.
    pub fn learn(&mut self, ifx: IfIndex, ip: A, mac: Mac, now: u64) -> Vec<P> {
        let old = self.entries.insert(
            (ifx, ip),
            Entry::Reachable {
                mac,
                learned: now,
                used: false,
            },
        );
        match old {
            Some(Entry::Incomplete { pending, .. }) => {
                self.incomplete -= 1;
                pending.into_iter().collect()
            }
            _ => Vec::new(),
        }
    }

    /// Resolve the next hop for `pkt`.
    pub fn resolve(&mut self, ifx: IfIndex, ip: A, pkt: P, now: u64) -> Resolve<P> {
        let (reachable_ms, probe) = (self.reachable_ms, self.probe);
        match self.entries.get_mut(&(ifx, ip)) {
            Some(Entry::Reachable { mac, learned, used }) if now < *learned + reachable_ms || (probe && *used) => {
                *used = true;
                return Resolve::Ready(*mac, pkt);
            }
            Some(Entry::Probe { mac, .. }) => return Resolve::Ready(*mac, pkt),
            Some(Entry::Incomplete { pending, .. }) => {
                if self.max_pending == 0 {
                    self.dropped += 1;
                    return Resolve::Queued { send_arp: false };
                }
                if pending.len() >= self.max_pending {
                    pending.pop_front();
                    self.dropped += 1;
                }
                pending.push_back(pkt);
                return Resolve::Queued { send_arp: false };
            }
            _ => {}
        }
        if self.incomplete >= self.max_incomplete {
            self.dropped += 1;
            self.incomplete_drops += 1;
            return Resolve::Queued { send_arp: false };
        }
        self.incomplete += 1;
        let mut pending = VecDeque::with_capacity(self.max_pending);
        if self.max_pending == 0 {
            self.dropped += 1;
        } else {
            pending.push_back(pkt);
        }
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

    /// Retry or give up on unresolved neighbors, probe entries in use past
    /// their lifetime and age out the others. Returns the (interface,
    /// address) pairs to send ARP requests for.
    pub fn poll(&mut self, now: u64) -> Vec<(IfIndex, A)> {
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
                        self.incomplete -= 1;
                        dead.push(k);
                    } else {
                        *tries += 1;
                        *last_try = now;
                        retry.push(k);
                    }
                }
                Entry::Probe { last_try, tries, .. } if now >= *last_try + RETRY_MS => {
                    if *tries >= MAX_TRIES {
                        dead.push(k);
                    } else {
                        *tries += 1;
                        *last_try = now;
                        self.probes += 1;
                        retry.push(k);
                    }
                }
                Entry::Reachable { mac, learned, used } if now >= *learned + self.reachable_ms => {
                    if self.probe && *used {
                        *e = Entry::Probe {
                            mac: *mac,
                            last_try: now,
                            tries: 1,
                        };
                        self.probes += 1;
                        retry.push(k);
                    } else {
                        dead.push(k);
                    }
                }
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
    fn no_pending_queue_drops_while_resolving() {
        // `neigh_pending=0` (the lab's control): still asks, holds nothing.
        let mut n: NeighTable<u32> = NeighTable::new().with_pending(0);
        assert!(matches!(n.resolve(0, IP, 1, 0), Resolve::Queued { send_arp: true }));
        assert!(matches!(n.resolve(0, IP, 2, 0), Resolve::Queued { send_arp: false }));
        assert_eq!(n.dropped, 2);
        assert_eq!(n.learn(0, IP, MAC, 1), [], "nothing was waiting");
        assert!(matches!(n.resolve(0, IP, 3, 2), Resolve::Ready(MAC, 3)), "resolved: sent");
        // One held at most with 1; more is capped at MAX_PENDING.
        let mut n: NeighTable<u32> = NeighTable::new().with_pending(1);
        n.resolve(0, IP, 1, 0);
        n.resolve(0, IP, 2, 0);
        assert_eq!((n.dropped, n.learn(0, IP, MAC, 1)), (1, alloc::vec![2]));
        let mut n: NeighTable<u32> = NeighTable::new().with_pending(99);
        for i in 0..5 {
            n.resolve(0, IP, i, 0);
        }
        assert_eq!(n.dropped, 2);
    }

    #[test]
    fn incomplete_entries_are_capped() {
        use core::net::Ipv6Addr;
        let mut n: NeighTable<u32, Ipv6Addr> = NeighTable::with_incomplete_cap(2);
        let a = |i: u16| Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i);
        assert!(matches!(n.resolve(0, a(1), 1, 0), Resolve::Queued { send_arp: true }));
        assert!(matches!(n.resolve(0, a(2), 2, 0), Resolve::Queued { send_arp: true }));
        // A scan's third address: dropped, no solicitation.
        assert!(matches!(n.resolve(0, a(3), 3, 0), Resolve::Queued { send_arp: false }));
        assert_eq!((n.dropped, n.incomplete_drops), (1, 1));
        // One resolves, one gives up: room again.
        assert_eq!(n.learn(0, a(1), MAC, 1), [1]);
        assert!(matches!(n.resolve(0, a(4), 4, 1), Resolve::Queued { send_arp: true }));
        for t in [1000, 2000, 3000] {
            n.poll(t);
        }
        assert!(matches!(n.resolve(0, a(5), 5, 3001), Resolve::Queued { send_arp: true }));
        // Queuing behind a neighbor already being resolved is not capped.
        assert!(matches!(n.resolve(0, a(5), 6, 3001), Resolve::Queued { send_arp: false }));
        assert_eq!(n.incomplete_drops, 1);
    }

    #[test]
    fn entries_age_out() {
        let mut n: NeighTable<u32> = NeighTable::new();
        n.learn(0, IP, MAC, 0);
        assert!(n.lookup(0, IP, REACHABLE_MS - 1).is_some());
        assert!(n.lookup(0, IP, REACHABLE_MS).is_none());
        assert!(n.poll(REACHABLE_MS).is_empty(), "unused: no probe");
        assert!(matches!(
            n.resolve(0, IP, 1, REACHABLE_MS),
            Resolve::Queued { send_arp: true }
        ));
    }

    const R: u64 = REACHABLE_MS;

    #[test]
    fn entries_in_use_are_probed_not_dropped() {
        let mut n: NeighTable<u32> = NeighTable::new();
        n.learn(0, IP, MAC, 0);
        assert!(matches!(n.resolve(0, IP, 1, 10), Resolve::Ready(..)));
        // Past the lifetime, before the poll: still sent to.
        assert!(matches!(n.resolve(0, IP, 2, R + 1), Resolve::Ready(m, 2) if m == MAC));
        assert_eq!(n.poll(R + 5), [(0, IP)], "probe");
        assert_eq!(n.probes, 1);
        assert!(matches!(n.resolve(0, IP, 3, R + 500), Resolve::Ready(m, 3) if m == MAC));
        // The answer: reachable again, nothing more to send.
        assert!(n.learn(0, IP, MAC, R + 600).is_empty());
        assert!(n.poll(R + 2000).is_empty());
        assert_eq!((n.dropped, n.probes), (0, 1));
    }

    #[test]
    fn an_unanswered_probe_removes_the_entry() {
        let mut n: NeighTable<u32> = NeighTable::new();
        n.learn(0, IP, MAC, 0);
        n.resolve(0, IP, 1, 1);
        assert_eq!(n.poll(R), [(0, IP)]);
        assert!(n.poll(R + 999).is_empty());
        assert_eq!(n.poll(R + 1000), [(0, IP)]);
        assert_eq!(n.poll(R + 2000), [(0, IP)]);
        assert!(matches!(n.resolve(0, IP, 2, R + 2500), Resolve::Ready(..)), "kept while probing");
        assert!(n.poll(R + 3000).is_empty(), "third probe failed: gone");
        assert!(n.lookup(0, IP, R + 3000).is_none());
        assert_eq!(n.probes, 3);
        assert!(matches!(
            n.resolve(0, IP, 3, R + 3001),
            Resolve::Queued { send_arp: true }
        ));
    }

    #[test]
    fn without_probing_entries_in_use_expire() {
        let mut n: NeighTable<u32> = NeighTable::new().with_timing(10_000, false);
        n.learn(0, IP, MAC, 0);
        n.resolve(0, IP, 1, 1);
        assert!(n.lookup(0, IP, 10_000).is_none());
        assert!(n.poll(10_000).is_empty());
        assert!(matches!(
            n.resolve(0, IP, 2, 10_000),
            Resolve::Queued { send_arp: true }
        ));
        assert_eq!(n.probes, 0);
    }

    #[test]
    fn a_new_mac_replaces_a_probed_entry() {
        let mut n: NeighTable<u32> = NeighTable::new();
        n.learn(0, IP, MAC, 0);
        n.resolve(0, IP, 1, 1);
        n.poll(R);
        let other: Mac = [2, 0, 0, 0, 0, 7];
        n.learn(0, IP, other, R + 100);
        assert_eq!(n.lookup(0, IP, R + 101), Some(other));
    }
}
