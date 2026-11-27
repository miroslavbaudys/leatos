//! IPv4 forwarding plane: routing, neighbor resolution, connection
//! tracking with NAT (masquerade), a stateful firewall and per-packet
//! classification for the qdisc (CAKE).
//!
//! - [`wire`]: header access and incremental checksums
//! - [`route`]: longest-prefix-match table
//! - [`neigh`]: ARP cache with a tiny bounded pending queue
//! - [`nd`]: ARP / ND answers for the router's own addresses
//! - [`local`]: the next hop of the router's own packets on a link
//! - [`udp`]: the router's own UDP datagrams, built and parsed
//! - [`tcp`]: the IP layer of the router's own TCP segments
//! - [`echo`]: ICMP / ICMPv6 echo for the router itself
//! - [`mcast`]: IGMP / MLD reports and queries for the router's groups
//! - [`conntrack`]: connections, NAPT with endpoint-independent mapping
//! - [`forwarder`]: the per-packet pipeline → [`forwarder::Verdict`]
//! - [`frag`]: IP fragments forwarded through NAT without reassembly
//!
//! Design rules (see `docs/architecture.md`): `#![no_std]` + `alloc`,
//! sans-IO (frames and `now_ms` in, verdicts out), no allocation per
//! forwarded packet, every input bounds-checked (fuzz-tested).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod conntrack;
pub mod echo;
pub mod forwarder;
pub mod frag;
pub mod local;
pub mod mcast;
pub mod nd;
pub mod neigh;
pub mod route;
pub mod tcp;
pub mod udp;
pub mod wire;

/// Interface index, as assigned by [`forwarder::Forwarder::add_interface`].
pub type IfIndex = u8;
