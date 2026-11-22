//! IPv4 forwarding plane: routing, neighbor resolution, connection
//! tracking with NAT (masquerade), a stateful firewall and per-packet
//! classification for the qdisc (CAKE).
//!
//! - [`wire`]: header access and incremental checksums
//! - [`route`]: longest-prefix-match table
//! - [`neigh`]: ARP cache with a tiny bounded pending queue
//! - [`nd`]: ARP / ND answers for the router's own addresses
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
pub mod forwarder;
pub mod frag;
pub mod nd;
pub mod neigh;
pub mod route;
pub mod wire;

/// Interface index, as assigned by [`forwarder::Forwarder::add_interface`].
pub type IfIndex = u8;
