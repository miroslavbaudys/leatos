//! Forwarding plane: LPM routing table, neighbor cache, conntrack, NAPT, firewall, MSS clamping.
//!
//! Planned modules: `lpm`, `neigh` (ARP/NDP cache + pending-packet queue),
//! `conntrack`, `nat`, `filter`, `pipeline` (per-packet run-to-completion).
//! See `docs/architecture.md#forwarding-plane`.
//!
//! Design rules (see `docs/architecture.md`):
//! - `#![no_std]` + `alloc`: the same code runs in the bare-metal kernel and
//!   in host tests.
//! - Sans-IO: no sockets, no clocks, no async runtime. Callers feed in bytes
//!   and the current time, and get back bytes to send and events.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
