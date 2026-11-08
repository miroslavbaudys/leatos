//! Queue management for bufferbloat mitigation: CoDel, FQ-CoDel, CAKE.
//!
//! Planned modules: `codel` (RFC 8289), `fq_codel` (RFC 8290), `cake`
//! (shaper, overhead compensation, COBALT, set-associative flow hashing,
//! host isolation, ingress mode, diffserv tins, ACK filter).
//! See `docs/bufferbloat-cake.md`.
//!
//! Design rules:
//! - `#![no_std]` + `alloc`, sans-IO: time is always passed in (`now`), so
//!   behaviour is deterministic and simulation-testable on the host.
//! - No allocation per packet; O(1) enqueue/dequeue.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
