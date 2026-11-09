//! Queue management for bufferbloat mitigation: the [`Qdisc`] interface,
//! [`fifo::BFifo`] (bounded tail-drop FIFO), [`codel::Codel`] (RFC 8289
//! AQM), [`fq_codel::FqCodel`] (RFC 8290 flow queueing), [`shaper::Shaper`],
//! and later CAKE (docs/bufferbloat-cake.md).
//!
//! The qdisc is the **only** place packets wait in rrouter. Egress is
//! pull-based: the datapath dequeues only when the driver has room, so a
//! full NIC ring makes packets wait here (where AQM can act), never in a
//! hidden driver queue.
//!
//! Design rules: `#![no_std]` + `alloc`, sans-IO (time is passed in as
//! nanoseconds), no allocation per packet, O(1) enqueue/dequeue.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod codel;
pub mod fifo;
pub mod fq_codel;
pub mod shaper;

/// What a qdisc needs to know about a packet.
pub trait Packet {
    /// Bytes counted against limits and shaping (wire length).
    fn len_bytes(&self) -> usize;
    /// Set ECN Congestion Experienced if the packet is ECN-capable (ECT).
    /// Returns `true` if marked; then the AQM keeps the packet instead of
    /// dropping it. The default (not ECN-capable) makes the AQM drop.
    fn mark_ce(&mut self) -> bool {
        false
    }
    /// Flow identity for flow queueing (FQ-CoDel): packets of one flow must
    /// get the same hash. Should be keyed, so outsiders cannot aim for
    /// collisions. Default: everything is one flow.
    fn flow_hash(&self) -> u32 {
        0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Dequeue<P> {
    Packet(P),
    /// Packets are queued but the shaper holds them until this time (ns).
    WaitUntil(u64),
    Empty,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub enqueued: u64,
    pub dequeued: u64,
    pub dropped: u64,
    /// Packets ECN-marked (CE) instead of dropped by the AQM.
    pub marked: u64,
    /// Drops/marks decided by the AQM (subset of dropped + marked; the rest
    /// are tail drops on overflow).
    pub aqm_actions: u64,
    pub backlog_packets: usize,
    pub backlog_bytes: usize,
}

pub trait Qdisc<P: Packet> {
    /// Queue a packet. On overflow the qdisc drops: the rejected packet is
    /// returned (it may be a different, older packet than `p`).
    fn enqueue(&mut self, p: P, now_ns: u64) -> Result<(), P>;
    fn dequeue(&mut self, now_ns: u64) -> Dequeue<P>;
    /// Room for at least one more packet? (lets local senders apply backpressure)
    fn has_room(&self) -> bool;
    fn stats(&self) -> Stats;
}
