//! Queue management for bufferbloat mitigation: the [`Qdisc`] interface,
//! [`fifo::BFifo`] (bounded tail-drop FIFO, the placeholder until CAKE),
//! and later CoDel, FQ-CoDel and CAKE (docs/bufferbloat-cake.md).
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

pub mod fifo;

/// What a qdisc needs to know about a packet.
pub trait Packet {
    /// Bytes counted against limits and shaping (wire length).
    fn len_bytes(&self) -> usize;
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
