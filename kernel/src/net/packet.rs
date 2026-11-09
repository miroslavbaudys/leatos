//! Packet buffers: a bounded, preallocated pool of fixed-size buffers.
//!
//! - **No allocation in the datapath:** all buffers are allocated at boot,
//!   and alloc/free only pop/push a preallocated free list.
//! - **Bounded memory:** when the pool is empty, allocation fails and the
//!   caller drops the packet. Queues (later: CAKE) cannot grow without
//!   limit; this is also the backstop for CAKE's memory limit.
//! - **Headroom:** every buffer reserves space in front of the data, so
//!   encapsulation (virtio-net header, VLAN, PPPoE) is a pointer move, not a copy.
//! - **[`PacketMeta`]** travels with every packet (docs/bufferbloat-cake.md §3.3).
//!
//! Thread context only.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

/// Buffer size: a full Ethernet frame + VLAN + PPPoE + virtio header + headroom.
pub const BUF_SIZE: usize = 2048;
/// Space reserved in front of the payload for headers added on egress.
pub const HEADROOM: usize = 128;

type Storage = Box<[u8; BUF_SIZE]>;

static POOL: Mutex<Vec<Storage>> = Mutex::new(Vec::new());
static CAPACITY: AtomicUsize = AtomicUsize::new(0);
static ALLOC_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// Per-packet metadata, filled in once during classification and used by the
/// qdisc (CAKE) on enqueue/dequeue.
#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)] // filled by classification (M4) and read by the qdisc (M6)
pub struct PacketMeta {
    /// Timestamp (timer ticks) when the packet entered a queue: CoDel sojourn time.
    pub enqueue_ts: u64,
    /// Hash of the pre-NAT 5-tuple (from conntrack).
    pub flow_hash: u32,
    /// Pre-NAT internal host hashes, for host isolation.
    pub src_host_hash: u16,
    pub dst_host_hash: u16,
    /// DiffServ code point (from the IP header).
    pub dscp: u8,
    /// DiffServ tin, mapped from DSCP by the qdisc.
    pub tin: u8,
    pub ecn_capable: bool,
    /// On-wire length after overhead compensation.
    pub wire_len: u32,
    /// Pure TCP ACK (for the ACK filter).
    pub is_pure_ack: bool,
    /// Interface the packet arrived on.
    pub ingress_if: u8,
}

/// Preallocate `count` buffers. Call once at boot.
pub fn init_pool(count: usize) {
    let mut pool = POOL.lock();
    assert!(pool.is_empty(), "packet pool initialised twice");
    pool.reserve_exact(count); // pushes on free never reallocate
    for _ in 0..count {
        pool.push(Box::new([0u8; BUF_SIZE]));
    }
    CAPACITY.store(count, Ordering::Relaxed);
}

/// (free, capacity, allocation failures)
pub fn pool_stats() -> (usize, usize, usize) {
    (
        POOL.lock().len(),
        CAPACITY.load(Ordering::Relaxed),
        ALLOC_FAILURES.load(Ordering::Relaxed),
    )
}

/// An owned packet buffer. Dropping it returns the storage to the pool.
pub struct PacketBuf {
    storage: Option<Storage>,
    start: usize,
    len: usize,
    #[allow(dead_code)] // see PacketMeta
    pub meta: PacketMeta,
}

impl PacketBuf {
    /// Take a buffer from the pool, empty with [`HEADROOM`] in front.
    pub fn alloc() -> Option<Self> {
        let Some(storage) = POOL.lock().pop() else {
            ALLOC_FAILURES.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        Some(Self {
            storage: Some(storage),
            start: HEADROOM,
            len: 0,
            meta: PacketMeta::default(),
        })
    }

    fn buf(&self) -> &[u8; BUF_SIZE] {
        self.storage.as_ref().expect("packet: storage taken")
    }

    fn buf_mut(&mut self) -> &mut [u8; BUF_SIZE] {
        self.storage.as_mut().expect("packet: storage taken")
    }

    /// The packet bytes.
    pub fn data(&self) -> &[u8] {
        &self.buf()[self.start..self.start + self.len]
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        let (s, l) = (self.start, self.len);
        &mut self.buf_mut()[s..s + l]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Resize the payload (keeping the start). Panics if it doesn't fit.
    pub fn set_len(&mut self, len: usize) {
        assert!(
            self.start + len <= BUF_SIZE,
            "packet: {len} bytes do not fit"
        );
        self.len = len;
    }

    /// Prepend `n` bytes (from headroom) and return them for writing a header.
    pub fn push_front(&mut self, n: usize) -> &mut [u8] {
        assert!(n <= self.start, "packet: headroom exhausted");
        self.start -= n;
        self.len += n;
        let s = self.start;
        &mut self.buf_mut()[s..s + n]
    }

    /// Strip `n` bytes from the front (header removal on ingress).
    pub fn pull_front(&mut self, n: usize) {
        assert!(n <= self.len, "packet: pull past end");
        self.start += n;
        self.len -= n;
    }

    /// The packet plus all tailroom after it (for in-place rewrites that may
    /// grow the packet, e.g. ICMP error generation).
    pub fn data_with_tailroom_mut(&mut self) -> &mut [u8] {
        let s = self.start;
        &mut self.buf_mut()[s..]
    }

    /// Receive area for DMA: the storage after [`HEADROOM`], so received
    /// packets keep headroom for re-encapsulation when forwarded. After the
    /// device fills it, call [`Self::set_rx_range`].
    pub fn rx_area_mut(&mut self) -> &mut [u8] {
        &mut self.buf_mut()[HEADROOM..]
    }

    /// Declare which bytes of the receive area hold the packet.
    pub fn set_rx_range(&mut self, offset: usize, len: usize) {
        assert!(
            HEADROOM + offset + len <= BUF_SIZE,
            "packet: rx range out of bounds"
        );
        self.start = HEADROOM + offset;
        self.len = len;
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        if let Some(s) = self.storage.take() {
            POOL.lock().push(s);
        }
    }
}

impl qdisc::Packet for PacketBuf {
    fn len_bytes(&self) -> usize {
        self.len
    }

    /// ECN: turn ECT(0)/ECT(1) into CE in an IPv4 frame (incremental header
    /// checksum update). Non-IPv4 and Not-ECT packets are left alone (the AQM
    /// drops them instead).
    fn mark_ce(&mut self) -> bool {
        use fwd::wire;
        let f = self.data_mut();
        if wire::ethertype(f) != Some(wire::ETHERTYPE_IPV4)
            || wire::Ipv4View::parse(f, wire::ETH_HDR).is_none()
        {
            return false;
        }
        let ip = wire::ETH_HDR;
        let old = wire::get16(f, ip);
        if f[ip + 1] & 0b11 == 0 {
            return false; // Not-ECT
        }
        f[ip + 1] |= 0b11; // CE
        let new = wire::get16(f, ip);
        let c = wire::csum_update16(wire::get16(f, ip + 10), old, new);
        wire::put16(f, ip + 10, c);
        true
    }
}
