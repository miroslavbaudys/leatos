//! Host tests: two stacks on a simulated link (`Net`), byte-exact checks;
//! `interop`: smoltcp's TCP as the peer.

mod interop;

use crate::wire::{self, ACK, FIN, Header, RST, SYN};
use crate::{Error, Socket, State, Tcp};
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub(crate) const A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
pub(crate) const B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

/// xorshift64*: deterministic link behaviour.
pub(crate) struct Rng(u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// True with probability `pct` %.
    pub fn pct(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

/// A segment on the wire: (deliver at, to side 0 = A / 1 = B, src, dst, bytes).
type InFlight = (u64, usize, IpAddr, IpAddr, Vec<u8>);

/// Link behaviour.
#[derive(Clone, Copy, Default)]
pub(crate) struct Link {
    pub delay_ms: u64,
    pub loss_pct: u64,
    /// Extra random delay up to this (reorders).
    pub jitter_ms: u64,
    pub dup_pct: u64,
}

/// Two stacks, A and B, on one link.
pub(crate) struct Net {
    pub now: u64,
    pub tcp: [Tcp; 2],
    pub link: Link,
    pub rng: Rng,
    wire: Vec<InFlight>,
    /// Every segment sent (side, header) for checks.
    pub log: Vec<(usize, Header, usize)>,
    /// Drop everything from this side (a peer gone).
    pub cut: [bool; 2],
}

impl Net {
    pub fn new(link: Link) -> Self {
        Self {
            now: 1000,
            tcp: [Tcp::new([1; 16]), Tcp::new([2; 16])],
            link,
            rng: Rng(0x1234_5678_9abc_def1),
            wire: Vec::new(),
            log: Vec::new(),
            cut: [false; 2],
        }
    }

    /// Inject a raw segment into side `to`.
    pub fn inject(&mut self, to: usize, src: IpAddr, dst: IpAddr, h: &Header, payload: &[u8]) {
        let mut b = vec![0u8; 1600];
        let n = wire::write(&mut b, src, dst, h, payload, &[]).unwrap();
        self.tcp[to].receive(self.now, src, dst, &b[..n]);
    }

    /// One millisecond: deliver what is due, poll both sides.
    pub fn step(&mut self) {
        self.step_then(|_| {});
    }

    /// As [`Self::step`], with `app` running between receiving and polling
    /// (as `svc` does: segments in, the services, segments out).
    pub fn step_then(&mut self, mut app: impl FnMut(&mut [Tcp; 2])) {
        self.now += 1;
        let now = self.now;
        let mut due = Vec::new();
        self.wire.retain(|s| {
            if s.0 <= now {
                due.push(s.clone());
                false
            } else {
                true
            }
        });
        for (_, to, src, dst, b) in due {
            self.tcp[to].receive(now, src, dst, &b);
        }
        app(&mut self.tcp);
        for side in 0..2 {
            let mut out = Vec::new();
            self.tcp[side].poll(now, |e| {
                let mut b = vec![0u8; e.len()];
                e.write(&mut b).unwrap();
                out.push((e.src.ip(), e.dst.ip(), b, e.header, e.payload_len()));
                true
            });
            for (src, dst, b, h, plen) in out {
                self.log.push((side, h, plen));
                if self.cut[side] || self.rng.pct(self.link.loss_pct) {
                    continue;
                }
                let jitter = if self.link.jitter_ms > 0 { self.rng.next() % self.link.jitter_ms } else { 0 };
                let at = now + self.link.delay_ms + jitter;
                if self.rng.pct(self.link.dup_pct) {
                    self.wire.push((at + 1, 1 - side, src, dst, b.clone()));
                }
                self.wire.push((at, 1 - side, src, dst, b));
            }
        }
    }

    pub fn run(&mut self, ms: u64) {
        for _ in 0..ms {
            self.step();
        }
    }

    /// Run until `f` holds (at most `limit` ms); false if it never did.
    pub fn until(&mut self, limit: u64, mut f: impl FnMut(&mut Self) -> bool) -> bool {
        for _ in 0..limit {
            if f(self) {
                return true;
            }
            self.step();
        }
        f(self)
    }
}

fn sa(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(ip, port)
}

/// A listening on B:80 and a client on A:40000 connected to it.
fn connected(link: Link, rx: usize, tx: usize) -> (Net, crate::Handle, crate::Handle) {
    let mut n = Net::new(link);
    let mut srv = Socket::new(rx, tx);
    srv.listen(80).unwrap();
    let hs = n.tcp[1].add(srv);
    let mut cli = Socket::new(rx, tx);
    cli.connect(sa(A, 40000), sa(B, 80)).unwrap();
    let hc = n.tcp[0].add(cli);
    assert!(n.until(20_000, |n| n.tcp[0].get(hc).state() == State::Established
        && n.tcp[1].get(hs).state() == State::Established));
    (n, hc, hs)
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed).wrapping_add((i >> 8) as u8)).collect()
}

/// Send `data` from (side, h) to (other side, k), reading as it comes;
/// returns what arrived.
fn transfer(n: &mut Net, from: (usize, crate::Handle), to: (usize, crate::Handle), data: &[u8], limit: u64) -> Vec<u8> {
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = [0u8; 3000];
    for _ in 0..limit {
        let s = n.tcp[from.0].get_mut(from.1);
        if sent < data.len() && s.can_send() {
            sent += s.send_slice(&data[sent..]).unwrap();
        }
        let r = n.tcp[to.0].get_mut(to.1);
        while r.can_recv() {
            let k = r.recv_slice(&mut buf).unwrap();
            got.extend_from_slice(&buf[..k]);
        }
        if got.len() == data.len() {
            break;
        }
        n.step();
    }
    got
}

#[test]
fn handshake_data_close() {
    let (mut n, hc, hs) = connected(Link { delay_ms: 5, ..Default::default() }, 4096, 4096);
    assert_eq!(n.tcp[1].get(hs).remote_endpoint(), Some(sa(A, 40000)));
    let got = transfer(&mut n, (0, hc), (1, hs), b"GET / HTTP/1.0\r\n\r\n", 1000);
    assert_eq!(got, b"GET / HTTP/1.0\r\n\r\n");
    let got = transfer(&mut n, (1, hs), (0, hc), b"HTTP/1.0 200 OK\r\n\r\nhello", 1000);
    assert_eq!(got, b"HTTP/1.0 200 OK\r\n\r\nhello");
    n.tcp[1].get_mut(hs).close();
    assert!(n.until(1000, |n| n.tcp[0].get(hc).state() == State::CloseWait));
    assert_eq!(n.tcp[0].get_mut(hc).recv_slice(&mut [0; 8]), Err(Error::Finished));
    n.tcp[0].get_mut(hc).close();
    assert!(n.until(1000, |n| n.tcp[0].get(hc).state() == State::Closed));
    assert_eq!(n.tcp[1].get(hs).state(), State::TimeWait);
    assert!(n.until(crate::socket::TIME_WAIT_MS + 10, |n| n.tcp[1].get(hs).state() == State::Closed));
    // The server listens again.
    n.tcp[1].get_mut(hs).listen(80).unwrap();
}

#[test]
fn mss_from_the_link() {
    let mut n = Net::new(Link::default());
    n.tcp[0].set_mtu(1492);
    let a6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
    let b6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    let mut srv = Socket::new(4096, 4096);
    srv.listen(80).unwrap();
    n.tcp[1].add(srv);
    let mut cli = Socket::new(4096, 4096);
    cli.connect(sa(a6, 40000), sa(b6, 80)).unwrap();
    let hc = n.tcp[0].add(cli);
    assert!(n.until(100, |n| n.tcp[0].get(hc).state() == State::Established));
    let syn = n.log.iter().find(|(s, h, _)| *s == 0 && h.flags == SYN).unwrap();
    assert_eq!(syn.1.mss, Some(1492 - 60));
    let synack = n.log.iter().find(|(s, h, _)| *s == 1 && h.flags == SYN | ACK).unwrap();
    assert_eq!(synack.1.mss, Some(1500 - 60));
}

#[test]
fn closed_port_gets_rst() {
    let mut n = Net::new(Link::default());
    let mut cli = Socket::new(1024, 1024);
    cli.connect(sa(A, 40000), sa(B, 22)).unwrap();
    let hc = n.tcp[0].add(cli);
    n.run(20);
    assert_eq!(n.tcp[0].get(hc).state(), State::Closed);
    assert_eq!(n.tcp[0].stats().refused, 1);
    assert_eq!(n.tcp[1].stats().no_socket, 1);
    let rst = n.log.iter().find(|(s, _, _)| *s == 1).unwrap().1;
    assert_eq!(rst.flags, RST | ACK);
}

#[test]
fn closed_port_silent_when_switched_off() {
    let mut n = Net::new(Link::default());
    n.tcp[1].set_rst_closed(false);
    let mut cli = Socket::new(1024, 1024);
    cli.connect(sa(A, 40000), sa(B, 22)).unwrap();
    let hc = n.tcp[0].add(cli);
    n.run(20);
    assert_eq!(n.tcp[0].get(hc).state(), State::SynSent);
    assert_eq!(n.tcp[1].stats().no_socket, 1);
    assert!(n.log.iter().all(|(s, _, _)| *s == 0));
}

#[test]
fn no_rst_for_a_rst() {
    let mut n = Net::new(Link::default());
    let h = Header { sport: 1234, dport: 80, seq: 5, ack: 0, flags: RST, window: 0, mss: None };
    n.inject(1, A, B, &h, &[]);
    n.run(5);
    assert!(n.log.is_empty());
}

#[test]
fn busy_listener_refuses_with_rst() {
    let (mut n, _hc, _hs) = connected(Link::default(), 1024, 1024);
    // A second client: nobody listens any more.
    let mut c2 = Socket::new(1024, 1024);
    c2.connect(sa(A, 40001), sa(B, 80)).unwrap();
    let h2 = n.tcp[0].add(c2);
    n.run(20);
    assert_eq!(n.tcp[0].get(h2).state(), State::Closed);
}

#[test]
fn bad_checksum_dropped() {
    let mut n = Net::new(Link::default());
    let mut srv = Socket::new(1024, 1024);
    srv.listen(80).unwrap();
    let hs = n.tcp[1].add(srv);
    let h = Header { sport: 1234, dport: 80, seq: 5, ack: 0, flags: SYN, window: 1000, mss: None };
    let mut b = vec![0u8; 64];
    let len = wire::write(&mut b, A, B, &h, &[], &[]).unwrap();
    b[4] ^= 1;
    n.tcp[1].receive(n.now, A, B, &b[..len]);
    assert_eq!(n.tcp[1].stats().bad_checksum, 1);
    assert_eq!(n.tcp[1].get(hs).state(), State::Listen);
}

#[test]
fn bulk_upload_with_loss_reordering_duplicates() {
    // The kernel upload: client → server into a 64 KiB receive ring.
    let link = Link { delay_ms: 3, loss_pct: 5, jitter_ms: 6, dup_pct: 2 };
    let (mut n, hc, hs) = connected(link, 64 * 1024, 16 * 1024);
    let data = pattern(2 << 20, 7);
    let got = transfer(&mut n, (0, hc), (1, hs), &data, 600_000);
    assert_eq!(got.len(), data.len());
    assert!(got == data, "data corrupted");
    let s = n.tcp[0].stats();
    assert!(s.retransmits + s.fast_retransmits > 0, "loss must have happened: {s:?}");
}

#[test]
fn bulk_download_with_loss() {
    let link = Link { delay_ms: 10, loss_pct: 5, jitter_ms: 4, dup_pct: 1 };
    let (mut n, hc, hs) = connected(link, 16 * 1024, 16 * 1024);
    let data = pattern(512 * 1024, 3);
    let got = transfer(&mut n, (1, hs), (0, hc), &data, 600_000);
    assert!(got == data);
}

#[test]
fn ipv6_transfer() {
    let mut n = Net::new(Link { delay_ms: 2, loss_pct: 2, ..Default::default() });
    let a6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
    let b6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let mut srv = Socket::new(8192, 8192);
    srv.listen(53).unwrap();
    let hs = n.tcp[1].add(srv);
    let mut cli = Socket::new(8192, 8192);
    cli.connect(sa(a6, 61000), sa(b6, 53)).unwrap();
    let hc = n.tcp[0].add(cli);
    assert!(n.until(10_000, |n| n.tcp[1].get(hs).state() == State::Established));
    let data = pattern(100_000, 9);
    assert!(transfer(&mut n, (0, hc), (1, hs), &data, 200_000) == data);
}

#[test]
fn zero_window_and_probes() {
    let (mut n, hc, hs) = connected(Link { delay_ms: 2, ..Default::default() }, 2048, 8192);
    let data = pattern(8192, 1);
    let c = n.tcp[0].get_mut(hc);
    assert_eq!(c.send_slice(&data).unwrap(), 8192);
    // The server does not read: its window closes, the client probes.
    n.run(5000);
    assert_eq!(n.tcp[1].get(hs).recv_queue(), 2048);
    assert!(n.tcp[0].stats().window_probes > 0);
    assert_eq!(n.tcp[0].get(hc).state(), State::Established);
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    assert!(n.until(60_000, |n| {
        let s = n.tcp[1].get_mut(hs);
        while s.can_recv() {
            let k = s.recv_slice(&mut buf).unwrap();
            got.extend_from_slice(&buf[..k]);
        }
        got.len() == data.len()
    }));
    assert!(got == data);
}

#[test]
fn zero_window_with_timeout_survives_live_peer() {
    let (mut n, hc, hs) = connected(Link { delay_ms: 2, ..Default::default() }, 1024, 4096);
    n.tcp[0].get_mut(hc).set_timeout(Some(2000));
    n.tcp[0].get_mut(hc).send_slice(&pattern(4096, 2)).unwrap();
    n.run(20_000);
    // Probes are answered: the peer lives, the connection stays.
    assert_eq!(n.tcp[0].get(hc).state(), State::Established);
    assert_eq!(n.tcp[1].get(hs).recv_queue(), 1024);
}

/// The client's current (seq, ack) as the server sees them: from the last
/// segment the client sent.
fn last_from(n: &Net, side: usize) -> Header {
    n.log.iter().rev().find(|(s, _, _)| *s == side).unwrap().1
}

#[test]
fn rfc5961_rst_in_window_gets_challenge_ack() {
    let (mut n, hc, hs) = connected(Link::default(), 4096, 4096);
    n.run(50);
    let c = last_from(&n, 0);
    let exact = c.seq;
    // In window but not exact: challenge ACK, connection stays.
    let h = Header { sport: 40000, dport: 80, seq: exact.wrapping_add(100), ack: 0, flags: RST, window: 0, mss: None };
    n.inject(1, A, B, &h, &[]);
    n.run(5);
    assert_eq!(n.tcp[1].get(hs).state(), State::Established);
    assert_eq!(n.tcp[1].stats().challenge_acks, 1);
    // Outside the window: silently ignored.
    let h = Header { seq: exact.wrapping_add(1_000_000), ..h };
    n.inject(1, A, B, &h, &[]);
    assert_eq!(n.tcp[1].get(hs).state(), State::Established);
    // Exact: the connection ends (negative control).
    let h = Header { seq: exact, ..h };
    n.inject(1, A, B, &h, &[]);
    assert_eq!(n.tcp[1].get(hs).state(), State::Closed);
    let _ = hc;
}

#[test]
fn rfc5961_syn_in_established_gets_challenge_ack() {
    let (mut n, _hc, hs) = connected(Link::default(), 4096, 4096);
    n.run(50);
    let c = last_from(&n, 0);
    let h = Header { sport: 40000, dport: 80, seq: c.seq, ack: 0, flags: SYN, window: 1000, mss: None };
    n.inject(1, A, B, &h, &[]);
    assert_eq!(n.tcp[1].get(hs).state(), State::Established);
    assert_eq!(n.tcp[1].stats().challenge_acks, 1);
}

#[test]
fn challenge_acks_rate_limited() {
    let (mut n, _hc, hs) = connected(Link::default(), 4096, 4096);
    n.run(50);
    let c = last_from(&n, 0);
    for i in 0..100 {
        let h = Header { sport: 40000, dport: 80, seq: c.seq.wrapping_add(10 + i), ack: 0, flags: RST, window: 0, mss: None };
        n.inject(1, A, B, &h, &[]);
    }
    assert_eq!(n.tcp[1].stats().challenge_acks, 10);
    assert_eq!(n.tcp[1].get(hs).state(), State::Established);
}

#[test]
fn ack_for_unsent_data_dropped() {
    let (mut n, _hc, hs) = connected(Link::default(), 4096, 4096);
    n.run(50);
    let c = last_from(&n, 0);
    let s = last_from(&n, 1);
    let h = Header {
        sport: 40000,
        dport: 80,
        seq: c.seq,
        ack: s.seq.wrapping_add(5000),
        flags: ACK,
        window: 1000,
        mss: None,
    };
    n.inject(1, A, B, &h, b"evil");
    assert_eq!(n.tcp[1].get(hs).recv_queue(), 0, "data with a bad ACK must not be taken");
}

#[test]
fn data_outside_window_ignored() {
    let (mut n, _hc, hs) = connected(Link::default(), 4096, 4096);
    n.run(50);
    let c = last_from(&n, 0);
    let h = Header { sport: 40000, dport: 80, seq: c.seq.wrapping_add(100_000), ack: c.ack, flags: ACK, window: 1000, mss: None };
    n.inject(1, A, B, &h, b"blind");
    assert_eq!(n.tcp[1].get(hs).recv_queue(), 0);
}

#[test]
fn out_of_order_reassembled() {
    let (mut n, _hc, hs) = connected(Link::default(), 4096, 4096);
    n.run(50);
    let c = last_from(&n, 0);
    let base = c.seq;
    let mk = |off: u32| Header { sport: 40000, dport: 80, seq: base.wrapping_add(off), ack: c.ack, flags: ACK, window: 1000, mss: None };
    n.inject(1, A, B, &mk(20), b"cccccccccc");
    n.inject(1, A, B, &mk(10), b"bbbbbbbbbb");
    assert_eq!(n.tcp[1].get(hs).recv_queue(), 0);
    n.inject(1, A, B, &mk(0), b"aaaaaaaaaa");
    let mut buf = [0u8; 64];
    let k = n.tcp[1].get_mut(hs).recv_slice(&mut buf).unwrap();
    assert_eq!(&buf[..k], b"aaaaaaaaaabbbbbbbbbbcccccccccc");
}

#[test]
fn peer_gone_times_out() {
    let (mut n, hc, _hs) = connected(Link { delay_ms: 2, ..Default::default() }, 4096, 4096);
    n.tcp[0].get_mut(hc).set_timeout(Some(10_000));
    n.cut[1] = true;
    n.tcp[0].get_mut(hc).send_slice(b"anyone?").unwrap();
    assert!(n.until(12_000, |n| n.tcp[0].get(hc).state() == State::Closed));
    assert!(n.now < 1000 + 12_000);
    assert_eq!(n.tcp[0].stats().timeouts, 1);
}

#[test]
fn retry_limit_without_timeout() {
    let (mut n, hc, _hs) = connected(Link { delay_ms: 2, ..Default::default() }, 4096, 4096);
    n.cut[1] = true;
    n.tcp[0].get_mut(hc).send_slice(b"anyone?").unwrap();
    assert!(n.until(20 * 60_000, |n| n.tcp[0].get(hc).state() == State::Closed));
}

#[test]
fn abort_sends_rst_even_when_listening_again() {
    let (mut n, hc, hs) = connected(Link::default(), 4096, 4096);
    let s = n.tcp[1].get_mut(hs);
    s.abort();
    s.listen(80).unwrap();
    assert!(n.until(100, |n| n.tcp[0].get(hc).state() == State::Closed));
    assert_eq!(n.tcp[1].get(hs).state(), State::Listen);
    assert_eq!(n.tcp[0].stats().resets_received, 1);
}

#[test]
fn simultaneous_close() {
    let (mut n, hc, hs) = connected(Link { delay_ms: 5, ..Default::default() }, 4096, 4096);
    n.tcp[0].get_mut(hc).close();
    n.tcp[1].get_mut(hs).close();
    assert!(n.until(1000, |n| {
        !n.tcp[0].get(hc).is_open() && !n.tcp[1].get(hs).is_open()
    }));
}

#[test]
fn close_with_queued_data_delivers_all() {
    let link = Link { delay_ms: 3, loss_pct: 10, ..Default::default() };
    let (mut n, hc, hs) = connected(link, 4096, 16 * 1024);
    let data = pattern(16 * 1024, 5);
    assert_eq!(n.tcp[1].get_mut(hs).send_slice(&data).unwrap(), data.len());
    n.tcp[1].get_mut(hs).close();
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    assert!(n.until(120_000, |n| {
        let s = n.tcp[0].get_mut(hc);
        while s.can_recv() {
            let k = s.recv_slice(&mut buf).unwrap();
            got.extend_from_slice(&buf[..k]);
        }
        s.state() == State::CloseWait && got.len() == data.len()
    }));
    assert!(got == data);
    n.tcp[0].get_mut(hc).close();
    assert!(n.until(60_000, |n| n.tcp[0].get(hc).state() == State::Closed));
}

#[test]
fn syn_received_gives_up_and_listens_again() {
    let mut n = Net::new(Link::default());
    let mut srv = Socket::new(1024, 1024);
    srv.listen(80).unwrap();
    let hs = n.tcp[1].add(srv);
    // A SYN from nowhere (spoofed): the SYN-ACK goes unanswered.
    let h = Header { sport: 5555, dport: 80, seq: 77, ack: 0, flags: SYN, window: 1000, mss: Some(1460) };
    n.inject(1, A, B, &h, &[]);
    assert_eq!(n.tcp[1].get(hs).state(), State::SynReceived);
    n.cut[1] = true;
    assert!(n.until(10 * 60_000, |n| n.tcp[1].get(hs).state() == State::Listen));
}

#[test]
fn syn_received_retransmitted_syn_gets_syn_ack() {
    let mut n = Net::new(Link::default());
    let mut srv = Socket::new(1024, 1024);
    srv.listen(80).unwrap();
    n.tcp[1].add(srv);
    let h = Header { sport: 5555, dport: 80, seq: 77, ack: 0, flags: SYN, window: 1000, mss: Some(1460) };
    // The SYN-ACKs reach nobody (A has no socket and would RST them).
    n.cut[1] = true;
    n.inject(1, A, B, &h, &[]);
    n.run(2);
    n.inject(1, A, B, &h, &[]);
    n.run(2);
    let synacks = n.log.iter().filter(|(s, h, _)| *s == 1 && h.flags == SYN | ACK).count();
    assert_eq!(synacks, 2);
}

#[test]
fn isn_depends_on_tuple_and_time() {
    let mut n = Net::new(Link::default());
    let mut srv = Socket::new(1024, 1024);
    srv.listen(80).unwrap();
    n.tcp[1].add(srv);
    let mut isns = Vec::new();
    for port in [5000u16, 5001] {
        let h = Header { sport: port, dport: 80, seq: 1, ack: 0, flags: SYN, window: 1000, mss: None };
        n.inject(1, A, B, &h, &[]);
        n.run(2);
        isns.push(last_from(&n, 1).seq);
        // Free the listener for the next SYN.
        let rst = Header { sport: port, dport: 80, seq: 2, ack: 0, flags: RST, window: 0, mss: None };
        n.inject(1, A, B, &rst, &[]);
    }
    assert_ne!(isns[0], isns[1]);
}

#[test]
fn fin_in_syn_received_path() {
    // Data and FIN with the handshake's last ACK.
    let mut n = Net::new(Link::default());
    let mut srv = Socket::new(1024, 1024);
    srv.listen(80).unwrap();
    let hs = n.tcp[1].add(srv);
    let h = Header { sport: 5555, dport: 80, seq: 100, ack: 0, flags: SYN, window: 1000, mss: None };
    n.inject(1, A, B, &h, &[]);
    n.run(2);
    let sa_ = last_from(&n, 1);
    let h = Header { sport: 5555, dport: 80, seq: 101, ack: sa_.seq.wrapping_add(1), flags: ACK | FIN, window: 1000, mss: None };
    n.inject(1, A, B, &h, b"q");
    let s = n.tcp[1].get_mut(hs);
    assert_eq!(s.state(), State::CloseWait);
    let mut b = [0u8; 4];
    assert_eq!(s.recv_slice(&mut b), Ok(1));
}

#[test]
fn ring_wraps() {
    let mut r = crate::ring::Ring::new(8);
    assert_eq!(r.push(b"abcdef"), 6);
    r.consume(4);
    assert_eq!(r.push(b"ghijklmn"), 6);
    let (a, b) = r.slices(0, 8);
    assert_eq!([a, b].concat(), b"efghijkl");
    let mut out = [0u8; 8];
    assert_eq!(r.pop(&mut out), 8);
    assert_eq!(&out, b"efghijkl");
}

#[test]
fn deadline_reflects_work() {
    let mut n = Net::new(Link::default());
    assert_eq!(n.tcp[0].next_deadline(n.now), None);
    let mut cli = Socket::new(1024, 1024);
    cli.connect(sa(A, 40000), sa(B, 80)).unwrap();
    n.tcp[0].add(cli);
    assert!(n.tcp[0].next_deadline(n.now).is_some_and(|t| t <= n.now));
    n.step();
    // SYN sent: the retransmission timer.
    let d = n.tcp[0].next_deadline(n.now).unwrap();
    assert!(d > n.now && d <= n.now + crate::socket::RTO_INIT_MS);
}


#[test]
fn window_update_restarts_the_sender_at_once() {
    let (mut n, hc, hs) = connected(Link { delay_ms: 2, ..Default::default() }, 4096, 16 * 1024);
    let data = pattern(16 * 1024, 4);
    n.tcp[0].get_mut(hc).send_slice(&data).unwrap();
    // The server reads nothing: its 4 KiB fill, the client stops.
    n.run(200);
    assert_eq!(n.tcp[1].get(hs).recv_queue(), 4096);
    let probes = n.tcp[0].stats().window_probes;
    // Now it reads everything as it comes: the window updates keep the
    // data flowing well before a persist timer (1 s) would.
    let start = n.now;
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    assert!(n.until(10_000, |n| {
        let s = n.tcp[1].get_mut(hs);
        while s.can_recv() {
            let k = s.recv_slice(&mut buf).unwrap();
            got.extend_from_slice(&buf[..k]);
        }
        got.len() == data.len()
    }));
    assert!(got == data);
    assert!(n.now - start < 200, "took {} ms", n.now - start);
    assert_eq!(n.tcp[0].stats().window_probes, probes);
}

#[test]
fn delayed_ack_waits_then_acks() {
    let (mut n, hc, hs) = connected(Link::default(), 4096, 4096);
    n.run(50);
    let before = n.log.iter().filter(|(s, _, _)| *s == 1).count();
    n.tcp[0].get_mut(hc).send_slice(b"x").unwrap();
    n.run(2);
    assert_eq!(n.tcp[1].get(hs).recv_queue(), 1);
    // Not yet acknowledged (delayed), then within ACK_DELAY_MS.
    assert_eq!(n.log.iter().filter(|(s, _, _)| *s == 1).count(), before);
    n.run(crate::socket::ACK_DELAY_MS + 2);
    assert_eq!(n.log.iter().filter(|(s, _, _)| *s == 1).count(), before + 1);
}

/// The server (B) closes first and, like mgmt, listens again as soon as
/// the socket is no longer open: in TIME-WAIT, before the ACK of the
/// client's FIN went out. Returns the client's FIN sequence number.
fn close_and_relisten(n: &mut Net, hc: crate::Handle, hs: crate::Handle) -> u32 {
    n.tcp[1].get_mut(hs).close();
    assert!(n.until(1000, |n| n.tcp[0].get(hc).state() == State::CloseWait));
    n.tcp[0].get_mut(hc).close();
    for _ in 0..1000 {
        n.step_then(|t| {
            let s = t[1].get_mut(hs);
            if !s.is_open() && s.state() != State::Listen {
                s.listen(80).unwrap();
            }
        });
        if n.tcp[0].get(hc).state() == State::Closed {
            break;
        }
    }
    assert_eq!(n.tcp[1].get(hs).state(), State::Listen);
    n.log.iter().rev().find(|(side, h, _)| *side == 0 && h.flags & FIN != 0).unwrap().1.seq
}

#[test]
fn time_wait_handed_off_on_listen_still_acks_the_fin() {
    let (mut n, hc, hs) = connected(Link { delay_ms: 5, ..Default::default() }, 4096, 4096);
    let fin = close_and_relisten(&mut n, hc, hs);
    // The client closed cleanly: its FIN acknowledged, no RST either way.
    assert_eq!(n.tcp[0].get(hc).state(), State::Closed);
    assert_eq!(n.tcp[0].stats().resets_received, 0);
    assert_eq!(n.tcp[1].stats().resets_sent, 0);
    assert_eq!(n.tcp[1].stats().no_socket, 0);
    let ack = n.log.iter().rev().find(|(side, h, _)| *side == 1 && h.flags & FIN == 0).unwrap().1;
    assert_eq!(ack.ack, fin.wrapping_add(1));
    assert_eq!(n.tcp[1].time_waits(), 1);
}

#[test]
fn repeated_fin_answered_from_the_time_wait_table() {
    let (mut n, hc, hs) = connected(Link { delay_ms: 5, ..Default::default() }, 4096, 4096);
    let fin = close_and_relisten(&mut n, hc, hs);
    let before = n.log.len();
    let h = Header { sport: 40000, dport: 80, seq: fin, ack: 0, flags: FIN | ACK, window: 4096, mss: None };
    n.inject(1, A, B, &h, &[]);
    n.run(2);
    let acks: Vec<_> = n.log[before..].iter().filter(|(side, _, _)| *side == 1).collect();
    assert_eq!(acks.len(), 1, "{acks:?}");
    assert_eq!(acks[0].1.flags, ACK);
    assert_eq!(acks[0].1.ack, fin.wrapping_add(1));
    assert_eq!(n.tcp[1].stats().time_wait, 1);
    assert_eq!(n.tcp[1].stats().resets_sent, 0);
    // RFC 1337: a RST does not end it, and gets no answer.
    let before = n.log.len();
    let r = Header { flags: RST, ..h };
    n.inject(1, A, B, &r, &[]);
    n.run(2);
    assert!(n.log[before..].iter().all(|(side, _, _)| *side == 0));
    assert_eq!(n.tcp[1].time_waits(), 1);
}

#[test]
fn new_syn_reuses_a_pair_in_time_wait() {
    let (mut n, hc, hs) = connected(Link { delay_ms: 5, ..Default::default() }, 4096, 4096);
    close_and_relisten(&mut n, hc, hs);
    n.run(100);
    n.tcp[0].get_mut(hc).connect(sa(A, 40000), sa(B, 80)).unwrap();
    assert!(n.until(2000, |n| n.tcp[0].get(hc).state() == State::Established
        && n.tcp[1].get(hs).state() == State::Established));
    assert_eq!(n.tcp[1].time_waits(), 0);
}

#[test]
fn time_wait_table_expires() {
    let (mut n, hc, hs) = connected(Link { delay_ms: 5, ..Default::default() }, 4096, 4096);
    let fin = close_and_relisten(&mut n, hc, hs);
    n.run(crate::socket::TIME_WAIT_MS + 10);
    let h = Header { sport: 40000, dport: 80, seq: fin, ack: 0, flags: FIN | ACK, window: 4096, mss: None };
    n.inject(1, A, B, &h, &[]);
    n.run(2);
    assert_eq!(n.tcp[1].time_waits(), 0);
    assert_eq!(n.tcp[1].stats().resets_sent, 1);
}
