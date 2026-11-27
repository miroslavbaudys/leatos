//! Interop: our TCP (A, 10.0.0.2) against smoltcp's (B, 10.0.0.1) on a
//! lossy simulated link, both directions, both as client and server.

use super::{A, B, Rng, pattern};
use crate::{Socket, State, Tcp};
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

#[derive(Default)]
struct Dev {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}

impl Device for Dev {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1500;
        c
    }
}

/// An IPv4 packet around a TCP segment.
fn ip4(src: Ipv4Addr, dst: Ipv4Addr, seg: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20 + seg.len()];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&((20 + seg.len()) as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let mut acc: u32 = 0;
    for w in p[..20].chunks(2) {
        acc += u32::from(u16::from_be_bytes([w[0], w[1]]));
    }
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    p[10..12].copy_from_slice(&(!(acc as u16)).to_be_bytes());
    p[20..].copy_from_slice(seg);
    p
}

fn v4(a: IpAddr) -> Ipv4Addr {
    match a {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => unreachable!(),
    }
}

struct Pair {
    now: u64,
    ours: Tcp,
    dev: Dev,
    iface: Interface,
    sockets: SocketSet<'static>,
    rng: Rng,
    loss: u64,
    /// In flight toward us / toward smoltcp: (deliver at, packet).
    to_us: Vec<(u64, Vec<u8>)>,
    to_them: Vec<(u64, Vec<u8>)>,
}

impl Pair {
    fn new(loss: u64) -> Self {
        let mut dev = Dev::default();
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = 42;
        let mut iface = Interface::new(cfg, &mut dev, Instant::from_millis(0));
        iface.update_ip_addrs(|a| {
            a.push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24)).unwrap();
        });
        Self {
            now: 1000,
            ours: Tcp::new([9; 16]),
            dev,
            iface,
            sockets: SocketSet::new(Vec::new()),
            rng: Rng(0xfeed_beef_1234_5678),
            loss,
            to_us: Vec::new(),
            to_them: Vec::new(),
        }
    }

    fn step(&mut self) {
        self.now += 1;
        let now = self.now;
        let (due, rest): (Vec<_>, Vec<_>) = self.to_us.drain(..).partition(|p| p.0 <= now);
        self.to_us = rest;
        for (_, p) in due {
            let ihl = usize::from(p[0] & 15) * 4;
            let src = IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19]));
            self.ours.receive(now, src, dst, &p[ihl..]);
        }
        let (due, rest): (Vec<_>, Vec<_>) = self.to_them.drain(..).partition(|p| p.0 <= now);
        self.to_them = rest;
        self.dev.rx.extend(due.into_iter().map(|p| p.1));
        self.iface.poll(Instant::from_millis(now as i64), &mut self.dev, &mut self.sockets);
        while let Some(p) = self.dev.tx.pop_front() {
            if !self.rng.pct(self.loss) {
                let d = 2 + self.rng.next() % 3;
                self.to_us.push((now + d, p));
            }
        }
        let mut out = Vec::new();
        self.ours.poll(now, |e| {
            let mut b = vec![0u8; e.len()];
            e.write(&mut b).unwrap();
            out.push(ip4(v4(e.src.ip()), v4(e.dst.ip()), &b));
            true
        });
        for p in out {
            if !self.rng.pct(self.loss) {
                let d = 2 + self.rng.next() % 3;
                self.to_them.push((now + d, p));
            }
        }
    }

    fn theirs(&mut self, h: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(h)
    }
}

fn smol_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 32 * 1024]), tcp::SocketBuffer::new(vec![0; 32 * 1024]))
}

/// Move `up` from us to them and `down` back, reading on both sides.
fn exchange(p: &mut Pair, ours: crate::Handle, theirs: SocketHandle, up: &[u8], down: &[u8]) {
    let (mut sent_up, mut sent_down) = (0, 0);
    let (mut got_up, mut got_down) = (Vec::new(), Vec::new());
    let mut buf = [0u8; 4096];
    for _ in 0..600_000 {
        let s = p.ours.get_mut(ours);
        if sent_up < up.len() && s.can_send() {
            sent_up += s.send_slice(&up[sent_up..]).unwrap();
        }
        while s.can_recv() {
            let k = s.recv_slice(&mut buf).unwrap();
            got_down.extend_from_slice(&buf[..k]);
        }
        let t = p.theirs(theirs);
        if sent_down < down.len() && t.can_send() {
            sent_down += t.send_slice(&down[sent_down..]).unwrap();
        }
        while t.can_recv() {
            let k = t.recv_slice(&mut buf).unwrap();
            got_up.extend_from_slice(&buf[..k]);
        }
        if got_up.len() == up.len() && got_down.len() == down.len() {
            break;
        }
        p.step();
    }
    assert!(got_up == up, "upstream: {} of {} bytes", got_up.len(), up.len());
    assert!(got_down == down, "downstream: {} of {} bytes", got_down.len(), down.len());
}

#[test]
fn our_client_smoltcp_server() {
    let mut p = Pair::new(3);
    let mut t = smol_socket();
    t.listen(80).unwrap();
    let th = p.sockets.add(t);
    let mut s = Socket::new(16 * 1024, 16 * 1024);
    s.connect(SocketAddr::new(A, 61000), SocketAddr::new(B, 80)).unwrap();
    let h = p.ours.add(s);
    for _ in 0..20_000 {
        if p.ours.get(h).state() == State::Established {
            break;
        }
        p.step();
    }
    assert_eq!(p.ours.get(h).state(), State::Established);
    exchange(&mut p, h, th, &pattern(1 << 20, 1), &pattern(256 * 1024, 2));
    p.ours.get_mut(h).close();
    p.theirs(th).close();
    for _ in 0..120_000 {
        if !p.ours.get(h).is_open() && !p.theirs(th).is_open() {
            break;
        }
        p.step();
    }
    assert!(!p.ours.get(h).is_open());
    assert!(!p.theirs(th).is_open());
}

#[test]
fn smoltcp_client_our_server() {
    let mut p = Pair::new(3);
    let mut s = Socket::new(64 * 1024, 16 * 1024);
    s.listen(80).unwrap();
    let h = p.ours.add(s);
    let mut t = smol_socket();
    t.connect(p.iface.context(), (IpAddress::v4(10, 0, 0, 2), 80), 50000).unwrap();
    let th = p.sockets.add(t);
    for _ in 0..20_000 {
        if p.ours.get(h).state() == State::Established {
            break;
        }
        p.step();
    }
    assert_eq!(p.ours.get(h).state(), State::Established);
    exchange(&mut p, h, th, &pattern(300 * 1024, 3), &pattern(2 << 20, 4));
    // The client closes first (an HTTP client after its answer).
    p.theirs(th).close();
    for _ in 0..60_000 {
        if p.ours.get(h).state() == State::CloseWait {
            break;
        }
        p.step();
    }
    assert_eq!(p.ours.get(h).state(), State::CloseWait);
    p.ours.get_mut(h).close();
    for _ in 0..60_000 {
        if p.ours.get(h).state() == State::Closed {
            break;
        }
        p.step();
    }
    assert_eq!(p.ours.get(h).state(), State::Closed);
}

#[test]
fn smoltcp_aborts_our_server_sees_it() {
    let mut p = Pair::new(0);
    let mut s = Socket::new(4096, 4096);
    s.listen(80).unwrap();
    let h = p.ours.add(s);
    let mut t = smol_socket();
    t.connect(p.iface.context(), (IpAddress::v4(10, 0, 0, 2), 80), 50001).unwrap();
    let th = p.sockets.add(t);
    for _ in 0..1000 {
        p.step();
    }
    assert_eq!(p.ours.get(h).state(), State::Established);
    p.theirs(th).abort();
    for _ in 0..100 {
        p.step();
    }
    assert_eq!(p.ours.get(h).state(), State::Closed);
}
