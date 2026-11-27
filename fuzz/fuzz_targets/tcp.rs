//! The router's TCP (`proto_tcp`), reachable from LAN clients (:80, :53)
//! and, for the DoT client's connections, from the WAN: arbitrary segments
//! (checksum right or wrong; sequence and ACK numbers absolute or relative
//! to what the stack last sent, to get past the window checks) to a
//! listening socket and a connecting one, with user calls and time steps
//! interleaved. Checks: no panic; buffers within their sizes; every segment
//! sent fits the MSS; a poll that says "now" sends something or stops
//! saying it (no livelock).
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use proto_tcp::wire::{self, Header};
use proto_tcp::{Socket, Tcp};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const US: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
const RX: usize = 2048;
const TX: usize = 4096;

#[derive(Arbitrary, Debug)]
struct Seg {
    to_client: bool,
    sport_other: bool,
    rel_seq: bool,
    seq: u32,
    rel_ack: bool,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    payload: Vec<u8>,
    bad_checksum: bool,
}

#[derive(Arbitrary, Debug)]
enum Op {
    Seg(Seg),
    Raw(Vec<u8>),
    Send(u16),
    Recv(u16),
    Close(bool),
    Abort(bool),
    Relisten,
    Advance(u16),
}

fuzz_target!(|ops: Vec<Op>| {
    let mut tcp = Tcp::new([7; 16]);
    let mut srv = Socket::new(RX, TX);
    srv.listen(80).unwrap();
    srv.set_timeout(Some(10_000));
    let hs = tcp.add(srv);
    let mut cli = Socket::new(RX, TX);
    cli.connect(SocketAddr::new(US, 61000), SocketAddr::new(PEER, 853)).unwrap();
    let hc = tcp.add(cli);
    let mut now = 1000u64;
    // What we last sent per socket port (our seq + len, our ack).
    let mut last: [(u32, u32); 2] = [(0, 0); 2];
    let mut poll = |tcp: &mut Tcp, now: u64, last: &mut [(u32, u32); 2]| {
        for _ in 0..8 {
            let mut sent = 0;
            tcp.poll(now, |e| {
                let mut b = [0u8; 1600];
                let n = e.write(&mut b).expect("fits");
                let seg = wire::parse(&b[..n]).expect("we parse what we send");
                assert!(seg.payload.len() <= 1460, "beyond the MSS");
                assert_eq!(wire::checksum(e.src.ip(), e.dst.ip(), &b[..n]), Some(0));
                let k = usize::from(e.src.port() == 61000);
                last[k] = (seg.seq.wrapping_add(seg.seq_len()), seg.ack);
                sent += 1;
                true
            });
            match tcp.next_deadline(now) {
                Some(t) if t <= now && sent > 0 => continue,
                Some(t) if t <= now => panic!("deadline now but nothing to send: {:?}", (0..2).map(|i| format!("{:?}", tcp.get(if i == 0 { hs } else { hc }))).collect::<Vec<_>>()),
                _ => return,
            }
        }
    };
    for op in ops.into_iter().take(200) {
        match op {
            Op::Seg(s) => {
                let k = usize::from(s.to_client);
                let (sport, dport) = if s.to_client { (853, 61000) } else { (if s.sport_other { 5001 } else { 5000 }, 80) };
                let seq = if s.rel_seq { last[k].1.wrapping_add(s.seq % 4096) } else { s.seq };
                let ack = if s.rel_ack { last[k].0.wrapping_add(s.ack % 16).wrapping_sub(8) } else { s.ack };
                let h = Header { sport, dport, seq, ack, flags: s.flags & 0x3f, window: s.window, mss: s.mss };
                let payload = &s.payload[..s.payload.len().min(1400)];
                let mut b = [0u8; 1500];
                let n = wire::write(&mut b, PEER, US, &h, payload, &[]).unwrap();
                if s.bad_checksum {
                    b[16] ^= 0x55;
                }
                tcp.receive(now, PEER, US, &b[..n]);
            }
            Op::Raw(b) => tcp.receive(now, PEER, US, &b),
            Op::Send(n) => {
                for h in [hs, hc] {
                    let _ = tcp.get_mut(h).send_slice(&vec![0x5a; usize::from(n)]);
                }
            }
            Op::Recv(n) => {
                for h in [hs, hc] {
                    let mut b = vec![0u8; usize::from(n)];
                    let _ = tcp.get_mut(h).recv_slice(&mut b);
                }
            }
            Op::Close(c) => tcp.get_mut(if c { hc } else { hs }).close(),
            Op::Abort(c) => tcp.get_mut(if c { hc } else { hs }).abort(),
            Op::Relisten => {
                let s = tcp.get_mut(hs);
                if !s.is_open() {
                    s.listen(80).unwrap();
                }
            }
            Op::Advance(ms) => now += u64::from(ms),
        }
        poll(&mut tcp, now, &mut last);
        for h in [hs, hc] {
            let s = tcp.get(h);
            assert!(s.recv_queue() <= RX);
            assert!(s.send_queue() <= TX);
        }
    }
});
