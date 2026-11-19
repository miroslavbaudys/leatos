//! The SNTP client (`crates/proto-sntp`): replies from the WAN. Valid
//! replies to the client's own last request (any stratum, leap and times),
//! damaged ones, replies from other servers, raw bytes. Checks: requests
//! go to configured servers only.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use proto_sntp::{Client, packet};
use leatos_fuzz::damage;

#[derive(Arbitrary, Debug)]
enum Op {
    Reply { from: u8, stratum: u8, leap: u8, rx_ns: i64, tx_ns: i64, delay_ms: u16, noise: Option<Vec<u8>> },
    Raw { from: u8, data: Vec<u8> },
    Tick(u32),
    Restart,
    Servers(u8),
}

fuzz_target!(|input: (u64, Vec<Op>)| {
    let (seed, ops) = input;
    let mut c: Client<u8> = Client::new(seed);
    c.set_servers(&[0, 1, 2]);
    let mut servers = 3u8;
    let mut now = 0u64;
    let mut last: Option<(u8, [u8; packet::LEN])> = None;
    for op in ops.into_iter().take(200) {
        while let Some(req) = c.poll(now) {
            assert!(req.server < servers, "request to server {} of {servers}", req.server);
            last = Some((req.server, req.data));
        }
        match op {
            Op::Reply { from, stratum, leap, rx_ns, tx_ns, delay_ms, noise } => {
                let Some((server, req)) = last else { continue };
                now += u64::from(delay_ms) * 1_000_000;
                let mut b = packet::reply(&req, stratum, rx_ns, tx_ns);
                b[0] = (b[0] & 0x3f) | (leap << 6);
                if let Some(n) = &noise {
                    damage(&mut b, n);
                }
                let from = if from % 4 == 0 { from } else { server };
                c.handle(from, &b, now);
            }
            Op::Raw { from, data } => c.handle(from, &data, now),
            Op::Tick(ms) => now += u64::from(ms) * 1_000_000,
            Op::Restart => c.restart(now),
            Op::Servers(n) => {
                servers = n % 4;
                let list: Vec<u8> = (0..servers).collect();
                c.set_servers(&list);
            }
        }
        let _ = c.take_update();
        let _ = (c.next_deadline(), c.status());
        let _ = packet::parse_reply(&[], 0);
    }
});
