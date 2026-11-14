use crate::packet::{self, Reject};
use crate::*;

const S: u64 = 1_000_000_000;
const MS: u64 = 1_000_000;
/// 2026-11-14T12:00:00Z in Unix ns.
const UNIX_NOW: i64 = 1_794_916_800 * 1_000_000_000;

fn answer(req: &Request<u8>, unix_at_mono0: i64, sent: u64, one_way: u64, stratum: u8) -> [u8; 48] {
    let t2 = unix_at_mono0 + (sent + one_way) as i64;
    packet::reply(&req.data, stratum, t2, t2 + 1000)
}

#[test]
fn request_layout() {
    let r = packet::request(0x0102_0304_0506_0708);
    assert_eq!(r.len(), 48);
    assert_eq!(r[0], 0x23); // LI 0, VN 4, mode 3
    assert_eq!(&r[40..48], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(r[1..40].iter().all(|&b| b == 0));
}

#[test]
fn timestamp_round_trip_and_eras() {
    for ns in [UNIX_NOW, UNIX_NOW + 123_456_789, 2_085_978_496 * S as i64 + 5, 4_000_000_000 * S as i64] {
        let back = packet::ntp_to_unix_ns(packet::unix_ns_to_ntp(ns));
        assert!((back - ns).abs() <= 1, "{ns} -> {back}");
    }
    // NTP era 0 ends 2036-02-07T06:28:16Z = Unix 2_085_978_496.
    let wrap = 2_085_978_496i64 * S as i64;
    assert_eq!(packet::unix_ns_to_ntp(wrap) >> 32, 0);
    assert_eq!(packet::ntp_to_unix_ns(0), wrap);
    // A plain era-0 timestamp from 2026.
    let t = (packet::UNIX_EPOCH_NTP + 1_794_916_800) << 32;
    assert_eq!(packet::ntp_to_unix_ns(t), UNIX_NOW);
}

#[test]
fn reply_checks() {
    let req = packet::request(77);
    let good = packet::reply(&req, 2, UNIX_NOW, UNIX_NOW + 5);
    let r = packet::parse_reply(&good, 77).unwrap();
    assert_eq!((r.stratum, r.leap), (2, 0));
    assert!((r.receive - UNIX_NOW).abs() <= 1);

    assert_eq!(packet::parse_reply(&good[..47], 77), Err(Reject::Short));
    assert_eq!(packet::parse_reply(&good, 78), Err(Reject::Origin));
    let edit = |f: &dyn Fn(&mut [u8; 48])| {
        let mut p = good;
        f(&mut p);
        packet::parse_reply(&p, 77)
    };
    assert_eq!(edit(&|p| p[0] = (4 << 3) | 3), Err(Reject::Mode));
    assert_eq!(edit(&|p| p[0] = (2 << 3) | 4), Err(Reject::Version));
    assert!(edit(&|p| p[0] = (3 << 3) | 4).is_ok()); // NTPv3 servers are fine
    assert_eq!(
        edit(&|p| {
            p[1] = 0;
            p[12..16].copy_from_slice(b"RATE");
        }),
        Err(Reject::Kiss(*b"RATE"))
    );
    assert_eq!(edit(&|p| p[1] = 16), Err(Reject::Stratum));
    assert_eq!(edit(&|p| p[0] |= 3 << 6), Err(Reject::Unsynchronised));
    assert_eq!(edit(&|p| p[40..48].fill(0)), Err(Reject::NoTime));
    assert_eq!(edit(&|p| p[32..40].fill(0)), Err(Reject::NoTime));
}

#[test]
fn offset_and_delay() {
    // Client clock: mono. Server: unix = mono + 1000 s. 10 ms each way,
    // server holds the request 1 ms.
    let off = 1000 * S as i64;
    let t1 = 5 * S;
    let t2 = off + (t1 + 10 * MS) as i64;
    let t3 = t2 + MS as i64;
    let t4 = t1 + 21 * MS;
    let s = Sample::from_times(t1, t2, t3, t4, 1);
    assert_eq!(s.offset, off);
    assert_eq!(s.delay, 20 * MS);
    // Asymmetric path: the error is half the asymmetry.
    let t2 = off + (t1 + 30 * MS) as i64;
    let s = Sample::from_times(t1, t2, t2, t1 + 40 * MS, 1);
    assert_eq!(s.offset, off + 10 * MS as i64);
}

/// Drive the client: each request is answered by `respond` (or lost),
/// replies arrive `rtt` later. Returns the updates applied.
fn run(
    c: &mut Client<u8>,
    from: u64,
    until: u64,
    mut respond: impl FnMut(&Request<u8>, u64) -> Option<(u64, [u8; 48])>,
) -> Vec<(u64, Sample)> {
    let mut now = from;
    let mut updates = Vec::new();
    let mut inflight: Option<(u64, u8, [u8; 48])> = None;
    while now < until {
        if let Some((at, server, data)) = inflight
            && at <= now
        {
            c.handle(server, &data, now);
            inflight = None;
        }
        while let Some(req) = c.poll(now) {
            if let Some((delay, data)) = respond(&req, now) {
                inflight = Some((now + delay, req.server, data));
            }
        }
        if let Some(u) = c.take_update() {
            updates.push((now, u));
        }
        now += 10 * MS;
    }
    updates
}

#[test]
fn burst_takes_lowest_delay_then_backs_off() {
    let off = UNIX_NOW;
    let mut c = Client::new(1);
    c.set_servers(&[9]);
    let mut n = 0;
    let delays = [80 * MS, 20 * MS, 60 * MS, 40 * MS];
    let mut times = Vec::new();
    let ups = run(&mut c, 0, 4000 * S, |req, now| {
        let d = delays.get(n).copied().unwrap_or(20 * MS);
        n += 1;
        times.push(now);
        Some((d, answer(req, off, now, d / 2, 2)))
    });
    // The burst: 4 requests 2 s apart, then one update from the 20 ms sample.
    assert_eq!(&times[..4], &[0, 2 * S, 4 * S, 6 * S]);
    let (at, first) = ups[0];
    assert!(first.delay.abs_diff(20 * MS) < 10_000);
    assert!((first.offset - off).abs() < MS as i64);
    assert!((6 * S..7 * S).contains(&at));
    // Then 64, 128, 256, 512, 1024, 1024 s apart.
    let gaps: Vec<u64> = times[4..].windows(2).map(|w| (w[1] - w[0]) / S).collect();
    assert_eq!(&gaps[..5], &[128, 256, 512, 1024, 1024]);
    assert_eq!((times[4] - times[3]) / S, 64);
    assert!(c.status().synced.is_some());
    assert_eq!(c.status().server, Some(9));
}

#[test]
fn timeouts_rotate_servers_and_retry_later() {
    let mut c = Client::new(2);
    c.set_servers(&[1, 2]);
    let mut asked = Vec::new();
    let ups = run(&mut c, 0, 60 * S, |req, now| {
        asked.push((now / MS, req.server));
        // Server 1 never answers; server 2 does.
        (req.server == 2).then(|| (10 * MS, answer(req, UNIX_NOW, now, 5 * MS, 1)))
    });
    // Two losses (3 s timeout each) on server 1, then server 2.
    assert_eq!(asked[0], (0, 1));
    assert_eq!(asked[1], (3000, 1));
    assert_eq!(asked[2].1, 2);
    assert_eq!(c.status().lost, 2);
    assert!(!ups.is_empty());
    assert_eq!(c.status().server, Some(2));
}

#[test]
fn nobody_answers_backs_off() {
    let mut c = Client::new(3);
    c.set_servers(&[1]);
    let mut times = Vec::new();
    let ups = run(&mut c, 0, 400 * S, |_, now| {
        times.push(now / S);
        None
    });
    assert!(ups.is_empty());
    // Burst of 4 (each lost after 3 s), then waits of 8, 16, 32, 64, 64 s.
    let firsts: Vec<u64> = times.chunks(4).map(|c| c[0]).collect();
    let gaps: Vec<u64> = firsts.windows(2).map(|w| w[1] - w[0]).collect();
    assert_eq!(gaps[0], 12 + 8);
    assert_eq!(gaps[1], 12 + 16);
    assert_eq!(gaps[2], 12 + 32);
    assert_eq!(gaps[3], 12 + 64);
    assert_eq!(gaps[4], 12 + 64);
    assert!(c.status().synced.is_none());
}

#[test]
fn spoofed_and_rejected_replies() {
    let mut c = Client::new(4);
    c.set_servers(&[1]);
    let req = c.poll(0).unwrap();
    // From the wrong host, or with the wrong cookie: ignored, still pending.
    c.handle(2, &answer(&req, UNIX_NOW, 0, MS, 1), MS);
    let mut other = req.clone();
    other.data[47] ^= 0xff;
    c.handle(1, &answer(&other, UNIX_NOW, 0, MS, 1), MS);
    assert_eq!(c.next_deadline(), Some(TIMEOUT));
    // Unsynchronised server: rejected, counted, not applied.
    c.handle(1, &answer(&req, UNIX_NOW, 0, MS, 16), 2 * MS);
    assert_eq!(c.status().rejected, 1);
    assert_eq!(c.take_update(), None);
    assert_eq!(c.next_deadline(), Some(2 * S));
}

#[test]
fn jump_starts_a_new_burst() {
    let mut off = UNIX_NOW;
    let mut c = Client::new(5);
    c.set_servers(&[1]);
    let mut count = 0;
    let ups = run(&mut c, 0, 600 * S, |req, now| {
        count += 1;
        if count == 6 {
            off += 5 * S as i64; // the server's clock jumps
        }
        Some((10 * MS, answer(req, off, now, 5 * MS, 1)))
    });
    // First burst → update; one steady sample agrees → update; the jump
    // triggers a burst whose result is the new offset.
    let last = ups.last().unwrap().1;
    assert!((last.offset - (UNIX_NOW + 5 * S as i64)).abs() < MS as i64);
    assert!(ups.len() >= 3);
}

#[test]
fn server_list_changes() {
    let mut c: Client<u8> = Client::new(6);
    assert_eq!(c.poll(0), None);
    assert_eq!(c.next_deadline(), None);
    c.set_servers(&[1, 2]);
    let r = c.poll(0).unwrap();
    assert_eq!(r.server, 1);
    // Server 1 removed while asked: the request is dropped, 2 is next.
    c.set_servers(&[2]);
    c.handle(1, &answer(&r, UNIX_NOW, 0, MS, 1), MS);
    assert_eq!(c.status().received, 0);
    assert_eq!(c.poll(2 * S).unwrap().server, 2);
}
