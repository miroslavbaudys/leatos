//! CAKE's ACK filter (Linux `sch_cake` `ack-filter`), conservative: when
//! a pure TCP ACK is queued behind an older one of the same connection
//! that it makes redundant, the older one is dropped. On an asymmetric
//! line (VDSL 100/20) the ACKs of a download take a real share of the
//! upload; once the upload is busy they queue, and only the newest of
//! them carries information the sender still needs.
//!
//! [`supersedes`] decides on the packets' bytes (IP header onward; the
//! qdisc gets them from [`crate::Packet::pure_ack`]). The older ACK is
//! redundant only if everything it tells the sender is also in the newer
//! one:
//! - same addresses and ports, both pure ACKs (flags ACK or ACK+PSH, no
//!   SYN/FIN/RST/URG/ECE/CWR/AE, no payload), same IP ECN bits and not CE;
//! - the newer acknowledges **more** (`ack` strictly after; wrapping).
//!   Equal ACK numbers are duplicate ACKs, the sender's loss signal, and
//!   are never filtered;
//! - TCP options only NOP, EOL, SACK and timestamps (anything else, e.g.
//!   MPTCP's data ACKs, is not understood, so not filtered); timestamps on
//!   both or neither, not going backwards;
//! - every SACK block of the older one, as far as it lies above the newer
//!   ACK number, is covered by a SACK block of the newer one.
//!
//! IPv4 without IP options, or IPv6 without extension headers (TCP right
//! behind the fixed header). Anything that does not parse is never
//! filtered.

/// Pure-ACK fields of one packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ack {
    /// Source and destination (IPv4: the first 8 bytes, the rest zero;
    /// `v6` tells the families apart).
    addrs: [u8; 32],
    v6: bool,
    ports: [u8; 4],
    ecn: u8,
    flags: u8,
    ack: u32,
    ts: Option<(u32, u32)>,
    sacks: [(u32, u32); 4],
    nsack: usize,
}

const TCP_FIN: u8 = 0x01;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn be32(b: &[u8], i: usize) -> Option<u32> {
    let s = b.get(i..i + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// `a` is after `b` in sequence space (RFC 1982 style, wrapping).
fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

fn parse(b: &[u8]) -> Option<Ack> {
    let mut addrs = [0u8; 32];
    let (tcp, ecn, v6) = match *b.first()? >> 4 {
        // IPv4, no options, not a fragment, TCP.
        4 => {
            if b[0] != 0x45 || *b.get(9)? != 6 || be16(b, 6)? & 0x3fff != 0 {
                return None;
            }
            let total = be16(b, 2)? as usize;
            addrs[..8].copy_from_slice(b.get(12..20)?);
            (b.get(20..total)?, b[1] & 3, false)
        }
        // IPv6, TCP right behind the fixed header.
        6 => {
            if *b.get(6)? != 6 {
                return None;
            }
            let plen = be16(b, 4)? as usize;
            addrs.copy_from_slice(b.get(8..40)?);
            (b.get(40..40 + plen)?, (b[1] >> 4) & 3, true)
        }
        _ => return None,
    };
    let doff = (*tcp.get(12)? >> 4) as usize * 4;
    // Header only: no payload. The low bit of byte 12 is AE (AccECN).
    if doff < 20 || doff != tcp.len() || tcp[12] & 0x0f != 0 {
        return None;
    }
    let flags = tcp[13];
    if flags & !TCP_PSH != TCP_ACK || flags & TCP_FIN != 0 {
        return None;
    }
    let mut a = Ack {
        addrs,
        v6,
        ports: tcp.get(0..4)?.try_into().ok()?,
        ecn,
        flags,
        ack: be32(tcp, 8)?,
        ts: None,
        sacks: [(0, 0); 4],
        nsack: 0,
    };
    let (mut i, mut seen_sack) = (20, false);
    while i < doff {
        match tcp[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let len = *tcp.get(i + 1)? as usize;
                if len < 2 || i + len > doff {
                    return None;
                }
                match (kind, len) {
                    (8, 10) if a.ts.is_none() => {
                        a.ts = Some((be32(tcp, i + 2)?, be32(tcp, i + 6)?));
                    }
                    (5, _) if !seen_sack && (len - 2).is_multiple_of(8) && len <= 2 + 4 * 8 => {
                        seen_sack = true;
                        a.nsack = (len - 2) / 8;
                        for (k, block) in a.sacks[..a.nsack].iter_mut().enumerate() {
                            let o = i + 2 + 8 * k;
                            *block = (be32(tcp, o)?, be32(tcp, o + 4)?);
                        }
                    }
                    _ => return None, // unknown, duplicate or malformed
                }
                i += len;
            }
        }
    }
    Some(a)
}

/// Does the pure ACK `new` make the older queued ACK `old` redundant?
/// Both are IP packets (header onward). See the module docs.
pub fn supersedes(new: &[u8], old: &[u8]) -> bool {
    let (Some(n), Some(o)) = (parse(new), parse(old)) else {
        return false;
    };
    if n.v6 != o.v6 || n.addrs != o.addrs || n.ports != o.ports || n.flags != o.flags {
        return false;
    }
    if n.ecn != o.ecn || o.ecn == 3 {
        return false; // a CE mark on the old one must reach the receiver
    }
    if !after(n.ack, o.ack) {
        return false;
    }
    match (n.ts, o.ts) {
        (None, None) => {}
        (Some((nv, ne)), Some((ov, oe))) => {
            if after(ov, nv) || after(oe, ne) {
                return false;
            }
        }
        _ => return false,
    }
    // Each old SACK block, as far as it lies above the new ACK number,
    // must be inside one of the new ACK's blocks.
    o.sacks[..o.nsack].iter().all(|&(l, r)| {
        if !after(r, n.ack) {
            return true; // now acknowledged cumulatively
        }
        let l = if after(n.ack, l) { n.ack } else { l };
        n.sacks[..n.nsack]
            .iter()
            .any(|&(nl, nr)| !after(nl, l) && !after(r, nr))
    })
}

/// Test and fuzz helper: an IPv4 pure ACK from 10.0.0.1:`sport` to
/// 192.0.2.1:80 with the given ACK number, TCP flags, timestamps and SACK
/// blocks.
#[doc(hidden)]
pub fn build_ack(
    sport: u16,
    ack: u32,
    flags: u8,
    ts: Option<(u32, u32)>,
    sacks: &[(u32, u32)],
) -> alloc::vec::Vec<u8> {
    let mut opts = alloc::vec::Vec::new();
    if let Some((v, e)) = ts {
        opts.extend_from_slice(&[1, 1, 8, 10]);
        opts.extend_from_slice(&v.to_be_bytes());
        opts.extend_from_slice(&e.to_be_bytes());
    }
    if !sacks.is_empty() {
        opts.extend_from_slice(&[1, 1, 5, 2 + 8 * sacks.len() as u8]);
        for (l, r) in sacks {
            opts.extend_from_slice(&l.to_be_bytes());
            opts.extend_from_slice(&r.to_be_bytes());
        }
    }
    while opts.len() % 4 != 0 {
        opts.push(0);
    }
    let tcp_len = 20 + opts.len();
    let total = 20 + tcp_len;
    let mut b = alloc::vec![0u8; total];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    b[6] = 0x40; // DF
    b[8] = 64;
    b[9] = 6;
    b[12..16].copy_from_slice(&[10, 0, 0, 1]);
    b[16..20].copy_from_slice(&[192, 0, 2, 1]);
    let t = &mut b[20..];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&80u16.to_be_bytes());
    t[4..8].copy_from_slice(&1000u32.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = ((tcp_len / 4) as u8) << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&502u16.to_be_bytes());
    t[20..20 + opts.len()].copy_from_slice(&opts);
    b
}

/// Test and fuzz helper: the same segment over IPv6 (2001:db8::1 →
/// 2001:db8::2), the traffic class's ECN bits from the IPv4 header's.
#[doc(hidden)]
pub fn to_ipv6(v4: &[u8]) -> alloc::vec::Vec<u8> {
    let tcp = &v4[20..];
    let mut b = alloc::vec![0u8; 40];
    b[0] = 0x60;
    b[1] = (v4[1] & 3) << 4;
    b[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    b[6] = 6;
    b[7] = 64;
    b[8..10].copy_from_slice(&[0x20, 0x01]);
    b[10..12].copy_from_slice(&[0x0d, 0xb8]);
    b[23] = 1;
    b[24..26].copy_from_slice(&[0x20, 0x01]);
    b[26..28].copy_from_slice(&[0x0d, 0xb8]);
    b[39] = 2;
    b.extend_from_slice(tcp);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACK: u8 = TCP_ACK;

    #[test]
    fn ipv6_acks_are_filtered_like_ipv4() {
        let a6 = |ack| to_ipv6(&a(ack));
        assert!(supersedes(&a6(2000), &a6(1000)));
        assert!(!supersedes(&a6(1000), &a6(1000)), "duplicate ACK kept");
        assert!(!supersedes(&a6(1000), &a6(2000)));
        // One family never supersedes the other.
        assert!(!supersedes(&a6(2000), &a(1000)) && !supersedes(&a(2000), &a6(1000)));
        // A CE mark on the older one must reach the receiver.
        let mut ce = a6(1000);
        ce[1] |= 3 << 4;
        let mut ce_new = a6(2000);
        ce_new[1] |= 3 << 4;
        assert!(!supersedes(&ce_new, &ce));
        // Behind an extension header: not understood, never filtered.
        let mut ext = a6(1000);
        ext[6] = 0;
        assert!(!supersedes(&a6(2000), &ext));
        // With timestamps and SACK as for IPv4.
        let s = |ack, r| to_ipv6(&build_ack(5000, ack, ACK, Some((ack, 1)), &[(3000, r)]));
        assert!(supersedes(&s(2000, 4000), &s(1000, 4000)));
        assert!(!supersedes(&s(2000, 3500), &s(1000, 4000)), "SACK not covered");
    }

    fn a(ack: u32) -> alloc::vec::Vec<u8> {
        build_ack(5000, ack, ACK, None, &[])
    }

    #[test]
    fn newer_cumulative_ack_supersedes() {
        assert!(supersedes(&a(2000), &a(1000)));
        assert!(!supersedes(&a(1000), &a(2000)), "older does not supersede newer");
        // Wrapping sequence space.
        assert!(supersedes(&a(10), &a(u32::MAX - 10)));
        // PSH on both is fine; a flag difference is not.
        let p = |ack| build_ack(5000, ack, ACK | TCP_PSH, None, &[]);
        assert!(supersedes(&p(2000), &p(1000)));
        assert!(!supersedes(&p(2000), &a(1000)));
    }

    #[test]
    fn duplicate_acks_are_kept() {
        assert!(!supersedes(&a(1000), &a(1000)));
        let s = |r| build_ack(5000, 1000, ACK, None, &[(2000, r)]);
        assert!(!supersedes(&s(4000), &s(3000)), "dupack with more SACK: kept (loss signal)");
    }

    #[test]
    fn other_connections_and_non_acks_are_kept() {
        assert!(!supersedes(&build_ack(5001, 2000, ACK, None, &[]), &a(1000)));
        for flags in [ACK | TCP_FIN, ACK | 0x02, ACK | 0x04, ACK | 0x20, ACK | 0x40, ACK | 0x80] {
            let f = |ack| build_ack(5000, ack, flags, None, &[]);
            assert!(!supersedes(&f(2000), &f(1000)), "flags {flags:#x}");
        }
        // Payload: not a pure ACK.
        let mut d = a(1000);
        d.extend_from_slice(&[0; 4]);
        let total = d.len() as u16;
        d[2..4].copy_from_slice(&total.to_be_bytes());
        assert!(!supersedes(&a(2000), &d));
        // AccECN's AE bit.
        let mut e = a(1000);
        e[20 + 12] |= 1;
        assert!(!supersedes(&a(2000), &e));
        // A CE-marked old ACK, and differing ECN codepoints.
        let mut ce = a(1000);
        ce[1] |= 3;
        let mut ce2 = a(2000);
        ce2[1] |= 3;
        assert!(!supersedes(&ce2, &ce));
        let mut ect = a(1000);
        ect[1] |= 2;
        assert!(!supersedes(&a(2000), &ect));
    }

    #[test]
    fn timestamps_must_not_go_backwards() {
        let t = |ack, v, e| build_ack(5000, ack, ACK, Some((v, e)), &[]);
        assert!(supersedes(&t(2000, 11, 7), &t(1000, 10, 7)));
        assert!(supersedes(&t(2000, 10, 7), &t(1000, 10, 7)));
        assert!(!supersedes(&t(2000, 9, 7), &t(1000, 10, 7)));
        assert!(!supersedes(&t(2000, 10, 6), &t(1000, 10, 7)));
        assert!(!supersedes(&a(2000), &t(1000, 10, 7)), "options must match");
    }

    #[test]
    fn sack_blocks_must_be_covered() {
        let s = |ack, b: &[(u32, u32)]| build_ack(5000, ack, ACK, None, b);
        // Old SACKs 3000-4000; new ACK 2000 SACKs 3000-5000: covered.
        assert!(supersedes(&s(2000, &[(3000, 5000)]), &s(1000, &[(3000, 4000)])));
        // New SACK misses part of the old block.
        assert!(!supersedes(&s(2000, &[(3500, 5000)]), &s(1000, &[(3000, 4000)])));
        // New cumulative ACK passes the old block: nothing left to cover.
        assert!(supersedes(&s(4000, &[]), &s(1000, &[(3000, 4000)])));
        // ...or passes part of it; the rest must be covered.
        assert!(supersedes(&s(3500, &[(3500, 4000)]), &s(1000, &[(3000, 4000)])));
        assert!(!supersedes(&s(3500, &[]), &s(1000, &[(3000, 4000)])));
        // One of several blocks uncovered.
        assert!(!supersedes(
            &s(2000, &[(3000, 4000)]),
            &s(1000, &[(3000, 4000), (6000, 7000)])
        ));
    }

    #[test]
    fn unknown_or_malformed_options_are_kept() {
        let mut m = a(1000);
        // Replace the header with one carrying an MSS option (kind 2).
        let mut opt = build_ack(5000, 1000, ACK, Some((1, 1)), &[]);
        opt[20 + 22] = 2; // the TS option's kind byte -> MSS with length 10
        assert!(!supersedes(&a(2000), &opt));
        // Option length running past the header.
        let mut bad = build_ack(5000, 1000, ACK, Some((1, 1)), &[]);
        bad[20 + 23] = 40;
        assert!(!supersedes(&a(2000), &bad));
        // Truncated packets and garbage never panic.
        m.truncate(30);
        assert!(!supersedes(&a(2000), &m));
        for n in 0..60 {
            let full = build_ack(5000, 1000, ACK, Some((1, 1)), &[(1, 2)]);
            let cut = &full[..n.min(full.len())];
            let _ = supersedes(cut, &full);
            let _ = supersedes(&full, cut);
        }
        // IP options, fragments, not TCP.
        let mut ipopt = a(1000);
        ipopt[0] = 0x46;
        assert!(!supersedes(&a(2000), &ipopt));
        let mut frag = a(1000);
        frag[6] = 0x20;
        assert!(!supersedes(&a(2000), &frag));
        let mut udp = a(1000);
        udp[9] = 17;
        assert!(!supersedes(&a(2000), &udp));
    }
}
