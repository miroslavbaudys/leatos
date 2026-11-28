//! Install images (`crates/install-image`, docs/install.md): the module a
//! boot loader hands the installer (checked by hash, but a crafted image
//! must be refused or planned safely, never crash or write outside the
//! target). Checks: an accepted image's plan is ascending, covers every
//! sector of the image exactly once and then only the target's last
//! sectors, with data pieces of whole sectors; `build` round-trips.
#![no_main]

use install_image::{GPT_BACKUP_SECTORS, Piece, SECTOR, build, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (extra, max, rest) = match data {
        [e, m, rest @ ..] => (*e as u64, (*m as u64).max(1), rest),
        _ => return,
    };
    if let Ok(img) = parse(rest) {
        // Big steps over the gaps: an image may claim many sectors.
        for max in [max, u64::MAX] {
            let Some(target) = img.sectors().checked_add(extra) else { continue };
            let mut at = 0u64;
            let tail = target.saturating_sub(GPT_BACKUP_SECTORS).max(img.sectors());
            for p in img.plan(target, max).unwrap() {
                let n = p.sectors();
                assert!(n >= 1 && n <= max, "{p:?}");
                if at == img.sectors() && at < tail {
                    at = tail; // the jump to the GPT backup area
                }
                assert_eq!(p.lba(), at, "not contiguous: {p:?}");
                if let Piece::Data { data, .. } = p {
                    assert_eq!(data.len() % SECTOR, 0);
                    assert!(p.lba() + n <= img.sectors());
                }
                at += n;
                assert!(at <= target);
            }
            assert_eq!(at, if target > img.sectors() { target } else { img.sectors() });
        }
    }
    // Any raw image round-trips.
    let raw = &rest[..rest.len().min(64 << 10)];
    let built = build(raw);
    let img = parse(&built).expect("built image refused");
    let mut disk = vec![0x5au8; img.sectors() as usize * SECTOR];
    for p in img.plan(img.sectors(), max).unwrap() {
        let (at, len) = (p.lba() as usize * SECTOR, p.sectors() as usize * SECTOR);
        match p {
            Piece::Data { data, .. } => disk[at..at + len].copy_from_slice(data),
            Piece::Zero { .. } => disk[at..at + len].fill(0),
        }
    }
    assert_eq!(&disk[..raw.len()], raw);
    assert!(disk[raw.len()..].iter().all(|&b| b == 0));
});
