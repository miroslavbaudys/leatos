use crate::mbr;
use crate::*;
use alloc::vec;
use alloc::vec::Vec;

/// A store partition in RAM.
struct Disk {
    bytes: Vec<u8>,
}

impl Disk {
    fn new(layout: &Layout) -> Self {
        let mut bytes = vec![0; layout.sectors as usize * SECTOR];
        bytes[..SECTOR].copy_from_slice(&layout.encode());
        Disk { bytes }
    }

    fn clone_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn sector_mut(&mut self, lba: u64) -> &mut [u8] {
        let at = lba as usize * SECTOR;
        &mut self.bytes[at..at + SECTOR]
    }

    fn write(&mut self, lba: u64, data: &[u8]) {
        let at = lba as usize * SECTOR;
        self.bytes[at..at + data.len()].copy_from_slice(data);
    }

    fn slot(&self, area: &Area, s: Slot) -> &[u8] {
        let at = area.slot_lba(s) as usize * SECTOR;
        &self.bytes[at..at + area.slot_sectors as usize * SECTOR]
    }

    fn state(&self, area: &Area) -> AreaState {
        AreaState::from_slots(area, self.slot(area, Slot::A), self.slot(area, Slot::B))
    }

    /// The current payload (`max_version` 1).
    fn load(&self, area: &Area) -> Option<Vec<u8>> {
        let (s, h) = self.state(area).current(1)?;
        Some(self.slot(area, s)[SECTOR..SECTOR + h.len as usize].to_vec())
    }

    /// Sector writes of a plan in the required order.
    fn steps(plan: &WritePlan) -> Vec<(u64, Vec<u8>)> {
        let mut v: Vec<(u64, Vec<u8>)> = plan
            .payload
            .chunks(SECTOR)
            .enumerate()
            .map(|(i, c)| (plan.payload_lba + i as u64, c.to_vec()))
            .collect();
        v.push((plan.header_lba, plan.header_sector.to_vec()));
        v
    }

    fn save(&mut self, area: &Area, version: u32, payload: &[u8]) -> WritePlan {
        let st = self.state(area);
        let cur = st.current(version).map(|c| c.0);
        let plan = st.plan_write(area, cur, version, payload).unwrap();
        for (lba, d) in Disk::steps(&plan) {
            self.write(lba, &d);
        }
        assert_eq!(
            check_slot(area, self.slot(area, plan.slot)),
            SlotState::Valid(plan.header)
        );
        plan
    }
}

fn small_layout() -> Layout {
    Layout::new(
        64,
        &[
            Area::new("config", 8, 10).unwrap(),
            Area::new("leases", 32, 4).unwrap(),
        ],
    )
    .unwrap()
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn standard_layout_round_trips() {
    let l = Layout::standard(STANDARD_MIN_SECTORS).unwrap();
    let names: Vec<&str> = l.areas().iter().map(|a| a.name()).collect();
    assert_eq!(names, ["config", "leases", "images"]);
    let c = l.area("config").unwrap();
    assert_eq!(c.max_payload(), 511 * SECTOR);
    let img = l.area("images").unwrap();
    assert_eq!(img.slot_sectors, 14336); // 7 MiB each in 16 MiB
    assert!(img.end() <= l.sectors);
    assert_eq!(Layout::parse(&l.encode(), STANDARD_MIN_SECTORS).unwrap(), l);
    // A bigger partition is fine, a smaller one is not.
    assert!(Layout::parse(&l.encode(), STANDARD_MIN_SECTORS * 2).is_ok());
    assert_eq!(
        Layout::parse(&l.encode(), STANDARD_MIN_SECTORS - 1),
        Err(Error::PartitionTooSmall {
            need: STANDARD_MIN_SECTORS,
            have: STANDARD_MIN_SECTORS - 1
        })
    );
    assert!(matches!(
        Layout::standard(1000),
        Err(Error::PartitionTooSmall { .. })
    ));
}

#[test]
fn layout_rejects_bad_headers() {
    let l = small_layout();
    let good = l.encode();
    assert!(Layout::parse(&good, 64).is_ok());
    assert_eq!(Layout::parse(&good[..100], 64), Err(Error::Short));
    assert_eq!(Layout::parse(&[0; SECTOR], 64), Err(Error::BadMagic));

    let mut s = good;
    s[30] ^= 1;
    assert_eq!(Layout::parse(&s, 64), Err(Error::BadChecksum));

    let reseal = |f: &dyn Fn(&mut [u8; SECTOR])| {
        let mut s = good;
        f(&mut s);
        let c = boot_image::crc32(0, &s[..SECTOR - 4]);
        s[SECTOR - 4..].copy_from_slice(&c.to_le_bytes());
        Layout::parse(&s, 64)
    };
    assert_eq!(reseal(&|s| s[8] = 2), Err(Error::UnsupportedLayout(2)));
    assert_eq!(
        reseal(&|s| s[11] = 0x10),
        Err(Error::UnsupportedSectorSize(4096))
    );
    assert_eq!(reseal(&|s| s[12] = 17), Err(Error::TooManyAreas(17)));
    assert_eq!(reseal(&|s| s[24] = b' '), Err(Error::BadAreaName));
    // "config\0x": a byte after the NUL padding.
    assert_eq!(reseal(&|s| s[31] = b'x'), Err(Error::BadAreaName));
    // Second area renamed to the first.
    assert_eq!(
        reseal(&|s| s[40..48].copy_from_slice(b"config\0\0")),
        Err(Error::DuplicateArea)
    );
    // Second area moved onto the first.
    assert_eq!(reseal(&|s| s[48] = 12), Err(Error::AreasOverlap));
}

#[test]
fn layout_checks_areas() {
    let a = |n, f, s| Area::new(n, f, s).unwrap();
    assert_eq!(Layout::new(64, &[a("x", 0, 4)]), Err(Error::AreaOutOfRange));
    assert_eq!(
        Layout::new(64, &[a("x", 60, 4)]),
        Err(Error::AreaOutOfRange)
    );
    assert!(Layout::new(64, &[a("x", 56, 4)]).is_ok()); // ends exactly at 64
    assert_eq!(Layout::new(64, &[a("x", 8, 1)]), Err(Error::SlotTooSmall));
    assert_eq!(
        Layout::new(64, &[a("x", 8, 4), a("y", 15, 4)]),
        Err(Error::AreasOverlap)
    );
    assert!(Layout::new(64, &[a("x", 8, 4), a("y", 16, 4)]).is_ok());
    assert_eq!(Area::new("", 8, 4), Err(Error::BadAreaName));
    assert_eq!(Area::new("ninechars", 8, 4), Err(Error::BadAreaName));
    assert_eq!(Area::new("conf ig", 8, 4), Err(Error::BadAreaName));
}

#[test]
fn mbr_finds_store_partition() {
    let mut m = [0u8; SECTOR];
    assert_eq!(mbr::partitions(&m), None); // no 55 aa
    m[510] = 0x55;
    m[511] = 0xaa;
    let entry = |m: &mut [u8; SECTOR], i: usize, kind: u8, lba: u32, n: u32| {
        let e = &mut m[446 + 16 * i..446 + 16 * (i + 1)];
        e[4] = kind;
        e[8..12].copy_from_slice(&lba.to_le_bytes());
        e[12..16].copy_from_slice(&n.to_le_bytes());
    };
    assert_eq!(mbr::find_store(&m), None);
    entry(&mut m, 0, 0x0c, 2048, 129024);
    entry(&mut m, 1, mbr::STORE_PARTITION_TYPE, 0, 32768); // first LBA 0: unused entry
    assert_eq!(mbr::find_store(&m), None);
    entry(&mut m, 1, mbr::STORE_PARTITION_TYPE, 131072, 32768);
    let p = mbr::find_store(&m).unwrap();
    assert_eq!(
        p,
        mbr::Partition {
            index: 1,
            kind: 0xda,
            first_lba: 131072,
            sectors: 32768
        }
    );
    assert_eq!(mbr::partitions(&m).unwrap().iter().flatten().count(), 2);
}

#[test]
fn empty_store_has_no_record() {
    let l = small_layout();
    let d = Disk::new(&l);
    let c = l.area("config").unwrap();
    assert_eq!(
        d.state(c),
        AreaState {
            a: SlotState::Empty,
            b: SlotState::Empty
        }
    );
    assert_eq!(d.load(c), None);
}

#[test]
fn saves_alternate_slots_and_increase_seq() {
    let l = small_layout();
    let mut d = Disk::new(&l);
    let c = *l.area("config").unwrap();
    let mut slots = Vec::new();
    for i in 0..5u8 {
        let p = payload(700 + i as usize * 300, i);
        let plan = d.save(&c, 1, &p);
        assert_eq!(plan.header.seq, i as u64 + 1);
        slots.push(plan.slot);
        assert_eq!(d.load(&c).unwrap(), p);
    }
    assert_eq!(slots, [Slot::A, Slot::B, Slot::A, Slot::B, Slot::A]);
    // The other area is untouched.
    let le = l.area("leases").unwrap();
    assert_eq!(d.load(le), None);
}

#[test]
fn empty_and_max_payloads() {
    let l = small_layout();
    let mut d = Disk::new(&l);
    let c = *l.area("config").unwrap();
    d.save(&c, 1, b"");
    assert_eq!(d.load(&c).unwrap(), b"");
    let max = payload(c.max_payload(), 7);
    d.save(&c, 1, &max);
    assert_eq!(d.load(&c).unwrap(), max);
    let st = d.state(&c);
    assert_eq!(
        st.plan_write(&c, Some(Slot::B), 1, &payload(c.max_payload() + 1, 0)),
        Err(Error::PayloadTooLarge {
            len: c.max_payload() + 1,
            max: c.max_payload()
        })
    );
}

#[test]
fn corruption_falls_back_to_previous_record() {
    let l = small_layout();
    let mut d = Disk::new(&l);
    let c = *l.area("config").unwrap();
    let old = payload(1000, 1);
    let new = payload(1200, 2);
    d.save(&c, 1, &old);
    let plan = d.save(&c, 1, &new);

    // A flipped payload bit.
    let mut d1 = Disk {
        bytes: d.bytes.clone(),
    };
    d1.sector_mut(plan.payload_lba + 1)[10] ^= 0x40;
    assert_eq!(*d1.state(&c).slot(plan.slot), SlotState::Corrupt);
    assert_eq!(d1.load(&c).unwrap(), old);

    // A flipped header bit.
    let mut d2 = Disk {
        bytes: d.bytes.clone(),
    };
    d2.sector_mut(plan.header_lba)[17] ^= 1;
    assert_eq!(d2.load(&c).unwrap(), old);

    // Both gone: no record (defaults).
    let a_lba = c.slot_lba(Slot::A);
    d2.sector_mut(a_lba + 1)[0] ^= 1;
    assert_eq!(d2.load(&c), None);
}

#[test]
fn record_from_another_area_is_rejected() {
    let l = small_layout();
    let mut d = Disk::new(&l);
    let c = *l.area("config").unwrap();
    let le = *l.area("leases").unwrap();
    d.save(&le, 1, b"lease data");
    // Copy the leases record into config slot A.
    let rec = d.slot(&le, Slot::A)[..2 * SECTOR].to_vec();
    d.write(c.slot_lba(Slot::A), &rec);
    assert_eq!(*d.state(&c).slot(Slot::A), SlotState::Corrupt);
    assert_eq!(d.load(&c), None);
}

#[test]
fn length_beyond_slot_is_corrupt() {
    let l = small_layout();
    let le = *l.area("leases").unwrap(); // 3 payload sectors
    let h = RecordHeader {
        seq: 1,
        version: 1,
        len: 4 * SECTOR as u32,
        crc: 0,
        flags: 0,
    };
    let mut slot = vec![0; le.slot_sectors as usize * SECTOR];
    slot[..SECTOR].copy_from_slice(&h.encode(&le));
    assert_eq!(check_slot(&le, &slot), SlotState::Corrupt);
    assert!(matches!(
        RecordHeader::parse(&le, &slot),
        Err(Error::PayloadTooLarge { .. })
    ));
    // A buffer shorter than the payload is corrupt, not a panic.
    let h = RecordHeader {
        seq: 1,
        version: 1,
        len: 100,
        crc: 0,
        flags: 0,
    };
    assert_eq!(check_slot(&le, &h.encode(&le)), SlotState::Corrupt);
}

/// A kernel that understands schema 1 next to records a newer kernel
/// wrote with schema 2.
#[test]
fn newer_schema_is_skipped_and_never_overwritten_as_current() {
    let l = small_layout();
    let mut d = Disk::new(&l);
    let c = *l.area("config").unwrap();
    let v1 = payload(900, 1);
    let v2 = payload(950, 2);
    d.save(&c, 1, &v1); // A: v1, seq 1
    d.save(&c, 2, &v2); // B: v2, seq 2

    let st = d.state(&c);
    assert_eq!(st.current(2).unwrap().0, Slot::B);
    let (cur, h) = st.current(1).unwrap();
    assert_eq!((cur, h.version, h.seq), (Slot::A, 1, 1));

    // The old kernel saves: it must keep its current slot (A), overwrite
    // B, and use a seq above every valid record.
    let plan = st.plan_write(&c, Some(cur), 1, &v1).unwrap();
    assert_eq!((plan.slot, plan.header.seq), (Slot::B, 3));

    // No readable record at all for a kernel that only knows schema 0.
    assert_eq!(st.current(0), None);
    // Without a current record, the older valid slot is the target.
    assert_eq!(st.plan_write(&c, None, 0, b"x").unwrap().slot, Slot::A);
}

#[test]
fn invalid_slot_is_preferred_without_current_record() {
    let l = small_layout();
    let mut d = Disk::new(&l);
    let c = *l.area("config").unwrap();
    d.save(&c, 2, b"schema two"); // A
    let st = d.state(&c);
    assert_eq!(st.current(1), None);
    // B is empty: write there and keep the newer-schema record in A.
    assert_eq!(st.plan_write(&c, None, 1, b"one").unwrap().slot, Slot::B);
}

/// Power cut after every sector of a write, with and without a torn
/// (half-written) next sector, for growing, shrinking and first writes:
/// the store holds exactly the old record until the header sector is
/// complete, and exactly the new one after.
#[test]
fn power_cut_at_every_sector_keeps_old_or_new() {
    let l = small_layout();
    let c = *l.area("config").unwrap();
    let cases: [(&[usize], usize); 5] = [
        (&[], 1500),          // first write ever
        (&[1000], 2100),      // grows
        (&[3000, 2500], 700), // shrinks, overwrites a valid older slot
        (&[1024], 1024),      // sector-aligned
        (&[4000, 4000], 4000),
    ];
    for (history, new_len) in cases {
        let mut base = Disk::new(&l);
        for (i, &len) in history.iter().enumerate() {
            base.save(&c, 1, &payload(len, i as u8));
        }
        let old = base.load(&c);
        let new = payload(new_len, 0xa5);
        let st = base.state(&c);
        let plan = st
            .plan_write(&c, st.current(1).map(|x| x.0), 1, &new)
            .unwrap();
        let steps = Disk::steps(&plan);

        for cut in 0..=steps.len() {
            for tear in [None, Some(0x00u8), Some(0xff)] {
                if cut == steps.len() && tear.is_some() {
                    continue;
                }
                let mut d = Disk {
                    bytes: base.bytes.clone(),
                };
                for (lba, data) in &steps[..cut] {
                    d.write(*lba, data);
                }
                if let Some(fill) = tear {
                    // The next sector: first half new, the rest old (0x00
                    // case keeps the old bytes) or erased (0xff).
                    let (lba, data) = &steps[cut];
                    let s = d.sector_mut(*lba);
                    s[..SECTOR / 2].copy_from_slice(&data[..SECTOR / 2]);
                    if fill == 0xff {
                        s[SECTOR / 2..].fill(0xff);
                    }
                }
                let got = d.load(&c);
                if cut == steps.len() {
                    assert_eq!(
                        got.as_deref(),
                        Some(&new[..]),
                        "history {history:?}: complete write"
                    );
                } else {
                    assert_eq!(got, old, "history {history:?}: cut {cut} tear {tear:?}");
                }
            }
        }
    }
}

#[test]
fn header_round_trips() {
    let l = small_layout();
    let c = *l.area("config").unwrap();
    let h = RecordHeader {
        seq: u64::MAX - 1,
        version: 7,
        len: 4096,
        crc: 0xdead_beef,
        flags: FLAG_TRIAL | FLAG_BOOTED,
    };
    assert_eq!(RecordHeader::parse(&c, &h.encode(&c)), Ok(h));
    assert_eq!(h.payload_sectors(), 8);
    assert_eq!(RecordHeader { len: 4097, ..h }.payload_sectors(), 9);
    assert_eq!(RecordHeader { len: 0, ..h }.payload_sectors(), 0);
}

/// Trials (docs/config-and-storage.md §6): flags live in the header
/// sector only, so marking and confirming rewrite one sector; reverting
/// erases it. Every outcome, torn rewrites included, leaves either the
/// trial or the previous record current, never something else.
#[test]
fn trial_mark_confirm_and_revert() {
    let l = small_layout();
    let c = *l.area("config").unwrap();
    let mut d = Disk::new(&l);
    let old = payload(700, 1);
    let new = payload(800, 2);
    d.save(&c, 1, &old); // A, seq 1, confirmed
    let st = d.state(&c);
    let plan = st
        .plan_write(&c, st.current(1).map(|x| x.0), 1, &new)
        .unwrap()
        .with_flags(&c, FLAG_TRIAL);
    for (lba, data) in Disk::steps(&plan) {
        d.write(lba, &data);
    }
    let (slot, h) = d.state(&c).current(1).unwrap();
    assert_eq!((slot, h.seq, h.flags), (Slot::B, 2, FLAG_TRIAL));
    assert!(h.is_trial());

    // Mark booted: the payload stays valid under the rewritten header.
    let lba = c.slot_lba(Slot::B);
    let booted = h.with_flags(FLAG_TRIAL | FLAG_BOOTED);
    let mut clean = d.clone_bytes();
    d.write(lba, &booted.encode(&c));
    assert_eq!(d.state(&c).current(1), Some((Slot::B, booted)));
    assert_eq!(d.load(&c).unwrap(), new);

    // Confirm, torn in half: falls back to the previous record.
    let confirmed = booted.with_flags(0).encode(&c);
    let mut torn = d.slot(&c, Slot::B)[..SECTOR].to_vec();
    torn[..SECTOR / 2].copy_from_slice(&confirmed[..SECTOR / 2]);
    d.write(lba, &torn);
    assert_eq!(d.load(&c).unwrap(), old);
    // Confirm, whole: the new record, no flags.
    d.write(lba, &confirmed);
    assert_eq!(d.state(&c).current(1).unwrap().1.flags, 0);
    assert_eq!(d.load(&c).unwrap(), new);

    // Revert instead: an erased header sector makes the slot empty.
    core::mem::swap(&mut d.bytes, &mut clean);
    d.write(lba, &[0; SECTOR]);
    assert_eq!(*d.state(&c).slot(Slot::B), SlotState::Empty);
    assert_eq!(d.state(&c).current(1).map(|x| x.0), Some(Slot::A));
    assert_eq!(d.load(&c).unwrap(), old);
    // The next save goes into the erased slot, with a seq above both.
    let p = d.save(&c, 1, &payload(10, 3));
    assert_eq!((p.slot, p.header.seq), (Slot::B, 2));
}

/// Fuzz find (`store` target, 2026-11-22): a record with the highest
/// sequence number (only a crafted or damaged store has one) made the next
/// save's `seq + 1` overflow: in the kernel it wrapped to 0, the old record
/// stayed current and every later save was silently ignored. Such a header
/// is not valid, so a save replaces it and wins.
#[test]
fn a_record_with_the_last_sequence_number_is_not_current() {
    let layout = small_layout();
    let area = *layout.area("config").unwrap();
    let mut disk = Disk::new(&layout);
    let plan = disk.save(&area, 1, b"first");
    let mut h = plan.header;
    h.seq = u64::MAX;
    disk.write(area.slot_lba(plan.slot), &h.encode(&area));
    assert!(disk.state(&area).current(u32::MAX).is_none(), "seq u64::MAX taken as current");
    let next = disk.save(&area, 1, b"second");
    assert_eq!(next.header.seq, 1);
    assert_eq!(disk.load(&area).as_deref(), Some(&b"second"[..]));
    assert_eq!(disk.save(&area, 1, b"third").header.seq, 2);
    assert_eq!(disk.load(&area).as_deref(), Some(&b"third"[..]));
    // The highest valid one (fuzz find 2, `store` target): the next would
    // need u64::MAX, which is never valid: the save is refused, loudly,
    // instead of writing a record nobody reads.
    let st = disk.state(&area);
    let (s, h) = st.current(1).unwrap();
    let mut top = h;
    top.seq = u64::MAX - 1;
    disk.write(area.slot_lba(s), &top.encode(&area));
    let st = disk.state(&area);
    assert_eq!(st.current(1).map(|c| c.1.seq), Some(u64::MAX - 1));
    let cur = st.current(1).map(|c| c.0);
    assert_eq!(st.plan_write(&area, cur, 1, b"fourth"), Err(Error::LastSequence));
}
