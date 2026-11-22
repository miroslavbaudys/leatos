//! The store partition (`crates/config-store`): what the kernel reads from
//! the SD card or disk at boot, before any config exists: the MBR, the
//! store header (areas) and the A/B record slots. Checks: a header that
//! parses encodes back to itself and keeps its areas inside the partition;
//! from any two slot images, writing a record as planned (payload, then
//! header) gives a valid slot that becomes the current record, and the
//! other slot is untouched (the power-fail-safe rule).
#![no_main]

use arbitrary::Arbitrary;
use config_store::mbr::{find_store, partitions};
use config_store::{AreaState, Layout, SECTOR, SlotState, check_slot};
use libfuzzer_sys::fuzz_target;

/// A slot image: raw bytes, or a real record (any sequence number,
/// version and flags) with an optional damaged byte.
#[derive(Arbitrary, Debug)]
enum SlotGen {
    Raw(Vec<u8>),
    Record { seq: u64, version: u32, flags: u32, payload: Vec<u8>, damage: Option<(u16, u8)> },
}

impl SlotGen {
    fn image(&self, area: &config_store::Area) -> Vec<u8> {
        match self {
            SlotGen::Raw(b) => b.clone(),
            SlotGen::Record { seq, version, flags, payload, damage } => {
                let empty = AreaState::from_slots(area, &[], &[]);
                let Ok(plan) = empty.plan_write(area, None, *version, payload) else { return Vec::new() };
                let mut h = plan.header;
                h.seq = *seq;
                h.flags = *flags;
                let mut img = h.encode(area).to_vec();
                img.extend_from_slice(&plan.payload);
                if let Some((at, x)) = damage {
                    let at = usize::from(*at) % img.len();
                    img[at] ^= x | 1;
                }
                img
            }
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    mbr: Vec<u8>,
    header: Vec<u8>,
    sectors: u64,
    slot_a: SlotGen,
    slot_b: SlotGen,
    payload: Vec<u8>,
    version: u32,
    max_version: u32,
}

fuzz_target!(|i: Input| {
    let _ = partitions(&i.mbr);
    let _ = find_store(&i.mbr);
    if let Ok(l) = Layout::parse(&i.header, i.sectors) {
        assert!(l.areas().iter().all(|a| a.end() <= i.sectors), "an area past the partition");
        assert_eq!(Layout::parse(&l.encode(), i.sectors).ok(), Some(l.clone()), "header round trip");
    }
    let Ok(layout) = Layout::standard(i.sectors.clamp(config_store::STANDARD_MIN_SECTORS, 1 << 24)) else { return };
    for area in layout.areas() {
        let (slot_a, slot_b) = (i.slot_a.image(area), i.slot_b.image(area));
        let st = AreaState::from_slots(area, &slot_a, &slot_b);
        let cur = st.current(i.max_version);
        let Ok(plan) = st.plan_write(area, cur.map(|c| c.0), i.version, &i.payload) else { continue };
        if let Some((s, _)) = cur {
            assert_ne!(plan.slot, s, "the current record is never the target");
        }
        // The written slot: header sector, then the payload sectors.
        let mut img = plan.header_sector.to_vec();
        img.extend_from_slice(&plan.payload);
        assert_eq!(img.len() % SECTOR, 0);
        assert_eq!(check_slot(area, &img), SlotState::Valid(plan.header), "written slot invalid");
        let (a, b) = match plan.slot {
            config_store::Slot::A => (&img, &slot_b),
            config_store::Slot::B => (&slot_a, &img),
        };
        let after = AreaState::from_slots(area, a, b);
        assert_eq!(after.slot(plan.slot.other()), st.slot(plan.slot.other()), "the other slot changed");
        let want = (plan.slot, plan.header);
        assert_eq!(after.current(u32::MAX), Some(want), "new record not current");
    }
});
