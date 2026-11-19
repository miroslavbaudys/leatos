//! Kernel upload validation (`crates/boot-image`): the bytes of an
//! uploaded kernel (authenticated, but a corrupt image must be refused,
//! never crash the router). Checks: an accepted plan lies inside the
//! allowed range, its entry inside the image; flattening fits its length.
#![no_main]

use boot_image::{multiboot2, parse};
use libfuzzer_sys::fuzz_target;

const MIN: u64 = 0x10_0000;
const MAX: u64 = 0x1000_0000;

fuzz_target!(|data: &[u8]| {
    let _ = multiboot2::find_header(data);
    let _ = boot_image::crc32(0, data);
    for machine in [62u16, 183] {
        if let Ok(plan) = parse(data, machine, MIN, MAX) {
            assert!(MIN <= plan.lo && plan.lo <= plan.hi && plan.hi <= MAX, "{plan:?}");
            assert!((plan.lo..plan.hi).contains(&plan.entry), "entry outside: {plan:?}");
            for s in &plan.segments {
                assert!(s.filesz <= s.memsz && s.offset + s.filesz <= data.len(), "{s:?}");
                assert!(plan.lo <= s.paddr && s.paddr + s.memsz as u64 <= plan.hi, "{s:?}");
            }
            if plan.len() <= 1 << 24 {
                let mut out = vec![0u8; plan.len()];
                plan.flatten(data, &mut out);
            }
        }
    }
});
