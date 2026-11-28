//! The console's screen (`crates/text-screen`): any bytes the kernel
//! prints, in any split, with resizes in between (the loader's framebuffer
//! size), and drawing cells as glyphs. Checks: the cursor stays on the
//! screen; copying only the dirty ranges keeps a mirror (video memory)
//! equal to the screen, so the driver never leaves stale cells behind;
//! glyphs stay inside their cell.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use text_screen::{MAX_CELLS, Screen, glyph};

#[derive(Arbitrary, Debug)]
enum Op {
    Write(Vec<u8>),
    Resize(u16, u16),
    Draw(u16, bool),
}

fuzz_target!(|ops: Vec<Op>| {
    let mut s = Screen::new();
    let mut vram = s.cells().to_vec();
    for op in ops.into_iter().take(200) {
        match op {
            Op::Write(b) => s.write(&b),
            Op::Resize(c, r) => {
                s.resize(usize::from(c), usize::from(r));
                assert!(s.cols() * s.rows() <= MAX_CELLS && s.cols() >= 8 && s.rows() >= 1);
                vram = vec![0; s.cells().len()];
            }
            Op::Draw(cell, cursor) => glyph::draw(cell, cursor, |x, y, _| {
                assert!(x < glyph::WIDTH && y < glyph::HEIGHT);
            }),
        }
        assert!(s.cursor() < s.cells().len());
        if let Some(r) = s.take_dirty() {
            assert!(r.start < r.end && r.end <= s.cells().len());
            vram[r.clone()].copy_from_slice(&s.cells()[r]);
        }
        assert_eq!(&vram[..], s.cells(), "a changed cell was not marked dirty");
    }
});
