//! Glyphs for drawing cells into a framebuffer: Noto Sans Mono, 16 pixels
//! high, 7 wide, pre-rasterised with 8-bit intensities (anti-aliased; the
//! `noto-sans-mono-bitmap` crate: code MIT, font SIL OFL 1.1). Basic Latin
//! and Latin-1; the code page 437 characters [`crate::Screen`] stores map
//! back to them, the rest to a near ASCII stand-in.

use noto_sans_mono_bitmap::{FontWeight, RasterHeight, get_raster, get_raster_width};

pub const WIDTH: usize = 7;
pub const HEIGHT: usize = 16;
const WEIGHT: FontWeight = FontWeight::Regular;
const SIZE: RasterHeight = RasterHeight::Size16;
const _: () = assert!(get_raster_width(WEIGHT, SIZE) == WIDTH && SIZE.val() == HEIGHT);

/// The cursor: an underline over the cell's last rows.
const CURSOR_ROWS: usize = 2;

/// The character a code page 437 cell shows.
fn char_of(cp437: u8) -> char {
    match cp437 {
        0x20..=0x7e => cp437 as char,
        0xe6 => 'µ',
        0xf8 => '°',
        0xf1 => '±',
        0xfa => '·',
        0x1a | 0xf2 => '>',
        0x1b | 0xf3 => '<',
        0x18 => '^',
        0x19 => 'v',
        0xf7 => '~',
        0xfb => '*',
        0xc4 => '-',
        0xb3 => '|',
        _ => '?',
    }
}

/// Draw `cell`: `put(x, y, intensity)` for each of its [`WIDTH`] x
/// [`HEIGHT`] pixels (0 = background, 255 = full foreground), with the
/// cursor underline if `cursor`.
pub fn draw(cell: u16, cursor: bool, mut put: impl FnMut(usize, usize, u8)) {
    let raster = get_raster(char_of(cell as u8), WEIGHT, SIZE);
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let v = if cursor && y >= HEIGHT - CURSOR_ROWS {
                255
            } else {
                raster.as_ref().and_then(|r| r.pixel(x, y)).unwrap_or(0)
            };
            put(x, y, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BLANK;

    fn ink(cell: u16, cursor: bool) -> (u32, usize) {
        let (mut sum, mut n) = (0u32, 0);
        draw(cell, cursor, |x, y, v| {
            assert!(x < WIDTH && y < HEIGHT);
            sum += u32::from(v);
            n += 1;
        });
        (sum, n)
    }

    #[test]
    fn every_pixel_once() {
        assert_eq!(ink(BLANK, false), (0, WIDTH * HEIGHT), "a blank draws background");
        let (a, _) = ink(0x0700 | u16::from(b'A'), false);
        assert!(a > 255 * 10, "A has ink: {a}");
        let (c, _) = ink(BLANK, true);
        assert_eq!(c, 255 * (WIDTH * CURSOR_ROWS) as u32, "cursor underline");
    }

    #[test]
    fn cp437_characters_have_glyphs() {
        for b in [0xe6u8, 0xf8, 0xf1, 0xfa, 0x1a, 0xc4] {
            assert!(ink(0x0700 | u16::from(b), false).0 > 0, "{b:#x}");
        }
        assert_eq!(char_of(0x01), '?');
    }
}
