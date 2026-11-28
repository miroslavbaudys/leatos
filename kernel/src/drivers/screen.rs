//! The console mirrored on the machine's screen: what a Proxmox VM's
//! noVNC console shows (`vga: std`, docs/proxmox.md §8). Output only:
//! input stays on the serial console.
//!
//! Two kinds of screen:
//!
//! - **Framebuffer**: the linear framebuffer the boot loader set up
//!   (Multiboot2 tag 8, requested by `boot.S`'s header; Limine picks the
//!   display's preferred mode, 1280x800 in QEMU / Proxmox), 32 bits per
//!   pixel, 8-bit colour fields. Cells drawn with
//!   [`text_screen::glyph`] (7x16): 182x50 characters at 1280x800, the
//!   cursor as an underline.
//! - **VGA text** (80x25 at `arch::console::TEXT_SCREEN`) when the loader
//!   left the card in text mode (PVH boot, an older loader); the hardware
//!   cursor via `arch::console::text_cursor`.
//!
//! Everything printed goes into a [`text_screen::Screen`] from the first
//! boot line (no heap needed); [`early`] sizes it once the boot information
//! is known. [`init`], after PCI enumeration, decides: with a display
//! controller (PCI class 03) the screen is drawn and every later write
//! redraws the cells that changed; without one (the apu4: no graphics,
//! nothing decodes those addresses) the mirror stops for good and video
//! memory is never touched. Boot argument `screen=0` turns it off too.

use crate::mmio::Region;
use crate::pci::Pci;
use crate::println;
use boot_image::multiboot2::{FB_EGA_TEXT, FB_RGB, Framebuffer};
use spin::Mutex;
use text_screen::{MAX_CELLS, Screen, glyph};

/// Foreground at full intensity: light grey (VGA's 0xaaaaaa, a little
/// brighter for the anti-aliased glyphs).
const FG: u32 = 0xcc;

enum Out {
    Text(Region),
    Fb {
        mem: Region,
        pitch: usize,
        /// Bit positions of red, green and blue.
        shift: [u32; 3],
    },
}

struct Mirror {
    screen: Screen,
    /// What video memory shows (0 = unknown: drawn on the next flush).
    shown: [u16; MAX_CELLS],
    shown_cursor: Option<usize>,
    out: Option<Out>,
    /// The loader's framebuffer, if it is one we can draw on.
    fb: Option<Framebuffer>,
    /// The loader set a graphics mode we cannot draw on: no text mode
    /// either.
    graphics_unusable: bool,
    /// [`init`] found no screen: stop updating `screen`.
    off: bool,
}

static MIRROR: Mutex<Mirror> = Mutex::new(Mirror {
    screen: Screen::new(),
    shown: [0; MAX_CELLS],
    shown_cursor: None,
    out: None,
    fb: None,
    graphics_unusable: false,
    off: false,
});

impl Out {
    fn draw(&mut self, i: usize, cell: u16, cursor: bool, cols: usize) {
        match self {
            Out::Text(vram) => vram.write16(i * 2, cell),
            Out::Fb { mem, pitch, shift } => {
                let (x0, y0) = ((i % cols) * glyph::WIDTH, (i / cols) * glyph::HEIGHT);
                glyph::draw(cell, cursor, |x, y, v| {
                    let c = u32::from(v) * FG / 255;
                    let px = c << shift[0] | c << shift[1] | c << shift[2];
                    mem.write32((y0 + y) * *pitch + (x0 + x) * 4, px);
                });
            }
        }
    }
}

impl Mirror {
    fn write(&mut self, s: &str) {
        if self.off {
            return;
        }
        self.screen.write(s.as_bytes());
        self.flush();
    }

    /// Redraw the cells that changed, and the cursor.
    fn flush(&mut self) {
        let Some(out) = self.out.as_mut() else { return };
        let cols = self.screen.cols();
        let cursor = self.screen.cursor();
        let fb = matches!(out, Out::Fb { .. });
        if let Some(range) = self.screen.take_dirty() {
            let cells = self.screen.cells();
            for i in range {
                let at_cursor = fb && (i == cursor || Some(i) == self.shown_cursor);
                if cells[i] != self.shown[i] || at_cursor {
                    out.draw(i, cells[i], fb && i == cursor, cols);
                    self.shown[i] = cells[i];
                }
            }
        }
        if self.shown_cursor == Some(cursor) {
            return;
        }
        if fb {
            let cells = self.screen.cells();
            if let Some(old) = self.shown_cursor.filter(|&o| o < cells.len()) {
                out.draw(old, cells[old], false, cols);
            }
            out.draw(cursor, cells[cursor], true, cols);
        } else {
            crate::arch::console::text_cursor(cursor as u16);
        }
        self.shown_cursor = Some(cursor);
    }
}

/// Mirror console output (thread context, under the console's lock).
pub fn write(s: &str) {
    MIRROR.lock().write(s);
}

/// Fatal paths: mirror if the screen is free (a core that crashed while
/// holding it leaves the screen as it was).
pub fn emergency_write(s: &str) {
    if let Some(mut m) = MIRROR.try_lock() {
        m.write(s);
    }
}

/// A framebuffer [`Out::Fb`] can draw on: 32 bits per pixel, 8-bit colour
/// fields on byte boundaries, at least 8 columns of glyphs.
fn usable(fb: &Framebuffer) -> bool {
    fb.kind == FB_RGB
        && fb.bpp == 32
        && fb.rgb.iter().all(|&(pos, size)| size == 8 && pos % 8 == 0 && pos <= 24)
        && fb.pitch as u64 >= u64::from(fb.width) * 4
        && fb.width as usize >= 8 * glyph::WIDTH
        && fb.height as usize >= glyph::HEIGHT
}

/// After platform discovery: size the screen for the loader's framebuffer.
pub fn early(info: &crate::platform::BootInfo) {
    let Some(fb) = info.framebuffer.filter(|f| f.kind != FB_EGA_TEXT) else {
        return;
    };
    let mut m = MIRROR.lock();
    if usable(&fb) {
        m.screen.resize(fb.width as usize / glyph::WIDTH, fb.height as usize / glyph::HEIGHT);
        m.fb = Some(fb);
    } else {
        m.graphics_unusable = true;
    }
}

/// After PCI enumeration: draw the screen if there is a display controller.
pub fn init(pci: Option<&Pci>) {
    let display = pci.and_then(|p| p.devices.iter().find(|d| d.info.class == 0x03));
    let mut m = MIRROR.lock();
    let Some(dev) = display else {
        m.off = true;
        return;
    };
    if crate::config::screen_off() {
        m.off = true;
        drop(m);
        println!("  screen          : off (screen=0), display {}", dev.df);
        return;
    }
    let (out, what) = if let Some(fb) = m.fb {
        let len = fb.pitch as usize * fb.height as usize;
        let addr = fb.addr as usize;
        crate::mm::mmu::map_device(addr, addr + len);
        // SAFETY: the framebuffer the boot loader set up on the display
        // controller found above (Multiboot2 tag 8), mapped as device
        // memory just now; only this module accesses it, under MIRROR's
        // lock.
        let mut mem = unsafe { Region::new(addr, len) };
        // Black, margins included (the loader's menu may still be there).
        for off in (0..len).step_by(4) {
            mem.write32(off, 0);
        }
        let shift = fb.rgb.map(|(pos, _)| u32::from(pos));
        let out = Out::Fb { mem, pitch: fb.pitch as usize, shift };
        (out, ("framebuffer", fb.addr, fb.width, fb.height))
    } else if let (Some(addr), false) = (crate::arch::console::TEXT_SCREEN, m.graphics_unusable) {
        let len = m.screen.cols() * m.screen.rows() * 2;
        crate::mm::mmu::map_device(addr, addr + len);
        // SAFETY: the legacy VGA text buffer, decoded by the display
        // controller found above, mapped as device memory just now; only
        // this module accesses it, under MIRROR's lock.
        let vram = unsafe { Region::new(addr, len) };
        (Out::Text(vram), ("VGA text", addr as u64, 80, 25))
    } else {
        m.off = true;
        drop(m);
        println!("  screen          : none (graphics mode the console cannot draw on)");
        return;
    };
    m.out = Some(out);
    m.screen.mark_all_dirty();
    m.flush();
    let (cols, rows) = (m.screen.cols(), m.screen.rows());
    drop(m);
    let (kind, addr, w, h) = what;
    println!(
        "  screen          : {} {kind} {w}x{h} at {addr:#x}, console {cols}x{rows}",
        dev.df
    );
}
