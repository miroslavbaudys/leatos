//! In-RAM upgrade (x86_64): enter a new kernel the way a Multiboot2 loader
//! would, without firmware. `crate::upgrade` validates and flattens the
//! image into the staging area; [`exec`] then
//!
//! 1. builds Multiboot2 boot information from what this kernel was booted
//!    with (memory map, RSDP and framebuffer, saved by [`save`] during
//!    discovery; the current command line unless the upload gives a new one),
//! 2. builds an identity map of 0..4 GiB without NX (2 MiB pages) and copies
//!    the trampoline (`kexec.S`) into the staging area's scratch page,
//! 3. switches to that map and jumps to the trampoline, which copies the
//!    image over the old kernel, leaves long mode and jumps to the entry.
//!
//! Devices must be quiet before (NICs reset, interrupts off): the caller
//! drops the network interfaces first.

use boot_image::multiboot2::{self, MmapEntry};
use core::arch::asm;
use spin::Once;

pub const SUPPORTED: bool = true;

struct BootFacts {
    mmap: [MmapEntry; crate::platform::pvh::MAX_MMAP],
    mmap_len: usize,
    rsdp: [u8; 36],
    rsdp_len: usize,
    /// The loader's screen: the next kernel draws its console there too.
    framebuffer: Option<multiboot2::Framebuffer>,
}

static FACTS: Once<BootFacts> = Once::new();

/// Is `[start, start + len)` inside one firmware "available RAM" region?
pub(super) fn is_free_ram(start: u64, len: u64) -> bool {
    FACTS.get().is_some_and(|f| {
        f.mmap[..f.mmap_len]
            .iter()
            .any(|&(b, l, t)| t == 1 && b <= start && start + len <= b + l)
    })
}

unsafe extern "C" {
    static kexec_blob_start: u8;
    static kexec_blob_end: u8;
}

/// During discovery: keep the memory map and a copy of the RSDP (firmware
/// memory is unmapped later).
pub(super) fn save(mmap: &[MmapEntry], rsdp: &[u8], framebuffer: Option<multiboot2::Framebuffer>) {
    FACTS.call_once(|| {
        let mut f = BootFacts {
            mmap: [(0, 0, 0); crate::platform::pvh::MAX_MMAP],
            mmap_len: mmap.len().min(crate::platform::pvh::MAX_MMAP),
            rsdp: [0; 36],
            rsdp_len: rsdp.len().min(36),
            framebuffer,
        };
        f.mmap[..f.mmap_len].copy_from_slice(&mmap[..f.mmap_len]);
        f.rsdp[..f.rsdp_len].copy_from_slice(&rsdp[..f.rsdp_len]);
        f
    });
}

const SCRATCH_TABLES: usize = 0;
const SCRATCH_TRAMPOLINE: usize = 6 * 4096;
const SCRATCH_INFO: usize = 8 * 4096;
/// Scratch space [`exec`] needs (page tables, trampoline, boot information).
pub const SCRATCH_SIZE: usize = SCRATCH_INFO + 64 * 1024;

/// Copy `flat` to physical `dst`, enter it at `entry` with `cmdline`.
/// `scratch`: [`SCRATCH_SIZE`] bytes, page aligned, below 4 GiB, outside
/// `[dst, dst + flat.len())` and outside `flat`.
pub fn exec(flat: &[u8], dst: u64, entry: u64, cmdline: &str, scratch: &mut [u8]) -> ! {
    let base = scratch.as_ptr() as u64;
    assert!(scratch.len() >= SCRATCH_SIZE && base.is_multiple_of(4096));
    assert!(base + SCRATCH_SIZE as u64 <= 1 << 32 && entry < 1 << 32);
    assert!(
        flat.as_ptr() as u64 > dst,
        "kexec: source must lie above the destination"
    );
    let facts = FACTS.get().expect("kexec: boot facts not saved");

    let info = multiboot2::build_info(
        cmdline,
        &facts.mmap[..facts.mmap_len],
        &facts.rsdp[..facts.rsdp_len],
        facts.framebuffer.as_ref(),
    );
    assert!(
        info.len() <= SCRATCH_SIZE - SCRATCH_INFO,
        "kexec: boot info too large"
    );
    scratch[SCRATCH_INFO..SCRATCH_INFO + info.len()].copy_from_slice(&info);

    // Identity map 0..4 GiB, 2 MiB pages, present | writable | PS, no NX.
    let tables = &mut scratch[SCRATCH_TABLES..SCRATCH_TRAMPOLINE];
    tables.fill(0);
    let put =
        |t: &mut [u8], i: usize, v: u64| t[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    put(tables, 0, (base + 0x1000) | 3); // PML4[0] -> PDPT
    for i in 0..4 {
        put(
            &mut tables[0x1000..],
            i,
            (base + 0x2000 + i as u64 * 0x1000) | 3,
        );
    }
    for i in 0..2048 {
        put(&mut tables[0x2000..], i, (i as u64) << 21 | 0x83);
    }

    let (start, end) = (
        &raw const kexec_blob_start as usize,
        &raw const kexec_blob_end as usize,
    );
    assert!(end - start <= SCRATCH_INFO - SCRATCH_TRAMPOLINE);
    // SAFETY: the trampoline bytes between two labels in .rodata (kexec.S).
    let blob = unsafe { core::slice::from_raw_parts(start as *const u8, end - start) };
    scratch[SCRATCH_TRAMPOLINE..SCRATCH_TRAMPOLINE + blob.len()].copy_from_slice(blob);

    super::cpu::irq_disable();
    super::timer::stop();
    // The serial console's RX interrupt: off at the UART and the IOAPIC
    // (the next kernel programs neither before taking interrupts).
    super::console::rx_irq_off();
    super::irqchip::disable(super::exceptions::COM1_VECTOR);
    super::kbd::irq_off();
    super::irqchip::disable(super::exceptions::KBD_VECTOR);
    crate::println!(
        "  upgrade         : jumping to {entry:#x} ({} bytes at {dst:#x})",
        flat.len()
    );
    // SAFETY: never returns. The new page tables identity-map all of the
    // low 4 GiB, including the code running now (the kernel image), its
    // stack, the staging area and the destination; the trampoline then runs
    // from the staging area and overwrites this kernel, which is fine
    // because nothing of it runs any more. Interrupts are off and the
    // devices are quiet (module docs).
    unsafe {
        asm!(
            "mov cr3, {pt}",
            "jmp {tramp}",
            pt = in(reg) base + SCRATCH_TABLES as u64,
            tramp = in(reg) base + SCRATCH_TRAMPOLINE as u64,
            in("rdi") flat.as_ptr() as u64,
            in("rsi") dst,
            in("rdx") flat.len() as u64,
            in("rcx") entry,
            in("r8") base + SCRATCH_INFO as u64,
            options(noreturn)
        )
    }
}
