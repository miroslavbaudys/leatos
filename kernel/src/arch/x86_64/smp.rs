//! Secondary cores on x86_64: INIT-SIPI-SIPI into the real-mode
//! trampoline (`boot.S`, copied to [`TRAMPOLINE`] below 1 MiB), which
//! enters long mode on the boot page tables and jumps to `ap_start64`;
//! that switches to the kernel's final tables and stack and calls
//! [`ap_rust`].

use crate::timer;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

/// Physical address of the trampoline (must match `AP_TRAMPOLINE` in boot.S).
const TRAMPOLINE: u64 = 0x8000;

/// [cr3, stack top, core], read by `ap_start64`.
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)] // referenced by name from boot.S
static ap_boot: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

unsafe extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end: u8;
}

fn spin(d: Duration) {
    let end = timer::Instant::now().checked_add(d).unwrap();
    while timer::Instant::now() < end {
        core::hint::spin_loop();
    }
}

/// Copy the trampoline once (the page must be free RAM per the firmware map).
fn install_trampoline() -> Result<(), &'static str> {
    let start = &raw const ap_trampoline_start as usize;
    let len = &raw const ap_trampoline_end as usize - start;
    if !super::kexec::is_free_ram(TRAMPOLINE, 4096) || len > 4096 {
        return Err("no free RAM page at 0x8000 for the trampoline");
    }
    crate::mm::mmu::map_ram_rw(TRAMPOLINE as usize, TRAMPOLINE as usize + 4096);
    // SAFETY: the source is `len` bytes of kernel rodata between the two
    // boot.S labels; the destination is the free, now-mapped RW page at
    // TRAMPOLINE that nothing else uses. They do not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(start as *const u8, TRAMPOLINE as *mut u8, len);
    }
    Ok(())
}

/// Start `core` (APIC ID `hw_id`) on the given stacks.
pub fn start(
    core: usize,
    hw_id: u64,
    _exc_top: usize,
    stack_top: usize,
) -> Result<(), &'static str> {
    if core == 1 {
        install_trampoline()?;
    }
    let root = crate::mm::mmu::root();
    if root >= 1 << 32 {
        return Err("page tables above 4 GiB");
    }
    ap_boot[0].store(root, Ordering::Relaxed);
    ap_boot[1].store(stack_top as u64, Ordering::Relaxed);
    ap_boot[2].store(core as u64, Ordering::Release);
    let id = hw_id as u32;
    super::irqchip::set_apic_id(core, id);
    super::irqchip::send_init(id);
    spin(Duration::from_millis(10));
    for _ in 0..2 {
        super::irqchip::send_sipi(id, (TRAMPOLINE >> 12) as u8);
        spin(Duration::from_micros(200));
    }
    Ok(())
}

/// Called by `ap_start64` on a secondary core (final page tables, own stack).
#[unsafe(no_mangle)]
extern "C" fn ap_rust(core: usize) -> ! {
    super::exceptions::init_secondary(core);
    crate::smp::secondary_main(core)
}

/// Put the stopped secondary cores into wait-for-SIPI (before replacing
/// the kernel in RAM: a halted core would otherwise sit in code that gets
/// overwritten).
pub fn park_others() {
    for core in 1..crate::smp::online() {
        super::irqchip::send_init_core(core);
    }
}
