//! IDT, TSS and the trap handler.
//!
//! - CPU exceptions (vectors 0-31) are fatal: decode, report, halt. #PF,
//!   #DF, NMI and #MC run on IST1 = the dedicated exception stack, so a
//!   kernel stack overflow into the guard page is still reported.
//! - Vectors >= 32 are interrupts: dispatch to `crate::irq`, then EOI the
//!   local APIC (except the spurious vector, which must not be EOI'd).
//! - 224-239: the legacy PICs, remapped there and masked. Only their
//!   spurious IRQ 7/15, or an IRQ latched before masking, can arrive
//!   (real hardware does this right after the first `sti`); it is
//!   acknowledged at the PIC and counted as spurious.

use super::{cpu, irqchip};
use crate::{fatal_println, mm};
use core::arch::asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

core::arch::global_asm!(include_str!("isr.S"), options(att_syntax));

pub const TIMER_VECTOR: u32 = 32;
pub const MSI_VECTORS: core::ops::RangeInclusive<u32> = 48..=63;
pub const SPURIOUS_VECTOR: u32 = 255;
pub const PIC_VECTORS: core::ops::RangeInclusive<u32> = 224..=239;
/// Number of (vector, stub) pairs in isr.S.
const STUBS: usize = 32 + 1 + 16 + 16 + 1;

unsafe extern "C" {
    static isr_vectors: [[u64; 2]; STUBS];
    /// The TSS descriptor slot (selector 0x18) in boot.S's GDT.
    static gdt_tss: [AtomicU64; 2];
}

#[repr(C, align(16))]
struct Idt([AtomicU64; 512]);
static IDT: Idt = Idt([const { AtomicU64::new(0) }; 512]);

/// 104-byte 64-bit TSS; only IST1 and the I/O map base are used.
#[repr(C, align(16))]
struct Tss([AtomicU32; 26]);
static TSS: Tss = Tss([const { AtomicU32::new(0) }; 26]);

#[repr(C, packed)]
struct Dtr {
    limit: u16,
    base: u64,
}

/// Install TSS (IST1 = exception stack) and IDT. Called first thing in
/// 64-bit mode, so even discovery faults are reported.
pub fn init() {
    let ist1 = mm::sym::exc_stack_top() as u64;
    TSS.0[9].store(ist1 as u32, Ordering::Relaxed);
    TSS.0[10].store((ist1 >> 32) as u32, Ordering::Relaxed);
    TSS.0[25].store(104 << 16, Ordering::Relaxed); // I/O map base = limit: no bitmap
    let base = &TSS as *const Tss as u64;
    // SAFETY: `gdt_tss` is a 16-byte slot in boot.S's writable GDT; it is
    // only accessed through atomics.
    let slot = unsafe { &gdt_tss };
    slot[0].store(
        103 | (base & 0xff_ffff) << 16 | 0x89 << 40 | (base >> 24 & 0xff) << 56,
        Ordering::Relaxed,
    );
    slot[1].store(base >> 32, Ordering::Relaxed);
    // SAFETY: selector 0x18 is the TSS descriptor just written.
    unsafe { asm!("ltr {0:x}", in(reg) 0x18u16, options(nostack, preserves_flags)) };

    // SAFETY: `isr_vectors` is constant data in isr.S with exactly STUBS entries.
    let stubs = unsafe { &isr_vectors };
    for &[vector, handler] in stubs {
        let ist = matches!(vector, 2 | 8 | 14 | 18) as u64; // NMI, #DF, #PF, #MC
        let lo = (handler & 0xffff)
            | 0x08 << 16 // kernel code selector
            | ist << 32
            | 0x8e << 40 // present, DPL 0, 64-bit interrupt gate (IF cleared)
            | (handler >> 16 & 0xffff) << 48;
        IDT.0[vector as usize * 2].store(lo, Ordering::Relaxed);
        IDT.0[vector as usize * 2 + 1].store(handler >> 32, Ordering::Relaxed);
    }
    let dtr = Dtr {
        limit: (core::mem::size_of::<Idt>() - 1) as u16,
        base: &IDT as *const Idt as u64,
    };
    // SAFETY: the IDT is a static that lives forever and holds valid gates.
    unsafe { asm!("lidt [{}]", in(reg) &dtr, options(nostack, preserves_flags)) };
}

/// Saved state, in isr.S push order (lowest address first).
#[repr(C)]
pub struct Frame {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
    vector: u64,
    error: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

const NAMES: [&str; 32] = [
    "#DE divide error",
    "#DB debug",
    "NMI",
    "#BP breakpoint",
    "#OF overflow",
    "#BR bound range",
    "#UD invalid opcode",
    "#NM device not available",
    "#DF double fault",
    "coprocessor segment overrun",
    "#TS invalid TSS",
    "#NP segment not present",
    "#SS stack fault",
    "#GP general protection",
    "#PF page fault",
    "reserved",
    "#MF x87 floating point",
    "#AC alignment check",
    "#MC machine check",
    "#XM SIMD floating point",
    "#VE virtualization",
    "#CP control protection",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "#HV hypervisor injection",
    "#VC VMM communication",
    "#SX security",
    "reserved",
];

#[unsafe(no_mangle)]
extern "C" fn x86_trap(f: &mut Frame) {
    let vector = f.vector as u32;
    if vector >= 32 {
        if vector == SPURIOUS_VECTOR {
            crate::irq::note_spurious();
            return;
        }
        if PIC_VECTORS.contains(&vector) {
            irqchip::legacy_pic_ack((vector - PIC_VECTORS.start()) as u8);
            crate::irq::note_spurious();
            return;
        }
        crate::irq::dispatch(vector);
        irqchip::eoi();
        return;
    }
    fatal(f)
}

fn fatal(f: &Frame) -> ! {
    fatal_println!(
        "\n!!! UNHANDLED EXCEPTION: {} (vector {})",
        NAMES[f.vector as usize & 31],
        f.vector
    );
    fatal_println!("    error   = {:#x}", f.error);
    fatal_println!("    RIP     = {:#018x}  (faulting instruction)", f.rip);
    fatal_println!(
        "    RSP     = {:#018x}  RFLAGS {:#x}  CS {:#x}  SS {:#x}",
        f.rsp,
        f.rflags,
        f.cs,
        f.ss
    );
    fatal_println!(
        "    RAX {:#x} RBX {:#x} RCX {:#x} RDX {:#x} RSI {:#x} RDI {:#x} RBP {:#x}",
        f.rax,
        f.rbx,
        f.rcx,
        f.rdx,
        f.rsi,
        f.rdi,
        f.rbp
    );
    fatal_println!(
        "    R8 {:#x} R9 {:#x} R10 {:#x} R11 {:#x} R12 {:#x} R13 {:#x} R14 {:#x} R15 {:#x}",
        f.r8,
        f.r9,
        f.r10,
        f.r11,
        f.r12,
        f.r13,
        f.r14,
        f.r15
    );
    if f.vector == 14 {
        let addr = cpu::cr2();
        let access = if f.error & (1 << 4) != 0 {
            "fetch"
        } else if f.error & (1 << 1) != 0 {
            "write"
        } else {
            "read"
        };
        fatal_println!("    CR2     = {addr:#018x}  (fault address, {access})");
        fatal_println!(
            "    cause   : {}",
            if f.error & 1 != 0 {
                "permission fault"
            } else {
                "translation fault (unmapped)"
            }
        );
        if let Some(what) = mm::mmu::guard_page_name(addr as usize) {
            fatal_println!("    cause   : {what}");
        }
    }
    cpu::halt()
}
