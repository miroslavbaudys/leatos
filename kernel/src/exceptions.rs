//! Exception handling. For now every exception is fatal: `boot.S` vectors
//! jump here with the vector index and syndrome registers, we report and
//! halt. IRQ handling arrives with the GIC driver (milestone M1).

use crate::{arch, console, println};

const VECTORS: [&str; 16] = [
    "sync (EL1, SP0)", "irq (EL1, SP0)", "fiq (EL1, SP0)", "serror (EL1, SP0)",
    "sync (EL1, SPx)", "irq (EL1, SPx)", "fiq (EL1, SPx)", "serror (EL1, SPx)",
    "sync (EL0, A64)", "irq (EL0, A64)", "fiq (EL0, A64)", "serror (EL0, A64)",
    "sync (EL0, A32)", "irq (EL0, A32)", "fiq (EL0, A32)", "serror (EL0, A32)",
];

fn exception_class(ec: u64) -> &'static str {
    match ec {
        0x00 => "unknown",
        0x01 => "WFI/WFE trapped",
        0x07 => "FP/SIMD access trapped",
        0x15 => "SVC (AArch64)",
        0x16 => "HVC (AArch64)",
        0x17 => "SMC (AArch64)",
        0x18 => "MSR/MRS trapped",
        0x20 => "instruction abort (lower EL)",
        0x21 => "instruction abort (same EL)",
        0x22 => "PC alignment fault",
        0x24 => "data abort (lower EL)",
        0x25 => "data abort (same EL)",
        0x26 => "SP alignment fault",
        0x2f => "SError",
        0x3c => "BRK instruction",
        _ => "other",
    }
}

#[unsafe(no_mangle)]
extern "C" fn rust_exception(vector: u64, esr: u64, elr: u64, far: u64) -> ! {
    // SAFETY: fatal path, never returns.
    unsafe { console::force_unlock() };
    let ec = (esr >> 26) & 0x3f;
    println!("\n!!! UNHANDLED EXCEPTION: {}", VECTORS[(vector & 0xf) as usize]);
    println!("    ESR_EL1 = {esr:#018x}  (EC {ec:#04x}: {})", exception_class(ec));
    println!("    ELR_EL1 = {elr:#018x}  (faulting PC)");
    println!("    FAR_EL1 = {far:#018x}  (fault address)");
    arch::halt()
}
