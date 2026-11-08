//! Exception entry points called from the vector table in `boot.S`.
//!
//! - `rust_irq`: normal IRQ path (on SP_EL1, IRQs masked): acknowledge,
//!   dispatch to `crate::irq`, EOI, until nothing is pending.
//! - `rust_exception`: every other vector is fatal; decode and report, then
//!   halt. Runs on the exception stack, so kernel stack overflows are reported.

use super::irqchip;
use crate::{fatal_println, mm};

#[unsafe(no_mangle)]
extern "C" fn rust_irq() {
    let mut handled_any = false;
    loop {
        let iar = irqchip::ack();
        let intid = iar & 0x00ff_ffff;
        if intid >= 1020 {
            // 1020..=1023: special/spurious, nothing (more) pending.
            if !handled_any {
                crate::irq::note_spurious();
            }
            break;
        }
        handled_any = true;
        crate::irq::dispatch(intid);
        irqchip::eoi(iar);
    }
}

const VECTORS: [&str; 16] = [
    "sync (EL1, SP0)",
    "irq (EL1, SP0)",
    "fiq (EL1, SP0)",
    "serror (EL1, SP0)",
    "sync (EL1, SPx)",
    "irq (EL1, SPx)",
    "fiq (EL1, SPx)",
    "serror (EL1, SPx)",
    "sync (EL0, A64)",
    "irq (EL0, A64)",
    "fiq (EL0, A64)",
    "serror (EL0, A64)",
    "sync (EL0, A32)",
    "irq (EL0, A32)",
    "fiq (EL0, A32)",
    "serror (EL0, A32)",
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

/// Decode the fault status code of an instruction/data abort.
fn fault_status(fsc: u64) -> &'static str {
    match fsc {
        0b000100..=0b000111 => "translation fault (unmapped)",
        0b001000..=0b001011 => "access flag fault",
        0b001100..=0b001111 => "permission fault",
        0b010000 => "synchronous external abort",
        0b100001 => "alignment fault",
        0b110000 => "TLB conflict abort",
        _ => "other fault",
    }
}

#[unsafe(no_mangle)]
extern "C" fn rust_exception(vector: u64, esr: u64, elr: u64, far: u64) -> ! {
    let ec = (esr >> 26) & 0x3f;
    fatal_println!(
        "\n!!! UNHANDLED EXCEPTION: {}",
        VECTORS[(vector & 0xf) as usize]
    );
    fatal_println!(
        "    ESR_EL1 = {esr:#018x}  (EC {ec:#04x}: {})",
        exception_class(ec)
    );
    fatal_println!("    ELR_EL1 = {elr:#018x}  (faulting PC)");
    if matches!(ec, 0x20 | 0x21 | 0x24 | 0x25) {
        let access = match (ec >= 0x24, esr & (1 << 6) != 0) {
            (true, true) => ", write",
            (true, false) => ", read",
            (false, _) => ", fetch",
        };
        fatal_println!("    FAR_EL1 = {far:#018x}  (fault address{access})");
        fatal_println!("    cause   : {}", fault_status(esr & 0x3f));
        if let Some(what) = mm::mmu::guard_page_name(far as usize) {
            fatal_println!("    cause   : {what}");
        }
    }
    super::cpu::halt()
}
