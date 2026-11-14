//! Multicore bring-up (docs/smp.md, roadmap M11).
//!
//! Core 0 boots alone. After the heap, MMU, interrupt controller and timer
//! are up, [`start`] starts up to [`MAX_CORES`] − 1 further cores (capped
//! by the boot argument `cores=N`) through the arch backend (aarch64: PSCI
//! `CPU_ON`; x86_64: INIT-SIPI-SIPI). Each enters [`secondary_main`] with
//! the MMU on and its own stacks (linker script: `__ap_stacks`, guard
//! pages unmapped), sets up its interrupt controller interface and timer,
//! and runs its own executor loop.
//!
//! Tasks are pinned to a core (`executor::spawn_on`); a wakeup for a task
//! on another core sends that core a wake IPI. [`stop_others`] halts the
//! other cores (panic, upgrade).

use crate::platform::BootInfo;
use crate::{arch, executor, irq, mm, println, timer};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::time::Duration;

/// Most cores rrouter uses (the apu4 has 4).
pub const MAX_CORES: usize = 4;
/// The wake/stop IPI: SGI 0 on aarch64, a fixed vector on x86_64.
static ONLINE: AtomicUsize = AtomicUsize::new(1);
static STOP: AtomicBool = AtomicBool::new(false);

/// This core's index (0 = the boot core).
#[inline]
pub fn current() -> usize {
    arch::cpu::core_id()
}

/// Cores running (1 until [`start`]).
pub fn online() -> usize {
    ONLINE.load(Ordering::Acquire)
}

/// IRQ context: a wake IPI only needs to end `wfi`; a stop IPI halts.
fn on_ipi(_intid: u32) {
    if STOP.load(Ordering::Acquire) {
        // Not `halt`: in smoke builds that powers off, and the core that
        // stopped us may still be reporting or about to reset.
        arch::cpu::park();
    }
}

/// Start the other cores. Call once on core 0 after `irqchip::init` and
/// `timer::init_irq`, before tasks are spawned on other cores.
pub fn start(info: &BootInfo) {
    let ipi = arch::irqchip::IPI_INTID;
    irq::register(ipi, on_ipi, irq::new_event());
    arch::irqchip::enable(ipi, irq::Trigger::Edge);

    let wanted = info
        .cpus
        .min(MAX_CORES)
        .min(crate::config::cores().unwrap_or(MAX_CORES))
        .max(1);
    for (core, &hw_id) in info.cpu_ids.iter().enumerate().take(wanted).skip(1) {
        let (exc_top, stack_top) = mm::stacks::secondary(core);
        if let Err(e) = arch::smp::start(core, hw_id, exc_top, stack_top) {
            println!("  smp             : core {core} did not start: {e}");
            break;
        }
        let deadline = timer::Instant::now()
            .checked_add(Duration::from_millis(500))
            .unwrap();
        while online() <= core {
            if timer::Instant::now() >= deadline {
                println!("  smp             : core {core} did not come online");
                break;
            }
            core::hint::spin_loop();
        }
        if online() <= core {
            break;
        }
    }
    println!(
        "  smp             : {} of {} core(s) online{}",
        online(),
        info.cpus,
        if wanted < info.cpus.min(MAX_CORES) {
            " (cores= limit)"
        } else {
            ""
        }
    );
}

/// Entry of every secondary core (called by the arch backend with the MMU
/// on, this core's stacks and exception vectors set, IRQs masked).
pub fn secondary_main(core: usize) -> ! {
    arch::irqchip::init_secondary();
    arch::irqchip::enable(arch::irqchip::IPI_INTID, irq::Trigger::Edge);
    timer::init_secondary();
    ONLINE.fetch_add(1, Ordering::AcqRel);
    debug_assert_eq!(current(), core);
    irq::enable();
    executor::run()
}

/// Wake `core` from `wfi` (its executor then finds the queued task).
pub fn wake(core: usize) {
    if core != current() {
        arch::irqchip::send_ipi(core);
    }
}

/// Halt every other core (panic; before replacing the kernel in RAM).
pub fn stop_others() {
    STOP.store(true, Ordering::Release);
    let me = current();
    for core in 0..online() {
        if core != me {
            arch::irqchip::send_ipi(core);
        }
    }
}
