//! Watchdog (roadmap M8): a stuck core resets the machine instead of
//! leaving the router dead until someone power-cycles it.
//!
//! Two layers:
//!
//! 1. **Software, across cores.** Every online core runs a tiny
//!    `watchdog` task (`Priority::Datapath`, once per second: it must
//!    not be starved by a busy but yielding datapath) that records when
//!    it last ran and checks the others. A core not seen for [`STALL`]
//!    is stuck: in one task's poll (an endless loop, a deadlock), with
//!    interrupts masked, or without its timer. The checker reports the
//!    core and the task it is polling and resets (`fatal::die`).
//! 2. **Hardware** (`drivers::watchdog`: QEMU's i6300esb, the apu4's
//!    FCH timer), petted by the checkers only while every core is fresh.
//!    It covers what the first layer cannot: all cores stuck, or one core
//!    only (`cores=1`).
//!
//! A checker that finds its own last run older than [`STALL`] does not
//! accuse anyone: the whole machine was paused (a VM on a sleeping host),
//! and everyone is late together.
//!
//! The hardware timer is armed twice: early ([`arm_early`], right after
//! the probe, before the NICs are brought up or a kernel from the store
//! is entered), so a hang during the rest of the boot resets too; and
//! again in [`start`]. A probe never stops a timer the previous kernel
//! left running (in-RAM upgrade, kernel from the store), it reloads it.
//!
//! Boot arguments: `watchdog=0` turns both layers off (gdb), and
//! `watchdog_secs=N` sets the hardware timeout (default 30 s).

use crate::drivers::watchdog::HwWatchdog;
use crate::executor::{self, Priority};
use crate::{config, fatal_println, println, smp, timer};
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use spin::Mutex;

/// A core not seen for this long is stuck.
pub const STALL: Duration = Duration::from_secs(5);
const PERIOD: Duration = Duration::from_secs(1);
const CORES: usize = smp::MAX_CORES;

/// Per core: when its checker last ran (timer ticks; 0 = not yet).
static LAST_SEEN: [AtomicU64; CORES] = [const { AtomicU64::new(0) }; CORES];
static HW: Mutex<Option<Box<dyn HwWatchdog>>> = Mutex::new(None);
static FIRED: AtomicBool = AtomicBool::new(false);

/// What the status page shows.
#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub enabled: bool,
    pub hw: Option<&'static str>,
    pub hw_secs: u32,
    /// The previous reset was the hardware watchdog's.
    pub fired_last_boot: bool,
}

static STATUS: spin::Once<Status> = spin::Once::new();

pub fn status() -> Option<Status> {
    STATUS.get().copied()
}

/// Arm the hardware timer right after its probe (unless `watchdog=0`):
/// nothing pets it until [`start`], so the rest of the boot must take
/// less than the timeout.
pub fn arm_early(hw: &mut Option<Box<dyn HwWatchdog>>) {
    let cfg = config::watchdog();
    if cfg.enabled
        && let Some(w) = hw.as_mut()
    {
        w.start(cfg.hw_secs);
    }
}

/// Arm the hardware watchdog (if any) and start one checker per online
/// core. Call once, after the other tasks are spawned, just before
/// `executor::run`.
pub fn start(hw: Option<Box<dyn HwWatchdog>>) {
    let cfg = config::watchdog();
    let fired = hw.as_ref().is_some_and(|w| w.fired_last_boot());
    FIRED.store(fired, Ordering::Relaxed);
    let st = Status {
        enabled: cfg.enabled,
        hw: hw.as_ref().map(|w| w.name()),
        hw_secs: cfg.hw_secs,
        fired_last_boot: fired,
    };
    STATUS.call_once(|| st);
    let last = if fired {
        " (last reset: by the watchdog)"
    } else {
        ""
    };
    if !cfg.enabled {
        // The previous kernel may have left it running (the probe keeps it).
        if let Some(mut w) = hw {
            w.stop();
        }
        println!("  watchdog        : off (watchdog=0){last}");
        return;
    }
    let online = smp::online();
    match hw {
        Some(mut w) => {
            w.start(cfg.hw_secs);
            println!(
                "  watchdog        : {} {} s + cross-core check ({} core(s), stall {} s){last}",
                w.name(),
                cfg.hw_secs,
                online,
                STALL.as_secs()
            );
            *HW.lock() = Some(w);
        }
        None => println!(
            "  watchdog        : software only ({} core(s), stall {} s; no hardware timer){last}",
            online,
            STALL.as_secs()
        ),
    }
    let now = timer::ticks();
    for (core, seen) in LAST_SEEN.iter().enumerate().take(online) {
        seen.store(now, Ordering::Relaxed);
        executor::spawn_on(core, Priority::Datapath, "watchdog", check(core));
    }
}

/// Stop the hardware timer before a deliberate reset or kernel switch,
/// so a slow firmware boot is not cut short. The software checkers die
/// with the cores.
pub fn stop() {
    // Never wait: this runs on the way down, maybe with a core stuck
    // while holding the lock.
    if let Some(mut hw) = HW.try_lock()
        && let Some(w) = hw.as_mut()
    {
        w.stop();
    }
}

/// Restart the hardware countdown now: right before entering a new kernel
/// in RAM, which then has the full timeout to boot and take over (its
/// probe reloads the timer, `start` arms it again). A new kernel that
/// hangs on the way is reset.
pub fn pet_now() {
    if let Some(mut hw) = HW.try_lock()
        && let Some(w) = hw.as_mut()
    {
        w.pet();
    }
}

async fn check(core: usize) {
    let stall = timer::duration_to_ticks(STALL);
    loop {
        let now = timer::ticks();
        let mine = LAST_SEEN[core].swap(now, Ordering::AcqRel);
        // Paused as a whole (see the module docs): nobody is to blame.
        let i_was_late = now.saturating_sub(mine) > stall;
        let mut healthy = true;
        for (other, seen) in LAST_SEEN.iter().enumerate().take(smp::online()) {
            let seen = seen.load(Ordering::Acquire);
            if other == core || seen == 0 {
                continue;
            }
            let late = now.saturating_sub(seen);
            if late > stall {
                healthy = false;
                if !i_was_late {
                    stalled(other, late);
                }
            }
        }
        if healthy
            && let Some(mut hw) = HW.try_lock()
            && let Some(w) = hw.as_mut()
        {
            w.pet();
        }
        timer::sleep(PERIOD).await;
    }
}

fn stalled(core: usize, late_ticks: u64) -> ! {
    crate::fatal::enter();
    let late = timer::ticks_to_duration(late_ticks);
    fatal_println!(
        "\n!!! WATCHDOG: core {core} stalled for {}.{} s (in task \"{}\", noticed by core {})",
        late.as_secs(),
        late.subsec_millis() / 100,
        executor::polling(core).unwrap_or("-"),
        smp::current()
    );
    crate::fatal::die()
}
