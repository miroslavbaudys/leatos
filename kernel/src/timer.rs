//! Tickless high-resolution timers (arch-neutral).
//!
//! There is no periodic tick (CAKE requirement, docs/bufferbloat-cake.md
//! §3.2). The hardware comparator (`CNTV_CVAL_EL0` on aarch64, TSC-deadline on
//! x86_64) is always programmed to the earliest pending deadline, or the timer is switched off when nothing is
//! waiting. Resolution is one counter tick (about 42 ns at 24 MHz under HVF).
//!
//! **Hybrid idle** (docs/bufferbloat-cake.md §3.2): some hypervisors wake
//! an idle vCPU late (macOS HVF: up to ~3 ms after `wfi`). With a non-zero
//! spin window, the comparator is armed `spin_window` *early*; once the next
//! deadline is within the window, the executor spins (IRQs enabled) instead
//! of `wfi`, and the exact-deadline interrupt arrives in microseconds. On
//! real hardware the window is 0: plain tickless `wfi`.
//!
//! IRQ path: the handler only masks the timer, then `FIRED` is signalled.
//! Expired timers are processed and their wakers called by the executor in
//! thread context ([`process`]). The hardware side is `arch::timer`.

use crate::arch::timer as hw;
use crate::irq::{self, IrqEvent, Trigger};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use spin::Mutex;

static BOOT_TICKS: AtomicU64 = AtomicU64::new(0);
static FREQ: AtomicU64 = AtomicU64::new(1);
static TIMER_IRQS: AtomicU64 = AtomicU64::new(0);
static NEXT_ID: AtomicU64 = AtomicU64::new(0);
const CORES: usize = crate::smp::MAX_CORES;
/// Per core: the timer interrupt fired (signalled by [`on_irq`]).
static FIRED: [IrqEvent; CORES] = [const { IrqEvent::new() }; CORES];
/// Per core: earliest pending deadline (ticks), `u64::MAX` if none.
/// Lock-free mirror of the `TIMERS` minimum for the executor's idle decisions.
static NEXT_DEADLINE: [AtomicU64; CORES] = [const { AtomicU64::new(u64::MAX) }; CORES];
static TIMER_INTID: AtomicU64 = AtomicU64::new(0);
/// Hybrid-idle spin window in ticks (0 = disabled).
static SPIN_TICKS: AtomicU64 = AtomicU64::new(0);

/// Pending timers per core, keyed by (deadline in ticks, unique id). A
/// sleep registers on the core that polls it (tasks are pinned), and that
/// core's comparator fires for it. Thread context only.
static TIMERS: [Mutex<BTreeMap<(u64, u64), Waker>>; CORES] =
    [const { Mutex::new(BTreeMap::new()) }; CORES];

fn core() -> usize {
    crate::smp::current()
}

/// Counter frequency in Hz.
pub fn frequency() -> u64 {
    FREQ.load(Ordering::Relaxed)
}

/// Raw counter value.
#[inline]
pub fn ticks() -> u64 {
    hw::ticks()
}

// ---- Time types ----------------------------------------------------------------

/// A point in time (virtual counter ticks since power-on).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl Instant {
    pub fn now() -> Self {
        Instant(ticks())
    }
    pub fn elapsed(self) -> Duration {
        ticks_to_duration(ticks().saturating_sub(self.0))
    }
    pub fn saturating_duration_since(self, earlier: Instant) -> Duration {
        ticks_to_duration(self.0.saturating_sub(earlier.0))
    }
    pub fn checked_add(self, d: Duration) -> Option<Self> {
        self.0.checked_add(duration_to_ticks(d)).map(Instant)
    }
}

/// Duration → ticks, rounded **up** so a sleep never ends early.
pub fn duration_to_ticks(d: Duration) -> u64 {
    let f = FREQ.load(Ordering::Relaxed) as u128;
    (d.as_nanos() * f).div_ceil(1_000_000_000) as u64
}

pub fn ticks_to_duration(t: u64) -> Duration {
    let f = FREQ.load(Ordering::Relaxed) as u128;
    Duration::from_nanos((t as u128 * 1_000_000_000 / f) as u64)
}

/// Time since [`init`].
pub fn uptime() -> Duration {
    ticks_to_duration(ticks() - BOOT_TICKS.load(Ordering::Relaxed))
}

pub fn irq_count() -> u64 {
    TIMER_IRQS.load(Ordering::Relaxed)
}

// ---- Setup and IRQ ---------------------------------------------------------------

/// Start the monotonic clock. Works before the interrupt controller is up.
pub fn init_clock() {
    FREQ.store(hw::frequency(), Ordering::Relaxed);
    BOOT_TICKS.store(ticks(), Ordering::Relaxed);
}

/// Hook the timer interrupt up (requires the interrupt controller).
pub fn init_irq(intid: u32) {
    hw::stop();
    TIMER_INTID.store(intid as u64, Ordering::Relaxed);
    // The per-core `FIRED` flag is raised by `on_irq` itself; the event the
    // dispatcher signals is unused.
    irq::register(intid, on_irq, irq::new_event());
    crate::arch::irqchip::enable(intid, Trigger::Level);
}

/// The timer's interrupt ID (0 before [`init_irq`]).
pub fn intid() -> u32 {
    TIMER_INTID.load(Ordering::Relaxed) as u32
}

/// The same on a secondary core (its own comparator and interrupt).
pub fn init_secondary() {
    hw::stop();
    crate::arch::irqchip::enable(TIMER_INTID.load(Ordering::Relaxed) as u32, Trigger::Level);
}

/// IRQ context: silence this core's level-sensitive timer output.
fn on_irq(_intid: u32) {
    hw::mask_from_irq();
    TIMER_IRQS.fetch_add(1, Ordering::Relaxed);
    FIRED[core()].signal();
}

/// Set the hybrid-idle spin window (0 disables it). See the module docs.
pub fn set_spin_window(d: Duration) {
    SPIN_TICKS.store(duration_to_ticks(d), Ordering::Relaxed);
}

pub fn spin_window() -> Duration {
    ticks_to_duration(SPIN_TICKS.load(Ordering::Relaxed))
}

/// True if [`process`] has work: the timer fired, or the earliest deadline
/// has passed (also covers an interrupt that is late or was missed).
pub fn pending() -> bool {
    let c = core();
    FIRED[c].is_fired() || NEXT_DEADLINE[c].load(Ordering::Acquire) <= ticks()
}

/// If the next deadline is within the spin window, return it: the executor
/// should spin until then instead of sleeping in `wfi`.
pub fn spin_until() -> Option<u64> {
    let d = NEXT_DEADLINE[core()].load(Ordering::Acquire);
    let w = SPIN_TICKS.load(Ordering::Relaxed);
    (d != u64::MAX && w > 0 && d <= ticks().saturating_add(w)).then_some(d)
}

/// Program this core's comparator for the earliest deadline of `c`'s
/// timers (`c` is this core; early by the spin window if it is further
/// away than that), or turn the timer off.
fn program(c: usize, timers: &BTreeMap<(u64, u64), Waker>) {
    match timers.keys().next() {
        Some(&(deadline, _)) => {
            NEXT_DEADLINE[c].store(deadline, Ordering::Release);
            let w = SPIN_TICKS.load(Ordering::Relaxed);
            let early = deadline.saturating_sub(w);
            // Far away: wake early, then spin the rest. Close: exact deadline.
            hw::set_deadline(if early > ticks() { early } else { deadline });
        }
        None => {
            NEXT_DEADLINE[c].store(u64::MAX, Ordering::Release);
            hw::stop();
        }
    }
}

/// Thread context: wake every expired timer and re-arm the comparator.
/// Called by the executor on every loop iteration.
pub fn process() {
    let c = core();
    let fired = FIRED[c].take();
    if !fired && NEXT_DEADLINE[c].load(Ordering::Acquire) > ticks() {
        return;
    }
    let now = ticks();
    let mut expired: Vec<Waker> = Vec::new();
    {
        let mut timers = TIMERS[c].lock();
        while let Some(entry) = timers.first_entry() {
            if entry.key().0 > now {
                break;
            }
            expired.push(entry.remove());
        }
        program(c, &timers);
    }
    // Wake outside the lock.
    for w in expired {
        w.wake();
    }
}

// ---- Sleep future ------------------------------------------------------------------

/// Future returned by [`sleep`] / [`sleep_until`].
pub struct Sleep {
    deadline: u64,
    /// (core whose timer list holds it, key) once registered.
    key: Option<(usize, (u64, u64))>,
}

pub fn sleep(d: Duration) -> Sleep {
    sleep_until(Instant::now().checked_add(d).expect("sleep: overflow"))
}

pub fn sleep_until(deadline: Instant) -> Sleep {
    Sleep {
        deadline: deadline.0,
        key: None,
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if ticks() >= self.deadline {
            if let Some((c, k)) = self.key.take() {
                TIMERS[c].lock().remove(&k);
            }
            return Poll::Ready(());
        }
        let deadline = self.deadline;
        let c = core();
        let (kc, key) = *self
            .key
            .get_or_insert_with(|| (c, (deadline, NEXT_ID.fetch_add(1, Ordering::Relaxed))));
        debug_assert_eq!(kc, c, "sleep polled on another core than it registered on");
        let mut timers = TIMERS[kc].lock();
        timers.insert(key, cx.waker().clone());
        program(kc, &timers);
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some((c, k)) = self.key.take() {
            let mut timers = TIMERS[c].lock();
            // Only this core's comparator can be reprogrammed from here; a
            // stale deadline elsewhere just causes one early wakeup.
            if timers.remove(&k).is_some() && c == core() {
                program(c, &timers);
            }
        }
    }
}
