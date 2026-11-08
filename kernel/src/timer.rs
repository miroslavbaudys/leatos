//! Tickless high-resolution timers on the ARM generic *virtual* timer.
//!
//! There is no periodic tick (CAKE requirement, docs/bufferbloat-cake.md
//! §3.2). The comparator `CNTV_CVAL_EL0` is always programmed to the
//! earliest pending deadline, or the timer is switched off when nothing is
//! waiting. Resolution is one counter tick (about 42 ns at 24 MHz under HVF).
//!
//! IRQ path: the handler only masks the timer and sets `FIRED`. Expired
//! timers are processed and their wakers called by the executor in thread
//! context ([`process`]).

use crate::{gic, irq};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::arch::asm;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use spin::Mutex;

const CTL_ENABLE: u64 = 1 << 0;
const CTL_IMASK: u64 = 1 << 1;

static BOOT_TICKS: AtomicU64 = AtomicU64::new(0);
static FREQ: AtomicU64 = AtomicU64::new(1);
static FIRED: AtomicBool = AtomicBool::new(false);
static TIMER_IRQS: AtomicU64 = AtomicU64::new(0);
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// Pending timers, keyed by (deadline in ticks, unique id). Thread context only.
static TIMERS: Mutex<BTreeMap<(u64, u64), Waker>> = Mutex::new(BTreeMap::new());

// ---- Raw counter access --------------------------------------------------------

/// Counter frequency in Hz (CNTFRQ_EL0).
pub fn frequency() -> u64 {
    let f: u64;
    // SAFETY: reading CNTFRQ_EL0 has no side effects.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
    f
}

/// Raw virtual counter value (CNTVCT_EL0).
#[inline]
pub fn ticks() -> u64 {
    let t: u64;
    // SAFETY: `isb` + reading CNTVCT_EL0 has no side effects.
    unsafe { asm!("isb", "mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack)) };
    t
}

fn write_ctl(v: u64) {
    // SAFETY: CNTV_CTL_EL0 only controls the EL1 virtual timer.
    unsafe { asm!("msr cntv_ctl_el0, {}", "isb", in(reg) v, options(nomem, nostack)) };
}

fn write_cval(v: u64) {
    // SAFETY: CNTV_CVAL_EL0 only sets the virtual timer comparator.
    unsafe { asm!("msr cntv_cval_el0, {}", in(reg) v, options(nomem, nostack)) };
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

/// Start the monotonic clock. Works without the GIC.
pub fn init_clock() {
    FREQ.store(frequency().max(1), Ordering::Relaxed);
    BOOT_TICKS.store(ticks(), Ordering::Relaxed);
}

/// Hook the virtual timer interrupt up (requires the GIC).
pub fn init_irq(intid: u32) {
    write_ctl(0);
    irq::register(intid, on_irq);
    gic::enable_ppi(intid);
}

/// IRQ context: mask the (level-sensitive) timer output and flag the executor.
fn on_irq(_intid: u32) {
    write_ctl(CTL_ENABLE | CTL_IMASK);
    TIMER_IRQS.fetch_add(1, Ordering::Relaxed);
    FIRED.store(true, Ordering::Release);
}

/// True if the timer fired and [`process`] has work to do.
pub fn pending() -> bool {
    FIRED.load(Ordering::Acquire)
}

/// Program the comparator for the earliest deadline, or turn the timer off.
fn program(timers: &BTreeMap<(u64, u64), Waker>) {
    match timers.keys().next() {
        Some(&(deadline, _)) => {
            write_cval(deadline);
            write_ctl(CTL_ENABLE); // unmasked; fires immediately if already due
        }
        None => write_ctl(0),
    }
}

/// Thread context: wake every expired timer and re-arm the comparator.
/// Called by the executor on every loop iteration.
pub fn process() {
    if !FIRED.swap(false, Ordering::AcqRel) {
        return;
    }
    let now = ticks();
    let mut expired: Vec<Waker> = Vec::new();
    {
        let mut timers = TIMERS.lock();
        while let Some(entry) = timers.first_entry() {
            if entry.key().0 > now {
                break;
            }
            expired.push(entry.remove());
        }
        program(&timers);
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
    key: Option<(u64, u64)>,
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
            if let Some(k) = self.key.take() {
                TIMERS.lock().remove(&k);
            }
            return Poll::Ready(());
        }
        let deadline = self.deadline;
        let key = *self
            .key
            .get_or_insert_with(|| (deadline, NEXT_ID.fetch_add(1, Ordering::Relaxed)));
        let mut timers = TIMERS.lock();
        timers.insert(key, cx.waker().clone());
        program(&timers);
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(k) = self.key.take() {
            let mut timers = TIMERS.lock();
            if timers.remove(&k).is_some() {
                program(&timers);
            }
        }
    }
}
