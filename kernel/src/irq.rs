//! Arch-neutral interrupt dispatch and IRQ → executor signalling.
//!
//! Handler rules (see CLAUDE.md): an IRQ action may only touch hardware
//! (acknowledge or mask the source) and atomics. No allocation, no
//! `println!`, no locks also taken in thread context (except locks that
//! thread context always takes with IRQs masked, like the irqchip lock).
//! Work happens in tasks waiting on an [`IrqEvent`].

use crate::arch;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::{Mutex, Once};

pub const MAX_INTID: usize = 1020;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    Level,
    #[allow(dead_code)] // MSI-style and edge SPIs (x86 port, ITS)
    Edge,
}

/// A flag raised in IRQ context and awaited by a task.
pub struct IrqEvent {
    fired: AtomicBool,
    /// Touched only in thread context.
    waker: Mutex<Option<Waker>>,
}

impl IrqEvent {
    pub const fn new() -> Self {
        Self {
            fired: AtomicBool::new(false),
            waker: Mutex::new(None),
        }
    }

    /// IRQ-safe: mark the event as fired.
    pub fn signal(&self) {
        self.fired.store(true, Ordering::Release);
    }

    /// Consume the flag (thread context).
    pub fn take(&self) -> bool {
        self.fired.swap(false, Ordering::AcqRel)
    }

    pub fn is_fired(&self) -> bool {
        self.fired.load(Ordering::Acquire)
    }

    /// Poll-style wait: `Ready` (and consumed) if fired, otherwise registers
    /// the task's waker. For tasks waiting on several events at once.
    pub fn poll_wait(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.take() {
            return Poll::Ready(());
        }
        *self.waker.lock() = Some(cx.waker().clone());
        // Re-check: the IRQ may have fired between `take` and storing the waker.
        if self.take() {
            self.waker.lock().take();
            return Poll::Ready(());
        }
        Poll::Pending
    }

    /// Like [`Self::poll_wait`] but does **not** consume the flag: the caller
    /// decides which event to handle afterwards (via [`Self::take`]).
    pub fn poll_fired(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.is_fired() {
            return Poll::Ready(());
        }
        *self.waker.lock() = Some(cx.waker().clone());
        if self.is_fired() {
            self.waker.lock().take();
            return Poll::Ready(());
        }
        Poll::Pending
    }

    /// Wait until the event fires, then consume it.
    #[allow(dead_code)] // single-event waiters (future drivers)
    pub fn wait(&'static self) -> impl Future<Output = ()> {
        struct Wait(&'static IrqEvent);
        impl Future for Wait {
            type Output = ();
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                self.0.poll_wait(cx)
            }
        }
        Wait(self)
    }
}

struct Entry {
    action: fn(u32),
    event: &'static IrqEvent,
}

static HANDLERS: [Once<Entry>; MAX_INTID] = [const { Once::new() }; MAX_INTID];
/// Every registered event, for the executor's wake-up scan.
static EVENTS: Mutex<Vec<&'static IrqEvent>> = Mutex::new(Vec::new());
static IRQ_COUNT: AtomicU64 = AtomicU64::new(0);
/// Device interrupts per core (not the timer, not the wake IPI): shows where
/// NIC interrupts are delivered (`smp`, M11).
static DEV_IRQS: [AtomicU64; crate::smp::MAX_CORES] =
    [const { AtomicU64::new(0) }; crate::smp::MAX_CORES];
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

/// Register an interrupt: in IRQ context `action` runs (to ack/mask the
/// source) and then `event` is signalled. Each INTID can be registered once.
/// Does not enable the interrupt in the controller.
pub fn register(intid: u32, action: fn(u32), event: &'static IrqEvent) {
    let mut first = false;
    HANDLERS[intid as usize].call_once(|| {
        first = true;
        Entry { action, event }
    });
    assert!(first, "irq: intid {intid} registered twice");
}

/// Allocate an event that lives forever: one per device/IRQ source
/// ([`register`]), or a wakeup between tasks (`signal` from thread
/// context). Either way the executor delivers it ([`wake_fired`]).
pub fn new_event() -> &'static IrqEvent {
    let ev: &'static IrqEvent = Box::leak(Box::new(IrqEvent::new()));
    EVENTS.lock().push(ev);
    ev
}

/// Called by the arch IRQ entry for each acknowledged interrupt.
pub fn dispatch(intid: u32) {
    IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
    if intid != arch::irqchip::IPI_INTID && intid != crate::timer::intid() {
        DEV_IRQS[crate::smp::current()].fetch_add(1, Ordering::Relaxed);
    }
    match HANDLERS.get(intid as usize).and_then(Once::get) {
        Some(e) => {
            (e.action)(intid);
            e.event.signal();
        }
        // Unexpected interrupt: disable it so it cannot storm.
        None => arch::irqchip::disable(intid),
    }
}

pub fn note_spurious() {
    SPURIOUS.fetch_add(1, Ordering::Relaxed);
}

/// Thread context: wake the tasks waiting on fired events.
pub fn wake_fired() {
    for ev in EVENTS.lock().iter() {
        if ev.is_fired()
            && let Some(w) = ev.waker.lock().take()
        {
            w.wake();
        }
    }
}

/// Is any fired event waiting to be delivered to a task?
pub fn has_pending_wakeups() -> bool {
    EVENTS
        .lock()
        .iter()
        .any(|ev| ev.is_fired() && ev.waker.lock().is_some())
}

/// Device interrupts handled on `core`.
pub fn dev_irqs(core: usize) -> u64 {
    DEV_IRQS[core].load(Ordering::Relaxed)
}

/// Total IRQs dispatched / spurious (diagnostics).
pub fn count() -> u64 {
    IRQ_COUNT.load(Ordering::Relaxed)
}
pub fn spurious() -> u64 {
    SPURIOUS.load(Ordering::Relaxed)
}

pub fn enable() {
    arch::cpu::irq_enable();
}
pub fn disable() {
    arch::cpu::irq_disable();
}
