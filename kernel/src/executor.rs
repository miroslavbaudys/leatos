//! Single-core async executor with strict priority classes.
//!
//! - [`Priority::Datapath`] tasks (RX → forward → qdisc → TX) always run
//!   before [`Priority::Service`] tasks (DNS, DHCP, CLI…). After every poll
//!   the executor checks the datapath queue again, so a service task can only
//!   delay the datapath by the length of **one poll**. Keep polls short.
//!   Datapath tasks must yield after a bounded batch, or they starve services.
//! - Wakers may only be called from thread context (never from IRQ
//!   handlers); handlers set flags that the executor loop turns into wakeups.
//! - Idle: mask IRQs, re-check for work, `wfi`, unmask. A pending interrupt
//!   always ends `wfi` even while masked, so no wakeup is lost.

#[cfg(not(feature = "idle-poll"))]
use crate::arch;
use crate::{irq, timer};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    /// Packet processing: latency-critical.
    Datapath = 0,
    /// Control-plane services.
    Service = 1,
}

const CLASSES: usize = 2;

type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

struct Task {
    #[allow(dead_code)] // for future diagnostics (task listing)
    name: &'static str,
    prio: Priority,
    queued: AtomicBool,
    future: Mutex<Option<BoxFuture>>,
}

static QUEUES: [Mutex<VecDeque<Arc<Task>>>; CLASSES] =
    [const { Mutex::new(VecDeque::new()) }; CLASSES];
static POLLS: AtomicU64 = AtomicU64::new(0);
static IDLE_WAITS: AtomicU64 = AtomicU64::new(0);

impl Wake for Task {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        if !self.queued.swap(true, Ordering::AcqRel) {
            QUEUES[self.prio as usize].lock().push_back(self.clone());
        }
    }
}

/// Spawn a task. It will be polled the next time the executor runs.
pub fn spawn(prio: Priority, name: &'static str, fut: impl Future<Output = ()> + Send + 'static) {
    let task = Arc::new(Task {
        name,
        prio,
        queued: AtomicBool::new(true),
        future: Mutex::new(Some(Box::pin(fut))),
    });
    QUEUES[prio as usize].lock().push_back(task);
}

fn pop() -> Option<Arc<Task>> {
    QUEUES.iter().find_map(|q| q.lock().pop_front())
}

fn has_work() -> bool {
    timer::pending() || QUEUES.iter().any(|q| !q.lock().is_empty())
}

fn poll_task(task: Arc<Task>) {
    task.queued.store(false, Ordering::Release);
    let waker = Waker::from(task.clone());
    let mut cx = Context::from_waker(&waker);
    let mut slot = task.future.lock();
    if let Some(fut) = slot.as_mut() {
        POLLS.fetch_add(1, Ordering::Relaxed);
        if let Poll::Ready(()) = fut.as_mut().poll(&mut cx) {
            *slot = None; // completed; drop the future now
        }
    }
}

/// (polls, idle waits) for diagnostics.
pub fn stats() -> (u64, u64) {
    (
        POLLS.load(Ordering::Relaxed),
        IDLE_WAITS.load(Ordering::Relaxed),
    )
}

/// Run forever.
pub fn run() -> ! {
    loop {
        // Deferred interrupt work first (timer expiries → wakeups).
        timer::process();

        if let Some(task) = pop() {
            poll_task(task);
            continue;
        }

        irq::disable();
        if !has_work() {
            IDLE_WAITS.fetch_add(1, Ordering::Relaxed);
            #[cfg(not(feature = "idle-poll"))]
            arch::wait_for_interrupt();
        }
        irq::enable(); // pending IRQs are taken here
    }
}

/// Yield once, letting other ready tasks run. Note: with strict priorities a
/// yielding datapath task only lets other *datapath* tasks run; to let
/// services run it must actually wait (on I/O or a timer).
#[allow(dead_code)] // used by datapath tasks from M2 on
pub async fn yield_now() {
    struct YieldNow(bool);
    impl Future for YieldNow {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    YieldNow(false).await
}
