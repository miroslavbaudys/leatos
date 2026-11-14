//! Async executor with strict priority classes, one run loop per core
//! (tasks are pinned: `spawn_on`; a wakeup from another core sends a wake IPI).
//!
//! - [`Priority::Datapath`] tasks (RX → forward → qdisc → TX) always run
//!   before [`Priority::Service`] tasks (DNS, DHCP, CLI…). After every poll
//!   the executor checks the datapath queue again, so a service task can only
//!   delay the datapath by the length of **one poll**. Keep polls short.
//!   Datapath tasks must yield after a bounded batch, or they starve services.
//! - Wakers may only be called from thread context (never from IRQ
//!   handlers); handlers signal an `irq::IrqEvent`, which the executor loop
//!   turns into a wakeup.
//! - Idle: mask IRQs, re-check for work, `wfi`, unmask. A pending interrupt
//!   always ends `wfi` even while masked, so no wakeup is lost. With a
//!   hybrid-idle spin window (`timer::set_spin_window`), a deadline that is
//!   close is spun out with IRQs enabled instead.

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
    name: &'static str,
    prio: Priority,
    /// The core whose executor polls this task (`spawn_on`).
    core: usize,
    /// Timer ticks spent in this task's polls.
    busy: AtomicU64,
    queued: AtomicBool,
    future: Mutex<Option<BoxFuture>>,
}

const CORES: usize = crate::smp::MAX_CORES;

/// Every task ever spawned (for per-task CPU time).
static TASKS: Mutex<alloc::vec::Vec<Arc<Task>>> = Mutex::new(alloc::vec::Vec::new());
/// Run queues per core and priority class.
static QUEUES: [[Mutex<VecDeque<Arc<Task>>>; CLASSES]; CORES] =
    [const { [const { Mutex::new(VecDeque::new()) }; CLASSES] }; CORES];

/// Per-core counters.
struct CoreStats {
    polls: AtomicU64,
    idle_waits: AtomicU64,
    idle_spins: AtomicU64,
    spin_ticks: AtomicU64,
    /// Timer ticks spent in `wfi`/`hlt` (on x86_64 including the IRQ
    /// handlers, which run inside `sti; hlt`; on aarch64 they run after it).
    wait_ticks: AtomicU64,
    /// When the current `wfi`/`hlt` began (0 = not waiting), so a long wait
    /// counts as idle before it ends.
    wait_since: AtomicU64,
    /// Timer ticks spent polling tasks, per priority class.
    poll_ticks: [AtomicU64; CLASSES],
}

static STATS: [CoreStats; CORES] = [const {
    CoreStats {
        polls: AtomicU64::new(0),
        idle_waits: AtomicU64::new(0),
        idle_spins: AtomicU64::new(0),
        spin_ticks: AtomicU64::new(0),
        wait_ticks: AtomicU64::new(0),
        wait_since: AtomicU64::new(0),
        poll_ticks: [const { AtomicU64::new(0) }; CLASSES],
    }
}; CORES];

/// Cumulative CPU time accounting of one core in timer ticks (`cpuload`
/// takes the differences).
#[derive(Clone, Copy, Debug)]
pub struct CpuTicks {
    /// When the snapshot was taken.
    pub at: u64,
    /// Waiting: `wfi`/`hlt` plus hybrid-idle spinning.
    pub idle: u64,
    pub datapath: u64,
    pub service: u64,
}

/// Each task's name, core and the timer ticks its polls took so far.
pub fn task_ticks(mut f: impl FnMut(&'static str, usize, u64)) {
    for t in TASKS.lock().iter() {
        f(t.name, t.core, t.busy.load(Ordering::Relaxed));
    }
}

/// CPU time of `core`.
pub fn cpu_ticks(core: usize) -> CpuTicks {
    let s = &STATS[core];
    let at = timer::ticks();
    let since = s.wait_since.load(Ordering::Acquire);
    let ongoing = if since != 0 {
        at.saturating_sub(since)
    } else {
        0
    };
    CpuTicks {
        at,
        idle: s.wait_ticks.load(Ordering::Relaxed) + s.spin_ticks.load(Ordering::Relaxed) + ongoing,
        datapath: s.poll_ticks[Priority::Datapath as usize].load(Ordering::Relaxed),
        service: s.poll_ticks[Priority::Service as usize].load(Ordering::Relaxed),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Stats {
    pub polls: u64,
    /// Idle periods spent in `wfi`.
    pub idle_waits: u64,
    /// Idle periods spun out (hybrid idle) and the total time spent spinning.
    pub idle_spins: u64,
    pub spin_time: core::time::Duration,
}

impl Wake for Task {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        if !self.queued.swap(true, Ordering::AcqRel) {
            QUEUES[self.core][self.prio as usize]
                .lock()
                .push_back(self.clone());
            // Another core may sit in `wfi`: the IPI ends it.
            crate::smp::wake(self.core);
        }
    }
}

/// Spawn a task on the boot core. It is polled the next time that core's
/// executor runs.
pub fn spawn(prio: Priority, name: &'static str, fut: impl Future<Output = ()> + Send + 'static) {
    spawn_on(0, prio, name, fut);
}

/// Spawn a task pinned to `core` (must be online, or 0).
pub fn spawn_on(
    core: usize,
    prio: Priority,
    name: &'static str,
    fut: impl Future<Output = ()> + Send + 'static,
) {
    assert!(
        core < crate::smp::online(),
        "spawn_on: core {core} is not online"
    );
    let task = Arc::new(Task {
        name,
        prio,
        core,
        busy: AtomicU64::new(0),
        queued: AtomicBool::new(true),
        future: Mutex::new(Some(Box::pin(fut))),
    });
    TASKS.lock().push(task.clone());
    QUEUES[core][prio as usize].lock().push_back(task);
    crate::smp::wake(core);
}

fn pop(core: usize) -> Option<Arc<Task>> {
    QUEUES[core].iter().find_map(|q| q.lock().pop_front())
}

fn has_work(core: usize) -> bool {
    timer::pending()
        || irq::has_pending_wakeups()
        || QUEUES[core].iter().any(|q| !q.lock().is_empty())
}

fn poll_task(core: usize, task: Arc<Task>) {
    task.queued.store(false, Ordering::Release);
    let waker = Waker::from(task.clone());
    let mut cx = Context::from_waker(&waker);
    let mut slot = task.future.lock();
    if let Some(fut) = slot.as_mut() {
        let s = &STATS[core];
        s.polls.fetch_add(1, Ordering::Relaxed);
        let t0 = timer::ticks();
        let done = fut.as_mut().poll(&mut cx).is_ready();
        let dt = timer::ticks() - t0;
        s.poll_ticks[task.prio as usize].fetch_add(dt, Ordering::Relaxed);
        task.busy.fetch_add(dt, Ordering::Relaxed);
        if done {
            *slot = None; // completed; drop the future now
        }
    }
}

/// Counters for diagnostics (all cores).
pub fn stats() -> Stats {
    let sum = |f: fn(&CoreStats) -> &AtomicU64| -> u64 {
        STATS.iter().map(|s| f(s).load(Ordering::Relaxed)).sum()
    };
    Stats {
        polls: sum(|s| &s.polls),
        idle_waits: sum(|s| &s.idle_waits),
        idle_spins: sum(|s| &s.idle_spins),
        spin_time: timer::ticks_to_duration(sum(|s| &s.spin_ticks)),
    }
}

/// Run this core's tasks forever.
pub fn run() -> ! {
    let core = crate::smp::current();
    let s = &STATS[core];
    loop {
        // Deferred interrupt work first: timer expiries and device events → wakeups.
        timer::process();
        irq::wake_fired();

        if let Some(task) = pop(core) {
            poll_task(core, task);
            continue;
        }

        irq::disable();
        if !has_work(core) {
            // Hybrid idle: a deadline within the spin window is waited for
            // by spinning with IRQs enabled (precise), not by `wfi` (which
            // some hypervisors end milliseconds late).
            if let Some(deadline) = timer::spin_until() {
                irq::enable();
                let t0 = timer::ticks();
                while !has_work(core) && timer::ticks() < deadline {
                    core::hint::spin_loop();
                }
                s.idle_spins.fetch_add(1, Ordering::Relaxed);
                s.spin_ticks
                    .fetch_add(timer::ticks() - t0, Ordering::Relaxed);
                continue;
            }
            s.idle_waits.fetch_add(1, Ordering::Relaxed);
            #[cfg(not(feature = "idle-poll"))]
            {
                let t0 = timer::ticks();
                s.wait_since.store(t0, Ordering::Release);
                crate::arch::cpu::wait_for_interrupt();
                // Clear first: a snapshot in between undercounts briefly
                // rather than counting the wait twice.
                s.wait_since.store(0, Ordering::Release);
                s.wait_ticks
                    .fetch_add(timer::ticks() - t0, Ordering::Relaxed);
            }
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

/// Run a future to completion outside the executor (boot, before [`run`]).
/// Only for futures that make progress by polling on their own, like the
/// block driver's (`drivers::virtio_blk::VirtioBlk::wait` yields, then
/// polls the device again): nothing here sleeps or waits for a wake-up.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = core::pin::pin!(fut);
    let mut cx = Context::from_waker(core::task::Waker::noop());
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        core::hint::spin_loop();
    }
}
