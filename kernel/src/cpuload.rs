//! CPU load history for the management page: once a second, per core, how
//! much of the last second the core was busy, split into datapath polls, service
//! polls and the rest (IRQ handling, timers, the executor itself).
//!
//! "Datapath" is the `net` task (forwarding, CAKE); "service" is the
//! service-priority tasks, mainly `svc` (router stack, DHCP, DNS, web).
//!
//! The CPU temperature's history (`drivers::cputemp`) and the heap use
//! ([`memory_history`]) are sampled here too.
//!
//! The executor accounts the time ([`executor::cpu_ticks`]): idle = time
//! in `wfi`/`hlt` plus hybrid-idle spinning (waiting, not work), and the
//! duration of every task poll per priority. With the `idle-poll` feature
//! the core never idles, so it shows as fully busy (by design).

use crate::executor::{self, CpuTicks, Priority};
use crate::smp::{self, MAX_CORES};
use crate::timer;
use core::time::Duration;
use spin::Mutex;

/// Samples kept: 5 minutes at one per second.
pub const HISTORY: usize = 300;
pub const INTERVAL: Duration = Duration::from_secs(1);

/// One interval, in permille of its duration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    /// Everything but idle.
    pub busy: u16,
    pub datapath: u16,
    pub service: u16,
}

/// The last [`HISTORY`] values of something sampled every [`INTERVAL`].
pub struct Ring<T: Copy> {
    buf: [T; HISTORY],
    /// Next slot to write.
    head: usize,
    len: usize,
}

impl<T: Copy> Ring<T> {
    pub const fn new(zero: T) -> Self {
        Self {
            buf: [zero; HISTORY],
            head: 0,
            len: 0,
        }
    }

    pub fn push(&mut self, x: T) {
        self.buf[self.head] = x;
        self.head = (self.head + 1) % HISTORY;
        self.len = (self.len + 1).min(HISTORY);
    }

    /// Oldest first.
    pub fn for_each(&self, mut f: impl FnMut(T)) {
        let start = (self.head + HISTORY - self.len) % HISTORY;
        for i in 0..self.len {
            f(self.buf[(start + i) % HISTORY]);
        }
    }
}

/// One history per core.
static HIST: [Mutex<Ring<Sample>>; MAX_CORES] = [const {
    Mutex::new(Ring::new(Sample {
        busy: 0,
        datapath: 0,
        service: 0,
    }))
}; MAX_CORES];

/// Heap in use, KiB.
static MEM: Mutex<Ring<u32>> = Mutex::new(Ring::new(0));

fn permille(part: u64, whole: u64) -> u16 {
    (part.min(whole) * 1000).checked_div(whole).unwrap_or(0) as u16
}

/// The load between two snapshots.
fn sample(a: &CpuTicks, b: &CpuTicks) -> Sample {
    let elapsed = b.at.saturating_sub(a.at);
    let idle = b.idle.saturating_sub(a.idle);
    Sample {
        busy: permille(elapsed.saturating_sub(idle), elapsed),
        datapath: permille(b.datapath.saturating_sub(a.datapath), elapsed),
        service: permille(b.service.saturating_sub(a.service), elapsed),
    }
}

/// `core`'s samples, oldest first.
pub fn history(core: usize, f: impl FnMut(Sample)) {
    HIST[core].lock().for_each(f);
}

/// Heap in use (KiB) per interval, oldest first.
pub fn memory_history(f: impl FnMut(u32)) {
    MEM.lock().for_each(f);
}

/// The sampling task (service priority; it only takes a snapshot).
pub async fn sampler() {
    let mut last: [CpuTicks; MAX_CORES] = core::array::from_fn(executor::cpu_ticks);
    loop {
        timer::sleep(INTERVAL).await;
        for (core, prev) in last.iter_mut().enumerate().take(smp::online()) {
            let now = executor::cpu_ticks(core);
            let s = sample(prev, &now);
            *prev = now;
            HIST[core].lock().push(s);
        }
        let (used, _) = crate::mm::heap::usage();
        MEM.lock().push((used >> 10) as u32);
        crate::drivers::cputemp::sample();
    }
}

pub fn spawn() {
    executor::spawn(Priority::Service, "cpuload", sampler());
}
