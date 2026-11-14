//! CPU load history for the management page: once a second, how much of
//! the last second core 0 was busy, split into datapath polls, service
//! polls and the rest (IRQ handling, timers, the executor itself).
//!
//! "Datapath" is the `net` task, which also runs DHCP, DNS and the web
//! interface; "service" is the service-priority tasks.
//!
//! The executor accounts the time ([`executor::cpu_ticks`]): idle = time
//! in `wfi`/`hlt` plus hybrid-idle spinning (waiting, not work), and the
//! duration of every task poll per priority. With the `idle-poll` feature
//! the core never idles, so it shows as fully busy (by design).

use crate::executor::{self, CpuTicks, Priority};
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

struct History {
    buf: [Sample; HISTORY],
    /// Next slot to write.
    head: usize,
    len: usize,
}

static HIST: Mutex<History> = Mutex::new(History {
    buf: [Sample {
        busy: 0,
        datapath: 0,
        service: 0,
    }; HISTORY],
    head: 0,
    len: 0,
});

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

/// Oldest first.
pub fn history(mut f: impl FnMut(Sample)) {
    let h = HIST.lock();
    let start = (h.head + HISTORY - h.len) % HISTORY;
    for i in 0..h.len {
        f(h.buf[(start + i) % HISTORY]);
    }
}

/// The sampling task (service priority; it only takes a snapshot).
pub async fn sampler() {
    let mut last = executor::cpu_ticks();
    loop {
        timer::sleep(INTERVAL).await;
        let now = executor::cpu_ticks();
        let s = sample(&last, &now);
        last = now;
        let mut h = HIST.lock();
        let head = h.head;
        h.buf[head] = s;
        h.head = (head + 1) % HISTORY;
        h.len = (h.len + 1).min(HISTORY);
    }
}

pub fn spawn() {
    executor::spawn(Priority::Service, "cpuload", sampler());
}
