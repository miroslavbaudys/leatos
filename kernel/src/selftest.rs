//! Boot-time self-tests. They always run (they are cheap); with the
//! `smoke-test` feature the machine powers off afterwards so
//! `scripts/smoke-test.sh` can check the console output.
//!
//! The `fault-wx` / `fault-stack` features deliberately crash the kernel to
//! prove that W^X and the stack guard page work (see smoke-test.sh).

use crate::executor::{self, Priority};
use crate::psci::Conduit;
use crate::{irq, println, timer};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

static A_TICKS: AtomicU32 = AtomicU32::new(0);
static B_TICKS: AtomicU32 = AtomicU32::new(0);
/// Which class was polled first: 1 = datapath, 2 = service.
static FIRST: AtomicU32 = AtomicU32::new(0);

fn heap_self_test() {
    let v: Vec<u64> = (0..1024).collect();
    assert_eq!(v.iter().sum::<u64>(), 1023 * 1024 / 2);
    let b = Box::new([0xa5u8; 4096]);
    assert!(b.iter().all(|&x| x == 0xa5));
    let mut s = String::new();
    let n = 42;
    let _ = write!(s, "heap-{n}");
    assert_eq!(s, "heap-42");
    println!("  heap self-test  : ok");
}

/// Deliberate faults, compiled in only with the matching feature.
pub fn fault_tests() {
    heap_self_test();

    #[cfg(feature = "fault-wx")]
    {
        println!("fault-test: writing to .text (must be a permission fault)");
        let p = crate::dtb::sym::text_start() as *mut u32;
        // SAFETY: deliberately invalid; this must fault.
        unsafe { core::ptr::write_volatile(p, 0) };
        println!("fault-test: FAILED, .text is writable");
    }

    #[cfg(feature = "fault-stack")]
    {
        println!("fault-test: unbounded recursion (must hit the guard page)");
        #[inline(never)]
        #[allow(unconditional_recursion)] // the point of the test
        fn recurse(n: u64) -> u64 {
            let buf = core::hint::black_box([n; 64]);
            recurse(buf[0] + 1) + buf[63]
        }
        let r = recurse(0);
        println!("fault-test: FAILED, recursion returned {r}");
    }
}

pub fn spawn(psci: Conduit) {
    // Spawned in "wrong" order on purpose: the datapath task must still run first.
    executor::spawn(Priority::Service, "selftest-a", async {
        let _ = FIRST.compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
        for _ in 0..5 {
            timer::sleep(Duration::from_millis(20)).await;
            A_TICKS.fetch_add(1, Ordering::Relaxed);
        }
    });
    executor::spawn(Priority::Datapath, "selftest-b", async {
        let _ = FIRST.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
        for _ in 0..2 {
            timer::sleep(Duration::from_millis(50)).await;
            B_TICKS.fetch_add(1, Ordering::Relaxed);
        }
    });

    executor::spawn(Priority::Service, "selftest", async move {
        // Sleep accuracy: tickless timers should land close to the deadline.
        // The overshoot is dominated by how fast the host wakes the vCPU.
        let mut report = String::new();
        let mut worst = Duration::ZERO;
        for us in [100u64, 1_000, 10_000, 100_000] {
            let want = Duration::from_micros(us);
            let t0 = timer::Instant::now();
            timer::sleep(want).await;
            let got = t0.elapsed();
            assert!(got >= want, "sleep returned early: {got:?} < {want:?}");
            let over = got - want;
            worst = worst.max(over);
            let _ = write!(report, " {}us:+{}", us, over.as_micros());
        }
        println!("  sleep overshoot :{report} (us)");

        // Wait (bounded) for the concurrent sleepers, then check them.
        let deadline = timer::Instant::now()
            .checked_add(Duration::from_secs(2))
            .unwrap();
        while (
            A_TICKS.load(Ordering::Relaxed),
            B_TICKS.load(Ordering::Relaxed),
        ) != (5, 2)
        {
            assert!(
                timer::Instant::now() < deadline,
                "concurrent sleepers did not finish"
            );
            timer::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            FIRST.load(Ordering::Relaxed),
            1,
            "datapath task did not run first"
        );
        let (polls, idles) = executor::stats();
        println!(
            "  executor        : ok (priorities, {} timer irqs, {} irqs, {} spurious, {} polls, {} idle waits)",
            timer::irq_count(),
            irq::count(),
            irq::spurious(),
            polls,
            idles
        );
        println!("  uptime          : {} us", timer::uptime().as_micros());
        println!("rrouter: boot ok");

        #[cfg(feature = "smoke-test")]
        crate::psci::system_off(psci);

        #[cfg(not(feature = "smoke-test"))]
        {
            let _ = psci;
            println!("idle (Ctrl-A X to quit QEMU)");
            loop {
                timer::sleep(Duration::from_secs(60)).await;
                println!("uptime {} s", timer::uptime().as_secs());
            }
        }
    });
}
