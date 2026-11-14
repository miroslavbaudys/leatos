//! Boot-time self-tests. They always run (they are cheap); with the
//! `smoke-test` feature the machine powers off afterwards so
//! `scripts/smoke-test.sh` can check the console output.
//!
//! The `fault-wx` / `fault-stack` features deliberately crash the kernel to
//! prove that W^X and the stack guard page work (see smoke-test.sh).

use crate::executor::{self, Priority};
use crate::{irq, net, println, timer};
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

/// ECN marking on a real packet buffer: ECT(0) → CE with a valid header
/// checksum; Not-ECT is refused (the AQM drops those instead).
fn ecn_self_test() {
    use fwd::wire;
    use qdisc::Packet as _;
    let frame = |tos: u8| {
        let mut p = crate::net::packet::PacketBuf::alloc().expect("pool");
        p.set_len(wire::ETH_HDR + 20);
        let f = p.data_mut();
        f.fill(0);
        wire::put16(f, 12, wire::ETHERTYPE_IPV4);
        let ip = &mut f[wire::ETH_HDR..];
        ip[0] = 0x45;
        ip[1] = tos;
        wire::put16(ip, 2, 20);
        ip[8] = 64;
        ip[9] = wire::PROTO_UDP;
        let c = wire::checksum(&ip[..20]);
        wire::put16(ip, 10, c);
        p
    };
    let mut ect = frame(0xb8 | 0b10); // DSCP EF + ECT(0)
    assert!(ect.mark_ce(), "ECT packet must be markable");
    let f = ect.data();
    assert_eq!(f[wire::ETH_HDR + 1], 0xb8 | 0b11, "CE set, DSCP preserved");
    assert!(
        wire::Ipv4View::parse(f, wire::ETH_HDR).is_some(),
        "header checksum still valid"
    );
    let mut not_ect = frame(0xb8);
    assert!(!not_ect.mark_ce(), "Not-ECT must not be marked");
    println!("  ecn self-test   : ok (ECT(0) -> CE, checksum valid; Not-ECT refused)");
}

/// Deliberate faults, compiled in only with the matching feature.
pub fn fault_tests() {
    heap_self_test();
    ecn_self_test();

    #[cfg(feature = "fault-wx")]
    {
        println!("fault-test: writing to .text (must be a permission fault)");
        let p = crate::mm::sym::text_start() as *mut u32;
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

pub fn spawn(has_net: bool) {
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
        if has_net {
            // WAN should get a DHCP lease and the gateway should answer a ping.
            // Fatal only in smoke tests (QEMU's slirp always answers); on real
            // networks the gateway may ignore pings or DHCP may be slow.
            let deadline = timer::Instant::now()
                .checked_add(Duration::from_secs(10))
                .unwrap();
            let ok = loop {
                let (dhcp, ping) = (
                    net::stack::DHCP_OK.load(Ordering::Acquire),
                    net::stack::PING_OK.load(Ordering::Acquire),
                );
                if dhcp && ping {
                    break true;
                }
                if timer::Instant::now() >= deadline {
                    #[cfg(feature = "smoke-test")]
                    panic!("net: no DHCP lease / ping reply (dhcp={dhcp}, ping={ping})");
                    #[cfg(not(feature = "smoke-test"))]
                    {
                        println!(
                            "  net self-test   : WARN dhcp={dhcp} gateway-ping={ping} (continuing)"
                        );
                        break false;
                    }
                }
                timer::sleep(Duration::from_millis(10)).await;
            };
            let (free, cap, fails) = net::packet::pool_stats();
            if ok {
                println!(
                    "  net self-test   : ok (dhcp + ping; pool {free}/{cap} free, {fails} alloc failures, {} tx drops)",
                    net::device::tx_drops()
                );
            }
        }

        let st = executor::stats();
        println!(
            "  executor        : ok (priorities, {} timer irqs, {} irqs, {} spurious, {} polls)",
            timer::irq_count(),
            irq::count(),
            irq::spurious(),
            st.polls
        );
        let up = timer::uptime();
        println!(
            "  idle            : {} wfi, {} spins ({} ms spinning = {:.1}% of uptime)",
            st.idle_waits,
            st.idle_spins,
            st.spin_time.as_millis(),
            st.spin_time.as_secs_f64() * 100.0 / up.as_secs_f64().max(1e-9)
        );
        let (used, free) = crate::mm::heap::usage();
        println!(
            "  heap            : {} KiB used, {} MiB free",
            used >> 10,
            free >> 20
        );
        println!("  uptime          : {} us", timer::uptime().as_micros());
        println!("rrouter: boot ok");

        #[cfg(feature = "smoke-test")]
        crate::arch::power::off();

        #[cfg(not(feature = "smoke-test"))]
        {
            println!("running (under QEMU, Ctrl-A X quits)");
            loop {
                timer::sleep(Duration::from_secs(60)).await;
                println!("uptime {} s", timer::uptime().as_secs());
            }
        }
    });
}
