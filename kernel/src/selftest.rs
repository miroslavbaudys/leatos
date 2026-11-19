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
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;

static A_TICKS: AtomicU32 = AtomicU32::new(0);
static B_TICKS: AtomicU32 = AtomicU32::new(0);
/// Which class was polled first: 1 = datapath, 2 = service.
static FIRST: AtomicU32 = AtomicU32::new(0);
/// SMP self-test: when core 0 signalled, when the task on core 1 ran, and
/// how late a 10 ms sleep on core 1 ended (ticks / µs).
static SMP_SIGNALLED: AtomicU64 = AtomicU64::new(0);
static SMP_WOKEN: AtomicU64 = AtomicU64::new(0);
static SMP_SLEEP_OVER_US: AtomicU64 = AtomicU64::new(u64::MAX);

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

/// The temperature registers' decoding (the sensor itself exists only on
/// AMD hardware, so this is what QEMU can check).
fn cputemp_self_test() {
    use crate::drivers::cputemp::{decode_htc, decode_temp, fmt_mc};
    // CurTmp 433 × 0.125 °C = 54.125 °C.
    assert_eq!(decode_temp(433 << 21), 54_125);
    // Range select (bit 19) or CurTmpTjSel = 11b: 49 °C lower.
    assert_eq!(decode_temp(433 << 21 | 1 << 19), 5_125);
    assert_eq!(decode_temp(433 << 21 | 3 << 16), 5_125);
    assert_eq!(decode_temp(433 << 21 | 1 << 16), 54_125);
    // HtcTmpLmt 76: 52 + 38 = 90 °C; HtcEn clear = no limit.
    assert_eq!(decode_htc(76 << 16 | 1), Some(90_000));
    assert_eq!(decode_htc(76 << 16), None);
    assert_eq!(fmt_mc(54_125), "54.1 °C");
    assert_eq!(fmt_mc(-1_500), "-1.5 °C");
    println!("  temp self-test  : ok");
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
    cputemp_self_test();

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

/// After the boot report: a fault the machine must recover from by
/// rebooting (scripts/smoke-test.sh counts the boots).
#[cfg(any(feature = "fault-hang", feature = "fault-panic"))]
async fn late_fault() {
    // Let the watchdog settle (and pet the hardware timer once).
    timer::sleep(Duration::from_secs(2)).await;
    #[cfg(feature = "fault-panic")]
    panic!("fault-test: deliberate panic (must reboot)");
    #[cfg(feature = "fault-hang")]
    {
        // On the last core: the others' checkers must notice. With one
        // core nothing can, and only the hardware timer resets.
        let core = crate::smp::online() - 1;
        println!("fault-test: hanging a task on core {core} (must reboot)");
        executor::spawn_on(core, Priority::Service, "hang", async {
            loop {
                core::hint::spin_loop();
            }
        });
        loop {
            timer::sleep(Duration::from_secs(3600)).await;
        }
    }
}

/// `ct_bench=1` (M9): conntrack costs on this CPU with one shard holding
/// the whole table (the worst case for the once-a-second pass: a torrent
/// client's forward puts every connection in one shard). Prints µs per
/// operation; nothing is asserted.
pub fn conntrack_bench() {
    use fwd::conntrack::{Budget, Conntrack, Dir, Tuple};
    use fwd::wire::{PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_SYN};
    use net::datapath::{EXPIRE_PER_PASS, MAX_CONNS};
    use core::net::Ipv4Addr;
    let wan = Ipv4Addr::new(203, 0, 113, 10);
    let us = |t0: timer::Instant| t0.elapsed().as_micros() as u64;
    let tuple = |i: usize, proto: u8| Tuple {
        proto,
        // 128 hosts × 8 source ports (1024 NAT mappings, within one of 16
        // shards' ports) × 16 destinations.
        src: Ipv4Addr::new(192, 168, 1, (i % 128) as u8 + 1),
        sport: 40_000 + (i / 2048 % 8) as u16,
        dst: Ipv4Addr::new(198, 51, 100 + (i / 16_384) as u8, (i / 128 % 16) as u8 + 1),
        dport: 443,
    };
    let fill = |assured: bool| {
        let mut ct = Conntrack::new_shard(MAX_CONNS, 0x5eed, 16, 0);
        ct.set_budget(Budget::with_host_limit(MAX_CONNS, MAX_CONNS, 0x5eed));
        let t0 = timer::Instant::now();
        for i in 0..MAX_CONNS {
            let id = ct.create(0, tuple(i, PROTO_TCP), Some(wan), TCP_SYN).expect("bench: room");
            if assured {
                ct.update(0, id, Dir::Reply, TCP_SYN | TCP_ACK, 60);
                ct.update(0, id, Dir::Original, TCP_ACK, 60);
            }
        }
        (ct, us(t0))
    };
    let (mut ct, fill_us) = fill(true);
    assert_eq!(ct.len(), MAX_CONNS);
    let t0 = timer::Instant::now();
    let n = ct.expire(1000);
    let scan_us = us(t0);
    assert_eq!(n, 0);
    // Full of assured connections: every new one samples and is refused.
    const TRIES: usize = 1000;
    let t0 = timer::Instant::now();
    for i in 0..TRIES {
        assert!(ct.create(0, tuple(MAX_CONNS + i, PROTO_UDP), Some(wan), 0).is_none());
    }
    let refuse_ns = us(t0) * 1000 / TRIES as u64;
    let t0 = timer::Instant::now();
    let n = ct.expire_some(u64::MAX, EXPIRE_PER_PASS);
    let expire_pass_us = us(t0);
    assert_eq!(n, EXPIRE_PER_PASS);
    let t0 = timer::Instant::now();
    let n = ct.expire(u64::MAX);
    let expire_all_us = us(t0);
    assert_eq!(n, MAX_CONNS - EXPIRE_PER_PASS);
    // Full of unanswered connections: every new one early-drops one.
    let (mut ct, _) = fill(false);
    let t0 = timer::Instant::now();
    for i in 0..TRIES {
        assert!(ct.create(0, tuple(MAX_CONNS + i, PROTO_UDP), Some(wan), 0).is_some());
    }
    let evict_ns = us(t0) * 1000 / TRIES as u64;
    println!(
        "  ct bench        : {MAX_CONNS} conns in one shard: fill {} ns/conn, pass {scan_us} us (none expired), \
         expire {EXPIRE_PER_PASS} (a pass) {expire_pass_us} us, the other {} {expire_all_us} us; when full: refuse {refuse_ns} ns, early drop {evict_ns} ns",
        fill_us * 1000 / MAX_CONNS as u64,
        MAX_CONNS - EXPIRE_PER_PASS
    );
}

pub fn spawn(has_net: bool) {
    if crate::config::ct_bench() {
        executor::spawn(Priority::Service, "ct-bench", async { conntrack_bench() });
    }
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

    // SMP: a task pinned to core 1 waits for an event that core 0 signals
    // (cross-core wake + IPI), then sleeps on core 1 (its own timer queue
    // and comparator).
    let smp_event = (crate::smp::online() > 1).then(|| {
        let ev = irq::new_event();
        executor::spawn_on(1, Priority::Service, "selftest-smp", async move {
            ev.wait().await;
            SMP_WOKEN.store(timer::ticks(), Ordering::Release);
            let want = Duration::from_millis(10);
            let t0 = timer::Instant::now();
            timer::sleep(want).await;
            let over = t0.elapsed().saturating_sub(want).as_micros() as u64;
            SMP_SLEEP_OVER_US.store(over, Ordering::Release);
        });
        ev
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
                    net::svc::DHCP_OK.load(Ordering::Acquire),
                    net::svc::PING_OK.load(Ordering::Acquire),
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

        if let Some(ev) = smp_event {
            SMP_SIGNALLED.store(timer::ticks(), Ordering::Release);
            ev.signal();
            let deadline = timer::Instant::now()
                .checked_add(Duration::from_secs(2))
                .unwrap();
            while SMP_SLEEP_OVER_US.load(Ordering::Acquire) == u64::MAX {
                assert!(
                    timer::Instant::now() < deadline,
                    "smp self-test: task on core 1 did not run (woken: {})",
                    SMP_WOKEN.load(Ordering::Acquire) != 0
                );
                timer::sleep(Duration::from_millis(1)).await;
            }
            let wake = SMP_WOKEN
                .load(Ordering::Acquire)
                .saturating_sub(SMP_SIGNALLED.load(Ordering::Acquire));
            println!(
                "  smp self-test   : ok ({} cores; core 1 woken in {} us, 10 ms sleep on core 1 +{} us)",
                crate::smp::online(),
                timer::ticks_to_duration(wake).as_micros(),
                SMP_SLEEP_OVER_US.load(Ordering::Acquire)
            );
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
        println!("leatos: boot ok");

        #[cfg(any(feature = "fault-hang", feature = "fault-panic"))]
        late_fault().await;

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
