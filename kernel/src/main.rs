//! leatos — bare-metal unikernel for SOHO routing (aarch64 today, x86_64 later).
//!
//! Single address space; everything runs in kernel mode. Boot order is
//! arch-neutral (this file); the arch backend supplies entry, CPU, irqchip,
//! timer and MMU hardware (`arch/`). See docs/architecture.md and
//! docs/safety-and-portability.md.
//!
//! `unsafe` is denied crate-wide. Only modules declared with
//! `#[allow(unsafe_code)]` may use it: `grep -rn "allow(unsafe_code)"`
//! lists the whole audit surface.

#![no_std]
#![no_main]
#![deny(unsafe_code)]
// The x86_64 backend is a compile-only skeleton (no IRQ entry yet).
#![cfg_attr(target_arch = "x86_64", allow(dead_code))]

extern crate alloc;

mod arch;
mod cli;
mod config;
mod console;
mod cpuload;
mod drivers;
mod entropy;
mod executor;
mod fatal;
mod install;
mod irq;
mod mm;
#[allow(unsafe_code)] // the one constructor that turns an address into a device region
mod mmio;
mod net;
#[allow(unsafe_code)] // ECAM handle creation (2 operations)
mod pci;
mod platform;
#[allow(unsafe_code)] // feature-gated deliberate faults
mod selftest;
mod smp;
mod store;
mod timer;
mod upgrade;
mod wallclock;
mod watchdog;

use executor::Priority;

/// Arch-neutral kernel main, called by the arch entry point with the MMU on
/// and a valid stack. `boot_arg` is the firmware hand-off (DTB address in x0).
pub fn kmain(boot_arg: usize) -> ! {
    timer::init_clock();
    println!();
    println!(
        "leatos {} — bare metal (build {})",
        env!("CARGO_PKG_VERSION"),
        env!("LEATOS_BUILD")
    );
    println!("  privilege level : {}", arch::cpu::privilege_level());

    let info = arch::discover(boot_arg).unwrap_or_else(|e| panic!("platform discovery: {e}"));
    arch::console::init(info.console_base);
    arch::power::init(info.power);
    info.print();

    config::init(info.bootargs);
    mm::heap::init(&info);
    mm::mmu::init(&info);
    arch::irqchip::init(&info);
    timer::init_irq(info.timer_intid);
    timer::set_spin_window(config::idle_spin_window(
        info.virtual_machine,
        info.bootargs,
    ));
    irq::enable();
    console::init_rx(&info);
    println!(
        "  timer           : {} Hz, tickless, hybrid-idle spin window {} us",
        timer::frequency(),
        timer::spin_window().as_micros()
    );
    smp::start(&info);

    net::packet::init_pool(net_pool_size());
    // After the heap and the packet pool are in use: a module the heap
    // overlapped fails its hash here (docs/install.md §3.2).
    install::check_module();
    let mut pci = info.pcie.map(|p| pci::init(&p));
    if let Some(pci) = &pci {
        pci::print(pci);
    }
    if let Some(pci) = pci.as_mut() {
        drivers::cputemp::probe(pci);
    }
    // The config may live on a disk, so it is loaded once PCI is up. Code
    // above this line reads only boot arguments, never `config::get`.
    let mut store = pci.as_mut().and_then(store::open);
    // Armed early (and again by `watchdog::start`): a hang in the rest of
    // the boot, or in a kernel entered from the store, resets.
    let mut hw_watchdog = pci.as_mut().and_then(drivers::watchdog::probe);
    watchdog::arm_early(&mut hw_watchdog);
    // Persistent upgrades (docs/upgrades.md): the boot partition's kernel
    // enters the kernel stored on the disk, if there is one, and returns
    // only if it boots itself. Before `config::load`: the stored kernel
    // must be the one to mark a config trial booted.
    upgrade::boot(store.as_mut(), &mut hw_watchdog);
    config::load(store.as_mut(), info.virtual_machine);
    entropy::mix(config::bootargs().as_bytes());
    match pci.as_mut().and_then(drivers::ccp::probe) {
        Some(t) => entropy::add_hardware(t),
        None => println!("  entropy         : {}", entropy::status()),
    }
    wallclock::init_rtc();
    let qos = config::qos();
    let net = pci.as_mut().and_then(|p| net::stack::bring_up(p, &qos));
    let has_net = net.is_some();

    selftest::fault_tests();
    selftest::spawn(has_net);
    cpuload::spawn();
    if let Some((ports, hosts, shared)) = net {
        spawn_net(ports, hosts, shared, store);
    }
    watchdog::start(hw_watchdog);
    executor::run()
}

/// Place the network tasks (docs/smp.md): with two or more ports, one
/// datapath task per direction (download = WAN RX → every LAN port's TX,
/// upload = every LAN port's RX → WAN TX);
/// with 3+ cores each on its own core and the services on a third, with 2
/// cores both directions on core 0 and the services on core 1.
fn spawn_net(
    ports: &'static [net::stack::Port],
    hosts: alloc::vec::Vec<net::svc::HostIf>,
    shared: &'static net::shared::Shared,
    store: Option<store::Store>,
) {
    use net::stack::{Dir, PortSet, run_dir};
    let lay = net::stack::layout(ports.len(), smp::online());
    let dp = net::stack::new_datapath(shared);
    if ports.len() >= 2 {
        let lan = PortSet::range(1, ports.len());
        let down = Dir { rx: PortSet::one(0), tx: lan, primary: true };
        let up = Dir { rx: lan, tx: PortSet::one(0), primary: false };
        executor::spawn_on(lay.down, Priority::Datapath, "dp_down", run_dir(down, ports, shared, dp));
        executor::spawn_on(lay.up, Priority::Datapath, "dp_up", run_dir(up, ports, shared, dp));
        println!(
            "  datapath        : download on core {}, upload on core {}, services on core {}",
            lay.down, lay.up, lay.svc
        );
    } else {
        let one = Dir { rx: PortSet::one(0), tx: PortSet::one(0), primary: true };
        executor::spawn_on(lay.down, Priority::Datapath, "dp", run_dir(one, ports, shared, dp));
    }
    executor::spawn_on(lay.svc, Priority::Service, "svc", net::svc::run(hosts, shared, store));
}

/// Packet buffers to preallocate: the NICs' RX and TX rings plus room for
/// the queues (`config::QUEUE_PACKETS` each: wan0, the LAN ports, the WAN
/// ingress stage), so a swarm filling the download queue still leaves
/// buffers for the other direction. 8192 × 2.125 KiB ≈ 17 MiB.
fn net_pool_size() -> usize {
    8192
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    fatal::enter();
    fatal_println!("\n!!! KERNEL PANIC (core {}): {info}", smp::current());
    fatal::die()
}
