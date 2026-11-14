# Multicore (M11)

The apu4 has four Jaguar cores. rrouter used one until M11. This document
describes how the others are used and why it is done this way.

## Constraint: one CAKE per direction
CAKE shapes and shares bandwidth fairly only if one instance sees every
flow of a direction. So rrouter does not spread packets over cores by
flow (RSS), the usual way routers scale. It parallelises by **direction**
and by **kind of work** instead:

| Cores online | Core 0 | Core 1 | Core 2 |
|---|---|---|---|
| 1 | datapath (both directions) + services | | |
| 2 | datapath (both directions) | services (`svc`) | |
| ≥ 3 (step 3) | download datapath | upload datapath | services |

The boot argument `cores=N` caps the cores used, for A/B measurements
(`cores=1` = the single-core layout).

## Step 1: services split ✅
The datapath task `net` (`Priority::Datapath`) owns the NICs and the
forwarder. The services task `svc` (`Priority::Service`) owns smoltcp
and everything on it (WAN DHCP client, LAN DHCP server, DNS, web
interface). They share only `net::shared` (see `docs/architecture.md`
"Tasks"). Forwarded packets never leave the datapath, and router-local
TX goes straight into the qdisc, so no queue was added.

## Step 2: SMP bring-up (aarch64 ✅, x86_64 ✅)
- **Start:** `smp::start` (core 0, after the MMU, interrupt controller
  and timer are up) starts cores 1..`MAX_CORES` (4) through
  `arch::smp::start`.
  - aarch64: PSCI `CPU_ON` into `_secondary_start` (`boot.S`). It
    enables the MMU with the kernel's final tables (`secondary_ttbr`,
    cleaned to the point of coherency because the core reads it with
    the MMU off), takes its stacks from `secondary_stacks`, sets the
    vectors and `TPIDR_EL1` = core index, and calls
    `smp::secondary_main`.
  - x86_64: the boot core copies the trampoline (`boot.S`
    `ap_trampoline_start`) to 0x8000 (must be free RAM in the firmware
    map; mapped read-write, never executable, in the kernel's tables),
    then sends INIT-SIPI-SIPI. The trampoline goes from real to protected
    mode and into long mode on the **boot** page tables (identity
    0..4 GiB, executable), so W^X in the final tables is never relaxed.
    `ap_start64` (kernel text) then loads the final tables and the
    core's stack from `ap_boot` and calls `ap_rust`. Per core: a TSS
    (IST1 = its exception stack) and GDT slot (selector 0x18 + 16 ×
    core), a GS block holding the core index (`cpu::core_id`), and the
    local APIC set up like the boot core's (LAPIC timer, wake IPI vector
    33). The core list comes from the MADT with the boot core (CPUID
    APIC ID) moved first.
  - In-RAM upgrade with several cores: `upgrade::exec` stops the others
    and sends them INIT (wait-for-SIPI), so none runs in code that is
    being overwritten. The new kernel starts them again.
- **Stacks:** linker script `__ap_stacks`: per secondary core
  `[guard] 16 KiB exception stack [guard] 256 KiB kernel stack`.
  `mm::mmu::init` maps them and leaves the guard pages unmapped
  (`mm::stacks`).
- **Per core:**
  - interrupt controller interface: GICv3 redistributor found by
    affinity, CPU interface
  - timer: the comparator is per-core hardware; `timer.rs` keeps a
    timer queue, a deadline mirror and a fired flag per core. A sleep
    registers on the core that polls it.
  - executor run queues and CPU accounting (`cpuload` keeps one history
    per core; the status page draws one chart per core)
- **Tasks are pinned** (`executor::spawn_on`). Waking a task on another
  core queues it there and sends a wake IPI (aarch64: SGI 0), so a core
  in `wfi` sees it.
  - No wakeup is lost: the idle path masks IRQs, re-checks for work and
    only then runs `wfi`, and a pending IPI ends `wfi` even while masked.
- **Device interrupts** still go to core 0 (the core that enables them).
  Step 3 routes each NIC to its RX core.
- **Stopping:** on a panic (any core) and before replacing the kernel in
  RAM, `smp::stop_others` halts the other cores (stop flag + IPI).

### HVF note
macOS HVF's in-kernel GICv3 returns 0 for `GICR_TYPER` read as two 32-bit
halves, so the redistributor search read affinity 0 for every frame:
core 0 found its frame by luck, core 1 found none. `mmio::Region::read64`
does one 64-bit access. TCG answered either way.

### Checks
- `QEMU_SMP=4 scripts/smoke-test.sh`: the boot case requires
  `smp : 4 of …` and the SMP self-test. That test wakes a task on core 1
  from core 0 (wake latency printed, 18 µs under HVF) and runs a 10 ms
  sleep on core 1 (+2 µs).
  - Negative control: `QEMU_SMP=4 QEMU_APPEND=cores=1` fails the boot
    case.
- `QEMU_SMP=4 scripts/lab-test.sh`: the full lab, with `svc` on core 1
  (the per-task CPU line shows `svc@1`).

## Step 3: one datapath core per direction (next)
- **Tasks:** `dp_down` (WAN RX → forwarder → LAN qdisc → LAN TX) and
  `dp_up` (LAN RX → forwarder → WAN qdisc → WAN TX) on their own cores.
  Each NIC's interrupt goes to its RX core.
- **Shared between the two:**
  - `Mutex<Forwarder>` (conntrack/NAT), locked per RX batch
  - `Mutex<NeighTable>`: ARP replies arrive on the other direction's RX
  - `Mutex<Nic>` per port: RX by one core, TX by the other
- **If the forwarder lock limits the gain:** shard conntrack. NAT
  allocates external ports so that `port % shards` is the connection's
  shard, so WAN ingress finds the shard from the destination port.
