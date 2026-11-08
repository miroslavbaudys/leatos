# Running and debugging in QEMU

Requirements: QEMU ≥ 8 (`brew install qemu`) and the Rust toolchain. The
`aarch64-unknown-none` target is installed automatically via `rust-toolchain.toml`.

## Commands

| Command | What it does |
|---|---|
| `cargo kbuild` | build the kernel (debug) |
| `cargo kbuild --release` | build the kernel (release) |
| `cargo krun` | build and boot in QEMU (quit with `Ctrl-A X`) |
| `cargo ksmoke` | boot with the `smoke-test` feature (powers off after boot) |
| `scripts/smoke-test.sh` | automated boot tests (cases `boot`, `fault-wx`, `fault-stack`); non-zero exit on failure |
| `cargo test` | host unit tests for the `crates/*` protocol crates |
| `cargo kclippy` | clippy for the kernel |

`scripts/qemu-run.sh` reads these environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `QEMU_ACCEL` | `hvf` on Apple Silicon, else `tcg` | `tcg` = full emulation (slower; catches some issues HVF hides) |
| `QEMU_MEM` | `256M` | guest RAM, ≤ 3G (see boot-and-memory.md) |
| `QEMU_SMP` | `1` | number of CPUs |
| `QEMU_GDB` | `0` | `1` = start paused, with a gdb stub on `:1234` |
| `QEMU_NET` | `none` | `user` = two virtio-net-pci NICs (WAN `52:54:00:00:00:01`, LAN `…:02`) |
| `QEMU_PCAP_DIR` | unset | with `QEMU_NET=user`, write `wan.pcap` and `lan.pcap` |
| `QEMU_EXTRA` | unset | extra arguments passed to QEMU |

Run both `scripts/smoke-test.sh` and `QEMU_ACCEL=tcg scripts/smoke-test.sh`
before committing boot, MMU, IRQ or timer changes. `SMOKE_CASES="boot"`
selects cases, and `SMOKE_VERBOSE=1` prints the full console output.

### Kernel features
| Feature | Effect |
|---|---|
| `smoke-test` | power off after the self-tests (automation) |
| `idle-poll` | spin instead of `wfi` when idle; µs-precise timers on HVF, 100 % host CPU |
| `fault-wx` / `fault-stack` | deliberately write to `.text` / overflow the stack (used by smoke-test.sh) |

## Timer precision under QEMU: measured
The boot self-test measures sleep overshoot. On an M4 Max with QEMU 11.1:

| Mode | 100 µs | 1 ms | 10 ms | 100 ms |
|---|---|---|---|---|
| HVF, `wfi` idle (default) | +40 µs | +270 µs | +2.5 ms | +0.04–2.9 ms |
| HVF, `idle-poll` | +4 µs | +1 µs | +1 µs | +0–3 µs |
| TCG, `wfi` idle | +2.2 ms | +0.6 ms | +2.7 ms | +3.0 ms |

**Conclusion:** the timer and IRQ path are µs-precise. The millisecond slack
is the host waking an idle vCPU after `wfi` (it looks like macOS timer
coalescing, roughly proportional to the sleep length). Real hardware wakes
from `wfi` in microseconds. For latency and CAKE experiments in QEMU, build
with `idle-poll` (see docs/bufferbloat-cake.md §3.2).

## Debugging with gdb
```sh
QEMU_GDB=1 cargo krun
# in another terminal (lldb works too: `gdb-remote 1234`)
gdb target/aarch64-unknown-none/debug/rrouter -ex 'target remote :1234'
```
Useful QEMU options: `QEMU_EXTRA="-d int,guest_errors -D qemu.log"` logs
exceptions and invalid guest accesses (TCG only).

## Planned network lab (milestone M2+)
QEMU instances are connected with `-netdev dgram` UDP sockets, which needs no
root on macOS:

```
[VM isp]      Alpine aarch64: pppoe-server (rp-pppoe / accel-ppp),
              DHCPv6-PD (Kea/dnsmasq), upstream DNS, iperf3
    │ dgram 127.0.0.1:10001 <-> :10002   (WAN)
[VM rrouter]  this kernel, 2× virtio-net-pci
    │ dgram 127.0.0.1:10003 <-> :10004   (LAN)
[VM client]   Alpine: dhcpcd, dig, curl, rdisc6, iperf3
```

Example WAN link for the router VM:
```
-netdev dgram,id=wan,local.type=inet,local.host=127.0.0.1,local.port=10001,remote.type=inet,remote.host=127.0.0.1,remote.port=10002
-device virtio-net-pci,netdev=wan,mac=52:54:00:00:00:01
-object filter-dump,id=d1,netdev=wan,file=wan.pcap
```
End-to-end tests: boot all three VMs, then on the client run `dhcpcd`,
`dig nas.lan`, `curl http://isp`, `iperf3`, and assert on the results.
