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
| `cargo kcheck-x86` | type-check the kernel for x86_64 against the arch skeleton |
| `scripts/unsafe-report.sh` | list modules allowed to use `unsafe` and count unsafe constructs |
| `scripts/lab-test.sh` | end-to-end LAN test with an Alpine client VM (see below) |

`scripts/qemu-run.sh` reads these environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `QEMU_ACCEL` | `hvf` on Apple Silicon, else `tcg` | `tcg` = full emulation (slower; catches some issues HVF hides) |
| `QEMU_MEM` | `256M` | guest RAM, ≤ 3G (see boot-and-memory.md) |
| `QEMU_SMP` | `1` | number of CPUs |
| `QEMU_GDB` | `0` | `1` = start paused, with a gdb stub on `:1234` |
| `QEMU_NET` | `none` | `user` = two virtio-net-pci NICs on user-mode networking (WAN `52:54:00:00:00:01`, LAN `…:02`); `lab` = WAN user-mode, LAN on a UDP socket link to the lab client |
| `QEMU_PCAP_DIR` | unset | with `QEMU_NET=user`, write `wan.pcap` and `lan.pcap` |
| `QEMU_EXTRA` | unset | extra arguments passed to QEMU |

Run both `scripts/smoke-test.sh` and `QEMU_ACCEL=tcg scripts/smoke-test.sh`
before committing boot, MMU, IRQ, timer or driver changes. The smoke test
uses `QEMU_NET=user` by default: QEMU's built-in "slirp" network gives the
WAN a DHCP lease (10.0.2.15, gateway 10.0.2.2), and the boot test pings the gateway. `SMOKE_CASES="boot"`
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

## LAN lab: router + client VM (`scripts/lab-test.sh`)
```
[client VM]  Alpine 3.24 aarch64 (kernel + initramfs only), mac 52:54:00:00:00:10
    │ eth0 ── -netdev dgram  127.0.0.1:10004 <-> 127.0.0.1:10003 ── lan0
[rrouter]    192.168.1.1/24: DHCP server, DNS forwarder
    │ wan0 ── QEMU user-mode network (slirp): DHCP 10.0.2.15, DNS 10.0.2.3
```
- `scripts/lab/fetch-alpine.sh` downloads Alpine's netboot `vmlinuz-virt` +
  `initramfs-virt` (~20 MB) into `lab/cache/` (gitignored) and checks
  **pinned SHA-256s**. Alpine replaces netboot files on point releases, so
  on a mismatch, review and update the pins.
- `scripts/lab/build-client-initrd.sh` appends `lab/client/{init,udhcpc.sh}`
  as a second cpio archive. Linux unpacks archives in order, so our `/init`
  replaces Alpine's. The client loads `virtio_net` + `af_packet`, runs `udhcpc`,
  checks DNS (`nas.lan`, `router.lan`, its own DHCP hostname, reverse
  lookup, NXDOMAIN, upstream forwarding) and pings the router. It prints
  `LAB PASS/FAIL` lines and powers off.
- No root needed: the VMs talk over host UDP sockets.
- Options: `LAB_VERBOSE=1` (both consoles), `LAB_PCAP_DIR=dir` (router
  WAN/LAN pcaps), `LAB_KEEP_LOGS=1`, `QEMU_ACCEL=tcg`, `LAB_TIMEOUT=90`.
- The upstream check is informational: it needs the host to have internet access.

Planned extensions: an **ISP VM** on the router's WAN (instead of slirp)
for NAT/forwarding (M4) and PPPoE (M5), plus a flent/irtt load test for CAKE (M6).
