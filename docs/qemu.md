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
| `scripts/lab-test.sh` | end-to-end test with client + ISP VMs: DHCP, DNS, NAT, firewall (see below) |

`scripts/qemu-run.sh` reads these environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `QEMU_ACCEL` | `hvf` on Apple Silicon, else `tcg` | `tcg` = full emulation (slower; catches some issues HVF hides) |
| `QEMU_MEM` | `256M` | guest RAM, ≤ 3G (see boot-and-memory.md) |
| `QEMU_SMP` | `1` | number of CPUs |
| `QEMU_GDB` | `0` | `1` = start paused, with a gdb stub on `:1234` |
| `QEMU_NET` | `none` | `user` = two virtio-net-pci NICs on user-mode networking (WAN `52:54:00:00:00:01`, LAN `…:02`); `lab` = WAN and LAN on UDP socket links to the lab ISP and client VMs |
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

## Lab: client VM + rrouter + ISP VM (`scripts/lab-test.sh`)
```
[client VM]  ──LAN──  [rrouter]  ──WAN──  [ISP VM]
Alpine 3.24           192.168.1.1/24       203.0.113.1/24
52:54:00:00:00:10     WAN by DHCP from ISP udhcpd (lease .10–.20), httpd (+CGI), dnsd
udp :10004<->:10003   udp :10005<->:10006  (QEMU -netdev dgram: no root needed)
```
The VMs are Alpine's netboot kernel + initramfs with an overlay
(`lab/<role>/` + `busybox-extras`, built by `scripts/lab/build-initrd.sh`).
Downloads go into `lab/cache/` (gitignored), **pinned by SHA-256** in
`scripts/lab/fetch-alpine.sh`. Alpine replaces netboot files on point
releases, so on a mismatch, review and update the pins.

Checks run by the client (`lab/client/init`), each printed as `LAB PASS/FAIL`:

| Area | Check |
|---|---|
| DHCP | lease from rrouter (address, router, DNS, domain) |
| DNS | `nas.lan` (static), `router.lan`, own DHCP hostname, reverse PTR, NXDOMAIN for unknown `.lan`, **upstream** `isp.example` via the ISP's dnsd |
| Router | ping 192.168.1.1 |
| NAT | HTTP to the ISP; the ISP sees the router's **WAN address** as source (`/cgi-bin/ip`) |
| ICMP | ping through NAT (echo identifier translation) |
| TTL / ICMP errors | `traceroute`: hop 1 = rrouter's time-exceeded; hop 2 = the ISP's port-unreachable, **NAT-translated back** |
| Conntrack | 20 sequential TCP connections |
| Firewall | the ISP routes 192.168.1.0/24 via the router and connects *into* the client (`/cgi-bin/probe`); it must be blocked. The check requires `route=OK` and a working control connection, so "blocked" can't come from a broken probe. Verified once against a router with the WAN→LAN rule disabled: the check then fails with `target=OPEN`. |

Options: `LAB_VERBOSE=1` (all consoles), `LAB_PCAP_DIR=dir` (router
WAN/LAN pcaps), `LAB_KEEP_LOGS=1`, `QEMU_ACCEL=tcg`, `LAB_TIMEOUT=120`.
Next: PPPoE server on the ISP VM (M5), flent/irtt load tests for CAKE (M6).
