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
| `scripts/smoke-test.sh` | automated boot tests (cases `boot`, `fault-wx`, `fault-stack`, `panic`, `wdt-task`, `wdt-hw`); non-zero exit on failure |
| `cargo test` | host unit tests for `crates/*` and `tools/*` |
| `cargo kclippy [--features <f>]` | clippy for the kernel (run for each feature below) |
| `cargo kcheck-x86` | type-check the kernel for x86_64 |
| `cargo kbuild-x86` / `cargo krun-x86` / `cargo kclippy-x86` | build / boot (QEMU q35, TCG) / lint the x86_64 kernel |
| `RROUTER_ARCH=x86_64 scripts/smoke-test.sh` | the smoke tests with the x86_64 kernel |
| `RROUTER_ARCH=x86_64 scripts/lab-test.sh` | the lab with an x86_64 router (client and ISP VMs stay aarch64) |
| `scripts/unsafe-report.sh` | list modules allowed to use `unsafe` and count unsafe constructs |
| `scripts/lab-test.sh` | end-to-end test with client + ISP VMs: DHCP, DNS, NAT, firewall, shaping, … (see below) |
| `scripts/store-test.sh`, `lease-test.sh`, `cli-test.sh`, `pppoe-test.sh`, `vlan-test.sh`, `upgrade-test.sh`, `persist-test.sh` | feature tests; when to run each is listed in `CLAUDE.md` "Commands" |

`scripts/qemu-run.sh` boots either architecture. It reads the ELF's
machine type: x86-64 kernels boot on `-machine q35` through PVH (`-kernel`),
with SeaBIOS assigning the PCI BARs. On Apple Silicon x86 guests always use
TCG, the full lab included (functional, not performance). It reads these
environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `QEMU_ACCEL` | `hvf` on Apple Silicon, else `tcg` | `tcg` = full emulation (slower; catches some issues HVF hides) |
| `QEMU_MEM` | `256M` | guest RAM, ≤ 3G (see boot-and-memory.md) |
| `QEMU_SMP` | `1` | number of CPUs |
| `QEMU_GDB` | `0` | `1` = start paused, with a gdb stub on `:1234` |
| `QEMU_NET` | `none` | `user` = two NICs on user-mode networking (WAN `52:54:00:00:00:01`, LAN `…:02`); `lab` = WAN and LAN on UDP socket links to the lab ISP and client VMs; `mac` / `mac-internet` = LAN on macOS vmnet-host (`scripts/mac-lab.sh`, `scripts/mac-internet.sh`) |
| `QEMU_DISK` | unset | x86_64: boot this disk image through SeaBIOS (e.g. `target/apu4/leatos-apu4.img` from `scripts/apu-image.sh`: Limine → Multiboot2, the apu4 boot path) instead of `-kernel`; `QEMU_APPEND` is ignored (the command line is in `limine.conf`) |
| `QEMU_STORE` | unset | attach a store image (`cargo run -p leatstore -- create img`), written in place |
| `QEMU_STORE_BUS` | `virtio` | `sd` = attach `QEMU_STORE` as an SD card behind `sdhci-pci` (the apu4's driver; size a power of two) |
| `QEMU_WDT` | `1` | `0` = no i6300esb watchdog device |
| `QEMU_APPEND` | unset | kernel command line (boot arguments); `log=console` is added unless it sets `log=` |
| `QEMU_NIC` | `virtio` | NIC model for WAN and LAN: `igb` = QEMU's Intel 82576, driven by the igb driver written for the apu4's i211 (pinned to slots 4 and 6: each igb reserves SR-IOV VF functions at devfn + 0x80) |
| `QEMU_WAN_HOSTFWD` | unset | with `QEMU_NET=user`: forward a host port to the router's WAN, e.g. `tcp:127.0.0.1:8080-:80` (management interface; boot with `mgmt=wan`) |
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
| `fault-hang` / `fault-panic` | hang in a task / panic after "boot ok" (watchdog and panic cases, persistent-upgrade rollbacks) |

## Timer precision under QEMU: measured
The boot self-test measures sleep overshoot. On an M4 Max with QEMU 11.1:

| Mode | 100 µs | 1 ms | 10 ms | 100 ms |
|---|---|---|---|---|
| HVF, `wfi` idle (default) | +40 µs | +270 µs | +2.5 ms | +0.04–2.9 ms |
| HVF, `idle-poll` | +4 µs | +1 µs | +1 µs | +0–3 µs |
| TCG, `wfi` idle | +2.2 ms | +0.6 ms | +2.7 ms | +3.0 ms |
| **HVF, hybrid idle (default since M6)** | (+5 µs without NICs) | +1 µs | +1–4 µs | +1–2 µs |
| TCG, hybrid idle | | +35 µs | +36 µs | +38 µs |

Hybrid idle (spin only for the last ≤ 4 ms before a deadline) keeps idle
host CPU at about 0 % (`idle-poll`: 100 %). See bufferbloat-cake.md §3.2.

**Conclusion (M1):** the timer and IRQ path are µs-precise. The millisecond slack
is the host waking an idle vCPU after `wfi` (it looks like macOS timer
coalescing, roughly proportional to the sleep length). Real hardware wakes
from `wfi` in microseconds. Since M6, hybrid idle handles this by default
on virtual machines; `idle-poll` is only for experiments (see
docs/bufferbloat-cake.md §3.2).

## Debugging with gdb
```sh
QEMU_GDB=1 cargo krun
# in another terminal (lldb works too: `gdb-remote 1234`)
gdb target/aarch64-unknown-none/debug/leatos -ex 'target remote :1234'
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

Checks run by the client (`lab/client/init`), each printed as `LAB PASS/FAIL`.
The table lists the base set; the full list with every option
(`LAB_PPPOE`, `LAB_VLAN`, `LAB_GUEST`, `LAB_MDNS`, `LAB_DOT`, …) and its
negative controls is in `CLAUDE.md` "Commands":

| Area | Check |
|---|---|
| DHCP | lease from rrouter (address, router, DNS, domain) |
| DNS | `nas.lan` (static), `router.lan`, own DHCP hostname, reverse PTR, NXDOMAIN for unknown `.lan`, **upstream** `isp.example` via the ISP's dnsd |
| Router | ping 192.168.1.1 |
| NAT | HTTP to the ISP; the ISP sees the router's **WAN address** as source (`/cgi-bin/ip`) |
| ICMP | ping through NAT (echo identifier translation) |
| TTL / ICMP errors | `traceroute`: hop 1 = rrouter's time-exceeded; hop 2 = the ISP's port-unreachable, **NAT-translated back** |
| Conntrack | 20 sequential TCP connections |
| Shaper (M6) | router boots with `shape_up=shape_down=10000`. The client downloads 5 MB and uploads 20 × 120 KB (byte counts verified by the ISP's sink); both must land in 8.0–10.5 Mbit/s, and ping to the router *during* the download must average < 3 ms (flow isolation; `LAB_ROUTER_ARGS=qdisc=codel` fails it). `LAB_SHAPE_KBIT=0 LAB_EXPECT_KBIT=10000` is the negative control (must fail). This busybox's `wget --post-file` sends no body, hence `--post-data` chunks. |
| DNS cache | prefetch (ISP TTL 12 s) and serve-stale with the ISP's DNS stopped, EDE 3 on a crafted EDNS query |
| ECN, SNTP, CPU | per-direction ECN from the router's counters; router time from the ISP's ntpd (±5 s); per-task CPU split and core placement |
| Firewall | the ISP routes 192.168.1.0/24 via the router and connects *into* the client (`/cgi-bin/probe`); it must be blocked. The check requires `route=OK` and a working control connection, so "blocked" can't come from a broken probe. Verified once against a router with the WAN→LAN rule disabled: the check then fails with `target=OPEN`. |
| WAN input | the ISP probes the router's WAN (TCP 22, 80, 61000, ping): silent (negative controls `LAB_ROUTER_ARGS=mgmt=wan`, `LAB_WAN_OPEN=1`) |

Options: `LAB_VERBOSE=1` (all consoles), `LAB_PCAP_DIR=dir` (router
WAN/LAN pcaps), `LAB_KEEP_LOGS=1`, `QEMU_ACCEL=tcg`, `LAB_TIMEOUT=120`,
`LAB_ROUTER_ARGS="..."` (extra boot arguments). Open: flent/irtt load
tests for CAKE and a second LAN host (M6).

## Your Mac on rrouter's LAN (`scripts/mac-lab.sh`)
```
MacBook ──bridgeN (vmnet-host)── [rrouter LAN 192.168.1.1]
                                 [rrouter WAN] ──udp── [ISP VM 203.0.113.1]
```
The Mac joins rrouter's LAN through macOS **vmnet-host**. **Only lab traffic
goes through rrouter:** the script adds one route (203.0.113.0/24 via
192.168.1.1) and scoped DNS resolvers for `*.lan` / `*.example`
(`/etc/resolver/`). Your normal internet keeps using Wi-Fi or Ethernet.
Everything is removed on exit (Ctrl-C), including VMs, the route, and the
resolver files it created (marked with a header line).

```sh
scripts/mac-lab.sh           # start + checks, then stay up for manual testing
scripts/mac-lab.sh --check   # start + checks, tear down; exit 1 on failure
```
- **Run it in Terminal:** `sudo` asks for your password once. Homebrew's
  QEMU has no Apple vmnet entitlement, so the router VM runs as root (the
  ISP VM doesn't).
- vmnet-host runs its own small DHCP service on the segment. The script sets
  its range to 192.168.1.2–9 (`MAC_LAN_RANGE`), so the Mac's side gets
  **192.168.1.2**, clear of rrouter (.1) and its DHCP pool (.100–.199). The
  Mac is therefore statically addressed on this LAN; rrouter's DHCP server is
  tested by the VM lab.
- The script refuses to start if the Mac already uses 192.168.1.0/24 or 203.0.113.0/24.
- Checks from the Mac: ping rrouter; `dig` for `nas.lan` and upstream
  `isp.example`; the macOS resolver for `router.lan`; curl through NAT; the
  NATed source as seen by the ISP; ping and traceroute through NAT. A
  firewall probe into the Mac is informational only (the macOS application
  firewall could also block it; the VM lab has the rigorous check).
- Useful while it runs: `sudo tcpdump -ni bridgeN` or Wireshark on
  `bridgeN` to watch rrouter's traffic; `tail -f <logs>/router.log` for the console.

## Your Mac's internet through rrouter (`scripts/mac-internet.sh`, "Level 3")
```
MacBook ──bridgeN (vmnet-host, 192.168.1.2)── [rrouter LAN 192.168.1.1]
                                              [rrouter WAN] ══ vmnet-bridged on enX ══ home router → internet
```
```sh
scripts/mac-internet.sh                  # confirm, switch, run checks, stay up (Ctrl-C restores)
scripts/mac-internet.sh --check --yes    # switch, run checks, restore, exit code = result
scripts/mac-internet.sh --wan-if en7     # bridge onto a specific interface (e.g. USB Ethernet)
scripts/mac-internet.sh --ipv4-only      # turn IPv6 off while running (rrouter has no IPv6 yet)
scripts/mac-internet.sh --release        # optimised rrouter build (faster datapath)
scripts/mac-internet.sh --release --shape 42:50   # shape upload/download (Mbit/s) below the line rate
scripts/mac-internet.sh --restore        # undo a previous run (after a crash, kill -9, reboot)
```
- **WAN:** `vmnet-bridged` puts rrouter's WAN NIC (52:54:00:00:00:01) directly
  on your home network, where it gets its own DHCP lease (double NAT). It
  must be layer-2 bridged: a slirp or `vmnet-shared` WAN would route through
  the Mac itself and loop.
- **Wi-Fi caveat:** many access points drop frames from a second MAC address
  on one Wi-Fi client, so bridging over Wi-Fi often yields no WAN lease. The
  script detects that (no lease within 30 s) and stops *before* touching your
  network. A USB/Thunderbolt Ethernet adapter is the reliable option.
- **Mac changes:** 8 prefix routes via 192.168.1.1: `1/8, 2/7, 4/6, 8/5,
  16/4, 32/3, 64/2, 128/1`. Together they cover all of IPv4 except
  `0.0.0.0/8`, and they're more specific than the default route, so macOS's
  own default route is never modified. **Why not `0.0.0.0/1`:** vmnet-host
  installs an interface-scoped, gateway-less `default` route on the LAN
  bridge. A route keyed `0.0.0.0` shares its radix key with that route, and
  macOS then resolved lookups (e.g. 1.1.1.1) to the gateway-less route: the
  Mac ARPed for the destination itself ("Host is down"), while `128.0.0.0/1`
  worked. The split routes avoid the `0.0.0.0` key. After adding, test
  addresses across the space are verified, and the script restores at once if
  any doesn't route via rrouter. DNS for the active service is set to
  192.168.1.1, and with `--ipv4-only`, IPv6 is turned off.
- **Safety:**
  - it asks for confirmation;
  - it switches only after rrouter has a WAN lease and answers on the LAN;
  - the original DNS/IPv6 settings go to `lab/cache/mac-internet.state` *before* any change;
  - it restores on exit, Ctrl-C or error, and via `--restore` (a stale state file blocks new runs until restored);
  - a **watchdog** restores the network if rrouter exits or stops answering for ~15 s.
- **Checks:** the route for 1.1.1.1 goes via rrouter; traceroute hop 1 =
  rrouter, hop 2 = home router; system DNS resolves through rrouter;
  `router.lan`; HTTPS to example.com; ping 1.1.1.1.
- **Known limits:**
  - IPv6 traffic bypasses rrouter unless you use `--ipv4-only`;
  - DNS rebind protection refuses home-LAN names that resolve to private addresses;
  - QEMU-on-macOS timer slack (see above) adds latency jitter.

## Bufferbloat measurements (`scripts/bufferbloat.sh`)
```sh
scripts/bufferbloat.sh                    # auto-labels the path: direct / rrouter-debug / rrouter-release
scripts/bufferbloat.sh --label wifi-5ghz --streams 8 --duration 20 --no-upload
```
The script runs three phases while pinging 1.1.1.1 every 0.2 s: **idle**
(10 s), **download** (15 s) and **upload** (15 s), each with 4 parallel
streams of 25 MB transfers against Cloudflare's speed-test endpoints. It
reports RTT p50/p90/p99/max, loss, throughput and the **added latency**
(loaded p90 − idle p50), graded like Waveform (A+ < 5 ms, A < 30, B < 60,
C < 200, D < 400, F). Results are appended to `lab/cache/bufferbloat.csv`.

- **Validity check:** a run where a stream failed for good (non-retryable
  HTTP error), or a phase had less than 1 Mbit/s of load, is marked `INVALID`
  with the reason, and gets no grade. Rate limiting (HTTP 429) and 5xx errors
  are reported per phase. A rate-limited download stream switches to the next
  source (Cloudflare → OVH → Hetzner, ranged 25 MB reads); other cases retry
  after 1 s. Cloudflare rate-limits an IP after many runs in a short time. The retry
  path is tested against a local server that answers 429 first. The first version of
  the load generator silently produced no load (Cloudflare refuses single
  downloads above about 50 MB; `curl --data-binary @-` buffers all of stdin)
  and graded an idle line "A". Verified with a negative control (an
  oversized chunk gives HTTP 403, and the run is INVALID).
- No sudo needed; it uses roughly 100–500 MB of traffic, depending on your line.
- Compare paths: run once direct, once through `scripts/mac-internet.sh`
  (debug), once with `scripts/mac-internet.sh --release`. CAKE is on by
  default; results so far are in docs/bufferbloat-cake.md.
