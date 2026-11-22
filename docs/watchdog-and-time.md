# Watchdog, panic → reboot, SNTP (M8)

leatos has no isolation (`docs/architecture.md`): one stuck core or one
panic stops routing. A router that halts stays down until someone
power-cycles it. One that reboots is back in seconds.

## Fatal paths → reboot (`kernel/src/fatal.rs`)
A panic (`main.rs`), an unhandled CPU exception (`arch/*/exceptions.rs`)
and the software watchdog all end in `fatal::die()`. It:
1. masks IRQs;
2. stops the other cores (`smp::stop_others`; they `arch::cpu::park`,
   which never powers off, not even in smoke builds);
3. waits 3 s busy so the serial report drains;
4. stops the hardware watchdog;
5. resets (`arch::power::reset`).

A second fault while dying parks that core. Boot argument `panic=halt`
keeps today's halt for debugging. Faults before the clock runs (very early
boot) always halt, because they would only fault again.

## Watchdog (`kernel/src/watchdog.rs`, `drivers/watchdog.rs`)
Two layers:

| Layer | Catches | How |
|---|---|---|
| Cross-core check | one core stuck: endless poll, deadlock, IRQs masked, lost timer | every online core runs a `watchdog` task (`Priority::Datapath`, 1 s) that stamps `LAST_SEEN[core]` and checks the others; a core unseen for 5 s is reported with the task it is polling (`executor::polling`), then `fatal::die` |
| Hardware timer | all cores stuck, or the only core (`cores=1`) | petted by the checkers only while every core is fresh; timeout 30 s (`watchdog_secs=`) |

- A checker whose own last run is older than 5 s accuses no one: the
  whole machine was paused (a VM on a sleeping host).
- The hardware timer is stopped before a deliberate reboot, and petted
  right before an in-RAM upgrade (`upgrade::exec`). The new kernel's
  probe stops it and `watchdog::start` re-arms it, so a new kernel that
  hangs on the way is still reset.
- `watchdog=0` turns both layers off (gdb).

Hardware drivers (`HwWatchdog`: `start`, `pet`, `stop`, `fired_last_boot`):
- **i6300esb** (`drivers/i6300esb.rs`): QEMU `-device i6300esb`, added by
  `scripts/qemu-run.sh` (`QEMU_WDT=0` drops it). It is a PCI device, so it
  works on both arches. The registers decode the access width: preloads
  are 32-bit, reload/status 16-bit (`mmio::Region::read16/write16`), the
  config lock register 8-bit (`Pci::config_dword` + `Region::write8`).
- **AMD FCH** (`arch/x86_64/watchdog.rs`, the apu4): the EFCH layout of
  Linux `sp5100_tco`, found through the SMBus function 1022:780b rev ≥ 0x41.
  It uses PM index/data ports 0xcd6/0xcd7 and MMIO at 0xfeb00000 or
  0xfed80b00. Not testable in QEMU.

The boot log and `/api/status` (`watchdog`) say which layer runs and
whether the previous reset was the watchdog's.

Tests (`scripts/smoke-test.sh`; each passes only if a second boot is seen):

| Case | Fault | Negative control |
|---|---|---|
| `panic` | panic after boot | `QEMU_APPEND=panic=halt` |
| `wdt-task` | a task spinning in its poll on the last of 2+ cores | `QEMU_APPEND=watchdog=0` |
| `wdt-hw` | the same with `cores=1`, so only the i6300esb can reset; the next boot must report it | `QEMU_WDT=0` |

## SNTP (`crates/proto-sntp`, `kernel/src/net/ntp.rs`, `kernel/src/wallclock.rs`)
- `proto-sntp` (sans-IO) builds the request with a random cookie as the
  transmit timestamp.
- A reply counts only if all of these hold:
  - mode 4, VN 3/4, from the server asked
  - the origin timestamp equals the cookie
  - stratum 1–15 (0 = kiss-o'-death)
  - LI ≠ 3, non-zero timestamps
- Polling: a burst of 4 requests 2 s apart, of which the lowest-delay
  sample wins. Then one request every 64 s, doubling to 1024 s while the
  samples agree within 128 ms; a jump starts a new burst. A request is
  lost after 3 s, and 2 failures in a row move on to the next server.
  When nobody answers, retries back off from 8 s to 64 s.
- NTP era 1 (after 2036) is handled with a pivot at 2026.
- Servers: `time.ntp_servers` (default `pool.ntp.org`; empty = off), or the
  boot argument `ntp=a,b`.
- Names are resolved through the router's own DNS forwarder. `LanServices`
  passes our queries to its resolver as if from the client `127.0.0.1:1`
  and routes the answers back, so they share its cache and upstreams.
  smoltcp's DNS socket would use source ports in the NAT range.
- The UDP socket sits on the WAN, at a random port in 60000–60999 (the forwarder lets UDP in only to bound client ports, docs/security-audit.md §5 item 7).
- `wallclock` keeps the Unix time at monotonic 0. No clock discipline: the
  time is unknown until the first sync. It is shown on the status page and
  in `/api/status` (`time`).
- RTC (`arch::rtc`: x86_64 CMOS, ports 0x70/0x71; none on aarch64): read
  once at boot (`rtc : …` in the log) but never taken as the time; only
  DNS over TLS uses it, as a hint for certificate dates before SNTP
  (docs/dns-over-tls.md). After each sync it is set from the wall clock if
  more than 2 s off (`rtc : was N s off, set to …`). Only the time
  registers are written, never the rest of CMOS (coreboot's options); the
  century is taken as 20. Lab: `LEATOS_ARCH=x86_64 LAB_DOT=1
  QEMU_EXTRA="-rtc base=2040-01-01" LAB_EXPECT_DATES=expired`.
- Lab: the ISP VM runs `busybox ntpd -l`, a stratum 1 server from the
  host's clock, and `dnsd` serves `ntp.isp.example`. `scripts/lab-test.sh`
  passes `ntp=ntp.isp.example` and checks the router's time against the
  host's (±5 s). Negative control: `LAB_ROUTER_ARGS=ntp=203.0.113.99`.

Clients' NTP can be sent to a time server on the LAN with a redirect
(`[[firewall.redirect]]`, docs/config-v2.md), also NTP addressed to the
router, which serves none.

Open: an NTP server for the LAN (DHCP option 42), DHCP-provided NTP servers
on the WAN, and slewing instead of stepping (not needed while nothing
measures intervals in wall-clock time).
