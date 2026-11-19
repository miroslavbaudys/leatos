#!/usr/bin/env bash
# Boot-test the kernel in QEMU. Each case builds the kernel with specific
# features, boots it (the kernel powers off via PSCI so QEMU exits), and
# checks the console output. Exit code 0 = all cases passed.
#
#   scripts/smoke-test.sh                 # all cases
#   SMOKE_CASES="boot" scripts/smoke-test.sh
#   QEMU_ACCEL=tcg scripts/smoke-test.sh  # without hardware acceleration
#   RROUTER_ARCH=x86_64 scripts/smoke-test.sh   # x86_64 kernel on QEMU q35 (TCG)
#   RROUTER_BOOT=limine scripts/smoke-test.sh   # x86_64 via the apu4 disk image:
#                                               # SeaBIOS -> Limine -> Multiboot2
#   SMOKE_VERBOSE=1 ...                   # print full console output
#
# Cases:
#   boot         normal boot with 2 NICs: self-tests pass, WAN gets a DHCP lease, gateway answers ping
#   fault-wx     writing to .text must raise a permission fault (W^X)
#   fault-stack  unbounded recursion must hit the kernel stack guard page
#   panic        a panic after boot must reboot the machine (second boot seen)
#                negative control: QEMU_APPEND=panic=halt must fail it
#   wdt-task     a task stuck in its poll on one core (2 cores): another core's
#                watchdog check must notice, name it and reboot
#                negative control: QEMU_APPEND=watchdog=0 must fail it
#   wdt-hw       the same with cores=1: nothing in software can notice, the
#                i6300esb hardware watchdog must reset (and report it on the next boot)
#                negative control: QEMU_WDT=0 must fail it
set -euo pipefail
cd "$(dirname "$0")/.."

CASES="${SMOKE_CASES:-boot fault-wx fault-stack panic wdt-task wdt-hw}"
BOOT_MODE="${RROUTER_BOOT:-kernel}"
case "$BOOT_MODE" in kernel) ;; limine) RROUTER_ARCH=x86_64 ;; *) echo "RROUTER_BOOT must be kernel or limine" >&2; exit 2 ;; esac
ARCH="${RROUTER_ARCH:-aarch64}"
case "$ARCH" in aarch64 | x86_64) ;; *) echo "RROUTER_ARCH must be aarch64 or x86_64" >&2; exit 2 ;; esac
TARGET="$ARCH-unknown-none"
KERNEL="target/$TARGET/debug/leatos"
# x86_64 runs under TCG on Apple Silicon: allow more time.
[[ "$ARCH" == x86_64 ]] && SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-40}"
LOG="$(mktemp -t rrouter-smoke.XXXXXX)"
IMG="$LOG.img"
trap 'rm -f "$LOG" "$IMG"' EXIT
FAILED=0

boot() { # features [extra kernel arguments] [boots to wait for]
  local args="${QEMU_APPEND:-}${2:+ $2}"
  args="${args# }"
  if [[ "$BOOT_MODE" == limine ]]; then
    scripts/apu-image.sh --debug --features "$1" --cmdline "log=console${args:+ $args}" --out "$IMG" >/dev/null
  else
    cargo build -p leatos-kernel --target "$TARGET" --features "$1" --quiet
  fi
  # macOS has no `timeout`: a background watchdog kills QEMU if the kernel hangs.
  if [[ "$BOOT_MODE" == limine ]]; then
    QEMU_DISK="$IMG" QEMU_NET="${QEMU_NET:-user}" scripts/qemu-run.sh >"$LOG" 2>&1 &
  else
    QEMU_APPEND="$args" QEMU_NET="${QEMU_NET:-user}" scripts/qemu-run.sh "$KERNEL" >"$LOG" 2>&1 &
  fi
  local qpid=$!
  ( sleep "${CASE_TIMEOUT:-${SMOKE_TIMEOUT:-20}}"; kill "$qpid" 2>/dev/null ) &
  local wpid=$!
  # Reboot cases: the machine never powers off; stop once enough boots are seen.
  local upid=
  if [[ -n "${3:-}" ]]; then
    ( while [[ "$(boots)" -lt "$3" ]]; do sleep 1; done; sleep 1; kill "$qpid" 2>/dev/null ) &
    upid=$!
  fi
  wait "$qpid" || true
  kill "$wpid" ${upid:+"$upid"} 2>/dev/null || true
  wait "$wpid" 2>/dev/null || true
  [[ -n "$upid" ]] && { wait "$upid" 2>/dev/null || true; }
  if [[ "${SMOKE_VERBOSE:-0}" == "1" ]]; then cat "$LOG"; fi
}

# Kernel banners in the log (each boot prints one).
boots() { grep -c -- "— bare metal" "$LOG" 2>/dev/null || true; }

has() { grep -q -- "$1" "$LOG"; }

result() { # name ok
  if [[ "$2" == "1" ]]; then
    echo "  [PASS] $1"
  else
    echo "  [FAIL] $1"
    FAILED=1
    sed 's/^/        | /' "$LOG" | tail -25
  fi
}

for c in $CASES; do
  case "$c" in
    boot)
      boot smoke-test
      ok=0
      if has "rrouter: boot ok" && has "net self-test   : ok" && has "temp self-test  : ok" && ! has "PANIC" && ! has "UNHANDLED"; then ok=1; fi
      # With QEMU_SMP=N (N > 1, up to 4): every core online and the
      # cross-core wake works. Negative control: QEMU_APPEND=cores=1 with
      # QEMU_SMP=4 must fail this case.
      smp="${QEMU_SMP:-1}"; [[ "$smp" -gt 4 ]] && smp=4
      if [[ "$smp" -gt 1 ]] && ! { has "smp             : $smp of" && has "smp self-test   : ok"; }; then ok=0; fi
      result "boot" "$ok"
      grep -E "sleep overshoot|executor  |net ping|net self-test|smp  " "$LOG" | sed 's/^/        /' || true
      ;;
    fault-wx)
      boot fault-wx panic=halt
      ok=0
      if has "UNHANDLED EXCEPTION" && has "permission fault" && ! has "FAILED"; then ok=1; fi
      result "fault-wx (W^X: .text not writable)" "$ok"
      ;;
    fault-stack)
      boot fault-stack panic=halt
      ok=0
      if has "kernel stack overflow (guard page)" && ! has "FAILED"; then ok=1; fi
      result "fault-stack (guard page catches overflow)" "$ok"
      ;;
    panic)
      CASE_TIMEOUT=$(( ${SMOKE_TIMEOUT:-20} + 15 )) boot fault-panic "" 2
      ok=0
      if has "KERNEL PANIC" && has "deliberate panic" && has "rebooting in" && [[ "$(boots)" -ge 2 ]]; then ok=1; fi
      result "panic (panic reboots the machine; $(boots) boot(s))" "$ok"
      ;;
    wdt-task)
      smp="${QEMU_SMP:-1}"; [[ "$smp" -lt 2 ]] && smp=2
      QEMU_SMP=$smp CASE_TIMEOUT=$(( ${SMOKE_TIMEOUT:-20} + 25 )) boot fault-hang "" 2
      ok=0
      if has "WATCHDOG: core $((smp - 1)) stalled" && has 'in task "hang"' && has "rebooting in" && [[ "$(boots)" -ge 2 ]]; then ok=1; fi
      result "wdt-task (cross-core check catches a stuck task, $smp cores; $(boots) boot(s))" "$ok"
      grep -E "WATCHDOG" "$LOG" | head -1 | sed 's/^/        /' || true
      ;;
    wdt-hw)
      # 10 s hardware timeout; one core, so no software check can run.
      CASE_TIMEOUT=$(( ${SMOKE_TIMEOUT:-20} * 2 + 15 )) boot fault-hang "cores=1 watchdog_secs=10" 2
      ok=0
      if has "watchdog        : i6300esb 10 s" && ! has "WATCHDOG:" && has "last reset: by the watchdog" && [[ "$(boots)" -ge 2 ]]; then ok=1; fi
      result "wdt-hw (i6300esb resets a hung single core; $(boots) boot(s))" "$ok"
      ;;
    *)
      echo "unknown case: $c" >&2
      FAILED=1
      ;;
  esac
done

if [[ "$FAILED" == "0" ]]; then
  echo "SMOKE TEST: PASS"
else
  echo "SMOKE TEST: FAIL" >&2
  exit 1
fi
