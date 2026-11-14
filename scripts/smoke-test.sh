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
set -euo pipefail
cd "$(dirname "$0")/.."

CASES="${SMOKE_CASES:-boot fault-wx fault-stack}"
BOOT_MODE="${RROUTER_BOOT:-kernel}"
case "$BOOT_MODE" in kernel) ;; limine) RROUTER_ARCH=x86_64 ;; *) echo "RROUTER_BOOT must be kernel or limine" >&2; exit 2 ;; esac
ARCH="${RROUTER_ARCH:-aarch64}"
case "$ARCH" in aarch64 | x86_64) ;; *) echo "RROUTER_ARCH must be aarch64 or x86_64" >&2; exit 2 ;; esac
TARGET="$ARCH-unknown-none"
KERNEL="target/$TARGET/debug/rrouter"
# x86_64 runs under TCG on Apple Silicon: allow more time.
[[ "$ARCH" == x86_64 ]] && SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-40}"
LOG="$(mktemp -t rrouter-smoke.XXXXXX)"
IMG="$LOG.img"
trap 'rm -f "$LOG" "$IMG"' EXIT
FAILED=0

boot() { # features
  if [[ "$BOOT_MODE" == limine ]]; then
    scripts/apu-image.sh --debug --features "$1" --out "$IMG" >/dev/null
  else
    cargo build -p rrouter-kernel --target "$TARGET" --features "$1" --quiet
  fi
  # macOS has no `timeout`: a background watchdog kills QEMU if the kernel hangs.
  if [[ "$BOOT_MODE" == limine ]]; then
    QEMU_DISK="$IMG" QEMU_NET="${QEMU_NET:-user}" scripts/qemu-run.sh >"$LOG" 2>&1 &
  else
    QEMU_NET="${QEMU_NET:-user}" scripts/qemu-run.sh "$KERNEL" >"$LOG" 2>&1 &
  fi
  local qpid=$!
  ( sleep "${SMOKE_TIMEOUT:-20}"; kill "$qpid" 2>/dev/null ) &
  local wpid=$!
  wait "$qpid" || true
  kill "$wpid" 2>/dev/null || true
  wait "$wpid" 2>/dev/null || true
  if [[ "${SMOKE_VERBOSE:-0}" == "1" ]]; then cat "$LOG"; fi
}

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
      if has "rrouter: boot ok" && has "net self-test   : ok" && ! has "PANIC" && ! has "UNHANDLED"; then ok=1; fi
      # With QEMU_SMP=N (N > 1, up to 4): every core online and the
      # cross-core wake works. Negative control: QEMU_APPEND=cores=1 with
      # QEMU_SMP=4 must fail this case.
      smp="${QEMU_SMP:-1}"; [[ "$smp" -gt 4 ]] && smp=4
      if [[ "$smp" -gt 1 ]] && ! { has "smp             : $smp of" && has "smp self-test   : ok"; }; then ok=0; fi
      result "boot" "$ok"
      grep -E "sleep overshoot|executor  |net ping|net self-test|smp  " "$LOG" | sed 's/^/        /' || true
      ;;
    fault-wx)
      boot fault-wx
      ok=0
      if has "UNHANDLED EXCEPTION" && has "permission fault" && ! has "FAILED"; then ok=1; fi
      result "fault-wx (W^X: .text not writable)" "$ok"
      ;;
    fault-stack)
      boot fault-stack
      ok=0
      if has "kernel stack overflow (guard page)" && ! has "FAILED"; then ok=1; fi
      result "fault-stack (guard page catches overflow)" "$ok"
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
