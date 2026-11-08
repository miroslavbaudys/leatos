#!/usr/bin/env bash
# Boot-test the kernel in QEMU. Each case builds the kernel with specific
# features, boots it (the kernel powers off via PSCI so QEMU exits), and
# checks the console output. Exit code 0 = all cases passed.
#
#   scripts/smoke-test.sh                 # all cases
#   SMOKE_CASES="boot" scripts/smoke-test.sh
#   QEMU_ACCEL=tcg scripts/smoke-test.sh  # without hardware acceleration
#   SMOKE_VERBOSE=1 ...                   # print full console output
#
# Cases:
#   boot         normal boot with 2 NICs: self-tests pass, PCI finds virtio-net
#   fault-wx     writing to .text must raise a permission fault (W^X)
#   fault-stack  unbounded recursion must hit the kernel stack guard page
set -euo pipefail
cd "$(dirname "$0")/.."

CASES="${SMOKE_CASES:-boot fault-wx fault-stack}"
KERNEL=target/aarch64-unknown-none/debug/rrouter
LOG="$(mktemp -t rrouter-smoke.XXXXXX)"
trap 'rm -f "$LOG"' EXIT
FAILED=0

boot() { # features
  cargo build -p rrouter-kernel --target aarch64-unknown-none --features "$1" --quiet
  # macOS has no `timeout`: a background watchdog kills QEMU if the kernel hangs.
  QEMU_NET="${QEMU_NET:-user}" scripts/qemu-run.sh "$KERNEL" >"$LOG" 2>&1 &
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
      if has "rrouter: boot ok" && has "virtio-net" && ! has "PANIC" && ! has "UNHANDLED"; then ok=1; fi
      result "boot" "$ok"
      grep -E "sleep overshoot|executor  " "$LOG" | sed 's/^/        /' || true
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
