#!/usr/bin/env bash
# Build the kernel with the `smoke-test` feature, boot it in QEMU and check
# that it reaches "rrouter: boot ok" and powers off. Exit code 0 = pass.
# Set QEMU_ACCEL=tcg to also test without hardware acceleration.
set -euo pipefail
cd "$(dirname "$0")/.."

LOG="$(mktemp -t rrouter-smoke.XXXXXX)"
trap 'rm -f "$LOG"' EXIT

cargo build -p rrouter-kernel --target aarch64-unknown-none --features smoke-test --quiet
KERNEL=target/aarch64-unknown-none/debug/rrouter

# The kernel powers off via PSCI, so QEMU exits on its own. A background
# watchdog kills it if the kernel hangs (macOS has no `timeout`).
scripts/qemu-run.sh "$KERNEL" >"$LOG" 2>&1 &
QPID=$!
( sleep "${SMOKE_TIMEOUT:-20}"; kill "$QPID" 2>/dev/null ) &
WPID=$!
wait "$QPID" || true
kill "$WPID" 2>/dev/null || true
wait "$WPID" 2>/dev/null || true

cat "$LOG"
if grep -q "rrouter: boot ok" "$LOG" && ! grep -q -e "PANIC" -e "UNHANDLED EXCEPTION" "$LOG"; then
  echo "SMOKE TEST: PASS"
else
  echo "SMOKE TEST: FAIL" >&2
  exit 1
fi
