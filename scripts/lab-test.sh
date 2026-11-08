#!/usr/bin/env bash
# End-to-end LAN test: rrouter VM + Alpine client VM connected by a UDP
# socket link (`-netdev dgram`, no root needed).
#
#   [client VM] eth0 ──dgram 127.0.0.1:10004<->10003── lan0 [rrouter] wan0 ── QEMU user-mode (slirp)
#
# The client (lab/client/init) gets a DHCP lease from rrouter, checks DNS
# (.lan zone, reverse lookups, NXDOMAIN, upstream forwarding) and pings the
# router, printing "LAB PASS/FAIL" lines. Exit code 0 = all checks passed.
#
#   LAB_VERBOSE=1        print both consoles
#   LAB_PCAP_DIR=dir     capture router WAN/LAN traffic to pcap
#   LAB_TIMEOUT=90       seconds before giving up
#   QEMU_ACCEL=tcg       run without hardware acceleration
set -euo pipefail
cd "$(dirname "$0")/.."

TIMEOUT="${LAB_TIMEOUT:-90}"
PORT="${LAB_LAN_PORT:-10003}"
WORK=$(mktemp -d -t rrouter-lab)
ROUTER_LOG="$WORK/router.log"
CLIENT_LOG="$WORK/client.log"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ "${LAB_KEEP_LOGS:-0}" == "1" ]]; then echo "logs: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

wait_for() { # file pattern seconds
  local i=0
  while ! grep -q -- "$2" "$1" 2>/dev/null; do
    sleep 0.2
    i=$((i + 1))
    if [[ $i -gt $(($3 * 5)) ]]; then return 1; fi
  done
}

if [[ -z "${QEMU_ACCEL:-}" ]]; then
  if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then QEMU_ACCEL=hvf; else QEMU_ACCEL=tcg; fi
fi
if [[ "$QEMU_ACCEL" == "hvf" ]]; then CPU=(-accel hvf -cpu host); else CPU=(-accel tcg -cpu cortex-a76); fi

echo "== build"
cargo build -q -p rrouter-kernel --target aarch64-unknown-none
INITRD=$(scripts/lab/build-client-initrd.sh | tail -1)
ALPINE_DIR=$(scripts/lab/fetch-alpine.sh | tail -1)

echo "== start rrouter (LAN on udp :$PORT)"
QEMU_NET=lab LAB_LAN_PORT="$PORT" QEMU_PCAP_DIR="${LAB_PCAP_DIR:-}" QEMU_ACCEL="$QEMU_ACCEL" \
  scripts/qemu-run.sh target/aarch64-unknown-none/debug/rrouter >"$ROUTER_LOG" 2>&1 &
PIDS+=($!)
if ! wait_for "$ROUTER_LOG" "rrouter: boot ok" 30; then
  echo "router did not boot:"; cat "$ROUTER_LOG"; exit 1
fi

echo "== start client (Alpine, mac 52:54:00:00:00:10)"
qemu-system-aarch64 -machine virt "${CPU[@]}" -m 512M -nographic \
  -kernel "$ALPINE_DIR/vmlinuz-virt" -initrd "$INITRD" \
  -append "console=ttyAMA0 rdinit=/init quiet loglevel=3" \
  -netdev "dgram,id=lan,local.type=inet,local.host=127.0.0.1,local.port=$((PORT + 1)),remote.type=inet,remote.host=127.0.0.1,remote.port=$PORT" \
  -device virtio-net-pci,netdev=lan,mac=52:54:00:00:00:10 \
  >"$CLIENT_LOG" 2>&1 &
CLIENT=$!
PIDS+=("$CLIENT")

if ! wait_for "$CLIENT_LOG" "LAB DONE" "$TIMEOUT"; then
  echo "client did not finish within ${TIMEOUT}s"
fi
sleep 0.5

if [[ "${LAB_VERBOSE:-0}" == "1" ]]; then
  echo "== router console"; sed 's/^/  r| /' "$ROUTER_LOG"
  echo "== client console"; tr -d '\r' <"$CLIENT_LOG" | sed 's/^/  c| /'
fi

echo "== router"
grep -E "dhcp  |lan services|net wan0 .*lease" "$ROUTER_LOG" | sed 's/^/  /' || true
echo "== results"
tr -d '\r' <"$CLIENT_LOG" | grep -E "^LAB (PASS|FAIL|INFO|WARN)|^    \|" | sed 's/^/  /' || true

if tr -d '\r' <"$CLIENT_LOG" | grep -q "LAB DONE fails=0" && ! tr -d '\r' <"$CLIENT_LOG" | grep -q "LAB FAIL"; then
  echo "LAB TEST: PASS"
else
  echo "LAB TEST: FAIL" >&2
  [[ "${LAB_VERBOSE:-0}" == "1" ]] || { echo "-- client console tail"; tr -d '\r' <"$CLIENT_LOG" | tail -30; }
  exit 1
fi
