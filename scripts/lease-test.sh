#!/usr/bin/env bash
# DHCP leases survive router restarts (the store's `leases` area,
# docs/config-and-storage.md): the router (with a store image) and the lab
# client VM (lab_leases=1 in lab/client/init) on the LAN, no ISP.
#   A, power cut: the client takes a lease; once the router logs the
#     periodic save, this script kills the router and starts it again on
#     the same store. Before any new DHCP from the client, the router must
#     list the lease (/api/status) and resolve the client's name.
#   B, reboot: the client takes a second lease (another MAC) and asks for
#     a reboot right away (POST /api/reboot): saved on the way down.
# Negative control: LEASE_TEST_NO_STORE=1 (no store: every lease check fails).
#   scripts/lease-test.sh            (RROUTER_ARCH=x86_64 for the x86 kernel)
set -euo pipefail
cd "$(dirname "$0")/.."

NO_STORE="${LEASE_TEST_NO_STORE:-0}"
LAN_PORT="${LAB_LAN_PORT:-10023}"
WAN_PORT="${LAB_WAN_PORT:-10025}"
ARCH="${RROUTER_ARCH:-aarch64}"
WORK=$(mktemp -d -t rrouter-leases)
PIDS=()
ROUTER_PID=""
cleanup() {
  for p in "${PIDS[@]:-}" $ROUTER_PID; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ "${LAB_KEEP_LOGS:-0}" == "1" ]]; then echo "logs: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

source scripts/lab/common.sh
lab_cpu_flags

echo "== build"
cargo build -q -p leatos-kernel --target "$ARCH-unknown-none"
cargo build -q -p leatstore --release
ALPINE_DIR=$(scripts/lab/fetch-alpine.sh | tail -1)
CLIENT_INITRD=$(scripts/lab/build-initrd.sh client | tail -1)

STORE=""
WHAT="no store: negative control"
if [[ "$NO_STORE" != 1 ]]; then
  WHAT="store"
  target/release/leatstore create "$WORK/store.img" --mib 32 >/dev/null
  STORE="$WORK/store.img"
fi

router() { # log
  QEMU_STORE="$STORE" QEMU_NET=lab LAB_LAN_PORT="$LAN_PORT" LAB_WAN_PORT="$WAN_PORT" QEMU_ACCEL="$QEMU_ACCEL" \
    QEMU_APPEND="mgmt_pass=lab-pass" scripts/qemu-run.sh "target/$ARCH-unknown-none/debug/leatos" >"$1" 2>&1 &
  ROUTER_PID=$!
  wait_for "$1" "rrouter: boot ok" 60 || { echo "router did not boot:"; cat "$1"; exit 1; }
}

echo "== start rrouter ($WHAT)"
router "$WORK/router1.log"
echo "== start client"
linux_vm "$CLIENT_INITRD" 52:54:00:00:00:10 $((LAN_PORT + 1)) "$LAN_PORT" "$WORK/client.log" "lab_leases=1"
wait_for "$WORK/client.log" "LAB leases: lease" 60 || { echo "client got no lease:"; tr -d '\r' <"$WORK/client.log" | tail -20; exit 1; }

# A: the periodic save (every 60 s), then a power cut.
if [[ -n "$STORE" ]]; then
  wait_for "$WORK/router1.log" "leases          : saved 1 " 90 || echo "  (no periodic save seen in the router log)"
else
  sleep 5
fi
echo "== power cut: kill the router, start it again"
kill "$ROUTER_PID" 2>/dev/null || true
wait "$ROUTER_PID" 2>/dev/null || true
router "$WORK/router2.log"

wait_for "$WORK/client.log" "LAB DONE" 300 || echo "client did not finish"
saved_line=$(tr -d '\r' <"$WORK/router1.log" | grep -a "leases          :" | tail -1 || true)
restored_line=$(tr -d '\r' <"$WORK/router2.log" | grep -a "leases          :" | head -1 || true)
echo "  router before the cut: ${saved_line# }"
echo "  router after the cut : ${restored_line# }"
if [[ "${LAB_VERBOSE:-0}" == "1" ]]; then
  for f in router1 router2 client; do echo "== $f"; tr -d '\r' <"$WORK/$f.log" | sed "s/^/  ${f:0:1}| /"; done
fi
echo "== results"
tr -d '\r' <"$WORK/client.log" | grep -a "LAB \(PASS\|FAIL\)" | sed 's/^/  /' || true
if tr -d '\r' <"$WORK/client.log" | grep -q "LAB DONE fails=0" && ! tr -d '\r' <"$WORK/client.log" | grep -q "LAB FAIL"; then
  echo "LEASE TEST ($ARCH, $WHAT): PASS"
else
  echo "LEASE TEST ($ARCH, $WHAT): FAIL"
  exit 1
fi
