#!/usr/bin/env bash
# End-to-end lab: three QEMU VMs joined by UDP socket links (no root needed).
#
#   [client]  ──LAN 10004<->10003──  [rrouter]  ──WAN 10005<->10006──  [ISP]
#   Alpine, DHCP client              192.168.1.1 / DHCP from ISP        203.0.113.1
#   runs all checks                  DHCP srv, DNS, NAT, firewall       udhcpd, httpd, dnsd
#
# The client (lab/client/init) checks LAN services (DHCP, DNS zone,
# upstream DNS via the ISP) and forwarding (TCP/ICMP through NAT, NATed
# source, traceroute = TTL + ICMP-error NAT, 20 connections, firewall probe
# from the ISP side), printing "LAB PASS/FAIL" lines.
# Exit code 0 = all checks passed.
#
#   LAB_VERBOSE=1        print all three consoles
#   LAB_PCAP_DIR=dir     capture router WAN/LAN traffic to pcap
#   LAB_KEEP_LOGS=1      keep console logs (path printed)
#   LAB_TIMEOUT=120      seconds before giving up
#   QEMU_ACCEL=tcg       run without hardware acceleration
set -euo pipefail
cd "$(dirname "$0")/.."

TIMEOUT="${LAB_TIMEOUT:-120}"
LAN_PORT="${LAB_LAN_PORT:-10003}"
WAN_PORT="${LAB_WAN_PORT:-10005}"
WORK=$(mktemp -d -t rrouter-lab)
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ "${LAB_KEEP_LOGS:-0}" == "1" ]]; then echo "logs: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

wait_for() { # file pattern seconds
  local i=0
  while ! tr -d '\r' <"$1" 2>/dev/null | grep -q -- "$2"; do
    sleep 0.2
    i=$((i + 1))
    if [[ $i -gt $(($3 * 5)) ]]; then return 1; fi
  done
}

if [[ -z "${QEMU_ACCEL:-}" ]]; then
  if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then QEMU_ACCEL=hvf; else QEMU_ACCEL=tcg; fi
fi
if [[ "$QEMU_ACCEL" == "hvf" ]]; then CPU=(-accel hvf -cpu host); else CPU=(-accel tcg -cpu cortex-a76); fi

linux_vm() { # name initrd mac local_port remote_port log
  qemu-system-aarch64 -machine virt "${CPU[@]}" -m 512M -nographic \
    -kernel "$ALPINE_DIR/vmlinuz-virt" -initrd "$2" \
    -append "console=ttyAMA0 rdinit=/init quiet loglevel=3" \
    -netdev "dgram,id=n0,local.type=inet,local.host=127.0.0.1,local.port=$4,remote.type=inet,remote.host=127.0.0.1,remote.port=$5" \
    -device "virtio-net-pci,netdev=n0,mac=$3" >"$6" 2>&1 &
  PIDS+=($!)
}

echo "== build"
cargo build -q -p rrouter-kernel --target aarch64-unknown-none
ALPINE_DIR=$(scripts/lab/fetch-alpine.sh | tail -1)
ISP_INITRD=$(scripts/lab/build-initrd.sh isp | tail -1)
CLIENT_INITRD=$(scripts/lab/build-initrd.sh client | tail -1)

echo "== start ISP (203.0.113.1)"
linux_vm isp "$ISP_INITRD" 52:54:00:00:01:01 $((WAN_PORT + 1)) "$WAN_PORT" "$WORK/isp.log"
wait_for "$WORK/isp.log" "LAB isp ready" 30 || { echo "ISP did not start:"; cat "$WORK/isp.log"; exit 1; }

echo "== start rrouter"
QEMU_NET=lab LAB_LAN_PORT="$LAN_PORT" LAB_WAN_PORT="$WAN_PORT" QEMU_PCAP_DIR="${LAB_PCAP_DIR:-}" QEMU_ACCEL="$QEMU_ACCEL" \
  scripts/qemu-run.sh target/aarch64-unknown-none/debug/rrouter >"$WORK/router.log" 2>&1 &
PIDS+=($!)
wait_for "$WORK/router.log" "rrouter: boot ok" 40 || { echo "router did not boot:"; cat "$WORK/router.log"; exit 1; }

echo "== start client"
linux_vm client "$CLIENT_INITRD" 52:54:00:00:00:10 $((LAN_PORT + 1)) "$LAN_PORT" "$WORK/client.log"
wait_for "$WORK/client.log" "LAB DONE" "$TIMEOUT" || echo "client did not finish within ${TIMEOUT}s"
sleep 0.5

if [[ "${LAB_VERBOSE:-0}" == "1" ]]; then
  for vm in isp router client; do
    echo "== $vm console"; tr -d '\r' <"$WORK/$vm.log" | sed "s/^/  ${vm:0:1}| /"
  done
fi

echo "== router"
tr -d '\r' <"$WORK/router.log" | grep -E "dhcp  |lan services|net wan0 .*lease|net ping" | sed 's/^/  /' || true
echo "== results"
tr -d '\r' <"$WORK/client.log" | grep -E "^LAB (PASS|FAIL|INFO|WARN)|^    \|" | sed 's/^/  /' || true

if tr -d '\r' <"$WORK/client.log" | grep -q "LAB DONE fails=0" && ! tr -d '\r' <"$WORK/client.log" | grep -q "LAB FAIL"; then
  echo "LAB TEST: PASS"
else
  echo "LAB TEST: FAIL" >&2
  if [[ "${LAB_VERBOSE:-0}" != "1" ]]; then
    echo "-- client console tail"; tr -d '\r' <"$WORK/client.log" | tail -25
  fi
  exit 1
fi
