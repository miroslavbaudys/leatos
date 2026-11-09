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
#   LAB_SHAPE_KBIT=10000 router shapes both directions at this rate and the
#                        client checks throughput + latency under load
#                        (0 = unshaped router, shaping checks skipped)
#   LAB_EXPECT_KBIT=N    what the client expects (default: LAB_SHAPE_KBIT);
#                        set it with LAB_SHAPE_KBIT=0 as a negative control
#   LAB_ROUTER_ARGS="…"  extra router boot arguments, e.g. qdisc=codel (single
#                        CoDel queue: the negative control for the flow-
#                        isolation latency check)
#   LAB_EXPECT_ECN=U:D   ECN the check expects per direction (1 = marks, 0 =
#                        drops; default: derived from the router arguments,
#                        i.e. 0:1). Set it against the router's real setting
#                        as a negative control, e.g. LAB_ROUTER_ARGS=ecn=1
#                        with the default expectation.
set -euo pipefail
cd "$(dirname "$0")/.."

TIMEOUT="${LAB_TIMEOUT:-120}"
SHAPE_KBIT="${LAB_SHAPE_KBIT:-10000}"
EXPECT_KBIT="${LAB_EXPECT_KBIT:-$SHAPE_KBIT}"
ROUTER_ARGS=""
[[ "$SHAPE_KBIT" != 0 ]] && ROUTER_ARGS="shape_up=$SHAPE_KBIT shape_down=$SHAPE_KBIT"
ROUTER_ARGS="$ROUTER_ARGS ${LAB_ROUTER_ARGS:-}"
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

source scripts/lab/common.sh
lab_cpu_flags

echo "== build"
cargo build -q -p rrouter-kernel --target aarch64-unknown-none
ALPINE_DIR=$(scripts/lab/fetch-alpine.sh | tail -1)
ISP_INITRD=$(scripts/lab/build-initrd.sh isp | tail -1)
CLIENT_INITRD=$(scripts/lab/build-initrd.sh client | tail -1)

echo "== start ISP (203.0.113.1)"
start_isp "$WAN_PORT" "$WORK/isp.log" || exit 1

echo "== start rrouter${ROUTER_ARGS:+ ($ROUTER_ARGS)}"
QEMU_NET=lab LAB_LAN_PORT="$LAN_PORT" LAB_WAN_PORT="$WAN_PORT" QEMU_PCAP_DIR="${LAB_PCAP_DIR:-}" QEMU_ACCEL="$QEMU_ACCEL" QEMU_APPEND="$ROUTER_ARGS" \
  scripts/qemu-run.sh target/aarch64-unknown-none/debug/rrouter >"$WORK/router.log" 2>&1 &
PIDS+=($!)
wait_for "$WORK/router.log" "rrouter: boot ok" 40 || { echo "router did not boot:"; cat "$WORK/router.log"; exit 1; }

echo "== start client"
linux_vm "$CLIENT_INITRD" 52:54:00:00:00:10 $((LAN_PORT + 1)) "$LAN_PORT" "$WORK/client.log" "lab_shape_kbit=$EXPECT_KBIT"
wait_for "$WORK/client.log" "LAB DONE" "$TIMEOUT" || echo "client did not finish within ${TIMEOUT}s"
sleep 0.5
# The router prints qdisc counters every 10 s: wait for one more round so
# they include the client's last (upload) phase.
if [[ "$SHAPE_KBIT" != 0 ]]; then
  n0=$(tr -d '\r' <"$WORK/router.log" | grep -c "qdisc wan0" || true)
  for _ in $(seq 1 130); do
    [[ $(tr -d '\r' <"$WORK/router.log" | grep -c "qdisc wan0" || true) -gt "$n0" ]] && break
    sleep 0.1
  done
fi

if [[ "${LAB_VERBOSE:-0}" == "1" ]]; then
  for vm in isp router client; do
    echo "== $vm console"; tr -d '\r' <"$WORK/$vm.log" | sed "s/^/  ${vm:0:1}| /"
  done
fi

echo "== router"
tr -d '\r' <"$WORK/router.log" | grep -E "dhcp  |lan services|net wan0 .*lease|net ping|qos |qdisc " | sed 's/^/  /' || true
echo "== results"
tr -d '\r' <"$WORK/client.log" | grep -E "^LAB (PASS|FAIL|INFO|WARN)|^    \|" | sed 's/^/  /' || true

# Per-direction ECN (router side): with ECN on, the AQM marks the client's
# ECN-capable traffic; with it off, it drops and never marks. Upload = WAN
# egress, download = LAN egress.
router_fails=0
if [[ "$SHAPE_KBIT" != 0 ]]; then
  bootarg() { echo " $ROUTER_ARGS " | sed -n "s/.* $1=\([0-9]*\) .*/\1/p"; }
  all=$(bootarg ecn)
  up=$(bootarg ecn_up); up=${up:-${all:-0}}
  down=$(bootarg ecn_down); down=${down:-${all:-1}}
  if [[ -n "${LAB_EXPECT_ECN:-}" ]]; then up=${LAB_EXPECT_ECN%%:*}; down=${LAB_EXPECT_ECN##*:}; fi
  for pair in "wan0 upload $up" "lan0 download $down"; do
    set -- $pair
    line=$(tr -d '\r' <"$WORK/router.log" | grep "qdisc $1 " | tail -1)
    drops=$(echo "$line" | sed -n 's/.*aqm drops \([0-9]*\).*/\1/p')
    marks=$(echo "$line" | sed -n 's/.*ecn marks \([0-9]*\).*/\1/p')
    what="$2 ($1): aqm drops ${drops:-?}, ecn marks ${marks:-?}"
    if [[ -z "$drops" || -z "$marks" ]]; then
      echo "  LAB FAIL: ecn $what (no router counters)"; router_fails=$((router_fails + 1))
    elif [[ "$3" == 1 && "$marks" -gt 0 ]]; then
      echo "  LAB PASS: ecn $2 on: $what"
    elif [[ "$3" == 0 && "$marks" == 0 && "$drops" -gt 0 ]]; then
      echo "  LAB PASS: ecn $2 off: $what"
    else
      echo "  LAB FAIL: ecn $2 expected $([[ "$3" == 1 ]] && echo marks || echo 'drops, no marks'): $what"
      router_fails=$((router_fails + 1))
    fi
  done
fi

if [[ "$router_fails" == 0 ]] && tr -d '\r' <"$WORK/client.log" | grep -q "LAB DONE fails=0" && ! tr -d '\r' <"$WORK/client.log" | grep -q "LAB FAIL"; then
  echo "LAB TEST: PASS"
else
  echo "LAB TEST: FAIL" >&2
  if [[ "${LAB_VERBOSE:-0}" != "1" ]]; then
    echo "-- client console tail"; tr -d '\r' <"$WORK/client.log" | tail -25
  fi
  exit 1
fi
