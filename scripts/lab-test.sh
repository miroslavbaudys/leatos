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
#   RROUTER_ARCH=x86_64  run the x86_64 router kernel (QEMU q35, TCG); the
#                        client and ISP VMs stay aarch64
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
#
#   LAB_VLAN=N           the ISP serves on 802.1Q VLAN N only and the router
#                        gets wan_vlan=N (after LAB_ROUTER_ARGS, so those win).
#                        Negative controls: LAB_ROUTER_ARGS=wan_vlan=0
#                        (untagged) or another VLAN must fail (no WAN lease).
#   LAB_BIG_PING=1472    ICMP data size of the client's full-size ping
#                        (1473 = negative control: fragmented, dropped).
#                        With PPPoE the default is 1464 (MTU 1492; 1465 =
#                        negative control: too big for the session, dropped).
#   LAB_PPPOE=pap|chap   the ISP is a PPPoE access concentrator only (no
#                        DHCP; pppoe-server from the pinned packages, needs
#                        modloop) requiring PAP or CHAP; the router gets
#                        wan_mode=pppoe pppoe_user=rrouter pppoe_pass=lab-secret
#                        (LAB_ROUTER_ARGS win). Checks: session up (router
#                        log), all client checks through it, and a reconnect
#                        after the ISP ends the session. Negative controls:
#                        LAB_ROUTER_ARGS=pppoe_pass=wrong or wan_mode=dhcp
#                        (no session, everything fails), LAB_PPPOE_KICK=stop
#                        (the ISP's server is stopped too: no reconnect).
#                        Combines with LAB_VLAN=N (PPPoE on the VLAN).
#   LAB_GUEST=1          the router boots from a store (tools/rrstore) with a
#                        second network: VLAN 20 on lan0, 10.20.0.1/24, zone
#                        "guest" (input: DHCP, DNS, ping; forwards to the
#                        WAN only). The client adds eth0.20 (8021q from
#                        modloop) and checks: guest lease, guest -> ISP,
#                        DNS + ping to the router allowed, the router's web
#                        interface blocked, new connections to the main LAN
#                        refused (router firewall drop counter). Negative
#                        control: LAB_GUEST_ZONE=lan puts the network in the
#                        main zone, so the last two checks must fail.
#                        Rules (step 4): guest-ping-nas (accept ICMP from
#                        the guest to 192.168.1.10, which the zones refuse)
#                        and guest-no-isp-web (reject guest TCP 80 to the
#                        WAN); the client checks both through the rules'
#                        hit counters and the traffic. Negative control:
#                        LAB_GUEST_RULES=0 (config without them: both fail).
#
# SNTP: the router syncs from the ISP's ntpd (ntp=ntp.isp.example: resolved
# through the router's DNS forwarder) and its clock must then be within 5 s
# of the host's. Negative control: LAB_ROUTER_ARGS=ntp=203.0.113.99
# (nothing answers there) must fail the check.
set -euo pipefail
cd "$(dirname "$0")/.."

TIMEOUT="${LAB_TIMEOUT:-120}"
SHAPE_KBIT="${LAB_SHAPE_KBIT:-10000}"
EXPECT_KBIT="${LAB_EXPECT_KBIT:-$SHAPE_KBIT}"
ROUTER_ARGS=""
[[ "$SHAPE_KBIT" != 0 ]] && ROUTER_ARGS="shape_up=$SHAPE_KBIT shape_down=$SHAPE_KBIT"
ROUTER_ARGS="$ROUTER_ARGS ${LAB_ROUTER_ARGS:-}"
# The first ntp= wins: only add the default when the caller sets none.
[[ " ${LAB_ROUTER_ARGS:-} " == *" ntp="* ]] || ROUTER_ARGS="$ROUTER_ARGS ntp=ntp.isp.example"
ISP_VLAN="${LAB_VLAN:-}"
# The router takes the first occurrence of an argument: LAB_ROUTER_ARGS wins.
[[ -n "$ISP_VLAN" ]] && ROUTER_ARGS="$ROUTER_ARGS wan_vlan=$ISP_VLAN"
ISP_PPPOE="${LAB_PPPOE:-}"
[[ "$ISP_PPPOE" == 1 ]] && ISP_PPPOE=pap
BIG_PING="${LAB_BIG_PING:-1472}"
if [[ -n "$ISP_PPPOE" ]]; then
  ROUTER_ARGS="$ROUTER_ARGS wan_mode=pppoe pppoe_user=rrouter pppoe_pass=lab-secret"
  BIG_PING="${LAB_BIG_PING:-1464}"
fi
GUEST="${LAB_GUEST:-}"
GUEST_ZONE="${LAB_GUEST_ZONE:-guest}"
GUEST_RULES="${LAB_GUEST_RULES:-1}"
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
ARCH="${RROUTER_ARCH:-aarch64}"
cargo build -q -p rrouter-kernel --target "$ARCH-unknown-none"
MODLOOP=""
[[ -n "$ISP_VLAN$ISP_PPPOE$GUEST" ]] && MODLOOP=modloop
ALPINE_DIR=$(scripts/lab/fetch-alpine.sh $MODLOOP | tail -1)
ISP_INITRD=$(scripts/lab/build-initrd.sh isp | tail -1)
CLIENT_INITRD=$(scripts/lab/build-initrd.sh client | tail -1)

echo "== start ISP (203.0.113.1${ISP_VLAN:+ on VLAN $ISP_VLAN}${ISP_PPPOE:+, PPPoE $ISP_PPPOE})"
start_isp "$WAN_PORT" "$WORK/isp.log" || exit 1

ROUTER_STORE=""
if [[ -n "$GUEST" ]]; then
  # Two networks; the stored config replaces the VM fixtures, so the nas
  # reservation the client resolves is listed here.
  cat >"$WORK/config.toml" <<CFG
version = 2

[[network]]
name = "lan"
ipv4 = "192.168.1.1/24"
[[network.dhcp.static]]
mac = "52:54:00:00:00:05"
ip = "192.168.1.10"
hostname = "nas"

[[network]]
name = "guest"
vlan = 20
ipv4 = "10.20.0.1/24"
zone = "$GUEST_ZONE"

[[zone]]
name = "guest"
input = "drop"
allow = ["dhcp", "dns", "ping"]
forward_to = ["wan"]
CFG
  [[ "$GUEST_RULES" == 1 ]] && cat >>"$WORK/config.toml" <<'CFG'

[[firewall.rule]]
name = "guest-ping-nas"
from = "guest"
to = "lan"
proto = "icmp"
dst = "192.168.1.10"
action = "accept"

[[firewall.rule]]
name = "guest-no-isp-web"
from = "guest"
to = "wan"
proto = "tcp"
dst_port = 80
action = "reject"
CFG
  cargo build -q -p rrstore --release
  target/release/rrstore create "$WORK/store.img" --mib 32 >/dev/null
  target/release/rrstore put "$WORK/store.img" config "$WORK/config.toml" >/dev/null
  ROUTER_STORE="$WORK/store.img"
  echo "== router config: networks lan + guest (VLAN 20, zone $GUEST_ZONE)$([[ "$GUEST_RULES" == 1 ]] && echo ", 2 rules")"
fi

echo "== start rrouter${ROUTER_ARGS:+ ($(echo "$ROUTER_ARGS" | sed 's/pppoe_pass=[^ ]*/pppoe_pass=***/'))}"
QEMU_STORE="$ROUTER_STORE" QEMU_NET=lab LAB_LAN_PORT="$LAN_PORT" LAB_WAN_PORT="$WAN_PORT" QEMU_PCAP_DIR="${LAB_PCAP_DIR:-}" QEMU_ACCEL="$QEMU_ACCEL" QEMU_APPEND="$ROUTER_ARGS" \
  scripts/qemu-run.sh "target/$ARCH-unknown-none/debug/rrouter" >"$WORK/router.log" 2>&1 &
PIDS+=($!)
wait_for "$WORK/router.log" "rrouter: boot ok" 40 || { echo "router did not boot:"; cat "$WORK/router.log"; exit 1; }
# When the host sees the router's first SNTP sync (compared with the time
# the router then reports).
( wait_for "$WORK/router.log" "ntp  .*synced to" 90 && date -u +%s >"$WORK/ntp-seen" ) &
PIDS+=($!)

echo "== start client"
VM_DISK="${GUEST:+$ALPINE_DIR/modloop-virt}" \
  linux_vm "$CLIENT_INITRD" 52:54:00:00:00:10 $((LAN_PORT + 1)) "$LAN_PORT" "$WORK/client.log" "lab_shape_kbit=$EXPECT_KBIT lab_big_ping=$BIG_PING${ISP_PPPOE:+ lab_pppoe_kick=${LAB_PPPOE_KICK:-kick}}${GUEST:+ lab_guest=$GUEST_ZONE lab_guest_rules=$GUEST_RULES}"
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
tr -d '\r' <"$WORK/router.log" | grep -E "dhcp  |lan services|net lan0  |net wan0 .*(lease|vlan|PPPoE)|pppoe |net ping|qos |qdisc |cpu  |ntp  |watchdog  |vlan  " | sed 's/^/  /' || true
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

# PPPoE: the session came up (MTU 1492, DNS from IPCP) before the client
# ran; the reconnect is the client's check.
if [[ -n "$ISP_PPPOE" ]]; then
  up=$(tr -d '\r' <"$WORK/router.log" | grep "pppoe wan0 .*: up," | head -1 || true)
  if echo "$up" | grep -q "203.0.113.50 peer 203.0.113.1 dns \[203.0.113.1\] mtu 1492 (AC isp-ac)"; then
    echo "  LAB PASS: pppoe ($ISP_PPPOE): ${up##*: }"
  else
    echo "  LAB FAIL: pppoe ($ISP_PPPOE): no session (${up:-no 'up' line in the router log})"
    tr -d '\r' <"$WORK/router.log" | grep "pppoe " | tail -3 | sed 's/^/    | /'
    router_fails=$((router_fails + 1))
  fi
fi

# SNTP: synced, and the time it then reported is the host's (±5 s; the
# ISP VM's clock comes from the host's RTC).
sync=$(tr -d '\r' <"$WORK/router.log" | grep "ntp  .*synced to" | head -1 || true)
utc=$(echo "$sync" | sed -n 's/.*: \([0-9-]*T[0-9:]*Z\)$/\1/p')
router_s=$( [[ -n "$utc" ]] && date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$utc" +%s 2>/dev/null || true)
seen_s=$(cat "$WORK/ntp-seen" 2>/dev/null || true)
if [[ -n "$router_s" && -n "$seen_s" ]]; then
  skew=$((router_s - seen_s)); abs=${skew#-}
  if [[ "$abs" -le 5 ]]; then
    echo "  LAB PASS: ntp: ${sync##*ntp             : } (host clock difference ${skew} s)"
  else
    echo "  LAB FAIL: ntp: router says $utc, host $(date -u -r "$seen_s" +%Y-%m-%dT%H:%M:%SZ) (${skew} s)"; router_fails=$((router_fails + 1))
  fi
else
  echo "  LAB FAIL: ntp: no sync (${sync:-no 'synced' line in the router log})"; router_fails=$((router_fails + 1))
fi

# CPU time per task (M11). Forwarding runs in the datapath tasks: dp_down
# (WAN RX -> LAN TX) and dp_up (LAN RX -> WAN TX); DHCP/DNS/web in svc.
# 1. split: svc did work, and each direction's task (loaded by the client's
#    download resp. upload phase) more of it. Negative control: a kernel
#    with one task doing everything (bdcf72e) has no svc/dp_* tasks.
# 2. placement: with QEMU_SMP >= 3 dp_up runs on core 1, else on core 0
#    (LAB_EXPECT_UP_CORE overrides). Negative control: QEMU_SMP=4 with
#    LAB_ROUTER_ARGS=cores=2 keeps dp_up on core 0 and fails.
line=$(tr -d '\r' <"$WORK/router.log" | grep "  cpu  " | tail -1 || true)
task_ms() { echo "$line" | sed -n "s/.*, $1@[0-9]* \([0-9]*\) ms.*/\1/p"; }
task_core() { echo "$line" | sed -n "s/.*, $1@\([0-9]*\) .*/\1/p"; }
down_ms=$(task_ms dp_down); up_ms=$(task_ms dp_up); svc_ms=$(task_ms svc)
what="dp_down ${down_ms:-?} ms, dp_up ${up_ms:-?} ms, svc ${svc_ms:-?} ms"
if [[ -z "$down_ms" || -z "$up_ms" || -z "$svc_ms" ]]; then
  echo "  LAB FAIL: cpu split: $what (no per-task counters)"; router_fails=$((router_fails + 1))
elif [[ "$svc_ms" -gt 0 && "$down_ms" -gt "$svc_ms" && "$up_ms" -gt "$svc_ms" ]]; then
  echo "  LAB PASS: cpu split: $what"
else
  echo "  LAB FAIL: cpu split: expected svc > 0 and each direction > svc: $what"; router_fails=$((router_fails + 1))
fi
smp="${QEMU_SMP:-1}"
want_up=${LAB_EXPECT_UP_CORE:-$([[ "$smp" -ge 3 ]] && echo 1 || echo 0)}
up_core=$(task_core dp_up); down_core=$(task_core dp_down)
if [[ "$up_core" == "$want_up" && "$down_core" == 0 ]]; then
  echo "  LAB PASS: cpu placement: dp_down on core ${down_core}, dp_up on core ${up_core} (QEMU_SMP=$smp)"
else
  echo "  LAB FAIL: cpu placement: expected dp_down on core 0, dp_up on core $want_up, got ${down_core:-?}/${up_core:-?}"
  router_fails=$((router_fails + 1))
fi
# 3. interrupts: the LAN NIC's interrupts are delivered to dp_up's core
#    (x86_64: MSI-X destination; aarch64: GIC routing on unmask), so with
#    QEMU_SMP >= 3 core 1 handles device interrupts. Same negative control.
irqs=$(echo "$line" | sed -n 's/.*dev irqs \[\(.*\)\].*/\1/p' | tr -d ' ')
irq_up=$(echo "$irqs" | cut -d, -f$((want_up + 1)))
if [[ -n "$irq_up" && "$irq_up" -gt 0 ]]; then
  echo "  LAB PASS: irq placement: device interrupts per core [$irqs], core $want_up handles the LAN NIC"
else
  echo "  LAB FAIL: irq placement: expected device interrupts on core $want_up, got [${irqs:-?}]"
  router_fails=$((router_fails + 1))
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
