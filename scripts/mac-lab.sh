#!/usr/bin/env bash
# Put this Mac on rrouter's LAN (macOS vmnet-host), with the lab ISP VM as
# rrouter's upstream. The Mac's normal internet (Wi-Fi/Ethernet) is NOT
# touched: only lab traffic is routed through rrouter.
#
#   MacBook ──bridgeN (vmnet-host, 192.168.1.2)── [rrouter LAN 192.168.1.1]
#                                                 [rrouter WAN] ──udp── [ISP VM 203.0.113.1]
#   Mac route:     203.0.113.0/24 via 192.168.1.1   (removed on exit)
#   Mac resolvers: /etc/resolver/{lan,example} -> 192.168.1.1   (removed on exit)
#
# Usage (run in Terminal: sudo will ask for your password once):
#   scripts/mac-lab.sh           start, run checks, stay up until Ctrl-C
#   scripts/mac-lab.sh --check   start, run checks, tear down (exit 1 on failure)
#
# Needs sudo only for: QEMU with vmnet (Homebrew QEMU lacks Apple's
# networking entitlement), the route, and the resolver files.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-interactive}"
[[ "$MODE" == "interactive" || "$MODE" == "--check" ]] || { sed -n '2,20p' "$0"; exit 2; }
[[ "$(uname -s)" == "Darwin" ]] || { echo "mac-lab: macOS only" >&2; exit 1; }

LAN_NET=192.168.1
ROUTER_LAN=192.168.1.1
ISP=203.0.113.1
WAN_PORT="${LAB_WAN_PORT:-10005}"
MARKER="# created by rrouter scripts/mac-lab.sh"
WORK=$(mktemp -d -t rrouter-maclab)
PIDS=()
ROUTER_PID=""
KEEPALIVE_PID=""
ROUTE_ADDED=0
RESOLVERS=()
HTTP_PID=""
fails=0

source scripts/lab/common.sh
lab_cpu_flags

cleanup() {
  set +e
  echo
  echo "== cleanup"
  [[ -n "$HTTP_PID" ]] && kill "$HTTP_PID" 2>/dev/null
  if [[ "$ROUTE_ADDED" == 1 ]]; then
    sudo -n route -n delete -net "$ISP/24" >/dev/null 2>&1 && echo "  removed route 203.0.113.0/24"
  fi
  for f in "${RESOLVERS[@]:-}"; do
    [[ -n "$f" ]] || continue
    if head -1 "$f" 2>/dev/null | grep -qF "$MARKER"; then sudo -n rm -f "$f" && echo "  removed $f"; fi
  done
  [[ -n "$ROUTER_PID" ]] && sudo -n kill "$ROUTER_PID" 2>/dev/null
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
  [[ -n "$KEEPALIVE_PID" ]] && kill "$KEEPALIVE_PID" 2>/dev/null
  wait 2>/dev/null
  echo "  VMs stopped; logs: $WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; fails=$((fails + 1)); }
info() { echo "  [INFO] $*"; }

# ---- preflight -------------------------------------------------------------------
QEMU_BIN=$(command -v qemu-system-aarch64) || { echo "qemu-system-aarch64 not found (brew install qemu)" >&2; exit 1; }
"$QEMU_BIN" -machine virt -netdev help 2>&1 | grep -q vmnet-host || { echo "this QEMU has no vmnet support" >&2; exit 1; }
check_no_subnet_conflict "192\\.168\\.1|203\\.0\\.113" || exit 1

echo "== sudo (for vmnet, one route and two resolver files)"
sudo_keepalive

echo "== build"
cargo build -q -p leatos-kernel --target aarch64-unknown-none
ALPINE_DIR=$(scripts/lab/fetch-alpine.sh | tail -1)
ISP_INITRD=$(scripts/lab/build-initrd.sh isp | tail -1)

# Interfaces before vmnet creates the bridge, to find the new one afterwards.
BEFORE=$(ifconfig -l)

echo "== start ISP VM ($ISP)"
start_isp "$WAN_PORT" "$WORK/isp.log"

echo "== start rrouter (LAN on vmnet-host, as root)"
sudo -n env QEMU_BIN="$QEMU_BIN" QEMU_NET=mac LAB_WAN_PORT="$WAN_PORT" QEMU_ACCEL="$QEMU_ACCEL" \
  scripts/qemu-run.sh target/aarch64-unknown-none/debug/leatos >"$WORK/router.log" 2>&1 &
ROUTER_PID=$!
if ! wait_for "$WORK/router.log" "rrouter: boot ok" 40; then
  echo "rrouter did not boot:"; tr -d '\r' <"$WORK/router.log" | tail -30; exit 1
fi
tr -d '\r' <"$WORK/router.log" | grep -E "net wan0 .*lease" | sed 's/^/  /'

# ---- find the Mac side of the vmnet LAN -------------------------------------------------
find_new_lan_if "$BEFORE" "$LAN_NET" || true
if [[ -z "$MAC_IF" ]]; then
  echo "mac-lab: no new interface with a $LAN_NET.x address appeared. Interfaces:" >&2
  ifconfig -l >&2
  exit 1
fi
if [[ "$MAC_IP" == "$ROUTER_LAN" ]]; then
  echo "mac-lab: vmnet gave the Mac $ROUTER_LAN, which clashes with rrouter" >&2; exit 1
fi
echo "== Mac joined rrouter's LAN: $MAC_IF = $MAC_IP"

# ---- route + scoped DNS for the lab only -------------------------------------------------
sudo -n route -n add -net "$ISP/24" "$ROUTER_LAN" >/dev/null
ROUTE_ADDED=1
echo "  route 203.0.113.0/24 via $ROUTER_LAN"
sudo -n mkdir -p /etc/resolver
for domain in lan example; do
  f="/etc/resolver/$domain"
  if [[ -e "$f" ]] && ! head -1 "$f" | grep -qF "$MARKER"; then
    info "$f exists and is not ours: left untouched (*.$domain won't use rrouter)"
    continue
  fi
  printf '%s\nnameserver %s\n' "$MARKER" "$ROUTER_LAN" | sudo -n tee "$f" >/dev/null
  RESOLVERS+=("$f")
  echo "  resolver *.$domain -> $ROUTER_LAN"
done

# ---- checks from the Mac ---------------------------------------------------------------------
echo "== checks (from this Mac)"
if ping -c 2 -t 3 "$ROUTER_LAN" >/dev/null 2>&1; then pass "ping rrouter $ROUTER_LAN"; else fail "ping rrouter"; fi

a=$(dig +short +time=2 +tries=1 @"$ROUTER_LAN" nas.lan A 2>/dev/null | head -1)
[[ "$a" == "192.168.1.10" ]] && pass "dns: dig @rrouter nas.lan -> $a" || fail "dns: nas.lan -> '$a'"
a=$(dig +short +time=2 +tries=1 @"$ROUTER_LAN" isp.example A 2>/dev/null | head -1)
[[ "$a" == "203.0.113.80" ]] && pass "dns: upstream isp.example -> $a (forwarded to the ISP)" || fail "dns: isp.example -> '$a'"
a=$(dscacheutil -q host -a name router.lan 2>/dev/null | awk '/ip_address/{print $2; exit}')
[[ "$a" == "$ROUTER_LAN" ]] && pass "dns: macOS resolver (/etc/resolver/lan) router.lan -> $a" || info "macOS resolver router.lan -> '$a' (cache? try: sudo killall -HUP mDNSResponder)"

body=$(curl -s -m 5 "http://$ISP/" || true)
[[ "$body" == "rrouter-lab-isp" ]] && pass "tcp: curl http://$ISP/ through NAT" || fail "tcp: curl http://$ISP/ ('$body')"
seen=$(curl -s -m 5 "http://$ISP/cgi-bin/ip" || true)
[[ "$seen" == 203.0.113.* ]] && pass "nat: ISP sees source $seen (not $MAC_IP)" || fail "nat: ISP sees '$seen'"
if ping -c 2 -t 3 "$ISP" >"$WORK/ping" 2>&1; then
  pass "icmp: ping $ISP ($(grep -o 'min/avg/max[^=]*= [^ ]*' "$WORK/ping" | sed 's/.*= //'))"
else
  fail "icmp: ping $ISP"
fi
tr_out=$(traceroute -n -m 2 -q 1 -w 2 "$ISP" 2>/dev/null || true)
h1=$(echo "$tr_out" | awk '$1=="1"{print $2}')
h2=$(echo "$tr_out" | awk '$1=="2"{print $2}')
[[ "$h1" == "$ROUTER_LAN" && "$h2" == "$ISP" ]] && pass "traceroute: hop1 $h1, hop2 $h2 (via NAT)" || fail "traceroute: hop1='$h1' hop2='$h2'"

# Firewall: the ISP tries to connect into this Mac. Informational only: the
# macOS application firewall could also block it (the VM lab has the
# rigorous version of this check, with a negative control).
python3 -m http.server 8080 --bind "$MAC_IP" >/dev/null 2>&1 &
HTTP_PID=$!
sleep 0.5
probe=$(curl -s -m 10 "http://$ISP/cgi-bin/probe?$MAC_IP" | tr '\n' ' ' || true)
info "firewall probe from the ISP into this Mac: $probe"
kill "$HTTP_PID" 2>/dev/null; HTTP_PID=""

if [[ "$fails" == 0 ]]; then echo "MAC LAB: PASS"; else echo "MAC LAB: FAIL ($fails)"; fi

if [[ "$MODE" == "--check" ]]; then
  [[ "$fails" == 0 ]]; exit $?
fi

cat <<EOT

== rrouter is up. This Mac is on its LAN as $MAC_IP ($MAC_IF).
Try:
  curl http://$ISP/                    # web server behind rrouter's NAT
  curl http://$ISP/cgi-bin/ip          # what the ISP sees (rrouter's WAN address)
  ping $ISP ; traceroute -n $ISP
  dig @$ROUTER_LAN nas.lan ; ping router.lan
  sudo tcpdump -ni $MAC_IF             # watch rrouter's LAN traffic (or Wireshark on $MAC_IF)
  tail -f $WORK/router.log      # rrouter console
Your normal internet still uses your usual interface. Ctrl-C to stop and clean up.
EOT
while true; do sleep 3600; done
