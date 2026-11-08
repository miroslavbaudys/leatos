#!/usr/bin/env bash
# "Level 3": route this Mac's IPv4 internet traffic and DNS through rrouter.
#
#   MacBook ──bridgeN (vmnet-host, 192.168.1.2)── [rrouter LAN 192.168.1.1]
#                                                 [rrouter WAN] ══ vmnet-bridged on <wan-if> ══ home router → internet
#
# rrouter's WAN is bridged at layer 2 onto a physical interface and gets its
# own lease from your home router (double NAT). The Mac then sends all IPv4
# traffic to rrouter via 8 prefix routes (1/8 … 64/2 + 128/1: more specific
# than the default route, so macOS's own default route stays untouched;
# verified after adding) and uses
# 192.168.1.1 as DNS server.
#
# Usage (in Terminal; sudo asks for your password):
#   scripts/mac-internet.sh [--wan-if enX] [--ipv4-only] [--release] [--yes] [--check]
#   scripts/mac-internet.sh --restore      undo everything from a previous run
#                                          (after a crash, kill -9, reboot, …)
#     --wan-if enX   physical interface to bridge the WAN onto (default: the
#                    interface of the current default route). Ethernet is
#                    strongly preferred: many Wi-Fi access points drop frames
#                    from the extra MAC address of a bridged VM.
#     --ipv4-only    turn IPv6 off on that service while running (rrouter has
#                    no IPv6 yet, so IPv6 traffic would bypass it); restored on exit
#     --release      run an optimised (release) build of rrouter instead of
#                    the debug build: much faster datapath (see bufferbloat.sh)
#     --yes          don't ask for confirmation
#     --check        run the checks, then restore and exit (exit 1 on failure)
#
# Safety: the original DNS/IPv6 settings are saved to lab/cache/mac-internet.state
# *before* anything changes; Ctrl-C, errors and --restore put them back. A
# watchdog restores the network if rrouter stops answering.
set -euo pipefail
cd "$(dirname "$0")/.."

STATE=lab/cache/mac-internet.state
# IPv4 space via rrouter, as "network netmask" pairs. The lower half is split
# into 1/8 … 64/2 because a route keyed 0.0.0.0 (like 0.0.0.0/1) shares its
# radix key with vmnet-host's interface-scoped default route on the LAN
# bridge, and macOS then resolves lookups to that gateway-less route
# ("Host is down"). 0.0.0.0/8 ("this network") is never routed anyway.
SPLIT_ROUTES=(
  "1.0.0.0 255.0.0.0" "2.0.0.0 254.0.0.0" "4.0.0.0 252.0.0.0" "8.0.0.0 248.0.0.0"
  "16.0.0.0 240.0.0.0" "32.0.0.0 224.0.0.0" "64.0.0.0 192.0.0.0" "128.0.0.0 128.0.0.0"
)
ROUTER_LAN=192.168.1.1
LAN_NET=192.168.1
WORK=$(mktemp -d -t rrouter-macinet)
PIDS=()
ROUTER_PID=""
KEEPALIVE_PID=""
fails=0

source scripts/lab/common.sh

WAN_IF=""
IPV4_ONLY=0
ASSUME_YES=0
PROFILE=debug
MODE=interactive
while [[ $# -gt 0 ]]; do
  case "$1" in
    --wan-if) WAN_IF="${2:?--wan-if needs an interface}"; shift 2 ;;
    --ipv4-only) IPV4_ONLY=1; shift ;;
    --release) PROFILE=release; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    --check) MODE=check; shift ;;
    --restore) MODE=restore; shift ;;
    -h | --help) sed -n '2,31p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done
[[ "$(uname -s)" == "Darwin" ]] || { echo "macOS only" >&2; exit 1; }

pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; fails=$((fails + 1)); }
info() { echo "  [INFO] $*"; }

# ---- restore: driven only by the state file -------------------------------------------
# State lines: SERVICE=<name>  DNS=<servers or Empty>  IPV6=<automatic|unchanged>  ROUTES=split
restore_network() {
  [[ -f "$STATE" ]] || return 0
  local svc dns v6 routes
  svc=$(sed -n 's/^SERVICE=//p' "$STATE")
  dns=$(sed -n 's/^DNS=//p' "$STATE")
  v6=$(sed -n 's/^IPV6=//p' "$STATE")
  routes=$(sed -n 's/^ROUTES=//p' "$STATE")
  echo "== restoring network settings (from $STATE)"
  if [[ -n "$routes" ]]; then
    local n=0 r
    for r in "${SPLIT_ROUTES[@]}"; do
      # shellcheck disable=SC2086 # "net mask" pair
      set -- $r
      sudo route -n delete -net "$1" -netmask "$2" "$ROUTER_LAN" >/dev/null 2>&1 && n=$((n + 1))
    done
    # Only for state files from the old 0.0.0.0/1 version: otherwise this
    # delete can match vmnet's own 0.0.0.0-keyed route on the LAN bridge.
    if [[ "$routes" == 1 ]]; then
      sudo route -n delete -net 0.0.0.0 -netmask 128.0.0.0 "$ROUTER_LAN" >/dev/null 2>&1 && n=$((n + 1))
    fi
    echo "  removed $n routes via $ROUTER_LAN"
  fi
  if [[ -n "$svc" && -n "$dns" ]]; then
    # shellcheck disable=SC2086 # intentional word splitting: list of servers
    sudo networksetup -setdnsservers "$svc" $dns && echo "  DNS for '$svc' restored to: $dns"
  fi
  if [[ -n "$svc" && "$v6" == automatic ]]; then
    sudo networksetup -setv6automatic "$svc" && echo "  IPv6 for '$svc' restored to automatic"
  fi
  sudo dscacheutil -flushcache 2>/dev/null || true
  sudo killall -HUP mDNSResponder 2>/dev/null || true
  rm -f "$STATE"
  echo "  done; default route: $(route -n get default 2>/dev/null | awk '/gateway/{print $2}') via $(route -n get default 2>/dev/null | awk '/interface/{print $2}')"
}

if [[ "$MODE" == restore ]]; then
  if [[ -f "$STATE" ]]; then sudo -v; restore_network; else echo "nothing to restore ($STATE not found)"; fi
  exit 0
fi

if [[ -f "$STATE" ]]; then
  echo "A previous run did not clean up ($STATE exists). Run: scripts/mac-internet.sh --restore" >&2
  exit 1
fi

cleanup() {
  set +e
  echo
  echo "== cleanup"
  restore_network
  [[ -n "$ROUTER_PID" ]] && sudo -n kill "$ROUTER_PID" 2>/dev/null
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
  [[ -n "$KEEPALIVE_PID" ]] && kill "$KEEPALIVE_PID" 2>/dev/null
  wait 2>/dev/null
  echo "  rrouter stopped; logs: $WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ---- preflight ----------------------------------------------------------------------------
QEMU_BIN=$(command -v qemu-system-aarch64) || { echo "qemu-system-aarch64 not found" >&2; exit 1; }
"$QEMU_BIN" -machine virt -netdev help 2>&1 | grep -q vmnet-bridged || { echo "this QEMU has no vmnet support" >&2; exit 1; }
[[ -n "$WAN_IF" ]] || WAN_IF=$(route -n get default 2>/dev/null | awk '/interface/{print $2}')
[[ -n "$WAN_IF" ]] || { echo "no default route: connect to a network first (or pass --wan-if)" >&2; exit 1; }
ifconfig "$WAN_IF" >/dev/null 2>&1 || { echo "no such interface: $WAN_IF" >&2; exit 1; }
SERVICE=$(networksetup -listnetworkserviceorder | awk -v dev="$WAN_IF" '
  /^\([0-9*]+\) /{name=$0; sub(/^\([0-9*]+\) /, "", name)} index($0, "Device: " dev ")"){print name; exit}')
[[ -n "$SERVICE" ]] || { echo "no network service found for $WAN_IF" >&2; exit 1; }
PORT=$(networksetup -listallhardwareports | awk -v dev="$WAN_IF" '/^Hardware Port:/{p=$0; sub(/^Hardware Port: /,"",p)} $0=="Device: " dev {print p; exit}')
check_no_subnet_conflict "192\\.168\\.1" || exit 1
HOME_GW=$(route -n get default 2>/dev/null | awk '/gateway/{print $2}')

echo "rrouter ($PROFILE build) will become this Mac's IPv4 router:"
echo "  WAN bridged onto : $WAN_IF ($PORT, service '$SERVICE'); home gateway $HOME_GW"
echo "  Mac changes      : routes for 1.0.0.0-255.255.255.255 (8 prefixes) via $ROUTER_LAN, DNS for '$SERVICE' -> $ROUTER_LAN$([[ $IPV4_ONLY == 1 ]] && echo ", IPv6 off")"
echo "  undo             : automatic on exit/Ctrl-C/watchdog; manual: scripts/mac-internet.sh --restore"
if [[ "$PORT" == Wi-Fi* ]]; then
  echo "  WARNING: bridging over Wi-Fi often fails (the access point drops the VM's MAC)."
  echo "           If rrouter gets no WAN lease, use an Ethernet adapter: --wan-if enX"
fi
if [[ "$ASSUME_YES" != 1 ]]; then
  read -r -p "Continue? [y/N] " answer
  [[ "$answer" == [yY]* ]] || { echo "aborted"; exit 1; }
fi

sudo_keepalive

echo "== build ($PROFILE)"
if [[ "$PROFILE" == release ]]; then
  cargo build -q -p rrouter-kernel --target aarch64-unknown-none --release
else
  cargo build -q -p rrouter-kernel --target aarch64-unknown-none
fi
KERNEL=target/aarch64-unknown-none/$PROFILE/rrouter
BEFORE=$(ifconfig -l)

echo "== start rrouter (WAN bridged on $WAN_IF, LAN on vmnet-host)"
sudo -n env QEMU_BIN="$QEMU_BIN" QEMU_NET=mac-internet MAC_WAN_IF="$WAN_IF" QEMU_ACCEL="${QEMU_ACCEL:-hvf}" \
  scripts/qemu-run.sh "$KERNEL" >"$WORK/router.log" 2>&1 &
ROUTER_PID=$!
if ! wait_for "$WORK/router.log" "net wan0 .*dhcp lease" 30; then
  echo "rrouter got no WAN lease on $WAN_IF within 30 s."
  [[ "$PORT" == Wi-Fi* ]] && echo "This is the known Wi-Fi bridging limitation: try an Ethernet adapter (--wan-if enX)."
  tr -d '\r' <"$WORK/router.log" | tail -15
  exit 1
fi
LEASE=$(tr -d '\r' <"$WORK/router.log" | grep -m1 "net wan0 .*dhcp lease" | sed 's/^ *//')
echo "  $LEASE"
wait_for "$WORK/router.log" "rrouter: boot ok" 20 || true

find_new_lan_if "$BEFORE" "$LAN_NET" || { echo "no vmnet LAN interface with a $LAN_NET.x address appeared" >&2; exit 1; }
[[ "$MAC_IP" != "$ROUTER_LAN" ]] || { echo "vmnet gave the Mac $ROUTER_LAN (clash)" >&2; exit 1; }
echo "== Mac joined rrouter's LAN: $MAC_IF = $MAC_IP"
ping -c 1 -t 3 "$ROUTER_LAN" >/dev/null 2>&1 || { echo "rrouter does not answer on $ROUTER_LAN; not switching" >&2; exit 1; }

# ---- switch: save state first, then change ------------------------------------------------
orig_dns=$(networksetup -getdnsservers "$SERVICE" | tr '\n' ' ' | sed 's/ *$//')
[[ "$orig_dns" == *"aren't any DNS Servers"* ]] && orig_dns=Empty
v6_state=unchanged
if [[ "$IPV4_ONLY" == 1 ]] && networksetup -getinfo "$SERVICE" | grep -q "^IPv6: Automatic"; then v6_state=automatic; fi
mkdir -p "$(dirname "$STATE")"
# BUILD= is informational (read by scripts/bufferbloat.sh to label results).
printf 'SERVICE=%s\nDNS=%s\nIPV6=%s\nROUTES=split\nBUILD=%s\n' "$SERVICE" "$orig_dns" "$v6_state" "$PROFILE" >"$STATE"

echo "== switching this Mac to rrouter"
for r in "${SPLIT_ROUTES[@]}"; do
  # shellcheck disable=SC2086 # "net mask" pair
  set -- $r
  sudo -n route -n add -net "$1" -netmask "$2" "$ROUTER_LAN" >/dev/null
done
# Verify addresses across the whole space before going further; restore at
# once if any of them does not route via rrouter.
for probe in 1.1.1.1 3.3.3.3 8.8.8.8 23.0.0.1 45.0.0.1 100.64.0.1 172.66.0.1 208.67.222.222; do
  got_gw=$(route -n get "$probe" 2>/dev/null | awk '/gateway:/{print $2}')
  got_if=$(route -n get "$probe" 2>/dev/null | awk '/interface:/{print $2}')
  if [[ "$got_gw" != "$ROUTER_LAN" || "$got_if" != "$MAC_IF" ]]; then
    echo "!! route check failed for $probe: gateway='$got_gw' interface='$got_if' (expected $ROUTER_LAN on $MAC_IF)"
    route -n get "$probe" 2>&1 | sed 's/^/     /'
    netstat -rn -f inet | grep -E "$MAC_IF" | sed 's/^/     /' || true
    echo "!! restoring network"; exit 1
  fi
done
echo "  verified: all of IPv4 (outside local subnets) routes via $ROUTER_LAN on $MAC_IF"
sudo -n networksetup -setdnsservers "$SERVICE" "$ROUTER_LAN"
[[ "$v6_state" == automatic ]] && sudo -n networksetup -setv6off "$SERVICE"
sudo -n dscacheutil -flushcache 2>/dev/null || true
sudo -n killall -HUP mDNSResponder 2>/dev/null || true
echo "  IPv4 via $ROUTER_LAN, DNS $ROUTER_LAN (was: $orig_dns)"

# ---- checks ------------------------------------------------------------------------------------
echo "== checks (destinations in both halves: 1.1.1.1 low, example.com/9.9.9.9 high)"
for probe in 1.1.1.1 9.9.9.9; do
  gw=$(route -n get "$probe" 2>/dev/null | awk '/gateway:/{print $2}')
  [[ "$gw" == "$ROUTER_LAN" ]] && pass "route to $probe via $gw" || fail "route to $probe via '$gw'"
done
tr_out=$(traceroute -n -m 2 -q 1 -w 2 1.1.1.1 2>/dev/null || true)
h1=$(echo "$tr_out" | awk '$1=="1"{print $2}')
h2=$(echo "$tr_out" | awk '$1=="2"{print $2}')
[[ "$h1" == "$ROUTER_LAN" ]] && pass "traceroute: hop1 $h1 (rrouter), hop2 ${h2:-?} (home router: $HOME_GW)" || fail "traceroute hop1='$h1' hop2='$h2'"
a=$(dig +short +time=3 +tries=1 example.com A 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
[[ -n "$a" ]] && pass "dns: system resolver example.com -> $a (via rrouter)" || fail "dns: example.com"
a=$(dig +short +time=2 +tries=1 @"$ROUTER_LAN" router.lan A 2>/dev/null | head -1)
[[ "$a" == "$ROUTER_LAN" ]] && pass "dns: router.lan -> $a" || fail "dns: router.lan -> '$a'"
code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 https://example.com/ || true)
[[ "$code" == 200 ]] && pass "https://example.com/ -> HTTP $code" || fail "https://example.com/ -> '$code'"
for probe in 1.1.1.1 9.9.9.9; do
  if ping -c 3 -t 5 "$probe" >"$WORK/ping-$probe" 2>&1; then
    pass "ping $probe ($(grep -o 'min/avg/max[^=]*= [^ ]*' "$WORK/ping-$probe" | sed 's/.*= //') ms)"
  else
    fail "ping $probe: $(grep -m1 -E 'sendto|timeout' "$WORK/ping-$probe" || true)"
  fi
done
if networksetup -getinfo "$SERVICE" | grep -q "^IPv6 IP address: [0-9a-f]"; then
  info "IPv6 is active on '$SERVICE': IPv6 traffic bypasses rrouter (use --ipv4-only)"
fi
info "rebind protection: local names on your home LAN resolving to private addresses are refused by rrouter's DNS"
if [[ "$fails" == 0 ]]; then echo "MAC INTERNET: PASS"; else echo "MAC INTERNET: FAIL ($fails)"; fi
if [[ "$MODE" == check ]]; then
  [[ "$fails" == 0 ]]; exit $?
fi

cat <<EOT

== This Mac now uses rrouter for IPv4 internet and DNS. Browse normally.
  WAN: $LEASE
  watch traffic : sudo tcpdump -ni $MAC_IF      (Wireshark on $MAC_IF)
  router console: tail -f $WORK/router.log
  bufferbloat   : https://www.waveform.com/tools/bufferbloat  (CAKE arrives in M6)
Ctrl-C restores your network. If anything goes wrong: scripts/mac-internet.sh --restore
EOT

# Watchdog: restore if rrouter dies or stops answering for ~15 s.
misses=0
while true; do
  sleep 5
  if ! sudo -n kill -0 "$ROUTER_PID" 2>/dev/null; then
    echo "!! rrouter exited: restoring network"; exit 1
  fi
  if ping -c 1 -t 2 "$ROUTER_LAN" >/dev/null 2>&1; then misses=0; else misses=$((misses + 1)); fi
  if [[ "$misses" -ge 3 ]]; then echo "!! rrouter not answering: restoring network"; exit 1; fi
done
