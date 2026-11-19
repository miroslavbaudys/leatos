#!/usr/bin/env bash
# WAN switched between DHCP and PPPoE on a running router (no reboot),
# through the serial CLI (UART fed from a FIFO, as scripts/vlan-test.sh),
# against the lab ISP VM as a PPPoE-only access concentrator (no DHCP
# server: LAB_PPPOE in scripts/lab-test.sh, which tests the datapath).
#
#   1. boots with DHCP: no lease (the ISP only speaks PPPoE)
#   2. config set wan.mode/pppoe + save: session up live, +8 B shaper
#      overhead, gateway answers; the password never appears on the console
#   3. reboot: PADT sent at shutdown (the ISP closes the session), and the
#      stored PPPoE config (with its password) brings the session up again
#   4. back to DHCP: the session is ended (PADT), overhead back to 0 B
#
#   scripts/pppoe-test.sh
#   RROUTER_ARCH=x86_64 scripts/pppoe-test.sh
#   PPPOE_TEST_SKIP_SAVE=1 scripts/pppoe-test.sh   # negative control: edits
#                                                  # never saved, the apply
#                                                  # checks must fail
#   PPPOE_TEST_VERBOSE=1 ...                       # print the relevant lines
#   PPPOE_TEST_PCAP_DIR=dir ...                    # capture the router's traffic
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C   # the console log has binary bytes: tr/grep must not choke
ARCH="${RROUTER_ARCH:-aarch64}"
case "$ARCH" in aarch64 | x86_64) ;; *) echo "RROUTER_ARCH must be aarch64 or x86_64" >&2; exit 2 ;; esac
TARGET="$ARCH-unknown-none"
T=20; [[ "$ARCH" == x86_64 ]] && T=60
LAN_PORT="${LAB_LAN_PORT:-12003}"
WAN_PORT="${LAB_WAN_PORT:-12005}"
WORK="$(mktemp -d -t rrouter-pppoe.XXXXXX)"
IMG="$WORK/store.img"; LOG="$WORK/console.log"; ISPLOG="$WORK/isp.log"; FIFO="$WORK/stdin"; QPID=
PIDS=()
cleanup() {
  exec 3>&- 2>/dev/null || true
  if [[ -n "$QPID" ]]; then kill "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; fi
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ "${PPPOE_TEST_VERBOSE:-0}" == 1 ]]; then
    tr -d '\r' <"$LOG" | grep -aE "net wan0|pppoe|qos wan0|net ping|cli  " | sed 's/^/  r| /'
    tr -d '\r' <"$ISPLOG" | grep -aE "pppoe-server|Modem hangup|Terminating" | sed 's/^/  i| /'
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
FAILED=0
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=1; }
count_in() { tr -d '\r' <"$1" | grep -ac -- "$2" || true; }
count() { count_in "$LOG" "$1"; }
wait_count_in() { local i; for i in $(seq 1 $(($4 * 5))); do [[ "$(count_in "$1" "$3")" -ge "$2" ]] && return 0; sleep 0.2; done; return 1; }
wait_count() { wait_count_in "$LOG" "$@"; }
send() { local n; n=$(count "rrouter> "); printf '%s\r' "$1" >&3; wait_count $((n + 1)) "rrouter> " "$T" || true; sleep 0.2; }
check() { # name n pattern seconds
  if wait_count "$2" "$3" "$4"; then pass "$1"; else fail "$1 (want $2 x '$3', have $(count "$3"))"; fi
}
check_isp() { # name n pattern seconds
  if wait_count_in "$ISPLOG" "$2" "$3" "$4"; then pass "$1"; else fail "$1 (ISP: want $2 x '$3', have $(count_in "$ISPLOG" "$3"))"; fi
}

source scripts/lab/common.sh
lab_cpu_flags
cargo build -p leatos-kernel --target "$TARGET" --quiet
cargo build -p leatstore --release --quiet
cp "target/$TARGET/debug/leatos" "$WORK/leatos.elf"
target/release/leatstore create "$IMG" --mib 32 >/dev/null
ALPINE_DIR=$(scripts/lab/fetch-alpine.sh modloop | tail -1)
ISP_INITRD=$(scripts/lab/build-initrd.sh isp | tail -1)
ISP_PPPOE=pap start_isp "$WAN_PORT" "$ISPLOG" || exit 1

mkfifo "$FIFO"
QEMU_APPEND="shape_up=10000 ntp=" QEMU_STORE="$IMG" QEMU_NET=lab QEMU_PCAP_DIR="${PPPOE_TEST_PCAP_DIR:-}" LAB_LAN_PORT="$LAN_PORT" LAB_WAN_PORT="$WAN_PORT" \
  QEMU_ACCEL="$QEMU_ACCEL" scripts/qemu-run.sh "$WORK/leatos.elf" <"$FIFO" >"$LOG" 2>&1 &
QPID=$!
exec 3>"$FIFO"
wait_count 1 "serial console ready" $((T * 2)) || { fail "cli started"; exit 1; }

echo "== 1. DHCP against a PPPoE-only ISP"
check "upload overhead 0 B" 1 "qos wan0 .*overhead 0 B" 1
sleep 5
if [[ "$(count "dhcp lease [0-9]")" == 0 ]]; then pass "no DHCP lease (the ISP only speaks PPPoE)"; else fail "got a DHCP lease"; fi

save() { [[ "${PPPOE_TEST_SKIP_SAVE:-0}" == 1 ]] || send "config save"; }

echo "== 2. switch to PPPoE live"
send 'config set wan.pppoe.username = "rrouter"'
send 'config set wan.pppoe.password = "lab-secret"'
send 'config set wan.mode = "pppoe"'
send "config diff"
send "config show pending"
check "the diff names the password, not its value" 1 "+ wan.pppoe.password = (secret)" 2
save
check "switch applied live" 1 "now untagged, restarting PPPoE" "$T"
check "session up" 1 "pppoe wan0 .*: up, 203.0.113.50 peer 203.0.113.1 dns \[203.0.113.1\] mtu 1492" "$T"
check "shaper overhead +8 B" 1 "qos wan0 .*now shaped.*overhead 8 B" "$T"
check "the gateway answers over the session" 1 "net ping .*203.0.113.1 seq=" "$T"
# (The UART echoes what is typed, like any console: only the router's own
# output counts.)
shown=$(tr -d '\r' <"$LOG" | grep -a "lab-secret" | grep -avc 'config set wan.pppoe.password = "lab-secret"' || true)
if [[ "$shown" == 0 ]]; then pass "the router never printed the password"; else fail "the router printed the password ($shown lines)"; fi

echo "== 3. reboot: PADT, then PPPoE from the store"
send "reboot"
check "PADT sent at shutdown" 1 "PPPoE session ended (PADT)" "$T"
# pppd on the ISP side: one hangup per ended session.
check_isp "the ISP ended the session" 1 "notice pppd.*Modem hangup" "$T"
check "PPPoE from the stored config at boot" 1 "net wan0 .*: PPPoE" $((T * 2))
check "session up after the reboot" 2 "pppoe wan0 .*: up, " $((T * 2))

echo "== 4. back to DHCP live"
send 'config set wan.mode = "dhcp"'
save
check "switch back applied live" 1 "now untagged, restarting DHCP" "$T"
check "DHCP again" 1 "net wan0 .*: DHCP" "$T"
check_isp "the session was ended (PADT)" 2 "notice pppd.*Modem hangup" "$T"
check "shaper overhead back to 0 B" 1 "qos wan0 .*now shaped.*overhead 0 B" "$T"

if [[ "$FAILED" == 0 ]]; then echo "PPPOE TEST ($ARCH): PASS"; else echo "PPPOE TEST ($ARCH): FAIL"; exit 1; fi
