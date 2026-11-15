#!/usr/bin/env bash
# WAN VLAN changed on a running router (no reboot), through the serial CLI
# (UART fed from a FIFO, as scripts/cli-test.sh). The WAN is QEMU user-mode
# networking (slirp, untagged): tagging it must lose the lease (slirp
# ignores tagged frames) and add the tag's 4 bytes to the upload shaper's
# overhead; untagging it again must get a new lease and drop them.
# The tagged datapath itself is tested by `LAB_VLAN=848 scripts/lab-test.sh`.
#
#   scripts/vlan-test.sh
#   RROUTER_ARCH=x86_64 scripts/vlan-test.sh
#   VLAN_TEST_SKIP_SAVE=1 scripts/vlan-test.sh   # negative control: edits
#                                                # never saved, the apply
#                                                # checks must fail
#   VLAN_TEST_VERBOSE=1 ...                      # print the relevant console lines
set -euo pipefail
cd "$(dirname "$0")/.."
ARCH="${RROUTER_ARCH:-aarch64}"
case "$ARCH" in aarch64 | x86_64) ;; *) echo "RROUTER_ARCH must be aarch64 or x86_64" >&2; exit 2 ;; esac
TARGET="$ARCH-unknown-none"
T=20; [[ "$ARCH" == x86_64 ]] && T=60
WORK="$(mktemp -d -t rrouter-vlan.XXXXXX)"
IMG="$WORK/store.img"; LOG="$WORK/console.log"; FIFO="$WORK/stdin"; QPID=
cleanup() {
  exec 3>&- 2>/dev/null || true
  if [[ -n "$QPID" ]]; then kill "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; fi
  [[ "${VLAN_TEST_VERBOSE:-0}" == 1 ]] && tr -d '\r' <"$LOG" | grep -aE "net wan0|vlan|qos wan0|cli  " | sed 's/^/  | /'
  rm -rf "$WORK"
}
trap cleanup EXIT
FAILED=0
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=1; }
count() { tr -d '\r' <"$LOG" | grep -ac -- "$1" || true; }
wait_count() { local i; for i in $(seq 1 $(($3 * 5))); do [[ "$(count "$2")" -ge "$1" ]] && return 0; sleep 0.2; done; return 1; }
send() { local n; n=$(count "rrouter> "); printf '%s\r' "$1" >&3; wait_count $((n + 1)) "rrouter> " "$T" || true; sleep 0.2; }
check() { # name n pattern seconds
  if wait_count "$2" "$3" "$4"; then pass "$1"; else fail "$1 (want $2 x '$3', have $(count "$3"))"; fi
}

cargo build -p rrouter-kernel --target "$TARGET" --quiet
cargo build -p rrstore --release --quiet
cp "target/$TARGET/debug/rrouter" "$WORK/rrouter.elf"
target/release/rrstore create "$IMG" --mib 32 >/dev/null
mkfifo "$FIFO"
QEMU_APPEND="shape_up=10000" QEMU_STORE="$IMG" QEMU_NET=user scripts/qemu-run.sh "$WORK/rrouter.elf" <"$FIFO" >"$LOG" 2>&1 &
QPID=$!
exec 3>"$FIFO"
wait_count 1 "serial console ready" $((T * 2)) || { fail "cli started"; exit 1; }
check "untagged boot: WAN lease" 1 "dhcp lease [0-9]" "$T"
check "untagged boot: upload overhead 0 B" 1 "qos wan0 .*overhead 0 B" 1

save() { [[ "${VLAN_TEST_SKIP_SAVE:-0}" == 1 ]] || send "config save"; }

echo "== tag the WAN (VLAN 848)"
send "config set wan.vlan = 848"
save
check "tagging applied live" 1 "now vlan 848 (pcp 0), restarting DHCP" "$T"
check "shaper overhead +4 B" 1 "qos wan0 .*now shaped.*overhead 4 B" "$T"
check "lease lost on the tagged link" 1 "dhcp lease lost" "$T"
sleep 5
if [[ "$(count "dhcp lease [0-9]")" == 1 ]]; then pass "no lease while tagged (slirp is untagged)"; else fail "got a lease while tagged"; fi

echo "== untag it again"
send "config unset wan.vlan"
save
check "untagging applied live" 1 "now untagged, restarting DHCP" "$T"
check "new lease after untagging" 2 "dhcp lease [0-9]" "$T"
check "shaper overhead back to 0 B" 2 "qos wan0 .*overhead 0 B" "$T"

if [[ "$FAILED" == 0 ]]; then echo "VLAN TEST ($ARCH): PASS"; else echo "VLAN TEST ($ARCH): FAIL"; exit 1; fi
