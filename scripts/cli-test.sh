#!/usr/bin/env bash
# Serial CLI end to end: boot the router with a store, type commands into
# its UART (QEMU's stdin, fed from a FIFO) and check the console.
#
#   scripts/cli-test.sh
#   RROUTER_ARCH=x86_64 scripts/cli-test.sh
#   QEMU_STORE_BUS=sd scripts/cli-test.sh      # store on the SD card
#   CLI_TEST_SKIP_SAVE=1 scripts/cli-test.sh   # negative control: the
#                                              # persistence checks must fail
#   CLI_TEST_LOG=console scripts/cli-test.sh   # negative control: log
#                                              # messages stay on the console,
#                                              # the RAM log checks must fail
#   CLI_TEST_VERBOSE=1 ...                     # print the console
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH="${RROUTER_ARCH:-aarch64}"
case "$ARCH" in aarch64 | x86_64) ;; *) echo "RROUTER_ARCH must be aarch64 or x86_64" >&2; exit 2 ;; esac
TARGET="$ARCH-unknown-none"
# x86_64 runs under TCG on Apple Silicon: allow more time.
T=20; [[ "$ARCH" == x86_64 ]] && T=60
WORK="$(mktemp -d -t rrouter-cli.XXXXXX)"
IMG="$WORK/store.img"
LOG="$WORK/console.log"
FIFO="$WORK/stdin"
QPID=
cleanup() {
  exec 3>&- 2>/dev/null || true
  if [[ -n "$QPID" ]]; then kill "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; fi
  if [[ "${CLI_TEST_VERBOSE:-0}" == 1 && -f "$LOG" ]]; then tr -d '\r' <"$LOG" | sed 's/^/  | /'; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
FAILED=0
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=1; }

count() { tr -d '\r' <"$LOG" | grep -ac -- "$1" || true; }
wait_count() { # n pattern seconds
  local i
  for i in $(seq 1 $(($3 * 5))); do
    [[ "$(count "$2")" -ge "$1" ]] && return 0
    sleep 0.2
  done
  return 1
}
OUT=
# send LINE: type it (with Enter) and wait for the next prompt; OUT = what
# the console printed in between.
send() {
  local before n
  before=$(wc -c <"$LOG" | tr -d ' ')
  n=$(count "rrouter> ")
  printf '%s\r' "$1" >&3
  wait_count $((n + 1)) "rrouter> " "$T" || true
  sleep 0.2
  OUT=$(tail -c +$((before + 1)) "$LOG" | tr -d '\r')
}
has() { echo "$OUT" | grep -aq -- "$1"; }
expect() { # name pattern
  if has "$2"; then pass "$1"; else fail "$1 (no '$2' in: $(echo "$OUT" | head -5 | tr '\n' '|'))"; fi
}

cargo build -p rrouter-kernel --target "$TARGET" --quiet
cargo build -p rrstore --release --quiet
cp "target/$TARGET/debug/rrouter" "$WORK/rrouter.elf"
target/release/rrstore create "$IMG" --mib 32 >/dev/null
mkfifo "$FIFO"

# The kernel's default: log messages go to the RAM log once the CLI runs.
QEMU_APPEND="log=${CLI_TEST_LOG:-ram}${QEMU_APPEND:+ $QEMU_APPEND}" \
QEMU_STORE="$IMG" QEMU_NET=user scripts/qemu-run.sh "$WORK/rrouter.elf" <"$FIFO" >"$LOG" 2>&1 &
QPID=$!
exec 3>"$FIFO"
wait_count 1 "serial console ready" $((T * 2)) || { fail "cli started"; exit 1; }
pass "cli started"

echo "== RAM log"
# The net self-test reports after the CLI is up: into the RAM log.
for _ in $(seq 1 "$T"); do send "log"; has "net self-test" && break; sleep 1; done
expect "log lists messages from after boot" '^\[ *[0-9]*\.[0-9]*\]   net self-test'
# On the console it would read "  net self-test" (after a redrawn prompt);
# in log output it has a timestamp.
if [[ "$(tr -d '\r' <"$LOG" | grep -a "net self-test   :" | grep -vac '^\[')" == 0 ]]; then pass "log messages stay off the console"; else fail "log messages stay off the console"; fi
send "log 1"
if [[ "$(echo "$OUT" | grep -ac '^\[')" == 1 ]]; then pass "log 1 shows one line"; else fail "log 1 shows one line"; fi

echo "== commands"
send "help"; expect "help lists the commands" "config set <setting> = <value>"
send "status"; expect "status: uptime" ", up "
expect "status: WAN port" "^wan0 "
expect "status: watchdog" "^watchdog : "
# No temperature sensor in QEMU (drivers/cputemp.rs: AMD family 16h only).
expect "status: temperature" "^temp     : - (no sensor)"
send "leases"; expect "leases answers" "no leases"
# Line editing: "statsx" + 2 backspaces + "us" = "status".
send $'statsx\x7f\x7fus'; expect "backspace edits the line" ", up "
send "bogus"; expect "unknown command" "unknown command: bogus"
send "status"; expect "console input through the interrupt" "^console  : rx interrupt"
# A paste: several lines at once run one by one, output in order.
n=$(count "rrouter> "); before=$(wc -c <"$LOG" | tr -d ' ')
printf 'leases\rhelp\rbogus2\r' >&3
wait_count $((n + 3)) "rrouter> " "$T" || true; sleep 0.2
OUT=$(tail -c +$((before + 1)) "$LOG" | tr -d '\r')
if echo "$OUT" | grep -a -e "no leases" -e "config set <setting>" -e "unknown command: bogus2" | tr '\n' '|' \
  | grep -aq "no leases|.*config set <setting>.*|.*unknown command: bogus2"; then pass "pasted lines run in order"
else fail "pasted lines run in order ($(echo "$OUT" | grep -a -e leases -e "config set" -e bogus2 | tr '\n' '|'))"; fi

echo "== config edit"
send "config show stored"; expect "show stored" "cache_entries = 4096"
send "config set dns.nosuch = 1"; expect "unknown setting refused" "unknown field"
send "config set dns.cache_entries = 5"; expect "out-of-range value pending" "pending: "
[[ "${CLI_TEST_SKIP_SAVE:-0}" == 1 ]] || { send "config save"; expect "save refuses an invalid config" "dns.cache_entries: must be 16"; }
send "config set dns.cache_entries = 1234"
send "config diff"; expect "diff shows the change" "+ dns.cache_entries = 1234"
if [[ "${CLI_TEST_SKIP_SAVE:-0}" != 1 ]]; then send "config save"; fi
expect "save applies live" "saved and applied"
send "log 10"; expect "the save is in the RAM log" "cli             : config saved"
send "config show running"; expect "running config has the new value" "cache_entries = 1234"
send "config diff"; expect "nothing pending after the save" "no pending edit"

echo "== LAN change: saved for good, reboots"
send 'config set lan.ipv4 = "10.20.0.1/24"'
# The lab's nas reservation (192.168.1.10) does not fit the new subnet.
[[ "${CLI_TEST_SKIP_SAVE:-0}" == 1 ]] || { send "config save"; expect "save names the reservation outside the subnet" "lan.dhcp.static\[0\].ip"; }
send "config unset lan.dhcp.static"
if [[ "${CLI_TEST_SKIP_SAVE:-0}" != 1 ]]; then
  printf 'config save\r' >&3
  wait_count 2 "serial console ready" $((T * 3)) || true
else
  send "reboot"
  wait_count 2 "serial console ready" $((T * 3)) || true
fi
if [[ "$(count "config          : .*lan 10.20.0.1/24")" -ge 1 ]]; then pass "rebooted with the new LAN"; else fail "rebooted with the new LAN"; fi
send "config show stored"
expect "stored config kept the cache size" "cache_entries = 1234"
expect "  ... and has the LAN address" 'ipv4 = "10.20.0.1/24"'

echo
if [[ "$FAILED" == 0 ]]; then echo "CLI TEST ($ARCH, ${QEMU_STORE_BUS:-virtio}): PASS"; else echo "CLI TEST ($ARCH, ${QEMU_STORE_BUS:-virtio}): FAIL"; exit 1; fi
