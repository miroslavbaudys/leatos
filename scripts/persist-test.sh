#!/usr/bin/env bash
# End-to-end test of persistent upgrades (docs/upgrades.md) on the x86_64
# kernel in QEMU: the store's `images` area, the boot partition's kernel as
# the loader (QEMU's -kernel plays it: every reset boots it again), trials,
# confirm and every rollback path.
#
#   scripts/persist-test.sh          # LAB_VERBOSE=1 prints the router console
#   QEMU_STORE_BUS=sd ...            # store on an SD card (sdhci-pci), as on the apu4
#
# Checks:
#   empty store -> the loader boots itself; refusals: no password -> 401,
#   garbage -> 422, X-Cmdline -> 422, confirm without a trial -> 409.
#   Persistent upload -> stored as a trial, reboot, the loader enters it;
#   during the trial: config save -> 409, in-RAM upgrade -> 409, confirm
#   without password -> 401; confirm -> the record is confirmed and the
#   kernel is entered again after a reboot. In-RAM upgrade from a stored
#   kernel -> runs as "in-RAM upgrade" (image=ram: no second chain-load).
# Rollbacks (each first proves the bad kernel was entered as a trial):
#   a kernel that panics; one that hangs (watchdog reset); one nobody
#   confirms (trial_secs); "roll back now"; QEMU killed during the trial.
#   Each lands on the previous confirmed kernel and erases the trial.
# Store negative controls: image=golden ignores stored kernels; a corrupt
#   record -> the loader boots itself.
# Negative control for the confirm check: PERSIST_TEST_CONTROL=no-confirm
#   skips the confirm, so "confirmed kernel entered after a reboot" fails.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PERSIST_TEST_PORT:-18082}"
URL="http://127.0.0.1:$PORT"
WORK="$(mktemp -d -t rrouter-persist.XXXXXX)"
IMG="$WORK/store.img"
LOG="$WORK/router.log"
QPID=
TARGET=x86_64-unknown-none
stop() {
  if [[ -n "$QPID" ]]; then kill "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; fi
  QPID=
}
cleanup() {
  stop
  if [[ "${LAB_VERBOSE:-0}" == 1 && -f "$LOG" ]]; then sed 's/^/  | /' "$LOG"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
FAILED=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then echo "  [PASS] $1"; else echo "  [FAIL] $1: expected '$2', got '$3'"; FAILED=1; fi
}
count() { grep -ac -- "$1" "$LOG" || true; }
wait_count() { # count pattern seconds
  local i
  for i in $(seq 1 "$3"); do
    [[ "$(count "$2")" -ge "$1" ]] && return 0
    sleep 1
  done
  return 1
}
boots() { count "— bare metal"; }
status() { # python expression over d = /api/status
  curl -s -m 5 -u admin:test "$URL/api/status" 2>/dev/null | python3 -I -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null || true
}
code() { curl -s -m 60 -o /dev/null -w '%{http_code}' "$@" || true; }
upload() { # file [endpoint] -> HTTP code
  code -m 180 -u admin:test -X POST --data-binary @"$1" "$URL${2:-/api/upgrade/persist}"
}
images() { "$RRSTORE" show "$IMG" | sed -n 's/^  images .*A: \(.*\)   B: \(.*\)$/A: \1 | B: \2/p'; }
source_now() { status 'd["image"]["source"]'; }
trial_now() { status '"-" if d["image"]["trial"] is None else d["image"]["trial"]["seq"]'; }

strip() { # elf out
  local objcopy
  objcopy="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
  if [[ -x "$objcopy" ]]; then "$objcopy" --strip-debug "$1" "$2"; else cp "$1" "$2"; fi
}
build() { # features out
  local args=(build -p rrouter-kernel --target "$TARGET" --release --quiet)
  [[ -n "$1" ]] && args+=(--features "$1")
  cargo "${args[@]}"
  strip "target/$TARGET/release/rrouter" "$2"
}
# Test kernels first; the plain build last, so the tree keeps it.
build fault-panic "$WORK/panic.elf"
build fault-hang "$WORK/hang.elf"
build "" "$WORK/new.elf"
cp "target/$TARGET/release/rrouter" "$WORK/boot.elf" # the loader (boot partition)
cargo build -p rrstore --release --quiet
RRSTORE=target/release/rrstore
"$RRSTORE" create "$IMG" --mib 32 >/dev/null

ARGS="mgmt=wan mgmt_pass=test lan=10.10.0.1/24 trial_secs=20"
start() { # extra boot arguments
  QEMU_NET=user QEMU_NIC=igb QEMU_STORE="$IMG" QEMU_WAN_HOSTFWD="tcp:127.0.0.1:$PORT-:80" \
    QEMU_APPEND="$ARGS${1:+ $1}" scripts/qemu-run.sh "$WORK/boot.elf" >>"$LOG" 2>&1 &
  QPID=$!
}
# The first boot is up: it has a WAN lease and serves the API.
wait_boot() { # seconds
  wait_count 1 "dhcp lease" "$1" || return 1
  local i
  for i in $(seq 1 "$1"); do
    [[ -n "$(status 'd["arch"]')" ]] && return 0
    sleep 1
  done
  return 1
}
# Wait until the router is down (the request led to a reboot), then up again
# with a fresh uptime.
wait_reboot() { # seconds
  local i down=0
  for i in $(seq 1 "$1"); do
    if [[ -z "$(status 'd["uptime_s"]')" ]]; then down=1; elif [[ "$down" == 1 ]]; then return 0; fi
    sleep 1
  done
  return 1
}

echo "== empty store: the loader boots itself"
start
wait_boot 150 || { echo "  [FAIL] router did not boot"; exit 1; }
check "no stored kernel: boot partition" "boot partition (no kernel in the store)" "$(source_now)"
check "status reports the build" "$(git describe --always --dirty --abbrev=10 2>/dev/null || echo unknown)" "$(status 'd["build"]')"
check "persist without password -> 401" 401 "$(code -X POST --data-binary @"$WORK/new.elf" "$URL/api/upgrade/persist")"
head -c 100000 /dev/urandom >"$WORK/garbage"
check "garbage -> 422" 422 "$(upload "$WORK/garbage")"
check "X-Cmdline with persist -> 422" 422 "$(code -u admin:test -H 'X-Cmdline: x=1' -X POST --data-binary @"$WORK/new.elf" "$URL/api/upgrade/persist")"
check "confirm without a trial -> 409" 409 "$(code -u admin:test -X POST "$URL/api/upgrade/confirm")"
check "refusals stored nothing" "A: empty | B: empty" "$(images)"

echo "== persistent upgrade, confirm"
check "persist accepted" 200 "$(upload "$WORK/new.elf")"
wait_reboot 240 || echo "  [FAIL] no reboot after the persistent upload"
check "loader entered the trial" 1 "$(count 'entering the stored kernel (slot A, seq 1, trial)')"
check "stored kernel runs as a trial" "store (slot A, seq 1)" "$(source_now)"
check "trial announced on the console" 1 "$(count 'trial kernel: confirm within 20 s or it is rolled back')"
check "trial seq in the status" 1 "$(trial_now)"
check "record marked booted" "A: seq 1 version 1 $(wc -c <"$WORK/new.elf" | tr -d ' ') bytes trial booted | B: empty" "$(images)"
check "config save during the trial -> 409" 409 "$(code -u admin:test -X POST --data-binary 'version = 2' "$URL/api/config")"
check "in-RAM upgrade during the trial -> 409" 409 "$(upload "$WORK/new.elf" /api/upgrade)"
check "confirm without password -> 401" 401 "$(code -X POST "$URL/api/upgrade/confirm")"
if [[ "${PERSIST_TEST_CONTROL:-}" == no-confirm ]]; then
  echo "  (negative control: not confirming)"
else
  check "confirm -> 200" 200 "$(code -u admin:test -X POST "$URL/api/upgrade/confirm")"
  check "record confirmed (flags cleared)" "A: seq 1 version 1 $(wc -c <"$WORK/new.elf" | tr -d ' ') bytes | B: empty" "$(images)"
  check "no trial after confirm" - "$(trial_now)"
  check "source unchanged after confirm" "store (slot A, seq 1)" "$(source_now)"
fi
check "reboot accepted" 200 "$(code -u admin:test -X POST "$URL/api/reboot")"
wait_reboot 240 || echo "  [FAIL] no reboot"
check "after a reboot: the confirmed kernel is entered" "store (slot A, seq 1)" "$(source_now)"
if [[ "${PERSIST_TEST_CONTROL:-}" == no-confirm ]]; then
  # The rest needs a confirmed kernel: stop here instead of timing out.
  echo "PERSIST TEST: FAIL (negative control: expected)"
  exit 1
fi

echo "== in-RAM upgrade from a stored kernel"
check "in-RAM upgrade accepted" 200 "$(upload "$WORK/new.elf" /api/upgrade)"
wait_reboot 120 || echo "  [FAIL] in-RAM kernel did not come up"
check "in-RAM kernel does not chain-load" "in-RAM upgrade" "$(source_now)"
code -u admin:test -X POST "$URL/api/reboot" >/dev/null
wait_reboot 240 || echo "  [FAIL] no reboot"

rollback() { # name file how failure-pattern; the trial goes to slot B, seq $SEQ (= 2)
  local name="$1" file="$2" how="$3" pattern="$4"
  echo "== rollback: $name"
  # An erased trial leaves only A seq 1, so every trial here is B seq 2:
  # compare log counts before and after.
  local before_fail before_enter before_rb
  before_fail="$(count "$pattern")"
  before_enter="$(count "entering the stored kernel (slot B, seq $SEQ, trial)")"
  before_rb="$(count "slot B seq $SEQ: trial kernel never confirmed: rolling back")"
  check "$name: persist accepted" 200 "$(upload "$file")"
  case "$how" in
    crash)
      # The bad kernel fails by itself; wait for the loader's rollback.
      wait_count $((before_rb + 1)) "slot B seq $SEQ: trial kernel never confirmed: rolling back" 240 ||
        echo "  [FAIL] $name: no rollback in the log"
      ;;
    timeout)
      wait_reboot 240 || echo "  [FAIL] $name: no reboot"
      check "$name: trial runs" "$SEQ" "$(trial_now)"
      wait_count 1 "trial kernel not confirmed within 20 s: reverting" 90 || echo "  [FAIL] $name: trial did not time out"
      ;;
    revert)
      wait_reboot 240 || echo "  [FAIL] $name: no reboot"
      check "$name: trial runs" "$SEQ" "$(trial_now)"
      check "$name: roll back now -> 200" 200 "$(code -u admin:test -X POST "$URL/api/upgrade/revert")"
      ;;
    kill)
      wait_reboot 240 || echo "  [FAIL] $name: no reboot"
      check "$name: trial runs" "$SEQ" "$(trial_now)"
      stop
      start
      ;;
  esac
  check "$name: the bad kernel was entered as a trial" 1 "$(( $(count "entering the stored kernel (slot B, seq $SEQ, trial)") > before_enter ))"
  if [[ -n "$pattern" ]]; then
    check "$name: it failed as intended" 1 "$(( $(count "$pattern") > before_fail ))"
  fi
  # Back on the confirmed kernel.
  local i
  for i in $(seq 1 240); do
    [[ "$(source_now)" == "store (slot A, seq 1)" && "$(trial_now)" == - ]] && break
    sleep 1
  done
  check "$name: back on the confirmed kernel" "store (slot A, seq 1)" "$(source_now)"
  check "$name: trial erased" "B: empty" "$(images | sed 's/.*| //')"
}
SEQ=2
rollback "kernel panics" "$WORK/panic.elf" crash "fault-test: deliberate panic"
rollback "kernel hangs (watchdog)" "$WORK/hang.elf" crash "fault-test: hanging a task"
rollback "no confirm within trial_secs" "$WORK/new.elf" timeout ""
rollback "roll back now" "$WORK/new.elf" revert ""
rollback "QEMU killed during the trial" "$WORK/new.elf" kill ""

echo "== negative controls"
stop
start "image=golden"
for _ in $(seq 1 180); do [[ -n "$(source_now)" ]] && break; sleep 1; done
check "image=golden: stored kernels not used" "boot partition (image=golden: stored kernels not used)" "$(source_now)"
stop
"$RRSTORE" corrupt "$IMG" images >/dev/null
start
for _ in $(seq 1 180); do [[ -n "$(source_now)" ]] && break; sleep 1; done
check "corrupt record: the loader boots itself" "boot partition (no kernel in the store)" "$(source_now)"
check "password masked in the log" 0 "$(count 'mgmt_pass=test')"

if [[ "$FAILED" == 0 ]]; then echo "PERSIST TEST: PASS"; else echo "PERSIST TEST: FAIL"; exit 1; fi
