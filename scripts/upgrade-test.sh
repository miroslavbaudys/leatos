#!/usr/bin/env bash
# End-to-end test of the management interface and the in-RAM upgrade on
# the x86_64 kernel in QEMU (q35, igb NICs, WAN on user networking with a
# host port forwarded to the router's port 80, booted with mgmt=wan).
#
#   scripts/upgrade-test.sh        # LAB_VERBOSE=1 prints the router console
#
# Checks (each refusal is a negative control for the accepting case):
#   status JSON and page; upload without / with a wrong password -> 401;
#   garbage -> 422; wrong CRC -> 422; unknown path -> 404; a valid upload
#   -> 200, the old kernel jumps, the new one boots with the new command
#   line, gets DHCP and serves the API again; a second upgrade from the
#   upgraded kernel; reboot -> the firmware boots the original kernel.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${UPGRADE_TEST_PORT:-18080}"
URL="http://127.0.0.1:$PORT"
WORK="$(mktemp -d -t rrouter-upgrade.XXXXXX)"
LOG="$WORK/router.log"
QPID=
cleanup() {
  [[ -n "$QPID" ]] && kill "$QPID" 2>/dev/null || true
  if [[ "${LAB_VERBOSE:-0}" == 1 && -f "$LOG" ]]; then sed 's/^/  | /' "$LOG"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
FAILED=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then echo "  [PASS] $1"; else echo "  [FAIL] $1: expected '$2', got '$3'"; FAILED=1; fi
}
wait_for() { # count pattern seconds
  local i
  for i in $(seq 1 "$3"); do
    [[ "$(grep -ac -- "$2" "$LOG" || true)" -ge "$1" ]] && return 0
    sleep 1
  done
  return 1
}

cargo build -p rrouter-kernel --target x86_64-unknown-none --release --quiet
ELF=target/x86_64-unknown-none/release/rrouter
OBJCOPY="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
if [[ -x "$OBJCOPY" ]]; then "$OBJCOPY" --strip-debug "$ELF" "$WORK/new.elf"; else cp "$ELF" "$WORK/new.elf"; fi
cp "$ELF" "$WORK/boot.elf" # boot a copy: the build may change under us
CRC="$(python3 -I -c 'import sys,zlib; print("%08x" % zlib.crc32(open(sys.argv[1],"rb").read()))' "$WORK/new.elf")"
# log=console: the uploaded kernels get ARGS as their command line, and
# the checks read their log messages from the console.
ARGS="log=console mgmt=wan mgmt_pass=test lan=10.10.0.1/24"

QEMU_NET=user QEMU_NIC=igb QEMU_WAN_HOSTFWD="tcp:127.0.0.1:$PORT-:80" QEMU_APPEND="$ARGS" \
  scripts/qemu-run.sh "$WORK/boot.elf" >"$LOG" 2>&1 &
QPID=$!
wait_for 1 "dhcp lease" 90 || { echo "  [FAIL] router did not boot"; exit 1; }

code() { curl -s -m 20 -o /dev/null -w '%{http_code}' "$@" || true; }
check "status JSON" "x86_64" "$(curl -s -m 5 "$URL/api/status" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["arch"])' 2>/dev/null || true)"
check "status page" "1" "$(curl -s -m 5 "$URL/" | grep -c '<title>rrouter</title>' || true)"
check "unknown path -> 404" 404 "$(code "$URL/nope")"
check "upload without password -> 401" 401 "$(code -X POST --data-binary @"$WORK/new.elf" "$URL/api/upgrade")"
check "upload with wrong password -> 401" 401 "$(code -u admin:wrong -X POST --data-binary @"$WORK/new.elf" "$URL/api/upgrade")"
sleep 1.2 # a wrong password blocks password checks for a second (429)
head -c 100000 /dev/urandom >"$WORK/garbage"
check "garbage upload -> 422" 422 "$(code -u admin:test -X POST --data-binary @"$WORK/garbage" "$URL/api/upgrade")"
# A whole kernel: as long as a real upload (the CRC is checked at the end).
check "wrong CRC -> 422" 422 "$(code -m 120 -u admin:test -H 'X-Image-CRC32: deadbeef' -X POST --data-binary @"$WORK/new.elf" "$URL/api/upgrade")"
check "refused uploads did not restart the kernel" 1 "$(grep -ac 'rrouter 0.1.0' "$LOG")"

for gen in 2 3; do
  check "upgrade $((gen - 1)) accepted" 200 "$(code -m 120 -u admin:test -H "X-Image-CRC32: $CRC" -H "X-Cmdline: $ARGS gen=$gen" -X POST --data-binary @"$WORK/new.elf" "$URL/api/upgrade")"
  ok=0
  wait_for "$gen" "dhcp lease" 90 && grep -aq "bootargs .*gen=$gen" "$LOG" && ok=1
  check "upgrade $((gen - 1)): new kernel booted with gen=$gen and got DHCP" 1 "$ok"
  check "upgrade $((gen - 1)): API answers again" x86_64 "$(curl -s -m 5 "$URL/api/status" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["arch"])' 2>/dev/null || true)"
done
check "password masked in the log" 0 "$(grep -ac 'mgmt_pass=test' "$LOG" || true)"

check "reboot accepted" 200 "$(code -u admin:test -X POST "$URL/api/reboot")"
ok=0
wait_for 4 "rrouter 0.1.0" 60 && [[ "$(grep -a 'bootargs' "$LOG" | tail -1)" != *gen=* ]] && ok=1
check "reboot: firmware boots the original kernel" 1 "$ok"

if [[ "$FAILED" == 0 ]]; then echo "UPGRADE TEST: PASS"; else echo "UPGRADE TEST: FAIL"; exit 1; fi
