#!/usr/bin/env bash
# End-to-end test of the persistent store (docs/config-and-storage.md):
# virtio-blk disk with a store partition (made by tools/rrstore), config
# read at boot, saved through the management interface, used after a
# reboot.
#
#   scripts/store-test.sh                       # aarch64 (HVF on Apple Silicon)
#   RROUTER_ARCH=x86_64 scripts/store-test.sh   # x86_64 (TCG)
#   LAB_VERBOSE=1 ...                           # print the router consoles
#
# Boot-time reads (each a control for the others):
#   empty store -> defaults; stored config -> used; stored config that does
#   not validate -> defaults; config=defaults -> store ignored.
# Save (WAN on user networking, mgmt=wan, host port forwarded to :80):
#   GET /api/config; POST without password -> 401; invalid TOML -> 422,
#   inconsistent config -> 422, both leave the store unchanged; a valid
#   config -> 200, written to the other slot, router reboots into it.
# Negative controls for the save: corrupt the new record -> the router
#   falls back to the old one; corrupt both -> defaults.
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH="${RROUTER_ARCH:-aarch64}"
case "$ARCH" in aarch64 | x86_64) ;; *) echo "RROUTER_ARCH must be aarch64 or x86_64" >&2; exit 2 ;; esac
TARGET="$ARCH-unknown-none"
PORT="${STORE_TEST_PORT:-18081}"
URL="http://127.0.0.1:$PORT"
WORK="$(mktemp -d -t rrouter-store.XXXXXX)"
IMG="$WORK/store.img"
LOG=
QPID=
stop() {
  if [[ -n "$QPID" ]]; then kill "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; fi
  QPID=
  if [[ "${LAB_VERBOSE:-0}" == 1 && -n "$LOG" && -f "$LOG" ]]; then sed 's/^/  | /' "$LOG" >&2; fi
}
cleanup() { stop; rm -rf "$WORK"; }
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
# The config line of boot number $1 (1 = first) in $LOG.
config_line() { grep -a "  config          : " "$LOG" | grep -v warning | sed -n "${1}p" | sed 's/^ *config *: //' | tr -d '\r'; }

cargo build -p rrouter-kernel --target "$TARGET" --release --quiet
cargo build -p rrstore --release --quiet
RRSTORE=target/release/rrstore
cp "target/$TARGET/release/rrouter" "$WORK/rrouter.elf" # the build may change under us

boot() { # name append [extra env...]: boot with the store, log to $WORK/name.log
  local name="$1" append="$2"
  shift 2
  LOG="$WORK/$name.log"
  env QEMU_STORE="$IMG" QEMU_APPEND="$append" "$@" scripts/qemu-run.sh "$WORK/rrouter.elf" >"$LOG" 2>&1 &
  QPID=$!
}
boot_config() { # name append: boot, return the config line, stop
  boot "$1" "$2"
  wait_for 1 "  config          : " 90 || true
  config_line 1
  stop
}

echo "== boot-time reads ($ARCH)"
"$RRSTORE" create "$IMG" >/dev/null
r="$(boot_config empty "")"
check "empty store -> defaults" "defaults (store has no valid config)" "${r%%,*}"

printf 'version = 1\n\n[lan]\nipv4 = "10.20.0.1/24"\n' >"$WORK/a.toml"
"$RRSTORE" put "$IMG" config "$WORK/a.toml" >/dev/null
r="$(boot_config stored "")"
check "stored config used" "stored (slot A, seq 1), lan 10.20.0.1/24" "${r%%, dhcp*}"
r="$(boot_config ignored "config=defaults")"
check "config=defaults ignores the store" "defaults (config=defaults: store ignored)" "${r%%,*}"

"$RRSTORE" create "$IMG" >/dev/null
printf 'version = 1\nbogus = 1\n' >"$WORK/bad.toml"
"$RRSTORE" put "$IMG" config "$WORK/bad.toml" --raw >/dev/null
r="$(boot_config rejected "")"
check "stored config that does not validate -> defaults" "defaults (stored config slot A rejected" "${r%%:*}"

echo "== save through the management interface"
"$RRSTORE" create "$IMG" >/dev/null
"$RRSTORE" put "$IMG" config "$WORK/a.toml" >/dev/null
boot save "mgmt=wan mgmt_pass=test" QEMU_NET=user QEMU_WAN_HOSTFWD="tcp:127.0.0.1:$PORT-:80"
wait_for 1 "dhcp lease" 120 || { echo "  [FAIL] router did not get a WAN lease"; stop; exit 1; }
code() { curl -s -m 20 -o /dev/null -w '%{http_code}' "$@" || true; }
seq_of() { "$RRSTORE" get "$IMG" config 2>&1 >/dev/null | sed -n 's/.*seq \([0-9]*\).*/\1/p'; }

check "GET /api/config shows the stored LAN" 1 "$(curl -s -m 10 "$URL/api/config" | grep -c '^ipv4 = "10.20.0.1/24"' || true)"
check "status reports the config source" "stored (slot A, seq 1)" \
  "$(curl -s -m 10 "$URL/api/status" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["config"])' 2>/dev/null || true)"
printf 'version = 1\n\n[lan]\nipv4 = "10.30.0.1/24"\n\n[[lan.dhcp.static]]\nmac = "52:54:00:00:00:07"\nip = "10.30.0.7"\nhostname = "printer"\n' >"$WORK/b.toml"
check "save without password -> 401" 401 "$(code -X POST --data-binary @"$WORK/b.toml" "$URL/api/config")"
check "invalid TOML -> 422" 422 "$(code -u admin:test -X POST --data-binary @"$WORK/bad.toml" "$URL/api/config")"
printf 'version = 1\n\n[lan]\nipv4 = "10.30.0.1/24"\n\n[lan.dhcp]\nrange = ["10.40.0.100", "10.40.0.199"]\n' >"$WORK/incons.toml"
check "inconsistent config -> 422" 422 "$(code -u admin:test -X POST --data-binary @"$WORK/incons.toml" "$URL/api/config")"
check "refused saves left the store unchanged" 1 "$(seq_of)"
check "valid config -> 200" 200 "$(code -u admin:test -X POST --data-binary @"$WORK/b.toml" "$URL/api/config")"
ok=0
wait_for 2 "  config          : " 90 && ok=1
check "router rebooted after the save" 1 "$ok"
r="$(config_line 2)"
check "rebooted into the saved config" "stored (slot B, seq 2), lan 10.30.0.1/24, dhcp 10.30.0.100–10.30.0.199, 1 reservation(s)" "$r"
wait_for 2 "dhcp lease" 120 || true
check "saved config readable after the reboot" 1 "$(curl -s -m 10 "$URL/api/config" | grep -c '^hostname = "printer"' || true)"
stop
check "host sees the new record (seq 2)" 2 "$(seq_of)"
check "kernel stored canonical TOML (defaults written out)" 1 "$("$RRSTORE" get "$IMG" config 2>/dev/null | grep -c '^cache_entries = ' || true)"

echo "== negative controls"
"$RRSTORE" corrupt "$IMG" config --slot B >/dev/null
r="$(boot_config fallback "")"
check "new record corrupt -> previous record" "stored (slot A, seq 1), lan 10.20.0.1/24" "${r%%, dhcp*}"
"$RRSTORE" corrupt "$IMG" config --slot A >/dev/null
r="$(boot_config both "")"
check "both records corrupt -> defaults" "defaults (store has no valid config)" "${r%%,*}"

if [[ "$FAILED" == 0 ]]; then echo "STORE TEST ($ARCH): PASS"; else echo "STORE TEST ($ARCH): FAIL"; exit 1; fi
