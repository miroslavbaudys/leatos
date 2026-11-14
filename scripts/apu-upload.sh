#!/usr/bin/env bash
# Build the x86_64 kernel and upgrade a running rrouter in RAM over HTTP
# (POST /api/upgrade, see kernel/src/net/mgmt.rs). Nothing is written to
# the boot medium: a power cycle boots the SD card's kernel again.
#
#   scripts/apu-upload.sh                      # release kernel -> $RROUTER_HOST
#   scripts/apu-upload.sh --host 192.168.1.156 --cmdline "mgmt=wan mgmt_pass=... shape_up=20000"
#   scripts/apu-upload.sh --debug              # debug kernel (bigger, slower)
#   scripts/apu-upload.sh --reboot             # only reboot the router
#
# Defaults: host from $RROUTER_HOST, password from $RROUTER_PASS or the
# file target/apu4/mgmt-pass (written by scripts/apu-image.sh --mgmt-wan).
# The command line stays the running kernel's unless --cmdline is given.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${RROUTER_HOST:-}"
PASS="${RROUTER_PASS:-}"
PROFILE=release
CMDLINE=
REBOOT=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift ;;
    --pass) PASS="$2"; shift ;;
    --cmdline) CMDLINE="$2"; shift ;;
    --debug) PROFILE=debug ;;
    --reboot) REBOOT=1 ;;
    -h | --help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ -n "$HOST" ]] || { echo "no router: --host ADDR or RROUTER_HOST" >&2; exit 2; }
if [[ -z "$PASS" && -f target/apu4/mgmt-pass ]]; then PASS="$(cat target/apu4/mgmt-pass)"; fi
[[ -n "$PASS" ]] || { echo "no password: --pass, RROUTER_PASS or target/apu4/mgmt-pass" >&2; exit 2; }
URL="http://$HOST"

status_line() { # prints "version uptime_s" or nothing
  curl -s -m 3 "$URL/api/status" 2>/dev/null |
    python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d["version"], d["uptime_s"])' 2>/dev/null || true
}

before="$(status_line)"
[[ -n "$before" ]] || { echo "router not reachable at $URL (boot it with mgmt=wan if you are on its WAN side)" >&2; exit 1; }
echo "router: $URL (version, uptime s: $before)"

if [[ "$REBOOT" == 1 ]]; then
  curl -s -m 10 -u "admin:$PASS" -X POST "$URL/api/reboot"; echo
  exit 0
fi

args=(build -p rrouter-kernel --target x86_64-unknown-none --quiet)
[[ "$PROFILE" == release ]] && args+=(--release)
cargo "${args[@]}"
ELF="target/x86_64-unknown-none/$PROFILE/rrouter"
# Strip debug info (12 MiB -> < 1 MiB) when llvm-objcopy is available.
OBJCOPY="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
UPLOAD="$(mktemp -t rrouter-upload.XXXXXX)"
trap 'rm -f "$UPLOAD"' EXIT
if [[ -x "$OBJCOPY" ]]; then "$OBJCOPY" --strip-debug "$ELF" "$UPLOAD"; else cp "$ELF" "$UPLOAD"; fi
CRC="$(python3 -I -c 'import sys,zlib; print("%08x" % zlib.crc32(open(sys.argv[1],"rb").read()))' "$UPLOAD")"
SIZE="$(wc -c <"$UPLOAD" | tr -d ' ')"

hdr=(-H "X-Image-CRC32: $CRC")
[[ -n "$CMDLINE" ]] && hdr+=(-H "X-Cmdline: $CMDLINE")
echo "upload: $PROFILE kernel, $SIZE bytes, crc32 $CRC${CMDLINE:+, cmdline \"$CMDLINE\"}"
out="$(curl -s -m 120 -u "admin:$PASS" "${hdr[@]}" -X POST --data-binary @"$UPLOAD" "$URL/api/upgrade" -w '\n%{http_code}')"
code="${out##*$'\n'}"
echo "router: ${out%$'\n'*} (HTTP $code)"
[[ "$code" == 200 ]] || exit 1

# The new kernel needs a few seconds (NIC reset, link, DHCP). It is back
# once the router was unreachable or its uptime restarted.
old_up="${before##* }"
down=0
for _ in $(seq 1 60); do
  sleep 1
  now="$(status_line)"
  if [[ -z "$now" ]]; then down=1; continue; fi
  if [[ "$down" == 1 || "${now##* }" -lt "$old_up" ]]; then
    echo "router is back: version, uptime s: $now"
    exit 0
  fi
done
echo "router did not come back within 60 s (check the serial console; a power cycle boots the SD card)" >&2
exit 1
