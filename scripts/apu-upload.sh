#!/usr/bin/env bash
# Build the x86_64 kernel and upgrade a running rrouter over HTTP
# (kernel/src/net/mgmt.rs, docs/upgrades.md). By default in RAM (POST
# /api/upgrade): nothing is written to the SD card, a power cycle boots its
# kernel again. With --persist the kernel is stored on the SD card (POST
# /api/upgrade/persist) and the router reboots into it as a trial; once it
# answers with the new build, this script confirms it. A kernel that
# panics, hangs or is not confirmed within the trial window is rolled back.
#
#   scripts/apu-upload.sh                      # release kernel -> $RROUTER_HOST, in RAM
#   scripts/apu-upload.sh --persist            # store it on the SD card, reboot, confirm
#   scripts/apu-upload.sh --persist --no-confirm   # leave the trial unconfirmed (rolls back)
#   scripts/apu-upload.sh --confirm | --revert # confirm / roll back the running trial kernel
#   scripts/apu-upload.sh --host 192.168.1.156 --cmdline "mgmt=wan mgmt_pass=... shape_up=20000"
#   scripts/apu-upload.sh --debug              # debug kernel (bigger, slower)
#   scripts/apu-upload.sh --reboot             # only reboot the router
#   scripts/apu-upload.sh --features fault-hang --cmdline "... cores=1"
#                                              # test kernel (here: the FCH watchdog)
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
FEATURES=
REBOOT=0
PERSIST=0
CONFIRM=1
TRIAL_OP=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift ;;
    --pass) PASS="$2"; shift ;;
    --cmdline) CMDLINE="$2"; shift ;;
    --debug) PROFILE=debug ;;
    --features) FEATURES="$2"; shift ;;
    --reboot) REBOOT=1 ;;
    --persist) PERSIST=1 ;;
    --no-confirm) CONFIRM=0 ;;
    --confirm) TRIAL_OP=confirm ;;
    --revert) TRIAL_OP=revert ;;
    -h | --help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ "$PERSIST" == 1 && -n "$CMDLINE" ]] && { echo "--persist: a stored kernel boots with the SD card's command line (no --cmdline)" >&2; exit 2; }
[[ -n "$HOST" ]] || { echo "no router: --host ADDR or RROUTER_HOST" >&2; exit 2; }
if [[ -z "$PASS" && -f target/apu4/mgmt-pass ]]; then PASS="$(cat target/apu4/mgmt-pass)"; fi
[[ -n "$PASS" ]] || { echo "no password: --pass, RROUTER_PASS or target/apu4/mgmt-pass" >&2; exit 2; }
URL="http://$HOST"

status_line() { # prints "version uptime_s" or nothing
  curl -s -m 3 "$URL/api/status" 2>/dev/null |
    python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d["version"], d["uptime_s"])' 2>/dev/null || true
}
image_line() { # prints "build|trial seq or -|source" or nothing
  curl -s -m 3 "$URL/api/status" 2>/dev/null |
    python3 -I -c 'import json,sys; d=json.load(sys.stdin); i=d.get("image") or {}; t=i.get("trial"); print("%s|%s|%s" % (d.get("build","?"), t["seq"] if t else "-", i.get("source","?")))' 2>/dev/null || true
}
trial_op() { # confirm | revert
  local out code
  out="$(curl -s -m 20 -u "admin:$PASS" -X POST "$URL/api/upgrade/$1" -w '\n%{http_code}')"
  code="${out##*$'\n'}"
  echo "router: ${out%$'\n'*} (HTTP $code)"
  [[ "$code" == 200 ]]
}

before="$(status_line)"
[[ -n "$before" ]] || { echo "router not reachable at $URL (boot it with mgmt=wan if you are on its WAN side)" >&2; exit 1; }
echo "router: $URL (version, uptime s: $before)"

if [[ "$REBOOT" == 1 ]]; then
  curl -s -m 10 -u "admin:$PASS" -X POST "$URL/api/reboot"; echo
  exit 0
fi
if [[ -n "$TRIAL_OP" ]]; then
  echo "kernel: $(image_line)"
  trial_op "$TRIAL_OP"
  exit $?
fi

args=(build -p rrouter-kernel --target x86_64-unknown-none --quiet)
[[ "$PROFILE" == release ]] && args+=(--release)
[[ -n "$FEATURES" ]] && args+=(--features "$FEATURES")
cargo "${args[@]}"
ELF="target/x86_64-unknown-none/$PROFILE/rrouter"
# Strip debug info (12 MiB -> < 1 MiB) when llvm-objcopy is available.
OBJCOPY="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
UPLOAD="$(mktemp -t rrouter-upload.XXXXXX)"
trap 'rm -f "$UPLOAD"' EXIT
if [[ -x "$OBJCOPY" ]]; then "$OBJCOPY" --strip-debug "$ELF" "$UPLOAD"; else cp "$ELF" "$UPLOAD"; fi
CRC="$(python3 -I -c 'import sys,zlib; print("%08x" % zlib.crc32(open(sys.argv[1],"rb").read()))' "$UPLOAD")"
SIZE="$(wc -c <"$UPLOAD" | tr -d ' ')"

# The id the kernel embeds (kernel/build.rs): the router must report it.
BUILD="$(git describe --always --dirty --abbrev=10 2>/dev/null || echo unknown)"

hdr=(-H "X-Image-CRC32: $CRC")
[[ -n "$CMDLINE" ]] && hdr+=(-H "X-Cmdline: $CMDLINE")
SHOWN="$(echo "$CMDLINE" | sed 's/mgmt_pass=[^ ]*/mgmt_pass=***/')"
ENDPOINT=/api/upgrade
[[ "$PERSIST" == 1 ]] && ENDPOINT=/api/upgrade/persist
echo "upload: $PROFILE kernel${FEATURES:+ ($FEATURES)} build $BUILD, $SIZE bytes, crc32 $CRC${CMDLINE:+, cmdline \"$SHOWN\"}$([[ "$PERSIST" == 1 ]] && echo ', stored on the SD card')"
out="$(curl -s -m 180 -u "admin:$PASS" "${hdr[@]}" -X POST --data-binary @"$UPLOAD" "$URL$ENDPOINT" -w '\n%{http_code}')"
code="${out##*$'\n'}"
echo "router: ${out%$'\n'*} (HTTP $code)"
[[ "$code" == 200 ]] || exit 1

# The new kernel needs a few seconds (NIC reset, link, DHCP), a persistent
# upgrade a whole firmware boot too. It is back once the router was
# unreachable or its uptime restarted.
WAIT=60
[[ "$PERSIST" == 1 ]] && WAIT=240
old_up="${before##* }"
down=0
back=
for _ in $(seq 1 "$WAIT"); do
  sleep 1
  now="$(status_line)"
  if [[ -z "$now" ]]; then down=1; continue; fi
  if [[ "$down" == 1 || "${now##* }" -lt "$old_up" ]]; then
    back="$now"
    break
  fi
done
if [[ -z "$back" ]]; then
  echo "router did not come back within $WAIT s (check the serial console; a power cycle boots the SD card)" >&2
  exit 1
fi
echo "router is back: version, uptime s: $back"
[[ "$PERSIST" == 1 ]] || exit 0

img="$(image_line)"
echo "kernel: build ${img%%|*}, ${img##*|}"
rest="${img#*|}"
if [[ "${rest%%|*}" == - ]]; then
  echo "the router does not run a trial kernel: the stored kernel was rolled back (see the serial console)" >&2
  exit 1
fi
if [[ "${img%%|*}" != "$BUILD" ]]; then
  echo "the trial kernel reports build ${img%%|*}, uploaded $BUILD: not confirming" >&2
  exit 1
fi
if [[ "$CONFIRM" == 0 ]]; then
  echo "not confirmed (--no-confirm): the router rolls back when the trial window ends"
  exit 0
fi
trial_op confirm
