#!/usr/bin/env bash
# Build the x86_64 kernel and upgrade a running leatos over HTTP
# (kernel/src/net/mgmt.rs, docs/upgrades.md). By default in RAM (POST
# /api/upgrade): nothing is written to the SD card, a power cycle boots its
# kernel again. With --persist the kernel is stored on the SD card (POST
# /api/upgrade/persist) and the router reboots into it as a trial; once it
# answers with the new build and has stayed up for --stable-secs (default
# 30, without a reboot in between), this script confirms it. A kernel that
# panics, hangs or is not confirmed within the trial window is rolled back.
#
#   scripts/apu-upload.sh                      # release kernel -> $LEATOS_HOST, in RAM
#   scripts/apu-upload.sh --persist            # store it on the SD card, reboot, confirm
#   scripts/apu-upload.sh --persist --no-confirm   # leave the trial unconfirmed (rolls back)
#   scripts/apu-upload.sh --persist --stable-secs 60   # longer stability window before confirming
#   scripts/apu-upload.sh --confirm | --revert # confirm / roll back the running trial kernel
#   scripts/apu-upload.sh --host ROUTER_IP --cmdline "mgmt=wan mgmt_pass=... shape_up=20000"
#   scripts/apu-upload.sh --debug              # debug kernel (bigger, slower)
#   scripts/apu-upload.sh --reboot             # only reboot the router
#   scripts/apu-upload.sh --features fault-hang --cmdline "... cores=1"
#                                              # test kernel (here: the FCH watchdog)
#   scripts/apu-upload.sh --host 127.0.0.1:18080 --persist \
#     --tunnel "ssh -o ServerAliveInterval=5 -o ServerAliveCountMax=60 -f -N -L 18080:192.168.1.1:80 user@jump"
#                                              # through an SSH tunnel that may drop
#
# --tunnel CMD (or $LEATOS_TUNNEL) re-runs CMD whenever nothing listens at
# the host any more (connection refused: the tunnel's ssh has exited, e.g.
# because the jump host's own path goes through the rebooting router), so a
# persistent upgrade can still be confirmed in its trial window. An upload
# cut off mid-way is checked: if the router reboots anyway, the trial is
# confirmed only if it runs the build that was uploaded.
#
# Defaults: host from $LEATOS_HOST, password from $LEATOS_PASS or the
# file target/apu4/mgmt-pass (written by scripts/apu-image.sh --mgmt-wan).
# The command line stays the running kernel's unless --cmdline is given.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${LEATOS_HOST:-}"
PASS="${LEATOS_PASS:-}"
TUNNEL="${LEATOS_TUNNEL:-}"
PROFILE=release
CMDLINE=
FEATURES=
REBOOT=0
PERSIST=0
CONFIRM=1
STABLE=30
TRIAL_OP=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift ;;
    --pass) PASS="$2"; shift ;;
    --tunnel) TUNNEL="$2"; shift ;;
    --cmdline) CMDLINE="$2"; shift ;;
    --debug) PROFILE=debug ;;
    --features) FEATURES="$2"; shift ;;
    --reboot) REBOOT=1 ;;
    --persist) PERSIST=1 ;;
    --no-confirm) CONFIRM=0 ;;
    --stable-secs) STABLE="$2"; shift ;;
    --confirm) TRIAL_OP=confirm ;;
    --revert) TRIAL_OP=revert ;;
    -h | --help) sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ "$PERSIST" == 1 && -n "$CMDLINE" ]] && { echo "--persist: a stored kernel boots with the SD card's command line (no --cmdline)" >&2; exit 2; }
[[ -n "$HOST" ]] || { echo "no router: --host ADDR or LEATOS_HOST" >&2; exit 2; }
if [[ -z "$PASS" && -f target/apu4/mgmt-pass ]]; then PASS="$(cat target/apu4/mgmt-pass)"; fi
[[ -n "$PASS" ]] || { echo "no password: --pass, LEATOS_PASS or target/apu4/mgmt-pass" >&2; exit 2; }
URL="http://$HOST"

# /api/status, re-opening the tunnel first when nothing listens at the host
# (curl exit 7) any more. Prints the body or nothing. Callers run it in
# $(...), so its state ("last re-open time, warned") lives in a file.
TUNSTATE="$(mktemp -t leatos-tunnel.XXXXXX)"
trap 'rm -f "$TUNSTATE"' EXIT
fetch_status() {
  local out rc=0 last=0 warned=0
  out="$(curl -s -m 3 -u "admin:$PASS" "$URL/api/status" 2>/dev/null)" || rc=$?
  if [[ "$rc" == 7 ]]; then
    read -r last warned <"$TUNSTATE" || true
    if [[ -n "$TUNNEL" ]]; then
      if [[ $(($(date +%s) - ${last:-0})) -ge 5 ]]; then
        echo "$(date +%s) 0" >"$TUNSTATE"
        echo "  (nothing listens at $HOST: re-opening the tunnel)" >&2
        eval "$TUNNEL" >/dev/null 2>&1 || true
        out="$(curl -s -m 3 -u "admin:$PASS" "$URL/api/status" 2>/dev/null)" || true
      fi
    elif [[ "${warned:-0}" == 0 ]]; then
      echo "0 1" >"$TUNSTATE"
      echo "  (nothing listens at $HOST: if it is an SSH tunnel, it has closed; --tunnel CMD re-opens it)" >&2
    fi
  fi
  printf '%s' "$out"
}
status_line() { # prints "version uptime_s" or nothing
  fetch_status |
    python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d["version"], d["uptime_s"])' 2>/dev/null || true
}
image_line() { # prints "build|trial seq or -|source" or nothing
  fetch_status |
    python3 -I -c 'import json,sys; d=json.load(sys.stdin); i=d.get("image") or {}; t=i.get("trial"); print("%s|%s|%s" % (d.get("build","?"), t["seq"] if t else "-", i.get("source","?")))' 2>/dev/null || true
}
trial_state() { # prints "uptime_s trial_seq remaining_s" ("-" for no trial), or nothing
  fetch_status |
    python3 -I -c 'import json,sys; d=json.load(sys.stdin); t=(d.get("image") or {}).get("trial"); print(d["uptime_s"], t["seq"] if t else "-", t["remaining_s"] if t else "-")' 2>/dev/null || true
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

args=(build -p leatos-kernel --target x86_64-unknown-none --quiet)
[[ "$PROFILE" == release ]] && args+=(--release)
[[ -n "$FEATURES" ]] && args+=(--features "$FEATURES")
cargo "${args[@]}"
ELF="target/x86_64-unknown-none/$PROFILE/leatos"
# Strip debug info (12 MiB -> < 1 MiB) when llvm-objcopy is available.
OBJCOPY="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
UPLOAD="$(mktemp -t leatos-upload.XXXXXX)"
trap 'rm -f "$UPLOAD" "$TUNSTATE"' EXIT
if [[ -x "$OBJCOPY" ]]; then "$OBJCOPY" --strip-debug "$ELF" "$UPLOAD"; else cp "$ELF" "$UPLOAD"; fi
CRC="$(python3 -I -c 'import sys,zlib; print("%08x" % zlib.crc32(open(sys.argv[1],"rb").read()))' "$UPLOAD")"
SIZE="$(wc -c <"$UPLOAD" | tr -d ' ')"

# The id the kernel embeds (kernel/build.rs), for the log only: build.rs
# runs only when kernel sources change, so it can differ from the tree.
BUILD="$(git describe --always --dirty --abbrev=10 2>/dev/null || echo unknown)"

hdr=(-H "X-Image-CRC32: $CRC")
[[ -n "$CMDLINE" ]] && hdr+=(-H "X-Cmdline: $CMDLINE")
SHOWN="$(echo "$CMDLINE" | sed 's/mgmt_pass=[^ ]*/mgmt_pass=***/')"
ENDPOINT=/api/upgrade
[[ "$PERSIST" == 1 ]] && ENDPOINT=/api/upgrade/persist
echo "upload: $PROFILE kernel${FEATURES:+ ($FEATURES)} build $BUILD, $SIZE bytes, crc32 $CRC${CMDLINE:+, cmdline \"$SHOWN\"}$([[ "$PERSIST" == 1 ]] && echo ', stored on the SD card')"
rc=0
out="$(curl -s -m 180 -u "admin:$PASS" "${hdr[@]}" -X POST --data-binary @"$UPLOAD" "$URL$ENDPOINT" -w '\n%{http_code}')" || rc=$?
STORED_SEQ=
INTERRUPTED=0
if [[ "$rc" != 0 ]]; then
  # Cut off (a tunnel dropping): the router may have stored it and be
  # rebooting, or have nothing. Its uptime and image tell.
  # Stored, it restarts within a second or two; still answering 10 s later
  # without its uptime going back means it took nothing.
  echo "upload interrupted (curl exit $rc): checking what the router has" >&2
  INTERRUPTED=1
  kept=0
  for _ in 1 2 3 4 5; do
    sleep 2
    now="$(status_line)"
    if [[ -n "$now" && "${now##* }" -ge "${before##* }" ]]; then kept=$((kept + 1)); else break; fi
  done
  if [[ "$kept" == 5 ]]; then
    img="$(image_line)"
    echo "the router kept running ${img%%|*} (up ${now##* } s, $(echo "$img" | cut -d'|' -f3)): nothing was stored, upload again" >&2
    exit 1
  fi
  echo "the router is restarting: following it" >&2
else
  code="${out##*$'\n'}"
  echo "router: ${out%$'\n'*} (HTTP $code)"
  [[ "$code" == 200 ]] || exit 1
  # The record the router stored ("... (slot A, seq 3, ...)"): the trial that
  # boots must be exactly this one.
  STORED_SEQ="$(printf '%s' "$out" | sed -n 's/.*, seq \([0-9]*\),.*/\1/p' | head -1)"
fi

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
  if [[ "${img%%|*}" == "$BUILD" ]]; then
    echo "the router runs $BUILD with no trial pending: already confirmed (from elsewhere, or while this script could not reach it)"
    exit 0
  fi
  echo "the router does not run a trial kernel: the stored kernel was rolled back (see the serial console)" >&2
  exit 1
fi
if [[ "$INTERRUPTED" == 1 && "${img%%|*}" == "$BUILD" ]]; then
  STORED_SEQ="${rest%%|*}"
  echo "the interrupted upload was stored: trial seq $STORED_SEQ runs $BUILD"
fi
if [[ -z "$STORED_SEQ" || "${rest%%|*}" != "$STORED_SEQ" ]]; then
  echo "the trial is seq ${rest%%|*}, the upload was stored as seq ${STORED_SEQ:-?}: not confirming" >&2
  exit 1
fi
if [[ "$CONFIRM" == 0 ]]; then
  echo "not confirmed (--no-confirm): the router rolls back when the trial window ends"
  exit 0
fi

# Answering once is not enough: a kernel that crashes a few seconds after
# its web interface comes up would be confirmed and then reboot forever.
# Confirm only once the same trial has stayed up for $STABLE s.
read -r up0 seq0 left0 <<<"$(trial_state)"
if [[ -z "${up0:-}" || "$seq0" == - ]]; then
  echo "the trial kernel is gone before the stability wait: not confirming" >&2
  exit 1
fi
if [[ "$left0" != - && "$left0" -le $((STABLE - up0 + 5)) ]]; then
  echo "trial window ($left0 s left) too short for --stable-secs $STABLE: not confirming (it rolls back)" >&2
  exit 1
fi
echo "stability check: waiting until the trial kernel (seq $seq0) has been up for $STABLE s"
last="$up0"
miss=0
while :; do
  read -r up seq left <<<"$(trial_state)"
  if [[ -z "${up:-}" ]]; then
    # Lost polls (Wi-Fi, a tunnel being re-opened) are not a crash; 20 s
    # of silence is.
    miss=$((miss + 1))
    if [[ "$miss" -ge 20 ]]; then
      echo "the trial kernel stopped answering at uptime ~$last s: not confirming (it is rolled back)" >&2
      exit 1
    fi
    sleep 1
    continue
  fi
  miss=0
  if [[ "$up" -lt "$last" || "$seq" != "$seq0" ]]; then
    echo "the router rebooted during the stability wait (uptime $last -> $up s, trial $seq0 -> $seq): not confirming" >&2
    exit 1
  fi
  last="$up"
  [[ "$up" -ge "$STABLE" ]] && break
  sleep 1
done
echo "stable: up $last s, trial seq $seq0 still pending"
trial_op confirm
