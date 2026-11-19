#!/usr/bin/env bash
# Bufferbloat test: latency idle vs. under saturating download / upload load.
#
# Runs three phases against public endpoints (Cloudflare speed test, ping to
# 1.1.1.1), each with a ping stream every 0.2 s:
#   idle      10 s, no load
#   download  15 s, N parallel downloads
#   upload    15 s, N parallel uploads
# and reports RTT percentiles, *added* latency under load (loaded p50/p90
# minus idle p50), throughput and a Waveform-style grade on added latency
# (A+ <5 ms, A <30, B <60, C <200, D <400, F otherwise).
#
# Results are appended to lab/cache/bufferbloat.csv (gitignored), labelled
# by path: "direct", "leatos-debug", "leatos-release" (from the
# mac-internet state file), or --label NAME.
#
# Usage: scripts/bufferbloat.sh [--label NAME] [--streams N] [--no-upload] [--duration S]
# No sudo needed. Uses roughly 100-500 MB of traffic, depending on your line.
set -euo pipefail
cd "$(dirname "$0")/.."

PING_TARGET=1.1.1.1
# Cloudflare refuses single downloads above ~50 MB (HTTP 403), so each stream
# fetches 25 MB chunks back to back until the phase ends.
CHUNK=25000000
# Download sources, in order. A stream that gets rate-limited (429) or a
# server error moves on to the next source (Cloudflare rate-limits an IP
# after many runs). The fallbacks are large static files, read with a byte
# range of $CHUNK.
DL_URLS=(
  "https://speed.cloudflare.com/__down?bytes=$CHUNK"
  "https://proof.ovh.net/files/1Gb.dat"
  "https://nbg1-speed.hetzner.com/1GB.bin"
)
UL_URL='https://speed.cloudflare.com/__up'
STREAMS=4
DURATION=15
IDLE=10
LABEL=""
UPLOAD=1
CSV=lab/cache/bufferbloat.csv

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label) LABEL="${2:?}"; shift 2 ;;
    --streams) STREAMS="${2:?}"; shift 2 ;;
    --duration) DURATION="${2:?}"; shift 2 ;;
    --no-upload) UPLOAD=0; shift ;;
    -h | --help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

WORK=$(mktemp -d -t leatos-bloat)
trap 'rm -rf "$WORK"; jobs -p | xargs kill 2>/dev/null || true' EXIT

# ---- which path are we measuring? ---------------------------------------------------------
gw=$(route -n get "$PING_TARGET" 2>/dev/null | awk '/gateway:/{print $2}')
if [[ -z "$LABEL" ]]; then
  if [[ "$gw" == 192.168.1.1 ]]; then
    build=$(sed -n 's/^BUILD=//p' lab/cache/mac-internet.state 2>/dev/null || true)
    shape=$(sed -n 's/^SHAPE=//p' lab/cache/mac-internet.state 2>/dev/null || true)
    xargs_=$(sed -n 's/^ARGS=//p' lab/cache/mac-internet.state 2>/dev/null | tr ' =' '_-' || true)
    LABEL="leatos-${build:-unknown}${shape:+-shaped-${shape/:/-}}${xargs_:+-$xargs_}"
  else
    LABEL=direct
  fi
fi
echo "== bufferbloat test: path '$LABEL' (gateway $gw), $STREAMS streams, ${DURATION}s per load phase"

# ---- helpers -------------------------------------------------------------------------------------
pinger() { # seconds outfile
  ping -i 0.2 -c $(($1 * 5)) -t $(($1 + 3)) "$PING_TARGET" >"$2" 2>&1 || true
}

# RTT samples (ms, one per line) from ping output.
samples() {
  awk -F'time=' '/time=/{split($2,a," "); print a[1]}' "$1" | sort -n
}

pct() { # sorted-file percentile(0-100)
  awk -v p="$2" '{v[NR]=$1} END{ if(NR==0){print "nan"; exit} i=int((p/100)*(NR-1))+1; printf "%.1f", v[i] }' "$1"
}

lost() { # ping output -> lost count
  local sent recv
  sent=$(awk '/packets transmitted/{print $1}' "$1")
  recv=$(awk '/packets transmitted/{print $4}' "$1")
  echo $(( ${sent:-0} - ${recv:-0} ))
}

grade() { # added latency ms
  awk -v d="$1" 'BEGIN{ if(d=="nan"){print "?"} else if(d<5)print "A+"; else if(d<30)print "A"; else if(d<60)print "B"; else if(d<200)print "C"; else if(d<400)print "D"; else print "F" }'
}

# Run $STREAMS streams of back-to-back $CHUNK-byte transfers for $DURATION s.
# Prints total Mbit/s. Rate limiting (HTTP 429) and server errors (5xx) are
# retried after 1 s and counted in $WORK/retry.*; other HTTP errors stop the
# stream and are recorded in $WORK/fatal.* (run invalid).
# Uploads send a prepared file: `--data-binary @-` would buffer all of
# stdin in memory before sending anything.
load() { # download|upload
  local end i
  end=$(( $(date +%s) + DURATION ))
  [[ "$1" == upload && ! -f "$WORK/chunk" ]] && head -c "$CHUNK" /dev/zero >"$WORK/chunk"
  for i in $(seq 1 "$STREAMS"); do
    (
      total=0
      src=0
      while :; do
        left=$(( end - $(date +%s) ))
        [[ $left -gt 0 ]] || break
        if [[ "$1" == download ]]; then
          out=$(curl -s -o /dev/null -m "$left" -r "0-$((CHUNK - 1))" -w '%{http_code} %{size_download}' "${DL_URLS[$src]}" 2>/dev/null || true)
        else
          out=$(curl -s -o /dev/null -m "$left" -X POST -H 'Content-Type: application/octet-stream' \
            --data-binary @"$WORK/chunk" -w '%{http_code} %{size_upload}' "$UL_URL" 2>/dev/null || true)
        fi
        code=${out%% *}
        bytes=${out##* }
        total=$(( total + ${bytes:-0} ))
        case "$code" in
          200 | 206 | 000 | 100) ;; # 206: ranged fallback; 000/100: cut off by the deadline
          429 | 5??)
            echo "HTTP $code" >>"$WORK/retry.$i"
            if [[ "$1" == download && $((src + 1)) -lt ${#DL_URLS[@]} ]]; then
              src=$((src + 1)) # rate-limited: switch to the next download source
            else
              sleep 1
            fi ;;
          *) echo "HTTP $code" >>"$WORK/fatal.$i"; break ;;
        esac
      done
      echo "$total" >"$WORK/bytes.$i"
    ) &
  done
  wait
  cat "$WORK"/bytes.* 2>/dev/null | awk -v t="$DURATION" '{s+=$1} END{printf "%.1f", s*8/t/1e6}'
  rm -f "$WORK"/bytes.*
}

phase() { # name -> sets <name>_p50/p90/p99/max/lost/mbps
  local name=$1 mbps="-"
  if [[ "$name" == idle ]]; then
    pinger "$IDLE" "$WORK/$name.ping"
  else
    pinger "$DURATION" "$WORK/$name.ping" &
    local pp=$!
    sleep 1
    mbps=$(load "$name")
    wait "$pp" || true
  fi
  eval "${name}_retries=$(cat "$WORK"/retry.* 2>/dev/null | wc -l | tr -d ' ')"
  eval "${name}_fatal=\"$(cat "$WORK"/fatal.* 2>/dev/null | sort | uniq -c | tr -s ' ' | tr '\n' ';')\""
  rm -f "$WORK"/retry.* "$WORK"/fatal.*
  samples "$WORK/$name.ping" >"$WORK/$name.sorted"
  eval "${name}_p50=$(pct "$WORK/$name.sorted" 50)"
  eval "${name}_p90=$(pct "$WORK/$name.sorted" 90)"
  eval "${name}_p99=$(pct "$WORK/$name.sorted" 99)"
  eval "${name}_max=$(pct "$WORK/$name.sorted" 100)"
  eval "${name}_lost=$(lost "$WORK/$name.ping")"
  eval "${name}_mbps=$mbps"
}

# ---- run ------------------------------------------------------------------------------------------
echo "  idle ..."
phase idle
echo "  download ..."
phase download
idle_retries=0 idle_fatal=""
if [[ "$UPLOAD" == 1 ]]; then
  echo "  upload ..."
  phase upload
else
  upload_p50=nan upload_p90=nan upload_p99=nan upload_max=nan upload_lost=0 upload_mbps=- upload_retries=0 upload_fatal=""
fi

# A run is valid only if both load phases actually loaded the line and no
# stream failed for good. Retried rate limits are reported, not fatal.
valid=1
reasons=""
for n in download upload; do
  eval "m=\$${n}_mbps r=\$${n}_retries f=\$${n}_fatal"
  [[ "$m" == "-" ]] && continue
  if awk -v m="$m" 'BEGIN{exit !(m < 1.0)}'; then valid=0; reasons+=" $n: only $m Mbit/s of load;"; fi
  if [[ -n "$f" ]]; then valid=0; reasons+=" $n: streams failed ($f);"; fi
  if [[ "$r" -gt 0 ]]; then echo "  note: $n phase hit $r rate-limited/5xx responses (switched download source, or retried after 1 s)"; fi
done

added() { awk -v a="$1" -v b="$2" 'BEGIN{ if(a=="nan"||b=="nan") print "nan"; else printf "%.1f", a-b }'; }
dl_add=$(added "$download_p90" "$idle_p50")
ul_add=$(added "$upload_p90" "$idle_p50")

printf '\n  %-9s %8s %8s %8s %8s %6s %10s\n' phase p50 p90 p99 max lost Mbit/s
for n in idle download upload; do
  eval "printf '  %-9s %8s %8s %8s %8s %6s %10s\n' $n \$${n}_p50 \$${n}_p90 \$${n}_p99 \$${n}_max \$${n}_lost \$${n}_mbps"
done
echo
if [[ "$valid" == 1 ]]; then
  echo "  added latency (loaded p90 - idle p50): download ${dl_add} ms [$(grade "$dl_add")], upload ${ul_add} ms [$(grade "$ul_add")]"
else
  echo "  INVALID RUN:$reasons no grade (not a bufferbloat result)"
fi

mkdir -p "$(dirname "$CSV")"
[[ -f "$CSV" ]] || echo "time,label,valid,gateway,streams,idle_p50,dl_p50,dl_p90,dl_max,dl_mbps,dl_added,ul_p50,ul_p90,ul_max,ul_mbps,ul_added" >"$CSV"
echo "$(date '+%Y-%m-%dT%H:%M:%S'),$LABEL,$valid,$gw,$STREAMS,$idle_p50,$download_p50,$download_p90,$download_max,$download_mbps,$dl_add,$upload_p50,$upload_p90,$upload_max,$upload_mbps,$ul_add" >>"$CSV"
echo "  appended to $CSV"
if [[ $(wc -l <"$CSV") -gt 2 ]]; then
  echo
  echo "  history:"
  column -s, -t "$CSV" | sed 's/^/    /'
fi
