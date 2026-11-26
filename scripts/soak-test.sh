#!/usr/bin/env bash
# Soak test (M9): watch a running leatos for days and judge whether it
# leaks or resets. It only observes: the load must come from real use (the
# apu4 as the home router) or from something else driving the lab router.
#
# Every --interval seconds it reads /api/status into lab/cache/soak-LABEL.csv
# (gitignored): uptime, heap used/free, packet pool free/capacity/failures,
# connections, early drops, forwarded/dropped packets, the longest conntrack
# pass (µs), the CPU temperature, neighbor drops and probes, and lan_nd's
# local_dropped (the router's own packets a neighbor table dropped). At the
# end (or on Ctrl-C, or with --report on an existing CSV) it checks:
#   reboot   uptime never went backwards (panic, watchdog or power loss)
#   heap     the *lowest* heap use in the last window is not above the lowest
#            in the first window (after warm-up) by more than 5 % + 256 KiB.
#            Heap use follows the connection count, so the quiet-time minimum
#            is what a leak raises. The first window starts only once the
#            DNS cache has filled (reached 99 % of its largest size in the
#            run): with serve-stale it grows to its cap (dns.cache_entries,
#            ~400 B per entry) and stays there, so a busy evening raises the
#            heap by MBs once (the 457cb97 apu4 soak: +1.6 MB at 31 h).
#   pool     the *highest* free packet count in the last window is not below
#            the first window's by more than 1 %: buffers that never come
#            back lower the idle maximum.
# and reports the run INVALID (not passed) unless it covered at least 90 %
# of the planned time with samples, forwarded at least --min-forwarded
# packets (the load actually happened) and left room for both windows after
# the warm-up and the cache fill (no leak check, no pass).
#
# Usage:
#   scripts/soak-test.sh [--host H] [--hours 72] [--interval 60] [--label NAME]
#                        [--warmup-hours 1] [--window-hours 6] [--min-forwarded N]
#   scripts/soak-test.sh --report lab/cache/soak-NAME.csv [--hours H] ...
# Defaults: host from $LEATOS_HOST, password from $LEATOS_PASS or
# target/apu4/mgmt-pass (none: the router has no password, reads are public).
# Exit: 0 pass, 1 fail, 2 usage, 3 invalid.
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C

HOST="${LEATOS_HOST:-}"
PASS="${LEATOS_PASS:-}"
HOURS=72
INTERVAL=60
LABEL=""
WARMUP_H=1
WINDOW_H=6
MIN_FWD=1000000
REPORT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift ;;
    --pass) PASS="$2"; shift ;;
    --hours) HOURS="$2"; shift ;;
    --interval) INTERVAL="$2"; shift ;;
    --label) LABEL="$2"; shift ;;
    --warmup-hours) WARMUP_H="$2"; shift ;;
    --window-hours) WINDOW_H="$2"; shift ;;
    --min-forwarded) MIN_FWD="$2"; shift ;;
    --report) REPORT="$2"; shift ;;
    -h | --help) sed -n '2,35p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

report() { # csv
  python3 -I - "$1" "$HOURS" "$WARMUP_H" "$WINDOW_H" "$MIN_FWD" <<'PY'
import csv, sys
path, hours, warm_h, win_h, min_fwd = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])
rows = [r for r in csv.DictReader(open(path)) if r["uptime_s"] != ""]
missed = sum(1 for r in csv.DictReader(open(path)) if r["uptime_s"] == "")
if len(rows) < 2:
    print("SOAK: INVALID: fewer than two samples"); sys.exit(3)
num = lambda r, k: int(r[k]) if r[k] not in ("", "null") else None
t0, t1 = int(rows[0]["ts"]), int(rows[-1]["ts"])
span_h = (t1 - t0) / 3600
fails, notes = [], []
# Reboots: uptime going backwards between samples.
reboots = [r["ts"] for a, r in zip(rows, rows[1:]) if num(r, "uptime_s") < num(a, "uptime_s")]
if reboots:
    fails.append(f"reboot: {len(reboots)} (first at ts {reboots[0]})")
# Counters restart with a reboot: sum the deltas per boot.
def delta(k):
    d = 0
    for a, r in zip(rows, rows[1:]):
        x, y = num(a, k), num(r, k)
        d += y if y < x else y - x
    return d
fwd = delta("forwarded")
# Leak checks on the longest stretch without a reboot.
seg, cur = [], [rows[0]]
for a, r in zip(rows, rows[1:]):
    if num(r, "uptime_s") < num(a, "uptime_s"):
        seg.append(cur); cur = []
    cur.append(r)
seg.append(cur)
run = max(seg, key=len)
s0 = int(run[0]["ts"]) + warm_h * 3600
# The DNS cache fills once to its cap: start the baseline after that (older
# CSVs have no dns_cached column: warm-up only).
dns = [(int(r["ts"]), num(r, "dns_cached")) for r in run if r.get("dns_cached") not in (None, "", "null")]
if dns:
    peak = max(c for _, c in dns)
    full = next(t for t, c in dns if c >= peak * 0.99)
    notes.append(f"DNS cache: {peak} entries, full after {(full - int(run[0]['ts'])) / 3600:.1f} h")
    s0 = max(s0, full)
first = [r for r in run if s0 <= int(r["ts"]) < s0 + win_h * 3600]
last = [r for r in run if int(r["ts"]) >= int(run[-1]["ts"]) - win_h * 3600]
leak_checked = bool(first and last and int(last[0]["ts"]) >= s0 + win_h * 3600)
if not leak_checked:
    notes.append(f"leak checks skipped: need warm-up {warm_h} h (and a full DNS cache) + two {win_h} h windows without a reboot")
else:
    h0 = min(num(r, "heap_used") for r in first)
    h1 = min(num(r, "heap_used") for r in last)
    allow = h0 * 0.05 + 256 * 1024
    ok = h1 - h0 <= allow
    (notes if ok else fails).append(f"heap: lowest use {h0 >> 10} KiB -> {h1 >> 10} KiB (allowed +{int(allow) >> 10} KiB)")
    p0 = max(num(r, "pool_free") for r in first)
    p1 = max(num(r, "pool_free") for r in last)
    ok = p0 - p1 <= max(1, p0 // 100)
    (notes if ok else fails).append(f"pool: highest free {p0} -> {p1} of {run[-1]['pool_cap']}")
temps = [num(r, "temp_mc") for r in rows if num(r, "temp_mc") is not None]
notes.append(
    f"samples {len(rows)} (missed {missed}) over {span_h:.1f} h; forwarded {fwd}; "
    f"pool alloc failures +{delta('pool_fail')}; early drops +{delta('early_drops')}; "
    f"connections max {max(num(r, 'conntrack') for r in rows)}; "
    f"conntrack pass max {max(num(r, 'pass_us_max') for r in rows)} us"
    + (f"; CPU max {max(temps) / 1000:.1f} °C" if temps else "")
)
for n in notes:
    print("  " + n)
for f in fails:
    print("  FAIL " + f)
invalid = []
if span_h < 0.9 * hours:
    invalid.append(f"covered {span_h:.1f} h of {hours:g} h")
if fwd < min_fwd:
    invalid.append(f"forwarded {fwd} < {min_fwd} packets (no load)")
if not leak_checked:
    invalid.append("no leak check")
if fails:
    print("SOAK: FAIL"); sys.exit(1)
if invalid:
    print("SOAK: INVALID: " + "; ".join(invalid)); sys.exit(3)
print("SOAK: PASS"); sys.exit(0)
PY
}

if [[ -n "$REPORT" ]]; then
  [[ -f "$REPORT" ]] || { echo "no such file: $REPORT" >&2; exit 2; }
  report "$REPORT"
  exit $?
fi

[[ -n "$HOST" ]] || { echo "no router: --host ADDR or LEATOS_HOST" >&2; exit 2; }
if [[ -z "$PASS" && -f target/apu4/mgmt-pass ]]; then PASS="$(cat target/apu4/mgmt-pass)"; fi
AUTH=()
[[ -n "$PASS" ]] && AUTH=(-u "admin:$PASS")
[[ -n "$LABEL" ]] || LABEL="$HOST-$(date +%Y%m%d-%H%M)"
mkdir -p lab/cache
CSV="lab/cache/soak-$LABEL.csv"
[[ -e "$CSV" ]] && { echo "$CSV exists: pick another --label" >&2; exit 2; }
echo "ts,uptime_s,build,heap_used,heap_free,pool_free,pool_cap,pool_fail,conntrack,early_drops,forwarded,dropped,pass_us_max,temp_mc,hk_us_max,heap_live,alloc_n,alloc_avg_ns,alloc_max_ns,dealloc_n,dealloc_avg_ns,dealloc_max_ns,dns_cached,neigh_drops,neigh_probes,local_dropped" >"$CSV"

sample() {
  local now json
  now="$(date +%s)"
  json="$(curl -s -m 10 ${AUTH[@]+"${AUTH[@]}"} "http://$HOST/api/status" 2>/dev/null || true)"
  printf '%s' "$json" | python3 -I -c '
import json, sys
now = sys.argv[1]
try:
    d = json.load(sys.stdin)
    t = d.get("temp") or {}
    v = [d["uptime_s"], d["build"], d["heap"]["used"], d["heap"]["free"], d["pool"]["free"],
         d["pool"]["capacity"], d["pool"]["alloc_failures"], d["conntrack"], d.get("early_drops", 0),
         d["forwarded"], d["dropped"], (d.get("conntrack_pass_us") or {}).get("max", 0), t.get("cpu_mc", "")]
    h = d["heap"]
    a, f = h.get("alloc") or {}, h.get("dealloc") or {}
    v += [(d.get("housekeeping_us") or {}).get("max", ""), h.get("live", ""),
          a.get("count", ""), a.get("avg_ns", ""), a.get("max_ns", ""),
          f.get("count", ""), f.get("avg_ns", ""), f.get("max_ns", ""),
          (d.get("dns") or {}).get("cached", "")]
    v += [(d.get("drop_reasons") or {}).get("neighbor", ""), d.get("neigh_probes", ""),
          (d.get("lan_nd") or {}).get("local_dropped", "")]
    print(",".join([now] + ["%s" % x for x in v]))
except Exception:
    print(now + "," * 25)
' "$now" >>"$CSV"
}

finish() {
  trap - INT TERM
  echo
  echo "soak: $CSV"
  set +e
  report "$CSV"
  exit $?
}
trap finish INT TERM

END=$(awk -v now="$(date +%s)" -v h="$HOURS" 'BEGIN { printf "%d", now + h * 3600 }')
echo "soak: $HOST for $HOURS h, every $INTERVAL s -> $CSV (Ctrl-C for the report so far)"
while [[ $(date +%s) -lt $END ]]; do
  sample
  tail -1 "$CSV" | awk -F, '$2 == "" { print "  no answer"; next }
    { printf "  up %ds  heap %d KiB  pool %d/%d  conns %d  dns %s  fwd %d\n", $2, $4 / 1024, $6, $7, $9, $23, $11 }'
  sleep "$INTERVAL" &
  wait $! || true
done
finish
