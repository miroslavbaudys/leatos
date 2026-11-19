#!/usr/bin/env bash
# End-to-end test of the persistent store (docs/config-and-storage.md):
# virtio-blk disk with a store partition (made by tools/rrstore), config
# read at boot, saved through the management interface, used after a
# reboot.
#
#   scripts/store-test.sh                       # aarch64 (HVF on Apple Silicon)
#   RROUTER_ARCH=x86_64 scripts/store-test.sh   # x86_64 (TCG)
#   LAB_VERBOSE=1 ...                           # print the router consoles
#   QEMU_STORE_BUS=sd ...                       # store on an SD card (sdhci-pci)
#   STORE_MIB=2048 ...                          # image size; QEMU's SD card is
#                                               # SDHC (block addressing) above 1 GiB
#
# Boot-time reads (each a control for the others):
#   empty store -> defaults; stored config -> used; stored config that does
#   not validate -> defaults; config=defaults -> store ignored.
# Save (WAN on user networking, mgmt=wan, host port forwarded to :80):
#   GET /api/info is public; status and config reads need the password
#   (401 without, as a token-less page gets); GET /api/config (TOML) and
#   /api/config.json; POST without password -> 401; invalid TOML -> 422, inconsistent config -> 422 naming the field,
#   both leave the store unchanged; a change without a trial (JSON, as the
#   page sends it) -> saved and applied live, no reboot: shaper rate, qdisc
#   rebuild, DHCP/DNS reconfigured; a rate-only change keeps the queue.
# Trials (LAN address changes; trial_secs=20):
#   saved as a trial -> boots as one; saving again -> 409; confirm without
#   password -> 401; confirm -> kept across a reboot. Controls: no confirm
#   -> reverted after the timeout; "revert now" -> reverted; router killed
#   during the trial -> the next boot reverts it.
# Negative controls for the store: corrupt the newest record -> the router
#   falls back to the previous one; corrupt both -> defaults.
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH="${RROUTER_ARCH:-aarch64}"
case "$ARCH" in aarch64 | x86_64) ;; *) echo "RROUTER_ARCH must be aarch64 or x86_64" >&2; exit 2 ;; esac
TARGET="$ARCH-unknown-none"
PORT="${STORE_TEST_PORT:-18081}"
URL="http://127.0.0.1:$PORT"
WORK="$(mktemp -d -t rrouter-store.XXXXXX)"
IMG="$WORK/store.img"
# Power of two: QEMU's SD card needs it.
STORE_MIB="${STORE_MIB:-32}"
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
CFG_LINE='  config          : .*, lan '
config_line() { grep -a -- "$CFG_LINE" "$LOG" | sed -n "${1}p" | sed 's/^ *config *: //' | tr -d '\r'; }
count() { grep -ac -- "$1" "$LOG" || true; }

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
  wait_for 1 "$CFG_LINE" 90 || true
  config_line 1
  stop
}

echo "== boot-time reads ($ARCH, ${QEMU_STORE_BUS:-virtio}, $STORE_MIB MiB)"
"$RRSTORE" create "$IMG" --mib "$STORE_MIB" >/dev/null
r="$(boot_config empty "")"
check "empty store -> defaults" "defaults (store has no valid config)" "${r%%,*}"

printf 'version = 2\n\n[[network]]\nname = "lan"\nipv4 = "10.20.0.1/24"\n' >"$WORK/a.toml"
"$RRSTORE" put "$IMG" config "$WORK/a.toml" >/dev/null
r="$(boot_config stored "")"
check "stored config used" "stored (slot A, seq 1), lan 10.20.0.1/24" "${r%%, dhcp*}"
r="$(boot_config ignored "config=defaults")"
check "config=defaults ignores the store" "defaults (config=defaults: store ignored)" "${r%%,*}"

"$RRSTORE" create "$IMG" --mib "$STORE_MIB" >/dev/null
printf 'version = 2\nbogus = 1\n' >"$WORK/bad.toml"
"$RRSTORE" put "$IMG" config "$WORK/bad.toml" --raw >/dev/null
r="$(boot_config rejected "")"
check "stored config that does not validate -> defaults" "defaults (stored config slot A rejected" "${r%%:*}"

# Schema version 1 ([lan]) is no longer read: such a record is rejected.
"$RRSTORE" create "$IMG" --mib "$STORE_MIB" >/dev/null
printf 'version = 1\n\n[lan]\nipv4 = "10.20.0.1/24"\n' >"$WORK/v1.toml"
"$RRSTORE" put "$IMG" config "$WORK/v1.toml" --raw --version 1 >/dev/null
r="$(boot_config v1 "")"
check "stored version 1 config -> defaults" "defaults (stored config slot A rejected" "${r%%:*}"

echo "== save through the management interface"
"$RRSTORE" create "$IMG" --mib "$STORE_MIB" >/dev/null
"$RRSTORE" put "$IMG" config "$WORK/a.toml" >/dev/null # A, seq 1: lan 10.20.0.1/24
boot save "mgmt=wan mgmt_pass=test trial_secs=20" QEMU_NET=user QEMU_WAN_HOSTFWD="tcp:127.0.0.1:$PORT-:80"
BOOTS=1
# Wait for boot number $1 to come up with a WAN lease (the API answers).
up() {
  wait_for "$1" "$CFG_LINE" 120 && wait_for "$1" "dhcp lease" 120
}
up 1 || { echo "  [FAIL] router did not get a WAN lease"; stop; exit 1; }
code() { curl -s -m 20 -o "$WORK/resp" -w '%{http_code}' "$@" || true; }
json() { python3 -I -c 'import json,sys
v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v=v[k] if not isinstance(v,list) else v[int(k)]
print(json.dumps(v) if isinstance(v,(dict,list,bool)) or v is None else v)' "$@" 2>/dev/null || true; }
AUTH=admin:test # reads need the password too (the one of the running boot)
status() { curl -s -m 10 -u "$AUTH" -o "$WORK/status" "$URL/api/status" || true; json "$WORK/status" "$1"; }
slot() { "$RRSTORE" get "$IMG" config 2>&1 >/dev/null | sed -n 's/.*slot \([AB]\), seq \([0-9]*\), version [0-9]*, flags \([0-9]*\).*/\1 \2 \3/p'; }
save_toml() { code -u admin:test -X POST -H 'Content-Type: application/toml' --data-binary @"$1" "$URL/api/config"; }
lan_toml() { printf 'version = 2\n\n[[network]]\nname = "lan"\nipv4 = "%s"\n\n[[network.dhcp.static]]\nmac = "52:54:00:00:00:07"\nip = "%s"\nhostname = "printer"\n' "$1/24" "${1%.1}.7" >"$WORK/lan.toml"; }

check "GET /api/info is public: a password exists" '{"auth":true}' "$(curl -s -m 10 "$URL/api/info" || true)"
check "reads without password -> 401 (status, config, config.json, effective.json)" "401 401 401 401" \
  "$(code "$URL/api/status") $(code "$URL/api/config") $(code "$URL/api/config.json") $(code "$URL/api/config/effective.json")"
check "  ... with a made-up token -> 401" 401 "$(code -H "Authorization: Bearer 0123456789abcdef0123456789abcdef" "$URL/api/status")"
check "GET /api/config shows the stored LAN" 1 "$(curl -s -m 10 -u "$AUTH" "$URL/api/config" | grep -c '^ipv4 = "10.20.0.1/24"' || true)"
curl -s -m 10 -u "$AUTH" -o "$WORK/cfg.json" "$URL/api/config.json" || true
check "GET /api/config.json shows the stored LAN (schema v2)" "10.20.0.1/24" "$(json "$WORK/cfg.json" network.0.ipv4)"
check "status reports the config source" "stored (slot A, seq 1)" "$(status config)"
check "status: no trial" "null" "$(json "$WORK/status" trial)"
check "status lists the boot-argument overrides (mgmt=wan only)" '{"mgmt.on_wan": "mgmt=wan"}' "$(json "$WORK/status" overrides)"
curl -s -m 10 -u "$AUTH" -o "$WORK/eff.json" "$URL/api/config/effective.json" || true
check "effective config = stored + boot arguments (on_wan from mgmt=wan)" "10.20.0.1/24 true false" \
  "$(json "$WORK/eff.json" network.0.ipv4) $(json "$WORK/eff.json" mgmt.on_wan) $(json "$WORK/cfg.json" mgmt.on_wan)"
lan_toml 10.30.0.1
check "save without password -> 401" 401 "$(code -X POST --data-binary @"$WORK/lan.toml" "$URL/api/config")"
check "invalid TOML -> 422" 422 "$(save_toml "$WORK/bad.toml")"
printf 'version = 2\n\n[[network]]\nname = "lan"\nipv4 = "10.30.0.1/24"\n\n[network.dhcp]\nrange = ["10.40.0.100", "10.40.0.199"]\n' >"$WORK/incons.toml"
check "inconsistent config -> 422" 422 "$(save_toml "$WORK/incons.toml")"
check "422 names the field" "network.lan.dhcp.range" "$(json "$WORK/resp" issues.0.path | cut -d'[' -f1)"
# Valid, but beyond what this kernel implements (a network on another
# port, lan1: no bridge yet): refused.
python3 -I -c 'import json,sys
c=json.load(open(sys.argv[1]))
c["network"][0]["ports"]=["lan1"]
open(sys.argv[2],"w").write(json.dumps(c))' "$WORK/cfg.json" "$WORK/v2.json"
check "unsupported setting (network on lan1) -> 422" 422 "$(code -u admin:test -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/v2.json" "$URL/api/config")"
check "  ... names it" "network.lan.ports" "$(json "$WORK/resp" issues.0.path)"
check "refused saves left the store unchanged" "A 1 0" "$(slot)"

# A change without a trial, sent as JSON the way the page does: saved and
# applied live, no reboot (DHCP reservation, DNS cache, shaping, qdisc).
python3 -I -c 'import json,sys
c=json.load(open(sys.argv[1])); c["dns"]["cache_entries"]=1000
c["network"][0]["dhcp"]["static"]=[{"mac":"52:54:00:00:00:08","ip":"10.20.0.8","hostname":"tv"}]
c["shaping"]["down_kbit"]=50000; c["shaping"]["qdisc"]="fq_codel"
open(sys.argv[2],"w").write(json.dumps(c))' "$WORK/cfg.json" "$WORK/new.json"
status uptime_s >/dev/null; up0="$(json "$WORK/status" uptime_s)"
check "JSON save -> 200" 200 "$(code -u admin:test -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/new.json" "$URL/api/config")"
check "JSON save: no trial, applied live" "false true" "$(json "$WORK/resp" trial) $(json "$WORK/resp" applied)"
sleep 3
check "no reboot (same boot, uptime went on)" "1 1" "$(count "$CFG_LINE") $([[ "$(status uptime_s)" -ge "$up0" ]] && echo 1 || echo 0)"
check "status: new config source" "stored (slot B, seq 2)" "$(status config)"
check "download shaper (WAN ingress) changed live" 50000 "$(json "$WORK/status" ingress.shaped_kbit)"
check "  ... upload shaper untouched, lan0 unshaped" "null null" "$(json "$WORK/status" interfaces.0.qdisc.shaped_kbit) $(json "$WORK/status" interfaces.1.qdisc.shaped_kbit)"
check "qdisc rebuilt as FQ-CoDel" "1 1" "$(count 'qos ingress    : now shaped 50000 kbit/s (download), overhead 0 B, FQ-CoDel') $(count 'qos lan0       : now unshaped, FQ-CoDel')"
check "DHCP and DNS reconfigured (1 reservation, cache 1000)" 1 "$(count 'lan services    : reconfigured: .*(1 static, 0 lease(s) dropped).*cache 1000')"
curl -s -m 10 -u "$AUTH" -o "$WORK/cfg.json" "$URL/api/config.json" || true
check "saved values read back" "1000 tv" "$(json "$WORK/cfg.json" dns.cache_entries) $(json "$WORK/cfg.json" network.0.dhcp.static.0.hostname)"
check "no trial after a harmless save" "0 null" "$(count 'config          : trial (') $(status trial)"
check "kernel stored canonical TOML (defaults written out)" 1 "$("$RRSTORE" get "$IMG" config 2>/dev/null | grep -c '^cache_entries = 1000' || true)"
# Always schema version 2, header and text (docs/config-v2.md §5).
check "  ... as version 2 (header and text)" "1 1 1" "$("$RRSTORE" show "$IMG" 2>/dev/null | grep -c 'seq 2 version 2 ' || true) $("$RRSTORE" get "$IMG" config 2>/dev/null | grep -c -e '^version = 2$' || true) $("$RRSTORE" get "$IMG" config 2>/dev/null | grep -c '^\[\[network\]\]$' || true)"
# Rate only: the queue is kept.
python3 -I -c 'import json,sys
c=json.load(open(sys.argv[1])); c["shaping"]["down_kbit"]=60000
open(sys.argv[1],"w").write(json.dumps(c))' "$WORK/cfg.json"
check "rate-only change -> 200, applied" "200 true" "$(code -u admin:test -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/cfg.json" "$URL/api/config") $(json "$WORK/resp" applied)"
check "  ... queue kept, new rate" "1 60000" "$(count 'qos ingress    : now shaped 60000 kbit/s (download), overhead 0 B, queue kept') $(status ingress.shaped_kbit)"

echo "== trials"
check "LAN change -> 200" 200 "$(save_toml "$WORK/lan.toml")"
check "LAN change is saved as a trial" "true 20 10.30.0.1" "$(json "$WORK/resp" trial) $(json "$WORK/resp" confirm_within_s) $(json "$WORK/resp" lan)"
up 2 || true
check "boots the trial" 1 "$(count 'config          : trial (slot B, seq 4)')"
check "rebooted into the trial config" "stored (slot B, seq 4), lan 10.30.0.1/24" "$(config_line 2 | sed 's/, dhcp.*//')"
check "status shows the trial" 4 "$(status trial.seq)"
check "store marks it booted" "B 4 3" "$(slot)"
check "save during a trial -> 409" 409 "$(save_toml "$WORK/a.toml")"
check "confirm without password -> 401" 401 "$(code -X POST "$URL/api/config/confirm")"
check "confirm -> 200" 200 "$(code -u admin:test -X POST "$URL/api/config/confirm")"
check "confirmed: no trial, flags cleared" "null B 4 0" "$(status trial) $(slot)"
check "confirm again -> 409" 409 "$(code -u admin:test -X POST "$URL/api/config/confirm")"
check "reboot -> 200" 200 "$(code -u admin:test -X POST "$URL/api/reboot")"
up 3 || true
check "confirmed config kept across a reboot" "stored (slot B, seq 4), lan 10.30.0.1/24" "$(config_line 3 | sed 's/, dhcp.*//')"
check "  ... and not as a trial" "1 null" "$(count 'config          : trial (') $(status trial)"

lan_toml 10.40.0.1
check "control, no confirm: trial saved" "200 true" "$(save_toml "$WORK/lan.toml") $(json "$WORK/resp" trial)"
up 4 || true
check "  ... boots as a trial" "stored (slot A, seq 5), lan 10.40.0.1/24" "$(config_line 4 | sed 's/, dhcp.*//')"
ok=0; wait_for 1 "not confirmed within 20 s: reverting" 40 && ok=1
check "  ... reverted after 20 s" 1 "$ok"
up 5 || true
check "  ... back on the confirmed config" "stored (slot B, seq 4), lan 10.30.0.1/24" "$(config_line 5 | sed 's/, dhcp.*//')"
check "  ... trial record erased" 1 "$("$RRSTORE" show "$IMG" | grep '^  config' | grep -c 'A: empty' || true)"

lan_toml 10.50.0.1
check "control, revert now: trial saved" 200 "$(save_toml "$WORK/lan.toml")"
up 6 || true
check "  ... boots as a trial" "stored (slot A, seq 5), lan 10.50.0.1/24" "$(config_line 6 | sed 's/, dhcp.*//')"
check "  ... revert -> 200" 200 "$(code -u admin:test -X POST "$URL/api/config/revert")"
up 7 || true
check "  ... back on the confirmed config" "stored (slot B, seq 4), lan 10.30.0.1/24" "$(config_line 7 | sed 's/, dhcp.*//')"

lan_toml 10.60.0.1
check "control, killed during the trial: trial saved" 200 "$(save_toml "$WORK/lan.toml")"
wait_for 8 "$CFG_LINE" 120 || true
check "  ... boots as a trial" "stored (slot A, seq 5), lan 10.60.0.1/24" "$(config_line 8 | sed 's/, dhcp.*//')"
stop
r="$(boot_config killed "")"
check "  ... next boot reverts it" "stored (slot B, seq 4, trial seq 5 reverted), lan 10.30.0.1/24" "${r%%, dhcp*}"
check "  ... trial record erased" "B 4 0" "$(slot)"

echo "== negative controls"
"$RRSTORE" put "$IMG" config "$WORK/a.toml" >/dev/null # A, seq 5: lan 10.20.0.1/24
"$RRSTORE" corrupt "$IMG" config --slot A >/dev/null
r="$(boot_config fallback "")"
check "newest record corrupt -> previous record" "stored (slot B, seq 4), lan 10.30.0.1/24" "${r%%, dhcp*}"
"$RRSTORE" corrupt "$IMG" config --slot B >/dev/null
r="$(boot_config both "")"
check "both records corrupt -> defaults" "defaults (store has no valid config)" "${r%%,*}"

echo "== networks change live (docs/config-v2.md §7)"
"$RRSTORE" create "$IMG" --mib "$STORE_MIB" >/dev/null
boot net "mgmt=wan mgmt_pass=test" QEMU_NET=user QEMU_WAN_HOSTFWD="tcp:127.0.0.1:$PORT-:80"
up 1 || true
curl -s -m 10 -u "$AUTH" -o "$WORK/cfg.json" "$URL/api/config.json" || true
python3 -I -c 'import json,sys
c=json.load(open(sys.argv[1]))
c["network"].append({"name":"guest","vlan":20,"ipv4":"10.20.0.1/24","zone":"guest"})
c["zone"]=[{"name":"guest","input":"drop","allow":["dhcp","dns"]}]
open(sys.argv[2],"w").write(json.dumps(c))' "$WORK/cfg.json" "$WORK/net.json"
check "network added -> 200, live: no reboot, no trial" "200 true false false" "$(code -u admin:test -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/net.json" "$URL/api/config") $(json "$WORK/resp" applied) $(json "$WORK/resp" reboot) $(json "$WORK/resp" trial)"
check "  ... stored as version 2" "1 1" "$("$RRSTORE" show "$IMG" 2>/dev/null | grep -c 'seq 1 version 2 ' || true) $("$RRSTORE" get "$IMG" config 2>/dev/null | grep -c -e '^version = 2$' || true)"
sleep 1
check "  ... in effect, same boot" "lan guest 20 guest 1" "$(status networks.0.name) $(status networks.1.name) $(status networks.1.vlan) $(status networks.1.zone) $(count "$CFG_LINE")"
check "  ... guest network up on VLAN 20, with services" "1 1" "$(count 'net lan0       : guest 10.20.0.1/24 (vlan 20, zone 2)') $(count 'lan services    : guest: dhcp 10.20.0.100')"
# Changed live too: another VLAN, then gone again.
python3 -I -c 'import json,sys
c=json.load(open(sys.argv[1])); c["network"][1]["vlan"]=30
open(sys.argv[2],"w").write(json.dumps(c))' "$WORK/net.json" "$WORK/net30.json"
check "  ... VLAN 20 -> 30, live" "200 false 30" "$(code -u admin:test -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/net30.json" "$URL/api/config") $(json "$WORK/resp" reboot) $(sleep 1; status networks.1.vlan)"
check "  ... removed again, live" "200 false 1 1" "$(code -u admin:test -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/cfg.json" "$URL/api/config") $(json "$WORK/resp" reboot) $(sleep 1; status networks | python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)))') $(count 'lan services    : guest: removed')"
# Back to the two networks for the rule checks below.
code -u admin:test -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/net.json" "$URL/api/config" >/dev/null
# A forwarding rule applies live (no reboot, no trial); the status lists it.
curl -s -m 10 -u "$AUTH" -o "$WORK/cfg.json" "$URL/api/config.json" || true
python3 -I -c 'import json,sys
c=json.load(open(sys.argv[1]))
c["firewall"]={"rule":[{"name":"no-smtp","from":"lan","to":"wan","proto":"tcp","dst_port":25,"action":"drop"}],
  "forward":[{"name":"nas","wan_port":8443,"to":"10.20.0.10:443"}]}
open(sys.argv[2],"w").write(json.dumps(c))' "$WORK/cfg.json" "$WORK/rule.json"
check "rule + port forward added -> 200, applied live" "200 true false" "$(code -u admin:test -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/rule.json" "$URL/api/config") $(json "$WORK/resp" applied) $(json "$WORK/resp" reboot)"
check "  ... in effect (status), still the same boot" "no-smtp 0 nas 0 1" "$(status rules.0.name) $(status rules.0.hits) $(status forwards.0.name) $(status forwards.0.hits) $(count "$CFG_LINE")"
stop

echo "== management password in the config, login sessions"
"$RRSTORE" create "$IMG" --mib "$STORE_MIB" >/dev/null
printf 'version = 2\n\n[mgmt]\non_wan = true\npassword_hash = "%s"\n' "$("$RRSTORE" hash 's3cret-pass')" >"$WORK/pw.toml"
"$RRSTORE" put "$IMG" config "$WORK/pw.toml" >/dev/null
boot pw "" QEMU_NET=user QEMU_WAN_HOSTFWD="tcp:127.0.0.1:$PORT-:80"   # no mgmt_pass=
up 1 || true
AUTH=admin:s3cret-pass
check "reads without password -> 401 (password from the config)" "401 200" "$(code "$URL/api/status") $(code -u "$AUTH" "$URL/api/status")"
check "password from the config" "true config" "$(status mgmt.auth) $(status mgmt.password)"
check "wrong password -> 401" 401 "$(code -u admin:wrong -X POST "$URL/api/login")"
check "  ... the right one at once -> 429 (one try per second)" 429 "$(code -u admin:s3cret-pass -X POST "$URL/api/login")"
sleep 1.2
check "right password -> 200" 200 "$(code -u admin:s3cret-pass -X POST "$URL/api/login")"
TOKEN="$(json "$WORK/resp" token)"
check "  ... with a 32-digit token" 32 "${#TOKEN}"
curl -s -m 10 -u "$AUTH" -o "$WORK/cfg.json" "$URL/api/config.json" || true
check "the hash is never shown" 0 "$(grep -c pbkdf2 "$WORK/cfg.json" || true)"
check "save with the token -> 200" 200 "$(code -H "Authorization: Bearer $TOKEN" -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/cfg.json" "$URL/api/config")"
check "  ... the hash is kept" 1 "$("$RRSTORE" get "$IMG" config 2>/dev/null | grep -c '^password_hash = "pbkdf2-sha256' || true)"
check "a made-up token -> 401" 401 "$(code -H "Authorization: Bearer 0123456789abcdef0123456789abcdef" -X POST "$URL/api/reboot")"
python3 -I -c 'import json,sys
c=json.load(open(sys.argv[1])); c["mgmt"]["password"]="n3w-password"
open(sys.argv[2],"w").write(json.dumps(c))' "$WORK/cfg.json" "$WORK/pw.json"
check "password change -> 200, live" "200 true" "$(code -H "Authorization: Bearer $TOKEN" -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/pw.json" "$URL/api/config") $(json "$WORK/resp" applied)"
check "  ... the session ends" 401 "$(code -H "Authorization: Bearer $TOKEN" -X POST "$URL/api/login")"
check "  ... stored as a hash only" "1 0" "$("$RRSTORE" get "$IMG" config 2>/dev/null | grep -c '^password_hash = "pbkdf2-sha256' || true) $("$RRSTORE" get "$IMG" config 2>/dev/null | grep -c 'n3w-password' || true)"
check "  ... the new password works" 200 "$(code -u admin:n3w-password -X POST "$URL/api/login")"
AUTH=admin:n3w-password
TOKEN="$(json "$WORK/resp" token)"
check "  ... the old one not" 401 "$(code -u admin:s3cret-pass -X POST "$URL/api/login")"
check "logout ends the session" "200 401" "$(code -H "Authorization: Bearer $TOKEN" -X POST "$URL/api/logout") $(code -H "Authorization: Bearer $TOKEN" -X POST "$URL/api/login")"
stop
"$RRSTORE" create "$IMG" --mib "$STORE_MIB" >/dev/null
boot nopw "mgmt=wan" QEMU_NET=user QEMU_WAN_HOSTFWD="tcp:127.0.0.1:$PORT-:80"
up 1 || true
check "control, no password anywhere: login refused" "403 false none" "$(code -u admin:anything -X POST "$URL/api/login") $(status mgmt.auth) $(status mgmt.password)"
check "  ... reads are public then (info, status, config.json)" '{"auth":false} 200 200' "$(curl -s -m 10 "$URL/api/info" || true) $(code "$URL/api/status") $(code "$URL/api/config.json")"
stop

WHAT="$ARCH, ${QEMU_STORE_BUS:-virtio}, $STORE_MIB MiB"
if [[ "$FAILED" == 0 ]]; then echo "STORE TEST ($WHAT): PASS"; else echo "STORE TEST ($WHAT): FAIL"; exit 1; fi
