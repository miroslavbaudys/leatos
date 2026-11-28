#!/usr/bin/env bash
# The installer end to end (docs/install.md): build the installer ISO
# (scripts/apu-image.sh --iso, seeded with a config), boot it in QEMU q35
# as a CD (as Proxmox attaches it) with a target disk, answer its prompt
# on the serial console, and check the target. x86_64 only (SeaBIOS +
# Limine), TCG on Apple Silicon.
#
#   scripts/install-test.sh
#   QEMU_STORE_BUS=sd scripts/install-test.sh    # the target is an SD card
#   QEMU_STORE_BUS=ahci scripts/install-test.sh  # a SATA disk (Proxmox sata0, apu4 mSATA)
#   INSTALL_TEST_VERBOSE=1 ...                   # print each console
#
# Cases (each negative control must leave the target unchanged):
#   fresh       target full of 0xff: installed and verified, the image's
#               config stored, the image's gaps zero, sectors past it
#               untouched, the last 33 (backup GPT) zero; it boots
#   wrong       a disk that was not listed is typed: nothing written
#   twice       the same ISO onto a second disk of the same machine: refused
#               (both would carry one store ID, docs/install.md §3.5)
#   keep        target with another config and a stale leases record:
#               that config carried over, the stale record gone
#   trial       the target's config is an unconfirmed trial: nothing written
#   unattended  install_target= + install_keep=0: no prompt, the image's
#               config wins over the target's
#   corrupt     one byte of the ISO's install image flipped: nothing written
#   stick       the ISO booted as a disk (a USB stick dd'ed from it; on q35
#               that disk is on the built-in AHCI controller, so leatos sees
#               it): the installer runs and does not offer its own medium
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C

T=180 # seconds for one installer run (TCG, debug kernel)
WORK="$(mktemp -d -t leatos-install.XXXXXX)"
TGT="$WORK/target.img"
LOG="$WORK/console.log"
FIFO="$WORK/stdin"
QPID=
stop_qemu() {
  exec 3>&- 2>/dev/null || true
  if [[ -n "$QPID" ]]; then kill "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; fi
  QPID=
  if [[ "${INSTALL_TEST_VERBOSE:-0}" == 1 && -f "$LOG" ]]; then tr -d '\r' <"$LOG" | sed 's/^/  | /'; fi
}
cleanup() { stop_qemu; rm -rf "$WORK"; }
trap cleanup EXIT
FAILED=0
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=1; }
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}
has() { tr -d '\r' <"$LOG" | grep -aq -- "$1"; }
wait_for() { # pattern seconds
  local i
  for i in $(seq 1 $(($2 * 5))); do
    has "$1" && return 0
    if [[ -n "$QPID" ]] && ! kill -0 "$QPID" 2>/dev/null; then return 1; fi
    sleep 0.2
  done
  return 1
}
LEATSTORE=target/release/leatstore
sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
cfg_ip() { "$LEATSTORE" get "$TGT" config 2>/dev/null | sed -n 's/^ipv4 = "\(.*\)"$/\1/p' | head -1; }

# boot ISO: the installer on the target; the console in $LOG, input on fd 3.
boot() {
  rm -f "$LOG" "$FIFO"
  mkfifo "$FIFO"
  QEMU_CDROM="$1" QEMU_STORE="$TGT" QEMU_ACCEL=tcg scripts/qemu-run.sh <"$FIFO" >"$LOG" 2>&1 &
  QPID=$!
  exec 3>"$FIFO"
}
# run ISO ANSWER: boot, answer the prompt (if ANSWER is set), wait for the
# installer's last word.
run() {
  boot "$1"
  if [[ -n "$2" ]]; then
    wait_for "type the PCI address" "$T" || { fail "installer prompt"; stop_qemu; return; }
    sleep 0.5
    printf '%s\r' "$2" >&3
  fi
  wait_for 'install: done\|nothing written\|install: FAILED' "$T" || fail "installer finished"
  stop_qemu
}

printf 'version = 2\n\n[[network]]\nname = "lan"\nipv4 = "%s"\n' 10.31.0.1/24 >"$WORK/a.toml"
printf 'version = 2\n\n[[network]]\nname = "lan"\nipv4 = "%s"\n' 10.32.0.1/24 >"$WORK/b.toml"
printf 'version = 2\n\n[[network]]\nname = "lan"\nipv4 = "%s"\n' 10.33.0.1/24 >"$WORK/c.toml"
cargo build -p leatstore --release --quiet
scripts/apu-image.sh --debug --iso --config "$WORK/a.toml" --out "$WORK/install.iso" 2>/dev/null
IMG_SECTORS=$((80 << 11))
TGT_SECTORS=$((128 << 11))

echo "== fresh"
# 0xff everywhere: every sector the installer leaves alone stays 0xff.
dd if=/dev/zero bs=1048576 count=128 2>/dev/null | tr '\000' '\377' >"$TGT"
check "target prepared" "$((TGT_SECTORS * 512))" "$(wc -c <"$TGT" | tr -d ' ')"
boot "$WORK/install.iso"
wait_for "type the PCI address" "$T" || fail "installer prompt"
# The target's PCI address, as the installer lists it.
# (An ATAPI CD on the same controller is listed as "not used": skipped.)
DF="$(tr -d '\r' <"$LOG" | grep -a ' MiB' | grep -av 'not offered' \
  | sed -n 's/^  \([0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]\.[0-7]\(\/[0-9]*\)\{0,1\}\)  .*/\1/p' | head -1)"
[[ -n "$DF" ]] && pass "target listed ($DF)" || fail "target listed"
printf '%s\r' "$DF" >&3
wait_for 'install: done\|nothing written\|install: FAILED' "$T" || true
if has "MiB written and verified"; then pass "written and verified"; else fail "written and verified"; fi
if has "install: done"; then pass "installer done"; else fail "installer done"; fi
if has "config: none to keep"; then pass "blank target: no config to keep"; else fail "blank target: no config to keep"; fi
stop_qemu
check "image's config stored" "10.31.0.1/24" "$(cfg_ip)"
sector_bytes() { dd if="$TGT" bs=512 skip="$1" count="$2" 2>/dev/null | od -An -tx1 -v | tr -s ' \n' '\n\n' | sort -u | tr -d '\n'; }
check "a gap in the image is zero (store slot area)" "00" "$(sector_bytes $(((64 << 11) + 2048 + 600)) 8)"
check "sectors past the image untouched" "ff" "$(sector_bytes "$IMG_SECTORS" 8)"
check "sector before the GPT backup untouched" "ff" "$(sector_bytes $((TGT_SECTORS - 34)) 1)"
check "last 33 sectors zero (backup GPT)" "00" "$(sector_bytes $((TGT_SECTORS - 33)) 33)"
# The installed disk boots (SeaBIOS -> its own Limine) and uses its store;
# SeaBIOS boots no SD card, so virtio and ahci only. On a copy: booting writes.
if [[ "${QEMU_STORE_BUS:-virtio}" != sd ]]; then
  cp "$TGT" "$WORK/boot.img"
  QEMU_DISK=store QEMU_STORE="$WORK/boot.img" QEMU_ACCEL=tcg scripts/qemu-run.sh </dev/null >"$LOG" 2>&1 &
  QPID=$!
  if wait_for "store config" "$T"; then pass "installed disk boots"; else fail "installed disk boots"; fi
  sleep 2
  if has "10.31.0.1"; then pass "installed disk uses the image's config"; else fail "installed disk uses the image's config"; fi
  if has "(store_id=$("$LEATSTORE" id "$TGT"))"; then pass "  ... chosen by its store_id="; else fail "  ... chosen by its store_id="; fi
  stop_qemu
  rm -f "$WORK/boot.img"
fi

echo "== wrong (negative control)"
before="$(sum "$TGT")"
run "$WORK/install.iso" "99:99.9"
if has "'99:99.9' is not one of the disks listed: nothing written"; then pass "refused"; else fail "refused"; fi
check "target unchanged" "$before" "$(sum "$TGT")"

echo "== twice (negative control)"
# A blank second disk (64 MiB, virtio) next to the installed one.
SECOND="$WORK/second.img"
dd if=/dev/zero of="$SECOND" bs=1048576 count=64 2>/dev/null
before="$(sum "$TGT") $(sum "$SECOND")"
rm -f "$LOG" "$FIFO"; mkfifo "$FIFO"
QEMU_CDROM="$WORK/install.iso" QEMU_STORE="$TGT" QEMU_ACCEL=tcg \
  QEMU_EXTRA="-drive file=$SECOND,format=raw,if=none,id=second -device virtio-blk-pci,drive=second" \
  scripts/qemu-run.sh <"$FIFO" >"$LOG" 2>&1 &
QPID=$!
exec 3>"$FIFO"
wait_for "type the PCI address" "$T" || fail "installer prompt"
DF2="$(tr -d '\r' <"$LOG" | grep -a 'virtio-blk 64 MiB' | sed -n 's/^  \([0-9a-f:.]*\)  .*/\1/p' | head -1)"
[[ -n "$DF2" ]] && pass "second disk listed ($DF2)" || fail "second disk listed"
printf '%s\r' "$DF2" >&3
wait_for 'install: done\|nothing written\|install: FAILED' "$T" || true
stop_qemu
if has "already holds a store with this image's ID.*nothing written"; then pass "refused"; else fail "refused"; fi
check "both disks unchanged" "$before" "$(sum "$TGT") $(sum "$SECOND")"

echo "== keep"
"$LEATSTORE" put "$TGT" config "$WORK/b.toml" >/dev/null
head -c 3000 /dev/urandom >"$WORK/junk"
"$LEATSTORE" put "$TGT" leases "$WORK/junk" --raw >/dev/null
check "stale leases record planted" "1" "$("$LEATSTORE" show "$TGT" | grep -c '^  leases .*A: seq')"
run "$WORK/install.iso" "$DF"
if has "config carried over"; then pass "config carried over"; else fail "config carried over"; fi
check "the target's config kept" "10.32.0.1/24" "$(cfg_ip)"
check "stale leases record gone" "0" "$("$LEATSTORE" show "$TGT" | grep -c '^  leases .*seq')"

echo "== trial (negative control)"
"$LEATSTORE" put "$TGT" config "$WORK/c.toml" --trial >/dev/null
before="$(sum "$TGT")"
run "$WORK/install.iso" "$DF"
if has "unconfirmed trial.*nothing written"; then pass "refused"; else fail "refused"; fi
check "target unchanged" "$before" "$(sum "$TGT")"

echo "== unattended"
scripts/apu-image.sh --debug --iso --config "$WORK/a.toml" \
  --install-args "install_target=$DF install_keep=0" --out "$WORK/unattended.iso" 2>/dev/null
run "$WORK/unattended.iso" ""
if has "install: target $DF (install_target=)"; then pass "no prompt"; else fail "no prompt"; fi
if has "not kept (install_keep=0)"; then pass "config not kept"; else fail "config not kept"; fi
if has "install: done"; then pass "installer done"; else fail "installer done"; fi
check "the image's config wins" "10.31.0.1/24" "$(cfg_ip)"

echo "== corrupt (negative control)"
cp "$WORK/install.iso" "$WORK/corrupt.iso"
off="$(grep -obUa LEATINST "$WORK/corrupt.iso" | head -1 | cut -d: -f1)"
at=$((off + 100000))
byte="$(dd if="$WORK/corrupt.iso" bs=1 skip="$at" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')"
printf "$(printf '\\%03o' $(((byte ^ 1) & 255)))" | dd of="$WORK/corrupt.iso" bs=1 seek="$at" conv=notrunc 2>/dev/null
before="$(sum "$TGT")"
run "$WORK/corrupt.iso" ""
if has "install image invalid (SHA-256 mismatch): nothing written"; then pass "refused"; else fail "refused"; fi
check "target unchanged" "$before" "$(sum "$TGT")"

echo "== stick"
QEMU_DISK="$WORK/install.iso" QEMU_ACCEL=tcg scripts/qemu-run.sh </dev/null >"$LOG" 2>&1 &
QPID=$!
wait_for 'nothing written' "$T" || true
if has "install image   : ok"; then pass "boots as a disk"; else fail "boots as a disk"; fi
if has "the install medium, not offered" && has "no disk to install to: nothing written"; then pass "its own medium is not offered"; else fail "its own medium is not offered"; fi
stop_qemu

if [[ "$FAILED" == 0 ]]; then echo "INSTALL TEST: PASS"; else echo "INSTALL TEST: FAIL"; exit 1; fi
