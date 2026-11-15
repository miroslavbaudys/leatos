#!/usr/bin/env bash
# Download the Alpine Linux aarch64 netboot kernel + initramfs and the
# busybox-extras package (udhcpd, httpd, dnsd) used by the lab VMs, plus
# the ISP VM's PPPoE server (rp-pppoe's pppoe-server, pppd and their
# libraries: scripts/lab-test.sh LAB_PPPOE=1), into lab/cache/
# (gitignored), and verify pinned SHA-256s.
#   Usage: fetch-alpine.sh [modloop]   (prints the directory)
# `modloop` also fetches modloop-virt, the squashfs with all of the
# kernel's modules (8021q for the VLAN lab: scripts/lab-test.sh LAB_VLAN=N,
# pppoe for LAB_PPPOE=1);
# it must match ALPINE_KERNEL.
# Alpine replaces netboot files on point releases: if a hash mismatches,
# review the new release and update ALPINE_* and the hashes below.
set -euo pipefail
cd "$(dirname "$0")/../.."

ALPINE_BRANCH=v3.24
ALPINE_KERNEL=6.18.60-0-virt   # informational
BASE="https://dl-cdn.alpinelinux.org/alpine/$ALPINE_BRANCH/releases/aarch64/netboot"
PKGS="https://dl-cdn.alpinelinux.org/alpine/$ALPINE_BRANCH/main/aarch64"
EXTRAS_APK=busybox-extras-1.37.0-r31.apk
# rp-pppoe 3.15 from Alpine 3.17 (needs only musl): 4.0 dropped user-mode
# PPPoE, and the virt kernel has no pppoe module for kernel mode.
RP_PPPOE_PKGS="https://dl-cdn.alpinelinux.org/alpine/v3.17/main/aarch64"
PPPOE_APKS="rp-pppoe-3.15-r0.apk ppp-daemon-2.5.3-r0.apk libpcap-1.10.7-r0.apk libssl3-3.5.9-r0.apk libcrypto3-3.5.9-r0.apk"
DIR="lab/cache/alpine-${ALPINE_BRANCH#v}"
# (macOS ships bash 3.2: no associative arrays)
sha_for() {
  case "$1" in
    vmlinuz-virt) echo cd05fed9e617b5df93dc62ece9b78c422fd94e9b432a2f7c092714b139d5eef4 ;;
    initramfs-virt) echo 189402937646965374ef2df5d37f76467135179ae168c88175df2fe3e264a0b0 ;;
    "$EXTRAS_APK") echo 64a2c66f44f2218473f56dd63355d988c3da0bdae6384d6d94d32587328ccea3 ;;
    modloop-virt) echo a726889467d1d4fefa4ba1ed710f28b9db1fbd019ca3eba2d4c6c65b33536343 ;;
    rp-pppoe-3.15-r0.apk) echo a9b56c9786368093ab7e6b49909208eb10de2f94c1ae36882379b6f13b65630e ;;
    ppp-daemon-2.5.3-r0.apk) echo b3c8367511030b16be81a59be8a07913f9bb44bda57cb12e3d9009a6a6769240 ;;
    libpcap-1.10.7-r0.apk) echo e0bcd33b4cf451476abbf0b61725ab0a4b61465a5bd427c7e7cb4bdadf65cee2 ;;
    libssl3-3.5.9-r0.apk) echo 20ac252b276d73f2c69c1d25f84537c7fba81caefc026c6be1094b394af2082e ;;
    libcrypto3-3.5.9-r0.apk) echo 2676a2b0b6e23ea2edccf3ee982b9842a665d52603d047de3d0a185dc316d983 ;;
  esac
}

FILES="vmlinuz-virt initramfs-virt $EXTRAS_APK $PPPOE_APKS"
[[ "${1:-}" == modloop ]] && FILES="$FILES modloop-virt"

mkdir -p "$DIR"
for f in $FILES; do
  url="$BASE/$f"
  [[ "$f" == *.apk ]] && url="$PKGS/$f"
  [[ "$f" == rp-pppoe-* ]] && url="$RP_PPPOE_PKGS/$f"
  if [[ ! -f "$DIR/$f" ]]; then
    echo "fetch: $url" >&2
    curl -fsSL --max-time 300 -o "$DIR/$f.part" "$url"
    mv "$DIR/$f.part" "$DIR/$f"
  fi
  got=$(shasum -a 256 "$DIR/$f" | cut -d' ' -f1)
  if [[ "$got" != "$(sha_for "$f")" ]]; then
    echo "fetch: SHA-256 mismatch for $f (kernel $ALPINE_KERNEL)" >&2
    echo "  expected $(sha_for "$f")" >&2
    echo "  got      $got" >&2
    exit 1
  fi
done
echo "$DIR"
