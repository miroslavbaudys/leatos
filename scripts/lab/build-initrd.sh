#!/usr/bin/env bash
# Build a lab VM initramfs: Alpine's initramfs-virt (kernel modules,
# busybox) plus an overlay archive with lab/<role>/ and busybox-extras
# (the ISP also gets pppoe-server, pppd and their libraries, stunnel and
# dnsmasq).
# Linux unpacks concatenated cpio archives in order, so the overlay's
# /init replaces Alpine's.   Usage: build-initrd.sh client|isp  (prints path)
set -euo pipefail
cd "$(dirname "$0")/../.."

ROLE="${1:?usage: build-initrd.sh client|isp}"
[[ -d "lab/$ROLE" ]] || { echo "no lab/$ROLE" >&2; exit 1; }
ALPINE_DIR=$(scripts/lab/fetch-alpine.sh | tail -1)
OUT="lab/cache/$ROLE-initrd.img"
STAGE=$(mktemp -d -t leatos-initrd)
trap 'rm -rf "$STAGE"' EXIT

# Packages first, so lab/<role>/ (e.g. /etc/ppp) overrides their files.
if [[ "$ROLE" == isp ]]; then
  for apk in rp-pppoe ppp-daemon libpcap libssl3 libcrypto3 stunnel dnsmasq; do
    tar -xzf "$ALPINE_DIR/$apk"-[0-9]*.apk -C "$STAGE" --exclude '.*' 2>/dev/null
  done
  # Kea's DHCPv6 server for prefix delegation (LAB_IPV6: fetch-alpine.sh kea).
  if [[ -n "${LAB_INITRD_KEA:-}" ]]; then
    for apk in kea-common kea-dhcp6 log4cplus libstdc++ libgcc; do
      tar -xzf "$ALPINE_DIR/$apk"-[0-9]*.apk -C "$STAGE" --exclude '.*' 2>/dev/null \
        || { echo "build-initrd: $apk missing (fetch-alpine.sh kea)" >&2; exit 1; }
    done
  fi
fi
cp -R "lab/$ROLE/." "$STAGE/"
mkdir -p "$STAGE/usr/bin"
tar -xzf "$ALPINE_DIR"/busybox-extras-*.apk -C "$STAGE/usr" bin/busybox-extras 2>/dev/null
chmod 0755 "$STAGE/init" "$STAGE/usr/bin/busybox-extras"
( cd "$STAGE" && find . -mindepth 1 | sed 's|^\./||' | cpio -o -H newc 2>/dev/null | gzip -9 ) > "$STAGE.cpio.gz"
cat "$ALPINE_DIR/initramfs-virt" "$STAGE.cpio.gz" > "$OUT"
rm -f "$STAGE.cpio.gz"
echo "$OUT"
