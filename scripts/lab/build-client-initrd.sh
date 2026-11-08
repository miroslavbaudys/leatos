#!/usr/bin/env bash
# Build the lab client initramfs: Alpine's initramfs-virt (kernel modules,
# busybox) with lab/client/{init,udhcpc.sh} appended as a second cpio
# archive. Linux unpacks concatenated archives in order, so our /init
# replaces Alpine's. Prints the output path.
set -euo pipefail
cd "$(dirname "$0")/../.."

ALPINE_DIR=$(scripts/lab/fetch-alpine.sh | tail -1)
OUT=lab/cache/client-initrd.img
STAGE=$(mktemp -d -t rrouter-initrd)
trap 'rm -rf "$STAGE"' EXIT

cp lab/client/init lab/client/udhcpc.sh "$STAGE/"
chmod 0755 "$STAGE/init" "$STAGE/udhcpc.sh"
( cd "$STAGE" && printf '%s\n' init udhcpc.sh | cpio -o -H newc 2>/dev/null | gzip -9 ) > "$STAGE/overlay.cpio.gz"
cat "$ALPINE_DIR/initramfs-virt" "$STAGE/overlay.cpio.gz" > "$OUT"
echo "$OUT"
