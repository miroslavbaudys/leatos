#!/usr/bin/env bash
# Download the Alpine Linux aarch64 netboot kernel + initramfs and the
# busybox-extras package (udhcpd, httpd, dnsd) used by the lab VMs, into
# lab/cache/ (gitignored), and verify pinned SHA-256s.
# Alpine replaces netboot files on point releases: if a hash mismatches,
# review the new release and update ALPINE_* and the hashes below.
set -euo pipefail
cd "$(dirname "$0")/../.."

ALPINE_BRANCH=v3.24
ALPINE_KERNEL=6.18.60-0-virt   # informational
BASE="https://dl-cdn.alpinelinux.org/alpine/$ALPINE_BRANCH/releases/aarch64/netboot"
PKGS="https://dl-cdn.alpinelinux.org/alpine/$ALPINE_BRANCH/main/aarch64"
EXTRAS_APK=busybox-extras-1.37.0-r31.apk
DIR="lab/cache/alpine-${ALPINE_BRANCH#v}"
# (macOS ships bash 3.2: no associative arrays)
sha_for() {
  case "$1" in
    vmlinuz-virt) echo cd05fed9e617b5df93dc62ece9b78c422fd94e9b432a2f7c092714b139d5eef4 ;;
    initramfs-virt) echo 189402937646965374ef2df5d37f76467135179ae168c88175df2fe3e264a0b0 ;;
    "$EXTRAS_APK") echo 64a2c66f44f2218473f56dd63355d988c3da0bdae6384d6d94d32587328ccea3 ;;
  esac
}

mkdir -p "$DIR"
for f in vmlinuz-virt initramfs-virt "$EXTRAS_APK"; do
  url="$BASE/$f"
  [[ "$f" == *.apk ]] && url="$PKGS/$f"
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
