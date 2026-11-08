#!/usr/bin/env bash
# Boot an rrouter kernel ELF in QEMU (aarch64 `virt`).
# Used as the cargo runner for aarch64-unknown-none (`cargo krun`).
#
# Environment:
#   QEMU_ACCEL=hvf|tcg   default: hvf on Apple Silicon macOS, tcg elsewhere
#   QEMU_MEM=256M        guest RAM (max 3G: boot.S maps RAM in 1..4 GiB only)
#   QEMU_SMP=1
#   QEMU_GDB=1           start paused with a gdb stub on :1234
#   QEMU_NET=none|user   none (default) or two user-mode virtio-net NICs (WAN, LAN)
#   QEMU_PCAP_DIR=dir    with QEMU_NET=user: dump WAN/LAN traffic to pcap files
#   QEMU_EXTRA="..."     extra QEMU arguments
set -euo pipefail

KERNEL="${1:?usage: qemu-run.sh <kernel-elf>}"
shift || true

if [[ -z "${QEMU_ACCEL:-}" ]]; then
  if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
    QEMU_ACCEL=hvf
  else
    QEMU_ACCEL=tcg
  fi
fi

if [[ "$QEMU_ACCEL" == "hvf" ]]; then
  CPU=(-accel hvf -cpu host)
else
  CPU=(-accel tcg -cpu cortex-a76)
fi

NET=(-nic none)
if [[ "${QEMU_NET:-none}" == "user" ]]; then
  NET=(
    -netdev user,id=wan -device virtio-net-pci,netdev=wan,mac=52:54:00:00:00:01
    -netdev user,id=lan -device virtio-net-pci,netdev=lan,mac=52:54:00:00:00:02
  )
  if [[ -n "${QEMU_PCAP_DIR:-}" ]]; then
    mkdir -p "$QEMU_PCAP_DIR"
    NET+=(
      -object "filter-dump,id=dwan,netdev=wan,file=$QEMU_PCAP_DIR/wan.pcap"
      -object "filter-dump,id=dlan,netdev=lan,file=$QEMU_PCAP_DIR/lan.pcap"
    )
  fi
fi

GDB=()
if [[ "${QEMU_GDB:-0}" == "1" ]]; then
  GDB=(-s -S)
  echo "qemu: waiting for gdb on :1234 (e.g. 'gdb $KERNEL -ex \"target remote :1234\"')" >&2
fi

# shellcheck disable=SC2206
EXTRA=(${QEMU_EXTRA:-})

exec qemu-system-aarch64 \
  -machine virt,gic-version=3 \
  "${CPU[@]}" \
  -smp "${QEMU_SMP:-1}" \
  -m "${QEMU_MEM:-256M}" \
  -nographic \
  -kernel "$KERNEL" \
  "${NET[@]}" \
  ${GDB[@]+"${GDB[@]}"} \
  ${EXTRA[@]+"${EXTRA[@]}"} \
  "$@"
