#!/usr/bin/env bash
# Boot an rrouter kernel ELF in QEMU (aarch64 `virt`).
# Used as the cargo runner for aarch64-unknown-none (`cargo krun`).
#
# Environment:
#   QEMU_ACCEL=hvf|tcg   default: hvf on Apple Silicon macOS, tcg elsewhere
#   QEMU_MEM=256M        guest RAM (max 3G: boot.S maps RAM in 1..4 GiB only)
#   QEMU_SMP=1
#   QEMU_GDB=1           start paused with a gdb stub on :1234
#   QEMU_BIN=path        QEMU binary (default: qemu-system-aarch64 from PATH;
#                        set it when running under sudo, whose PATH lacks Homebrew)
#   QEMU_NET=none|user|lab|mac
#                        none (default); user = WAN + LAN on QEMU user-mode
#                        networking; lab = WAN and LAN on UDP socket links to
#                        the ISP and client VMs (scripts/lab-test.sh)
#   LAB_LAN_PORT=10003   lab mode: router's LAN link port (client uses +1)
#   LAB_WAN_PORT=10005   lab mode: router's WAN link port (ISP uses +1)
#                        mac = WAN to the ISP VM like lab, LAN on macOS
#                        vmnet-host (the Mac itself joins the LAN; needs root,
#                        see scripts/mac-lab.sh)
#                        mac-internet = like mac, but the WAN is vmnet-bridged
#                        onto the physical interface MAC_WAN_IF (real upstream;
#                        see scripts/mac-internet.sh)
#   MAC_WAN_IF=en0       mac-internet mode: interface to bridge the WAN onto
#   MAC_LAN_RANGE=192.168.1.2,192.168.1.9   mac modes: vmnet's own address range
#                        (its first address goes to the Mac's bridge interface)
#   QEMU_PCAP_DIR=dir    with QEMU_NET=user: dump WAN/LAN traffic to pcap files
#   QEMU_APPEND="..."    kernel command line (DTB /chosen/bootargs), e.g.
#                        "shape_up=42000 shape_down=50000 idle_spin_us=0"
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
fi
if [[ "${QEMU_NET:-none}" == "lab" ]]; then
  lp="${LAB_LAN_PORT:-10003}"
  wp="${LAB_WAN_PORT:-10005}"
  NET=(
    -netdev "dgram,id=wan,local.type=inet,local.host=127.0.0.1,local.port=$wp,remote.type=inet,remote.host=127.0.0.1,remote.port=$((wp + 1))"
    -device virtio-net-pci,netdev=wan,mac=52:54:00:00:00:01
    -netdev "dgram,id=lan,local.type=inet,local.host=127.0.0.1,local.port=$lp,remote.type=inet,remote.host=127.0.0.1,remote.port=$((lp + 1))"
    -device virtio-net-pci,netdev=lan,mac=52:54:00:00:00:02
  )
fi
if [[ "${QEMU_NET:-none}" == "mac" || "${QEMU_NET:-none}" == "mac-internet" ]]; then
  wp="${LAB_WAN_PORT:-10005}"
  IFS=, read -r vstart vend <<<"${MAC_LAN_RANGE:-192.168.1.2,192.168.1.9}"
  if [[ "$QEMU_NET" == "mac-internet" ]]; then
    WAN_NETDEV="vmnet-bridged,id=wan,ifname=${MAC_WAN_IF:?MAC_WAN_IF required}"
  else
    WAN_NETDEV="dgram,id=wan,local.type=inet,local.host=127.0.0.1,local.port=$wp,remote.type=inet,remote.host=127.0.0.1,remote.port=$((wp + 1))"
  fi
  NET=(
    -netdev "$WAN_NETDEV"
    -device virtio-net-pci,netdev=wan,mac=52:54:00:00:00:01
    -netdev "vmnet-host,id=lan,start-address=$vstart,end-address=$vend,subnet-mask=255.255.255.0"
    -device virtio-net-pci,netdev=lan,mac=52:54:00:00:00:02
  )
fi
if [[ "${QEMU_NET:-none}" =~ ^(user|lab|mac|mac-internet)$ ]]; then
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
if [[ -n "${QEMU_APPEND:-}" ]]; then EXTRA+=(-append "$QEMU_APPEND"); fi

exec "${QEMU_BIN:-qemu-system-aarch64}" \
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
