#!/usr/bin/env bash
# Boot an rrouter kernel ELF in QEMU: aarch64 `virt`, or x86_64 `q35` when
# the ELF is an x86-64 build (PVH entry via -kernel; SeaBIOS assigns BARs).
# Used as the cargo runner for both targets (`cargo krun`, `cargo krun-x86`).
#
# Environment:
#   QEMU_ACCEL=hvf|tcg   default: hvf on Apple Silicon macOS, tcg elsewhere
#                        (x86_64 guests on Apple Silicon: always tcg)
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
#   QEMU_WAN_HOSTFWD=tcp:127.0.0.1:8080-:80
#                        with QEMU_NET=user: forward a host port to the router's
#                        WAN address (management tests; boot with mgmt=wan)
#   QEMU_PCAP_DIR=dir    with QEMU_NET=user: dump WAN/LAN traffic to pcap files
#   QEMU_DISK=img        boot a disk image via SeaBIOS + Limine instead of -kernel
#                        (x86_64; scripts/apu-image.sh); QEMU_APPEND is ignored
#   QEMU_STORE=img       attach img as a virtio-blk disk (the router's store; create
#                        one with `cargo run -q -p rrstore -- create img`). Written
#                        in place: pass a copy to keep the original
#   QEMU_STORE_BUS=virtio|sd   how QEMU_STORE is attached: virtio-blk (default) or an
#                        SD card behind QEMU's sdhci-pci (the apu4's SD driver).
#                        SD images must be a power of two in size (rrstore create --mib 32)
#   QEMU_NIC=virtio|igb  NIC model for WAN and LAN (default virtio): igb = QEMU's
#                        Intel 82576, driven by the same igb driver as the apu4's i211
#   QEMU_WDT=1|0         attach QEMU's i6300esb PCI watchdog (default 1; the
#                        router's hardware watchdog in the lab, both arches)
#   QEMU_APPEND="..."    kernel command line (DTB /chosen/bootargs), e.g.
#                        "shape_up=42000 shape_down=50000 idle_spin_us=0"
#                        log=console is added unless it sets log= (the
#                        scripts read log messages from the console; the
#                        kernel's default is its RAM log once booted)
#   QEMU_EXTRA="..."     extra QEMU arguments
set -euo pipefail

# QEMU_DISK=img: boot a disk image through the firmware (x86_64 only; built
# by scripts/apu-image.sh: SeaBIOS -> Limine -> Multiboot2), as on the apu4.
if [[ -n "${QEMU_DISK:-}" ]]; then
  KERNEL=
  ARCH=x86_64
  BOOT=(-drive "file=$QEMU_DISK,format=raw,snapshot=on")
else
  KERNEL="${1:?usage: qemu-run.sh <kernel-elf> (or QEMU_DISK=image)}"
  shift || true
  BOOT=(-kernel "$KERNEL")
  # ELF e_machine (bytes 18-19): 0xb7 = aarch64, 0x3e = x86-64.
  ARCH=aarch64
  if [[ "$(od -An -tx1 -j18 -N1 "$KERNEL" | tr -d ' ')" == "3e" ]]; then ARCH=x86_64; fi
fi

if [[ -z "${QEMU_ACCEL:-}" ]]; then
  if [[ "$ARCH" == aarch64 && "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
    QEMU_ACCEL=hvf
  elif [[ "$ARCH" == x86_64 && "$(uname -m)" == "x86_64" && -e /dev/kvm ]]; then
    QEMU_ACCEL=kvm
  else
    QEMU_ACCEL=tcg
  fi
fi

# An x86_64 guest can only use hardware acceleration on an x86_64 host.
if [[ "$ARCH" == x86_64 && "$(uname -m)" != x86_64 && "$QEMU_ACCEL" != tcg ]]; then QEMU_ACCEL=tcg; fi

if [[ "$ARCH" == x86_64 ]]; then
  MACHINE=(-machine q35 -vga none)
  # `max` gives TCG every feature it emulates (NX, x2APIC, invariant TSC).
  if [[ "$QEMU_ACCEL" == tcg ]]; then CPU=(-accel tcg -cpu max); else CPU=(-accel "$QEMU_ACCEL" -cpu host); fi
  DEFAULT_BIN=qemu-system-x86_64
elif [[ "$QEMU_ACCEL" == "hvf" ]]; then
  MACHINE=(-machine virt,gic-version=3)
  CPU=(-accel hvf -cpu host)
  DEFAULT_BIN=qemu-system-aarch64
else
  MACHINE=(-machine virt,gic-version=3)
  CPU=(-accel tcg -cpu cortex-a76)
  DEFAULT_BIN=qemu-system-aarch64
fi

# Fixed slots for igb: each one reserves its SR-IOV VF functions at
# devfn + 0x80, which collide when QEMU places two igbs next to each other.
WAN_ADDR=
LAN_ADDR=
case "${QEMU_NIC:-virtio}" in
  virtio) NIC=virtio-net-pci ;;
  igb) NIC=igb WAN_ADDR=,addr=0x4 LAN_ADDR=,addr=0x6 ;;
  *) echo "QEMU_NIC must be virtio or igb" >&2; exit 2 ;;
esac

NET=(-nic none)
if [[ "${QEMU_NET:-none}" == "user" ]]; then
  NET=(
    -netdev "user,id=wan${QEMU_WAN_HOSTFWD:+,hostfwd=$QEMU_WAN_HOSTFWD}" -device "$NIC,netdev=wan,mac=52:54:00:00:00:01$WAN_ADDR"
    -netdev user,id=lan -device "$NIC,netdev=lan,mac=52:54:00:00:00:02$LAN_ADDR"
  )
fi
if [[ "${QEMU_NET:-none}" == "lab" ]]; then
  lp="${LAB_LAN_PORT:-10003}"
  wp="${LAB_WAN_PORT:-10005}"
  NET=(
    -netdev "dgram,id=wan,local.type=inet,local.host=127.0.0.1,local.port=$wp,remote.type=inet,remote.host=127.0.0.1,remote.port=$((wp + 1))"
    -device "$NIC,netdev=wan,mac=52:54:00:00:00:01$WAN_ADDR"
    -netdev "dgram,id=lan,local.type=inet,local.host=127.0.0.1,local.port=$lp,remote.type=inet,remote.host=127.0.0.1,remote.port=$((lp + 1))"
    -device "$NIC,netdev=lan,mac=52:54:00:00:00:02$LAN_ADDR"
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
    -device "$NIC,netdev=wan,mac=52:54:00:00:00:01$WAN_ADDR"
    -netdev "vmnet-host,id=lan,start-address=$vstart,end-address=$vend,subnet-mask=255.255.255.0"
    -device "$NIC,netdev=lan,mac=52:54:00:00:00:02$LAN_ADDR"
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

# After the NICs, so their PCI slots (and the WAN/LAN order) stay the same.
STORE=()
if [[ -n "${QEMU_STORE:-}" ]]; then
  case "${QEMU_STORE_BUS:-virtio}" in
    virtio) STORE=(-drive "file=$QEMU_STORE,format=raw,if=none,id=store,cache=writethrough" -device virtio-blk-pci,drive=store) ;;
    sd) STORE=(-drive "file=$QEMU_STORE,format=raw,if=none,id=store,cache=writethrough" -device sdhci-pci,id=sdhci -device sd-card,drive=store,bus=sd-bus) ;;
    *) echo "QEMU_STORE_BUS must be virtio or sd" >&2; exit 2 ;;
  esac
fi

# Last, so the slots of the NICs and the store stay the same. A watchdog
# timeout resets the guest (QEMU's default action).
WDT=()
if [[ "${QEMU_WDT:-1}" == "1" ]]; then WDT=(-device i6300esb); fi

GDB=()
if [[ "${QEMU_GDB:-0}" == "1" ]]; then
  GDB=(-s -S)
  echo "qemu: waiting for gdb on :1234 (e.g. 'gdb $KERNEL -ex \"target remote :1234\"')" >&2
fi

# shellcheck disable=SC2206
EXTRA=(${QEMU_EXTRA:-})
APPEND="${QEMU_APPEND:-}"
case " $APPEND" in *" log="*) ;; *) APPEND="log=console${APPEND:+ $APPEND}" ;; esac
if [[ -z "${QEMU_DISK:-}" ]]; then EXTRA+=(-append "$APPEND"); fi

# QEMU_BIN (sudo callers) names the aarch64 binary; derive the x86 one from it.
BIN="${QEMU_BIN:-$DEFAULT_BIN}"
if [[ "$ARCH" == x86_64 ]]; then BIN="${BIN%qemu-system-aarch64}"; [[ "$BIN" == */ || -z "$BIN" ]] && BIN="${BIN}qemu-system-x86_64"; fi

exec "$BIN" \
  "${MACHINE[@]}" \
  "${CPU[@]}" \
  -smp "${QEMU_SMP:-1}" \
  -m "${QEMU_MEM:-256M}" \
  -nographic \
  "${BOOT[@]}" \
  "${NET[@]}" \
  ${STORE[@]+"${STORE[@]}"} \
  ${WDT[@]+"${WDT[@]}"} \
  ${GDB[@]+"${GDB[@]}"} \
  ${EXTRA[@]+"${EXTRA[@]}"} \
  "$@"
