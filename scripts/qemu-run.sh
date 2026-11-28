#!/usr/bin/env bash
# Boot a leatos kernel ELF in QEMU: aarch64 `virt`, or x86_64 `q35` when
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
#   LAB_LAN_PEER=port    lab mode: where the router's LAN frames go (default
#                        LAB_LAN_PORT + 1; LAB_TCP_LOSS: the relay)
#   LAB_LAN1_PORT=10007  lab mode: a third NIC, the LAN port lan1 (client's
#                        second NIC uses +1); unset = no lan1
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
#   QEMU_DISK=store      boot QEMU_STORE itself through the firmware (virtio or ahci, as
#                        Proxmox boots virtio0 / sata0): a disk the installer wrote
#   QEMU_CDROM=iso       boot an ISO as a CD via SeaBIOS + Limine (x86_64; the
#                        installer, scripts/apu-image.sh --iso), as Proxmox attaches it
#   QEMU_STORE=img       attach img as a virtio-blk disk (the router's store; create
#                        one with `cargo run -q -p leatstore -- create img`). Written
#                        in place: pass a copy to keep the original
#   QEMU_STORE_BUS=virtio|sd|ahci   how QEMU_STORE is attached: virtio-blk (default), an
#                        SD card behind QEMU's sdhci-pci (the apu4's SD driver), or a
#                        SATA disk on port 0 of an AHCI controller of its own (-device ahci,
#                        as Proxmox attaches sata0; the apu4's mSATA driver).
#                        SD images must be a power of two in size (leatstore create --mib 32)
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
#   QEMU_PROXMOX=1       x86_64: the device layout of a Proxmox VE q35 VM (from qemu-server's
#                        PCI.pm address map and pve-q35-4.0.cfg, docs/proxmox.md §1):
#                        -nodefaults, pci-bridges pci.0..pci.3 behind a DMI-to-PCI bridge,
#                        four PCIe root ports, ICH9 USB + audio on pcie.0; on pci.0: balloon
#                        (0x3), watchdog (0x4), ahci0 (0x7), virtio0 (0xa), net0..net2
#                        (0x12..0x14); the CD as ide2 (ide.1); boot by bootindex, strict.
#                        QEMU_STORE is virtio0 or sata0 (QEMU_STORE_BUS=ahci); QEMU_NIC=igb
#                        puts the NICs on the root ports (hostpci, pcie=1). Not Proxmox's
#                        QEMU (no +pveN machine) and no KVM here: a layout test.
set -euo pipefail

PVE="${QEMU_PROXMOX:-0}"
# Proxmox boots by bootindex (100, 101, ... in its boot order) with
# `-boot strict=on`: the CD first when there is one, then the disk.
STORE_BOOT=100
# QEMU_DISK=img: boot a disk image through the firmware (x86_64 only; built
# by scripts/apu-image.sh: SeaBIOS -> Limine -> Multiboot2), as on the apu4.
if [[ -n "${QEMU_CDROM:-}" ]]; then
  KERNEL=
  ARCH=x86_64
  BOOT=(-drive "file=$QEMU_CDROM,media=cdrom,readonly=on" -boot d)
  if [[ "$PVE" == 1 ]]; then
    BOOT=(-drive "file=$QEMU_CDROM,if=none,id=drive-ide2,media=cdrom,readonly=on"
      -device "ide-cd,bus=ide.1,unit=0,drive=drive-ide2,id=ide2,bootindex=100")
    STORE_BOOT=101
  fi
elif [[ "${QEMU_DISK:-}" == store ]]; then
  KERNEL=
  ARCH=x86_64
  BOOT=(-boot c) # not empty: bash 3.2 calls an empty array unbound under set -u
  [[ -n "${QEMU_STORE:-}" && "${QEMU_STORE_BUS:-virtio}" != sd ]] \
    || { echo "QEMU_DISK=store needs QEMU_STORE on virtio or ahci" >&2; exit 2; }
elif [[ -n "${QEMU_DISK:-}" ]]; then
  KERNEL=
  ARCH=x86_64
  BOOT=(-drive "file=$QEMU_DISK,format=raw,snapshot=on")
  if [[ "$PVE" == 1 ]]; then
    BOOT=(-drive "file=$QEMU_DISK,format=raw,snapshot=on,if=none,id=drive-ide0"
      -device "ide-hd,bus=ide.0,unit=0,drive=drive-ide0,id=ide0,bootindex=100")
    STORE_BOOT=101
  fi
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
if [[ "$PVE" == 1 && "$ARCH" != x86_64 ]]; then echo "QEMU_PROXMOX=1 is x86_64 only" >&2; exit 2; fi

if [[ "$ARCH" == x86_64 ]]; then
  MACHINE=(-machine q35 -vga none)
  if [[ "$PVE" == 1 ]]; then
    # pve-q35-4.0.cfg as -device lines; the S3/S4 globals of machines >= 9.2.
    MACHINE=(-machine q35 -nodefaults -serial mon:stdio -boot menu=on,strict=on
      -global ICH9-LPC.disable_s3=1 -global ICH9-LPC.disable_s4=1
      -device ich9-usb-ehci1,id=ehci,multifunction=on,bus=pcie.0,addr=1d.7
      -device ich9-usb-uhci1,id=uhci-1,multifunction=on,bus=pcie.0,addr=1d.0,masterbus=ehci.0,firstport=0
      -device ich9-usb-uhci2,id=uhci-2,multifunction=on,bus=pcie.0,addr=1d.1,masterbus=ehci.0,firstport=2
      -device ich9-usb-uhci3,id=uhci-3,multifunction=on,bus=pcie.0,addr=1d.2,masterbus=ehci.0,firstport=4
      -device ich9-usb-ehci2,id=ehci-2,multifunction=on,bus=pcie.0,addr=1a.7
      -device ich9-usb-uhci4,id=uhci-4,multifunction=on,bus=pcie.0,addr=1a.0,masterbus=ehci-2.0,firstport=0
      -device ich9-usb-uhci5,id=uhci-5,multifunction=on,bus=pcie.0,addr=1a.1,masterbus=ehci-2.0,firstport=2
      -device ich9-usb-uhci6,id=uhci-6,multifunction=on,bus=pcie.0,addr=1a.2,masterbus=ehci-2.0,firstport=4
      -device ich9-intel-hda,id=audio0,bus=pcie.0,addr=1b.0)
    for i in 1 2 3 4; do
      MACHINE+=(-device "pcie-root-port,id=ich9-pcie-port-$i,x-speed=16,x-width=32,multifunction=on,bus=pcie.0,addr=1c.$((i - 1)),port=$i,chassis=$i")
    done
    MACHINE+=(-device i82801b11-bridge,id=pcidmi,bus=pcie.0,addr=1e.0)
    for i in 0 1 2 3; do
      MACHINE+=(-device "pci-bridge,id=pci.$i,bus=pcidmi,addr=$((i + 1)).0,chassis_nr=$((i + 1))")
    done
    MACHINE+=(-device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x3)
  fi
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
LAN1_ADDR=
case "${QEMU_NIC:-virtio}" in
  virtio) NIC=virtio-net-pci ;;
  igb) NIC=igb WAN_ADDR=,addr=0x4 LAN_ADDR=,addr=0x6 LAN1_ADDR=,addr=0x8 ;;
  *) echo "QEMU_NIC must be virtio or igb" >&2; exit 2 ;;
esac
if [[ "$PVE" == 1 ]]; then
  case "$NIC" in
    # net0..net2 (PCI.pm); igb as passthrough (hostpci0..2 on the root ports).
    virtio-net-pci) WAN_ADDR=,bus=pci.0,addr=0x12,id=net0 LAN_ADDR=,bus=pci.0,addr=0x13,id=net1 LAN1_ADDR=,bus=pci.0,addr=0x14,id=net2 ;;
    igb) WAN_ADDR=,bus=ich9-pcie-port-1,addr=0x0 LAN_ADDR=,bus=ich9-pcie-port-2,addr=0x0 LAN1_ADDR=,bus=ich9-pcie-port-3,addr=0x0 ;;
  esac
fi

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
    -netdev "dgram,id=lan,local.type=inet,local.host=127.0.0.1,local.port=$lp,remote.type=inet,remote.host=127.0.0.1,remote.port=${LAB_LAN_PEER:-$((lp + 1))}"
    -device "$NIC,netdev=lan,mac=52:54:00:00:00:02$LAN_ADDR"
  )
  if [[ -n "${LAB_LAN1_PORT:-}" ]]; then
    l1="$LAB_LAN1_PORT"
    NET+=(
      -netdev "dgram,id=lan1,local.type=inet,local.host=127.0.0.1,local.port=$l1,remote.type=inet,remote.host=127.0.0.1,remote.port=$((l1 + 1))"
      -device "$NIC,netdev=lan1,mac=52:54:00:00:00:03$LAN1_ADDR"
    )
  fi
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
if [[ -n "${QEMU_STORE:-}" && "$PVE" == 1 ]]; then
  # virtio0 / sata0 (PCI.pm, DriveDevice.pm), always in the boot order.
  case "${QEMU_STORE_BUS:-virtio}" in
    virtio) STORE=(-drive "file=$QEMU_STORE,format=raw,if=none,id=drive-virtio0,cache=writethrough"
      -device "virtio-blk-pci,drive=drive-virtio0,id=virtio0,bus=pci.0,addr=0xa,bootindex=$STORE_BOOT") ;;
    ahci) STORE=(-drive "file=$QEMU_STORE,format=raw,if=none,id=drive-sata0,cache=writethrough"
      -device ahci,id=ahci0,multifunction=on,bus=pci.0,addr=0x7
      -device "ide-hd,bus=ahci0.0,drive=drive-sata0,id=sata0,bootindex=$STORE_BOOT") ;;
    *) echo "QEMU_PROXMOX=1: QEMU_STORE_BUS must be virtio or ahci" >&2; exit 2 ;;
  esac
elif [[ -n "${QEMU_STORE:-}" ]]; then
  [[ "${QEMU_DISK:-}" == store ]] && BOOTIDX=",bootindex=0"
  case "${QEMU_STORE_BUS:-virtio}" in
    virtio) STORE=(-drive "file=$QEMU_STORE,format=raw,if=none,id=store,cache=writethrough" -device "virtio-blk-pci,drive=store${BOOTIDX:-}") ;;
    sd) STORE=(-drive "file=$QEMU_STORE,format=raw,if=none,id=store,cache=writethrough" -device sdhci-pci,id=sdhci -device sd-card,drive=store,bus=sd-bus) ;;
    ahci) STORE=(-drive "file=$QEMU_STORE,format=raw,if=none,id=store,cache=writethrough" -device ahci,id=ahci0 -device "ide-hd,drive=store,bus=ahci0.0${BOOTIDX:-}") ;;
    *) echo "QEMU_STORE_BUS must be virtio, sd or ahci" >&2; exit 2 ;;
  esac
fi

# Last, so the slots of the NICs and the store stay the same. A watchdog
# timeout resets the guest (QEMU's default action).
WDT=()
if [[ "${QEMU_WDT:-1}" == "1" ]]; then WDT=(-device i6300esb); fi
if [[ "${QEMU_WDT:-1}" == "1" && "$PVE" == 1 ]]; then WDT=(-device i6300esb,bus=pci.0,addr=0x4); fi

GDB=()
if [[ "${QEMU_GDB:-0}" == "1" ]]; then
  GDB=(-s -S)
  echo "qemu: waiting for gdb on :1234 (e.g. 'gdb $KERNEL -ex \"target remote :1234\"')" >&2
fi

# shellcheck disable=SC2206
EXTRA=(${QEMU_EXTRA:-})
APPEND="${QEMU_APPEND:-}"
case " $APPEND" in *" log="*) ;; *) APPEND="log=console${APPEND:+ $APPEND}" ;; esac
if [[ -z "${QEMU_DISK:-}${QEMU_CDROM:-}" ]]; then EXTRA+=(-append "$APPEND"); fi

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
