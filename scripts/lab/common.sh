# Shared helpers for scripts/lab-test.sh and scripts/mac-lab.sh (sourced).
# Requires: PIDS array declared by the caller.

# Wait until `pattern` appears in `file` (CR-stripped), up to `seconds`.
wait_for() { # file pattern seconds
  local i=0
  while ! tr -d '\r' <"$1" 2>/dev/null | grep -q -- "$2"; do
    sleep 0.2
    i=$((i + 1))
    if [[ $i -gt $(($3 * 5)) ]]; then return 1; fi
  done
}

# CPU/accelerator flags for the Linux lab VMs.
lab_cpu_flags() {
  if [[ -z "${QEMU_ACCEL:-}" ]]; then
    if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then QEMU_ACCEL=hvf; else QEMU_ACCEL=tcg; fi
  fi
  if [[ "$QEMU_ACCEL" == "hvf" ]]; then CPU=(-accel hvf -cpu host); else CPU=(-accel tcg -cpu cortex-a76); fi
}

# Start an Alpine lab VM with one NIC on a UDP socket link (background; PID appended to PIDS).
# VM_DISK: optional read-only raw disk for the VM (/dev/vda).
# VM_NIC2="mac local_port remote_port": a second NIC (eth1).
linux_vm() { # initrd mac local_port remote_port log [extra kernel args]
  local disk=() nic2=()
  [[ -n "${VM_DISK:-}" ]] && disk=(-drive "file=$VM_DISK,if=virtio,format=raw,readonly=on")
  if [[ -n "${VM_NIC2:-}" ]]; then
    set -- "$1" "$2" "$3" "$4" "$5" "${6:-}" $VM_NIC2
    nic2=(-netdev "dgram,id=n1,local.type=inet,local.host=127.0.0.1,local.port=${8},remote.type=inet,remote.host=127.0.0.1,remote.port=${9}"
      -device "virtio-net-pci,netdev=n1,mac=${7}")
  fi
  qemu-system-aarch64 -machine virt "${CPU[@]}" -m 512M -nographic ${disk[@]+"${disk[@]}"} \
    -kernel "$ALPINE_DIR/vmlinuz-virt" -initrd "$1" \
    -append "console=ttyAMA0 rdinit=/init quiet loglevel=3 ${6:-}" \
    -netdev "dgram,id=n0,local.type=inet,local.host=127.0.0.1,local.port=$3,remote.type=inet,remote.host=127.0.0.1,remote.port=$4" \
    -device "virtio-net-pci,netdev=n0,mac=$2" ${nic2[@]+"${nic2[@]}"} >"$5" 2>&1 &
  PIDS+=($!)
}

# Start the ISP VM (203.0.113.1) on the router's WAN link and wait until ready.
# With ISP_VLAN=N it serves on VLAN N, with ISP_PPPOE=pap|chap it is a
# PPPoE access concentrator (both need ALPINE_DIR from
# `fetch-alpine.sh modloop`), with ISP_STATIC=1 it runs no DHCP server.
start_isp() { # wan_port log
  local args="${ISP_VLAN:+lab_vlan=$ISP_VLAN} ${ISP_PPPOE:+lab_pppoe=$ISP_PPPOE} ${ISP_STATIC:+lab_static=1}"
  if [[ -n "${ISP_VLAN:-}${ISP_PPPOE:-}" ]]; then
    VM_DISK="$ALPINE_DIR/modloop-virt" linux_vm "$ISP_INITRD" 52:54:00:00:01:01 $(($1 + 1)) "$1" "$2" "$args"
  else
    linux_vm "$ISP_INITRD" 52:54:00:00:01:01 $(($1 + 1)) "$1" "$2" "$args"
  fi
  wait_for "$2" "LAB isp ready" 30 || { echo "ISP did not start:"; cat "$2"; return 1; }
}

# ---- macOS helpers (mac-lab.sh, mac-internet.sh) ---------------------------------------

# Ask for sudo once and keep the timestamp fresh (sets KEEPALIVE_PID).
sudo_keepalive() {
  sudo -v
  ( while true; do sudo -n true 2>/dev/null; sleep 50; done ) &
  KEEPALIVE_PID=$!
}

# Find the interface vmnet created for rrouter's LAN: a new interface (not in
# $1, the `ifconfig -l` output from before QEMU started) with an address in
# $2 (e.g. "192.168.1"). Sets MAC_IF and MAC_IP; returns 1 after ~15 s.
find_new_lan_if() { # before-list net-prefix
  MAC_IF=""
  MAC_IP=""
  local ifn ip
  for _ in $(seq 1 75); do
    for ifn in $(ifconfig -l); do
      case " $1 " in *" $ifn "*) continue ;; esac
      ip=$(ifconfig "$ifn" 2>/dev/null | awk '$1=="inet"{print $2}' | grep "^$2\." | head -1 || true)
      if [[ -n "$ip" ]]; then MAC_IF=$ifn; MAC_IP=$ip; return 0; fi
    done
    sleep 0.2
  done
  return 1
}

# Refuse to run when this Mac already routes the lab subnets.
check_no_subnet_conflict() { # regex of destinations, e.g. "192\.168\.1|203\.0\.113"
  if netstat -rn -f inet | awk '{print $1}' | grep -qE "^($1)(\.|/|$)"; then
    echo "this Mac already has routes for the lab subnets:" >&2
    netstat -rn -f inet | grep -E "^($1)" >&2
    echo "refusing to start (would conflict). Disconnect that network first." >&2
    return 1
  fi
}
