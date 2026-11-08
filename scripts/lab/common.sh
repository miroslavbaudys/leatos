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
linux_vm() { # initrd mac local_port remote_port log
  qemu-system-aarch64 -machine virt "${CPU[@]}" -m 512M -nographic \
    -kernel "$ALPINE_DIR/vmlinuz-virt" -initrd "$1" \
    -append "console=ttyAMA0 rdinit=/init quiet loglevel=3" \
    -netdev "dgram,id=n0,local.type=inet,local.host=127.0.0.1,local.port=$3,remote.type=inet,remote.host=127.0.0.1,remote.port=$4" \
    -device "virtio-net-pci,netdev=n0,mac=$2" >"$5" 2>&1 &
  PIDS+=($!)
}

# Start the ISP VM (203.0.113.1) on the router's WAN link and wait until ready.
start_isp() { # wan_port log
  linux_vm "$ISP_INITRD" 52:54:00:00:01:01 $(($1 + 1)) "$1" "$2"
  wait_for "$2" "LAB isp ready" 30 || { echo "ISP did not start:"; cat "$2"; return 1; }
}
