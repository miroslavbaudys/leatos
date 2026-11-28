# leatos as a KVM / Proxmox VE guest (plan)

Status (2026-11-24): plan only, nothing implemented. x86_64 has run only under TCG (on the Mac);
KVM and Proxmox are untested. The apu4 stays the home router; a VM is a second instance or a
test bed until the steps below are done.

## 1. Where things stand

What already works for a q35 guest (QEMU supplies it all, leatos has the drivers):

- `scripts/qemu-run.sh` picks `-accel kvm -cpu host` on an x86_64 Linux host with `/dev/kvm`.
- Boot: SeaBIOS → Limine BIOS → Multiboot2, the apu4 image path (`LEATOS_BOOT=limine`); PVH
  direct boot with `-kernel`.
- Console: COM1 16550. Store: virtio-blk. NICs: virtio-net (MSI-X), igb for passthrough of
  i210/i211/82576. Watchdog: `i6300esb`. Persistent and in-RAM upgrades over HTTP.
- PCI: every bus in the ECAM window is scanned and firmware-assigned BARs are kept, so devices
  behind Proxmox's q35 PCI bridges should be found.

Gaps found (2026-11-24, by reading the code):

| Gap | Where | Effect on Proxmox |
|---|---|---|
| PCI only over ECAM (ACPI MCFG) | `kernel/src/pci.rs:1` | default machine `i440fx` has no MCFG: no devices at all |
| Disk: virtio-blk and SATA (AHCI, since 2026-11-28) | `kernel/src/drivers/mod.rs` `Disk` | default bus VirtIO SCSI boots (SeaBIOS) but the store is not found |
| Entropy: CCP TRNG or timing only | `kernel/src/entropy.rs` | VM pool is timing only (DNS ports, DoT, mgmt secrets) |
| Spin window 4 ms on any hypervisor | `kernel/src/config.rs:1595` | tuned for HVF; under KVM a host core spins near 100 % while shaping |
| TSC calibrated against the PIT (10 ms) | `kernel/src/arch/x86_64/timer.rs:22` | a descheduled vCPU skews it, and with it the shaper rates (min of 3 runs mitigates) |
| ACPI power button ignored | `kernel/src/arch/x86_64/power.rs` | "Shutdown" times out, Proxmox kills the VM (store survives, but slow and no PPPoE PADT) |
| Ports named in PCI order | docs/config-v2.md (`ports`) | adding a NIC can swap WAN and LAN |
| Console on the screen: US layout only | `kernel/src/drivers/screen.rs`, `arch/x86_64/kbd.rs` | noVNC (`vga: std`) shows the console (182x50) and types into the CLI through the PS/2 keyboard (2026-11-28); other layouts type US keys |

### 1.1 Proxmox's device layout in QEMU (`QEMU_PROXMOX=1`, 2026-11-28)

There is no Proxmox host to test on, and Proxmox VE is x86_64 only, so on an Apple Silicon Mac it
would run fully emulated, with its guests emulated again inside it. Instead, `scripts/qemu-run.sh`
reproduces the device layout Proxmox gives a q35 VM. It is taken from qemu-server's source at
HEAD (2026-11-28): the `get_pci_addr_map` in `src/PVE/QemuServer/PCI.pm`,
`src/usr/pve-q35-4.0.cfg`, `print_drivedevice_full` in `src/PVE/QemuServer/DriveDevice.pm`, and
`config_to_command` / `Machine.pm`:

- `-nodefaults`. `pcie.0` holds the ICH9 USB controllers (1d.x, 1a.x), audio (1b.0), four
  `pcie-root-port`s `ich9-pcie-port-1..4` (1c.0–1c.3), and the DMI-to-PCI bridge `pcidmi`
  (1e.0). Behind `pcidmi` sit four `pci-bridge`s `pci.0`–`pci.3`, so **every VM device is two
  bridges down** (bus 06 in QEMU's numbering).
- On `pci.0`: balloon 0x3 (on by default in Proxmox), watchdog i6300esb 0x4, `ahci0` 0x7,
  `virtio0` 0xa, `net0`–`net2` 0x12–0x14. `QEMU_NIC=igb` puts the NICs on the root ports, as
  passthrough with `pcie=1` does.
- The CD is `ide2`, which on q35 is `ide-cd,bus=ide.1,unit=0` on the built-in controller. Disks
  are `virtio0` (`virtio-blk-pci,...,id=virtio0,bus=pci.0,addr=0xa`) or `sata0`
  (`ide-hd,bus=ahci0.0`). Boot is by `bootindex` (CD 100, disk 101) with `-boot strict=on`.
- `ICH9-LPC.disable_s3=1` / `disable_s4=1`, as Proxmox sets for machines ≥ 9.2.
- **Not reproduced:** Proxmox's own QEMU build (the `q35+pveN` machine types, its patches),
  KVM, the `-global` lines from `Cfg2Cmd.pm` and the exact boot-order code (both unread),
  OVMF.

Results with it (2026-11-28, TCG):

- The kernel finds everything behind the bridges: virtio-net at 06:12.0 / 06:13.0 on MSI-X,
  the store on `virtio0` (06:0a.0), the watchdog, and a DHCP lease. igb on the root ports
  (01:00.0, 02:00.0) works too.
- `QEMU_PROXMOX=1 scripts/install-test.sh` passes for `virtio0` and `sata0` (06:07.0/0): the
  ISO on `ide2`, installed, the disk boots by `bootindex`.
- `QEMU_PROXMOX=1 LEATOS_ARCH=x86_64 scripts/lab-test.sh` passes.

## 2. Performance and latency rules for any VM

- **KVM only.** TCG is for tests (docs/qemu.md: "functional, not performance").
- **Always shape below the line rate.** virtio-net's ring empties into the host at once; the
  queue then builds in the host (tap `txqueuelen` 1000, bridge, physical NIC qdisc), which
  leatos cannot see. Shaping keeps those queues empty (docs/bufferbloat-cake.md §3.1).
- **Pin the vCPUs** (Proxmox `affinity:`), ≥ 3 cores to keep the M11 split (download, upload,
  services) on their own host cores; nothing else on them.
- **Passthrough beats virtio** for latency and keeps raw WAN frames off the host, but only for a
  NIC leatos has a driver for.
- **WAN bridge without a host IP**; Proxmox management on the LAN bridge with a static address.
- Proof is `scripts/bufferbloat.sh` on the real line in the VM, compared with the apu4 (A+ at
  90/18), with its validity checks.

## 3. Proxmox VM configuration (until the steps below land)

`/etc/pve/qemu-server/<vmid>.conf`:

```
machine: q35
bios: seabios
cpu: host
sockets: 1
cores: 4
numa: 0
memory: 1024
balloon: 0
affinity: 2-5
virtio0: local-lvm:vm-<vmid>-disk-0
boot: order=virtio0
net0: virtio=<mac>,bridge=vmbr1,firewall=0
net1: virtio=<mac>,bridge=vmbr0,firewall=0
serial0: socket
vga: serial0
watchdog: model=i6300esb,action=reset
agent: 0
tablet: 0
onboot: 1
startup: order=1,down=10
```

- `q35` (ECAM), SeaBIOS (image is Limine BIOS only), VirtIO Block (the store), virtio NICs with
  the Proxmox firewall off (it adds a bridge + veth pair per NIC: more queues, host conntrack).
- `net0` is `wan0` if PCI order follows the config: check the MACs in the boot log.
- Image: `scripts/apu-image.sh --config … --cmdline "mgmt_pass=… idle_spin_us=…"`, then
  `qm importdisk <vmid> leatos-apu4.img local-lvm` and `qm set <vmid> --virtio0 …`.
- Console: `qm terminal <vmid>` (or xterm.js in the GUI). With `vga: std` instead of
  `vga: serial0`, noVNC shows the same console (boot log, CLI) and its keyboard types into the
  CLI (US layout); both work at once with `serial0` kept.
- PPPoE on VLAN 848: tagged in leatos through a non-VLAN-aware bridge, or `tag=848` on `net0`.
- Passthrough instead of `net0`: `hostpci0: 0000:xx:00.0,pcie=1` (IOMMU on, i210/i211 only).
- Live migration (virtio only): use a common CPU type instead of `host`.
- To check on first boot: where SeaBIOS placed 64-bit BARs (above 4 GiB?), port order.

## 4. Steps

### Tier 1: needed for production use

1. **Entropy** (small). virtio-rng via `virtio_drivers::device::rng::VirtIORng`, mixed in like
   the CCP (`entropy::add_hardware`; one input among several); Proxmox `rng0:
   source=/dev/urandom`. Also RDRAND/RDSEED when the CPU is not AMD family 15h/16h (CPUID in
   `arch/x86_64`). Lab: `/api/status` names the source; negative control: no device → "timing
   only".
2. **KVM timer defaults** (small + a measurement). Detect KVM (CPUID 0x40000000 `KVMKVMKVM`),
   measure its idle wake-up (the timer table in docs/qemu.md) and default the spin window to it
   (likely 0–300 µs; `idle_spin_us=` still overrides). TSC frequency from CPUID 0x40000010 or
   0x15 when present, the PIT only as a fallback.
3. **Orderly shutdown on the ACPI power button** (small–medium). A fixed ACPI event (FADT PM1
   event block, `PWRBTN_STS`), no AML: poll it from the services task. To verify on ICH9: does
   the bit latch with `SCI_EN` clear, or must `ACPI_ENABLE` go to `SMI_CMD` first. Shutdown
   path: PPPoE PADT, leases saved, datapath stopped, ACPI S5. Useful on the apu4 as well
   (clean PPPoE exit on every reboot).

### Tier 2: Proxmox defaults and GUI integration

4. **QEMU guest agent** (medium). Proxmox `agent: 1,type=isa` gives the channel as an ISA serial
   port (COM2, 0x2f8, IRQ 3): the 16550 code suffices, no virtio-serial multiport (to confirm
   that Proxmox offers `type=isa`). Sans-IO JSON in a new `crates/proto-qga` with a fuzz target.
   Commands: `guest-sync-delimited`, `guest-ping`, `guest-info`, `guest-get-osinfo`,
   `guest-get-host-name`, `guest-get-time`, `guest-network-get-interfaces` (IPs in the Proxmox
   Summary), `guest-shutdown` (step 3's path), `guest-fsfreeze-*` (thawed, 0 filesystems: the
   store is power-cut-safe). Always refused: `guest-exec`, `guest-file-*`,
   `guest-set-user-password`. Lab: QEMU `-chardev socket … -device isa-serial`; negative
   control: `guest-exec` refused.
5. **PCI without MCFG** (small–medium): config access over ports 0xCF8/0xCFC behind
   `virtio-drivers`' `ConfigurationAccess`, in `arch/x86_64` (port I/O); neutral code unchanged.
   Makes `i440fx` work. Lab: `QEMU_MACHINE=pc` for smoke + lab.
6. **Ports by MAC** (medium): optional mapping in `config.toml` (e.g. `wan0 = "bc:24:11:…"`),
   validated; PCI order stays the default. Helps bare metal too. Lab: NIC order swapped in
   QEMU, mapping holds; negative control: without it the ports swap.
7. **VM image and docs** (small): install from the ISO (docs/install.md, M16 step 2, done in
   QEMU: `apu-image.sh --iso`, CD + `virtio0`, no host shell), or `apu-image.sh --target vm`,
   raw or qcow2 with a VM command line; optional `scripts/proxmox-create.sh` that only prints
   the `qm` commands. This file becomes the setup guide.

### Tier 3: comfort and performance

8. **Screen console** for noVNC: VGA text mode at 0xB8000 under SeaBIOS (`vga: std`,
   output-only log mirror, small) ✅ in QEMU (2026-11-28): `drivers::screen` +
   `crates/text-screen`. The Multiboot2 header asks for a framebuffer (optional, 32 bpp, the
   display's preferred mode: 1280x800 in QEMU), drawn with 7x16 Noto Sans Mono glyphs =
   182x50 characters; VGA text 80x25 when the loader left text mode (PVH). On only with a PCI
   display controller (class 03), `screen=0` off; kexec passes the framebuffer on.
   `QEMU_EXTRA="-device VGA,bus=pcie.0,addr=0x1 -display cocoa"` with `QEMU_PROXMOX=1` and a
   disk image shows it. Cost under TCG: ~120 ms of boot, ~11 ms per scrolled line (a redraw of
   the changed cells); KVM writes video memory at memory speed. Input: the PS/2 keyboard
   (i8042, ISA IRQ 1 via the MADT, `arch::kbd` + `crates/ps2-kbd`, scan code set 1, US layout)
   types into the CLI like the serial port; `kbd=0` off. No USB keyboard or `VirtIOInput`
   (Proxmox's keyboard is PS/2).
9. **virtio-scsi** (medium, own driver: INQUIRY, READ CAPACITY(16), READ/WRITE(16), SYNCHRONIZE
   CACHE): only if "use VirtIO Block" proves not enough.
10. **`VIRTIO_F_EVENT_IDX`** on virtio-net (small): fewer kicks and interrupts; measure CPU per
    Mbit/s under KVM before and after. No multiqueue (one queue pair per NIC, docs/smp.md).
11. **NIC drivers for passthrough** (large): i350 (igb family: check how far IDs and small
    register differences go), i225/i226 (igc, common in Proxmox mini PCs). Useful on bare
    metal too.

### Order

1, 2 → 3 → 7 and a first real Proxmox run (`bufferbloat.sh`, boot log checks) → 4 → 5, 6 →
tier 3 as needed. Each step runs what CLAUDE.md's table asks for, plus smoke and lab with
`QEMU_ACCEL=kvm` (also `LEATOS_BOOT=limine`, `QEMU_SMP=4`, `QEMU_NIC=igb`) on an x86_64 Linux
host.

## 5. Open questions

- An x86_64 Linux host for the KVM measurements (needed by step 2).
- The Proxmox host's NICs (virtio or passthrough) and IOMMU.
- Is leatos on Proxmox ever the main router? The router's uptime becomes the host's (Proxmox
  updates, reboots); until then the apu4 stays it.
