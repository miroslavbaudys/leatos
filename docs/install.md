# Installer: leatos installs itself from a USB stick or ISO (plan)

Status (2026-11-28): step 1 done in QEMU (module, heap carve-out, image format); the rest is
plan. Roadmap M16.

Today leatos is installed by flashing `target/apu4/leatos-apu4.img` (`scripts/apu-image.sh`) to
an SD card on the Mac; a Proxmox VM gets the same image with `qm importdisk`
(docs/proxmox.md §3). Neither works for an mSATA SSD inside the apu4 or for a VM created from
the Proxmox GUI. The goal: one **hybrid ISO** that boots as a CD-ROM in a VM and, written to a
USB stick, on the apu4; leatos then writes itself to the internal disk.

## 1. Choice: leatos installs itself (no Linux live system)

Considered and rejected: an Alpine live stick that runs `dd`. It needs no kernel code to
install, but leatos still needs AHCI to *run* from mSATA, and it adds a second OS to the
release (kernel, initrd, a musl `leatstore` build to keep the config).

Chosen: Limine on the ISO loads the leatos kernel **and the install image as a Multiboot2
module**; the kernel, booted with `install`, writes the module to a disk it has a driver for.

- **No USB, CD or ISO 9660 driver in leatos.** SeaBIOS reads the medium (int13 / El Torito);
  the image is in RAM when leatos starts.
- **The install medium can never be the target**, nor be mistaken for a store: leatos cannot
  see it.
- Targets: virtio-blk (Proxmox `virtio0`, works today), SD (`drivers::sdhci`, works today),
  AHCI (apu4 mSATA and SATA, Proxmox `sata0`: new driver, §3.1).
- On Proxmox the ISO is uploaded to the host's ISO storage and attached as the VM's CD drive;
  no shell on the host needed.

## 2. Flow

1. SeaBIOS boots the ISO (CD in a VM, USB stick on the apu4). Limine entry `install`:
   `protocol: multiboot2`, `path: boot():/boot/leatos`, `module_path: boot():/boot/install.lin`,
   `cmdline: install`.
2. leatos discovers the module (§3.2), checks its hash, starts only the console and the disk
   drivers: no datapath, no services, no WAN. A box mid-install never forwards traffic.
3. The console lists each disk with model, serial, size, partitions and whether it holds a
   store (the `store.rs` probe lines). The user types the **serial** (or PCI address) of the
   target; anything else aborts. `install_target=<serial>` skips the prompt (unattended,
   tests).
4. If the target has a store, its current `config` record is read and kept (§3.4).
5. The image is written (§3.3), read back and compared, flushed.
6. "Installed; remove the stick / eject the ISO" and a reboot. A medium left in boots the
   installer again, which writes nothing without step 3.

## 3. Work

### 3.1 AHCI driver (`drivers/ahci.rs`)

- PCI class 01:06, ABAR = BAR5 mapped with `mm::mmu::map_device`, registers through
  `mmio::Region`, unsafe confined to the module.
- Init: `GHC.AE`, per port COMRESET and spin-up, `IDENTIFY DEVICE` (model, serial, LBA48
  capacity); only ATA disks (signature 0x101), ATAPI ports are skipped.
- DMA memory from `mm` for the command list, FIS receive area and command table (PRDT).
- Commands: `READ DMA EXT`, `WRITE DMA EXT`, `FLUSH CACHE EXT` (a real flush, unlike the SD
  card; the store's two flushes per record use it). Polled, one command in flight, every wait
  yields, the buffers stay with the driver until the command completes (as virtio-blk).
- `Disk::Ahci` beside `Virtio` and `Sd`: the store, persistent upgrades and the probe lines in
  `/api/status` work unchanged.
- QEMU: q35 has ICH9 AHCI built in; aarch64 `virt` gets `-device ahci`.
  `QEMU_STORE_BUS=ahci` for store-, lease-, cli-, upgrade- and persist-test.
- apu4: the FCH SATA controller (expected at 00:11.0, AHCI mode) and the mSATA port: to check
  on the hardware as the SDHCI was (docs/config-and-storage.md §7).

Useful without the installer: an mSATA flashed in a USB adapter on the Mac with the normal
image boots and keeps its store on the mSATA.

### 3.2 Multiboot2 module

- `platform/multiboot2.rs` parses tag 3 (`mod_start`, `mod_end`, string) into `BootInfo`.
- **The module lies in RAM the memory map calls available**, and `parse` merges that RAM into
  the region after the kernel that becomes the heap. The module range must be cut out of it
  (or the region must end below it) before `heap::init`, else the heap overwrites the image.
  Proof in the test: the hash check of §3.3 runs after the heap is in use.
- PVH (`-kernel` in QEMU) has modules too (`modlist_paddr`): the same `BootInfo` field, so
  `-initrd` can feed the installer in quick tests.
- Done (2026-11-28): `BootInfo.module`, `mm::heap::region` (the larger side of RAM around the
  module, whole pages), `mmu` maps it read-only, `mm::heap::module`; `install::check_module`
  logs `install image : ok …` or `invalid (…)` after the heap and the packet pool are in use.
  Seen in QEMU: **Limine puts the module right after the kernel** (the heap went above it),
  QEMU's `-initrd` at the top of RAM (the heap and staging below it). Negative controls: a
  flipped byte → `invalid (SHA-256 mismatch)`; `module_carve=0` under Limine → the heap
  overwrites the module, `invalid (not an install image (magic))`. Quick test:
  `QEMU_EXTRA="-initrd img.lin" scripts/qemu-run.sh <x86_64 ELF>`.

### 3.3 Install image format (`crates/boot-image` or a new `crates/install-image`)

The raw image is 80 MiB of mostly zeros; the module is a list of extents instead:

- Header: magic `LEATINST`, version, target size needed, SHA-256 of everything after it.
- Extents `(lba, sectors, data)` in ascending order; every sector of the image **not** listed
  is written as **zeros**, not skipped. Reason: an old leatos record on a reused disk has a
  valid CRC; left in a store slot it could be taken as current.
- Also zeroed: the last 33 sectors of the target (a backup GPT from a previous OS would confuse
  Linux and some firmware).
- Sans-IO parser (`#![forbid(unsafe_code)]`), host tests, a fuzz target `install_image`.
- Done (2026-11-28): `crates/install-image` (`build`, `parse`, `Image::plan`; host tests flip
  every byte, forge tables with valid hashes; fuzz target `install_image`), `leatstore
  install-image <raw> <out>` (checks that the plan reproduces the raw image). An 80 MiB apu4
  image with a debug kernel: 5 extents.
- Built by `scripts/apu-image.sh --iso`: the normal image as now, converted to the extent
  format, plus a Limine **hybrid ISO** (`xorriso` + `limine bios-install`; `brew install
  xorriso`) with the kernel, the module and two entries: `install` and "boot leatos from the
  internal disk" (Limine chainloads it, so a forgotten stick still gets the router up).

### 3.4 Install mode in the kernel (`install.rs`)

- Boot arguments `install` and `install_target=` (rows in docs/boot-arguments.md).
- Target checks: big enough, not read-only, confirmed (§2 step 3).
- **Keeping the config:** before writing, `store::open` on the target alone; its current
  `config` record is held in RAM and, after the image is written, stored through
  `config-store` in the new store. Trials and stored kernels are not kept: the new boot
  partition kernel is the installed version. `install_keep=0` installs with the image's config
  (or defaults).
- **Exception to "the kernel never formats"** (docs/config-and-storage.md, Safety): only with
  `install` on the command line, a module whose hash checks, and the confirmation. That
  section names this exception.
- Progress on the console in MiB; the read-back compares against the module, not against what
  was sent.

### 3.5 Which store (needed once two disks can hold leatos)

`store::open` takes the first disk in PCI order with a store. With leatos on the SD card and
the mSATA, AHCI (00:11) wins over SD (00:14.7): Limine may boot the SD's kernel while
`upgrade::boot` enters a trial from the mSATA's store, and saves land there. The store header
has no identity to tell them apart.

- A random **store ID** in the store header (`leatstore format`, and the installer when it
  writes a store), a version bump in `crates/config-store` (fuzz target `store`).
- The generated `limine.conf` passes `store_id=`; the probe uses only that store. Without
  `store_id=` the old behaviour stays, with a warning when more than one store is found.
- Do this together with the AHCI driver, before any apu4 has leatos on two disks.

## 4. Tests (`scripts/install-test.sh`)

QEMU q35, SeaBIOS, the ISO as a CD (as Proxmox attaches it) and as a USB stick
(`qemu-xhci` + `usb-storage`), target virtio-blk and AHCI (`LEATOS_ARCH=x86_64`; aarch64 has
no SeaBIOS, so only the PVH `-initrd` path there).

| Check | Negative control |
|---|---|
| empty target: installed, reboot without the medium, store + seeded config used | wrong serial typed → target unchanged (hash before/after) |
| image hash checked | one byte flipped in the module → nothing written |
| reinstall over leatos: config kept, old slots zeroed | `install_keep=0` → image config; an old record planted in a skipped slot is gone |
| module survives the heap (§3.2) | carve-out disabled (debug switch) → hash fails |
| two stores + `store_id=` → the right one | no `store_id=` → warning in the log |
| AHCI store, upgrades, persist (`QEMU_STORE_BUS=ahci`) | as the virtio and SD runs |

On the hardware: apu4 boots the stick, installs to the mSATA, boots from it without the stick;
SeaBIOS boot order (USB before mSATA?) noted here. Proxmox: VM from the GUI with the ISO as CD
and `virtio0`, installed, ISO ejected, boots.

## 5. Steps

| Step | Size | Gives |
|---|---|---|
| 1. Module tag + heap carve-out, extent format crate ✅ (QEMU, 2026-11-28) | 2–3 days | image in RAM, checked |
| 2. Install mode on virtio-blk / SD, `--iso`, `install-test.sh` | ~1 wk | **Proxmox install from ISO** |
| 3. AHCI driver + `QEMU_STORE_BUS=ahci` tests | 1–1.5 wk | mSATA / `sata0` as boot + store |
| 4. Store ID + `store_id=` | 2–3 days | safe with two leatos disks |
| 5. apu4: AHCI at 00:11, USB stick install to mSATA, boot order | — | hardware check |

Step 2 serves Proxmox (M13 step 7) without AHCI; steps 3 and 4 go together before the apu4
gets an mSATA install.

## 6. Open questions

- UEFI: Proxmox `bios: ovmf` and newer boards. Limine can put a UEFI loader on the same ISO,
  but leatos has no UEFI entry (Multiboot2 from Limine UEFI hands over in 64-bit mode with a
  UEFI memory map): separate step.
- Does SeaBIOS on the apu4 boot a hybrid ISO from USB as well as a plain MBR image (it should;
  to verify)?
- Install over the network instead (upload the image to a running leatos and pick the target
  disk) reuses §3.3 / §3.4 without a stick: later, if wanted.
