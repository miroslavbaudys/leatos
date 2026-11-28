# Installer: leatos installs itself from a USB stick or ISO (plan)

Status (2026-11-28): steps 1–4 done in QEMU (module, heap carve-out, image format; install mode,
the installer ISO, `scripts/install-test.sh`; the AHCI driver; the store ID); the hardware checks
(step 5) are left. Roadmap M16.

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
module**; the kernel, booted with `install=1`, writes the module to a disk it has a driver for.

- **No USB, CD or ISO 9660 driver in leatos.** SeaBIOS reads the medium (int13 / El Torito);
  the image is in RAM when leatos starts.
- **The install medium can never be the target**, nor be mistaken for a store: leatos cannot
  see it.
- Targets: virtio-blk (Proxmox `virtio0`, works today), SD (`drivers::sdhci`, works today),
  AHCI (apu4 mSATA and SATA, Proxmox `sata0`: new driver, §3.1).
- On Proxmox the ISO is uploaded to the host's ISO storage and attached as the VM's CD drive;
  no shell on the host needed.

## 2. Flow

1. SeaBIOS boots the ISO (CD in a VM, USB stick on the apu4). Limine entry "leatos installer":
   `protocol: multiboot2`, `path: boot():/boot/leatos`, `module_path: boot():/boot/install.lin`,
   `cmdline: install=1` (+ `--install-args`).
2. leatos discovers the module (§3.2), checks its hash, starts only the console and the disk
   drivers: no datapath, no services, no WAN. A box mid-install never forwards traffic.
3. The console lists each disk with its PCI address, model, size and partitions
   (`  00:01.0  virtio-blk 128 MiB, p1 0x0c 63 MiB, p2 0xda 16 MiB`). The user types the
   target's **PCI address**; anything else aborts. `install_target=<PCI address>` skips the
   prompt (unattended, tests). The PCI address, not a serial: every disk has one, virtio-blk
   and SD cards do not always have a serial.
4. If the target has a store, its current `config` record is read and kept (§3.4).
5. The image is written (§3.3), read back and compared, flushed.
6. The kept config is stored in the new store; "done. Remove the install medium" and a reset
   after 5 s. A medium left in boots the installer again, which writes nothing without step 3
   (`install_target=` on a medium left in would install again: for tests and one-off use).
7. Any stop before the first write ends in `install: <why>: nothing written`; a failure after
   it in `install: FAILED: …` (run the installer again). Then the installer waits for a reset.

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

Done in QEMU (2026-11-28), as above, plus:
- No COMRESET on a port whose PHY sees no device (`DET` = 0 after 50 ms): q35's built-in
  controller has six ports, and a 1 s link wait each slowed every boot by seconds (the smoke
  test's two-boot watchdog case timed out). `DET` = 1 (device, no link) gets the COMRESET.
- `Disk::open` gives one disk per port, named `<PCI address>/<port>` (`00:1f.2/0`): the name in
  the store probe lines and the installer's list, and what `install_target=` takes. ATAPI
  devices are listed as `ATAPI (CD/DVD): not used` (q35 has an empty CD drive by default).
- The installer skips a disk that holds its own ISO (ISO 9660 volume ID `LEATOS_INSTALL` at
  byte 32768): an ISO on a SATA disk is visible to leatos, a USB stick or a CD is not.
- `Disk::flush` is async (FLUSH CACHE can take seconds on a disk).
- Tests: `QEMU_STORE_BUS=ahci` (store image on port 0 of a `-device ahci`, as Proxmox attaches
  `sata0`): store-, lease-, cli-test on aarch64 and x86_64, persist- and install-test pass;
  the installed SATA disk boots through SeaBIOS (`QEMU_DISK=store`) and finds its store.

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
- Built by `scripts/apu-image.sh --iso [--install-args "…"]` (done 2026-11-28,
  `target/apu4/leatos-install.iso`): the normal image (all of its options apply: `--config`,
  `--cmdline`, `--mgmt-pass`, …), converted to the extent format, plus a Limine **hybrid ISO**
  (`xorriso -as mkisofs` with `--protective-msdos-label -partition_offset 16`, so `limine
  bios-install` accepts the MBR; `brew install xorriso`) with the kernel and the module. One
  entry; a second one that chainloads the internal disk (a forgotten stick still gets the
  router up) is not done.

### 3.4 Install mode in the kernel (`install.rs`)

- Boot arguments `install=1`, `install_target=`, `install_keep=0` (docs/boot-arguments.md).
  `kmain` calls `install::run` right after PCI, before any store is opened or stored kernel
  entered; no watchdog is armed.
- Target checks: big enough, not read-only, confirmed (§2 step 3).
- **Keeping the config:** before writing, `store::probe` on the target alone; its current
  `config` record (the newest this kernel reads) is held in RAM if it parses and, after the
  image is written, stored with `Store::write_record` in the new store (a newer seq than the
  image's seeded config). An **unconfirmed trial** stops the install (nothing written): which
  of the two the user wants is not the installer's to guess; confirm or revert it, or
  `install_keep=0`. Leases, trials and stored kernels are not kept: the new boot partition
  kernel is the installed version. `install_keep=0` installs with the image's config (or
  defaults).
- **Exception to "the kernel never formats"** (docs/config-and-storage.md, Safety): only with
  `install` on the command line, a module whose hash checks, and the confirmation. That
  section names this exception.
- Progress on the console every 16 MiB; the read-back compares against the module, not
  against what was sent. Waiting for input polls the console every 20 ms (`block_on` spins: one
  core busy while the prompt waits).

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

Done in QEMU (2026-11-28), with two changes to the plan:
- **No layout version bump:** the ID is a u64 in header bytes 280..288, which every earlier
  header has zero (0 = no ID), under the same CRC. A bump would make every kernel from before
  it (a rollback target, the golden kernel of an older boot partition) refuse the store.
- **The installer keeps the image's ID** instead of writing a new one: the ID is also in the
  image's `limine.conf` on the FAT partition, which the installer would have to rewrite. Two
  disks from one ISO in one machine would then share an ID, so the installer **refuses** a
  target when another disk there already holds a store with the image's ID ("build a new ISO").
  Every `apu-image.sh` run formats a new store, so a new ID.
- `apu-image.sh` formats the store before writing `limine.conf`; both entries get
  `store_id=`. `leatstore id <img>` prints it, `show` and the boot log name it.
- `store::open` probes every disk now (it stopped at the first store). `store_id=` that no disk
  has, or that is not an ID: no store (defaults), said in the log: a foreign disk's store is
  never used in its place. Without `store_id=` (the apu4's current SD card, QEMU `-kernel`
  boots): the first store, `WARNING: N stores found` when there are several.
- Tests: `store-test.sh` "two stores" (a second virtio-blk later in PCI order: without the ID
  the first + warning, the second's ID → the second, an unknown or bad ID → no store);
  `install-test.sh` "twice" (refused, both disks unchanged) and the installed disk boots
  choosing its store by `store_id=`.

## 4. Tests (`scripts/install-test.sh`)

QEMU q35 under TCG, SeaBIOS, the ISO as a CD (`QEMU_CDROM`, as Proxmox attaches it) and as a
disk (`QEMU_DISK`, what a USB stick is to the BIOS), target virtio-blk (default, ~1 min) or SD
(`QEMU_STORE_BUS=sd`, ~4 min); x86_64 only (aarch64 has no SeaBIOS). Done 2026-11-28, both
buses pass:

| Case | Checks | Negative control |
|---|---|---|
| fresh | 0xff target: written + verified, image's config stored, a gap zero, sectors past the image still 0xff, last 33 zero; boots from the disk (`QEMU_DISK=store`, virtio only) with its config | – |
| wrong | – | an address not listed typed → nothing written, target hash unchanged |
| keep | another config carried over; a planted leases record gone | – |
| trial | – | unconfirmed config trial on the target → nothing written, hash unchanged |
| unattended | `install_target=` + `install_keep=0`: no prompt, the image's config wins | (the keep case) |
| corrupt | – | one byte of the ISO's module flipped → SHA-256 mismatch, nothing written |
| stick | the ISO boots as a disk; the installer offers no disk (never its own medium) | – |

Not in the script: module vs heap (§3.2; `module_carve=0` control, by hand); a real USB stick
(`qemu-xhci` + `usb-storage`, booted by hand 2026-11-28: SeaBIOS boots it, same result as
`stick`). AHCI targets (`QEMU_STORE_BUS=ahci`, ~2.5 min) pass since step 3; on q35 the `stick`
case's disk sits on the built-in AHCI controller and is skipped as the install medium. To come
with step 4 (done): two stores with and without `store_id=` (store-test), the same ISO twice
into one machine (install-test `twice`).

On the hardware: apu4 boots the stick, installs to the mSATA, boots from it without the stick;
SeaBIOS boot order (USB before mSATA?) noted here. Proxmox: VM from the GUI with the ISO as CD
and `virtio0`, installed, ISO ejected, boots.

## 5. Steps

| Step | Size | Gives |
|---|---|---|
| 1. Module tag + heap carve-out, extent format crate ✅ (QEMU, 2026-11-28) | 2–3 days | image in RAM, checked |
| 2. Install mode on virtio-blk / SD, `--iso`, `install-test.sh` ✅ (QEMU, 2026-11-28) | ~1 wk | **Proxmox install from ISO** |
| 3. AHCI driver + `QEMU_STORE_BUS=ahci` tests ✅ (QEMU, 2026-11-28) | 1–1.5 wk | mSATA / `sata0` as boot + store |
| 4. Store ID + `store_id=` ✅ (QEMU, 2026-11-28) | 2–3 days | safe with two leatos disks |
| 5. apu4: AHCI at 00:11, USB stick install to mSATA, boot order (⏳ 2026-11-28, below) | — | hardware check |

Step 2 serves Proxmox (M13 step 7) without AHCI; steps 3 and 4 go together before the apu4
gets an mSATA install.

## 6. Open questions

- UEFI: Proxmox `bios: ovmf` and newer boards. Limine can put a UEFI loader on the same ISO,
  but leatos has no UEFI entry (Multiboot2 from Limine UEFI hands over in 64-bit mode with a
  UEFI memory map): separate step.
- Does SeaBIOS on the apu4 boot a hybrid ISO from USB as well as a plain MBR image? **Yes**
  (2026-11-28): with the stick in, SeaBIOS boots it first, Limine shows "leatos installer".

On the apu4 (2026-11-28): FCH SATA `00:11.0 1022:7801 class 01.06`, AHCI 1.3, 2 ports (port 0 =
the "mSATA / mPCIe 3" slot, port 1 = the SATA connector). The Transcend TS16GMSA370 in the mSATA
slot links at 6 Gb/s but never sends its signature (TFD 0x80, SIG 0xffffffff) to leatos, SeaBIOS
("No bootable device") or Linux (OpenWrt: `ata1: COMRESET failed ... reset failed, giving up`),
also after reseating: a faulty SSD. An ADATA SU800 on port 1 works under Linux. The driver now
logs each recovery step with the port's registers (`ahci port N ...: TFD .. SSTS .. SERR ..`).
- Install over the network instead (upload the image to a running leatos and pick the target
  disk) reuses §3.3 / §3.4 without a stick: later, if wanted.
