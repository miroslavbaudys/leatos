# Kernel upgrades

Two ways to replace the running kernel over the network (x86_64 only:
both rely on `arch::kexec`):

| | In RAM | Persistent |
|---|---|---|
| Request | `POST /api/upgrade` | `POST /api/upgrade/persist` |
| Script | `scripts/apu-upload.sh` | `scripts/apu-upload.sh --persist` |
| Written to the SD card | nothing | the kernel, into the store's `images` area |
| After a power cycle | the boot partition's kernel | the stored kernel |
| Bad kernel | a power cycle recovers | rolled back automatically |
| Command line | the current one, or `X-Cmdline` | the boot partition's (Limine), `X-Cmdline` refused |

The in-RAM upgrade is the development loop. The persistent upgrade replaces
reflashing the SD card for every new kernel.

## 1. Pieces
- **Boot partition kernel** (`/boot/rrouter` on the FAT partition, started
  by Limine): the **loader** and the last fallback. The kernel never
  writes the FAT partition, so this kernel changes only when the card is
  reflashed (`scripts/apu-image.sh`). It must already contain the loader
  (any kernel from this change on does).
- **`images` area** of the store (docs/config-and-storage.md §2): two
  slots, A and B, about 7 MiB each on the 16 MiB store partition (a
  stripped release kernel is about 1.6 MB). A record's payload is the
  kernel ELF (record schema version 1, `upgrade::IMAGE_FORMAT`), with the
  record's CRC-32 over it. Writes follow the store's rules: the slot
  that is not current, payload first, header last, read back, so a power
  cut while storing leaves the previous kernel.
- **Trial flags** in the record header, as for config trials: bit 0 trial,
  bit 1 booted.

## 2. Boot
Every boot starts the boot partition's kernel. In `kmain`, after PCI and
the store are up and the hardware watchdog is probed and armed, but
before the config is loaded and before any NIC is brought up,
`upgrade::boot` decides:

| Boot argument `image=` | Meaning |
|---|---|
| (none) | this is the boot partition's kernel: act as the loader |
| `A:<seq>`, `B:<seq>` | entered by the loader from that record (added by the loader) |
| `ram` | entered by an in-RAM upgrade (added by `POST /api/upgrade`): no loading |
| `golden` | ignore stored kernels (recovery; the second Limine menu entry) |

As the loader, it reads the current `images` record:

| Current record | Action |
|---|---|
| none valid | boot itself |
| confirmed | read, check (`boot_image::parse`, Multiboot2 header), enter |
| trial, booted bit clear | set the booted bit (one sector), enter |
| trial, booted bit set | it never confirmed: erase it, look again (the previous record, or boot itself) |
| fails the checks | a trial: erase it, look again; a confirmed one: boot itself |

Entering = copy the payload into the staging area, `upgrade::prepare`,
re-arm the hardware watchdog with its full timeout, then `upgrade::exec`
(the other cores are parked, the image is copied into place and entered
like a Multiboot2 loader would, with the same command line plus
`image=<slot>:<seq>`). The loader runs before `config::load`, so a config
trial is marked booted only by the kernel that will run it.

`/api/status` has `build` (git commit of the running kernel,
`kernel/build.rs`) and `image`: `source` (`boot partition (...)`, `store
(slot A, seq 3)`, `in-RAM upgrade`) and `trial` (`{seq, remaining_s}` or
`null`).

## 3. Upgrade and confirm
1. `POST /api/upgrade/persist` (Basic auth): the body is streamed into the
   staging area and checked as for the in-RAM upgrade (`X-Image-CRC32`,
   ELF and Multiboot2 checks). Then the services task writes it to the
   `images` area as a trial record and the router reboots (firmware
   reset, so the whole boot path is tested: firmware, Limine, loader).
2. The loader marks the trial booted and enters it. The new kernel shows
   a banner with a countdown (`trial_secs`, default 120 s).
3. `POST /api/upgrade/confirm` clears the flags: from now on the loader
   enters this kernel at every boot. `scripts/apu-upload.sh --persist`
   confirms only after the router answers again **and reports the
   uploaded build** as the trial: the kernel booted, has a network and
   serves the web interface.
4. `POST /api/upgrade/revert`, or no confirm within `trial_secs`: the
   trial is erased and the router reboots into the previous kernel.

The next persistent upgrade goes into the other slot, so the last
confirmed kernel always stays until a newer one is confirmed.

While a trial kernel runs, refused with 409: another upgrade (in RAM or
persistent), config saves (web and serial console), and a persistent
upgrade while a config trial is pending. A newer kernel could store a
config the kernel a rollback returns to cannot read
(docs/config-and-storage.md §4), and two trials at once could revert
each other's previous record.

## 4. What a bad kernel does
| Failure of the trial kernel | Recovery |
|---|---|
| panic, exception | `fatal` resets → booted bit set → rolled back |
| triple fault | CPU reset → rolled back |
| hang, any core | cross-core watchdog or the hardware watchdog resets → rolled back |
| hang before its watchdog starts | the hardware watchdog the loader armed (the probe keeps a running timer running) |
| boots, but no network or web interface | nobody confirms → reboot after `trial_secs` → rolled back |
| power cut, reset by hand | booted bit set → rolled back |
| power cut while it is stored | header written last → the previous kernel |
| corrupt record | CRC fails → the previous record, or the boot partition's kernel |

Not covered: a kernel booted with `watchdog=0` that hangs stays hung
until a power cycle (which then rolls it back). A kernel that confirms
itself is not possible: only a request confirms.

## 5. Recovery
- Limine menu (serial, 3 s timeout): the second entry adds `image=golden`
  and boots the boot partition's kernel without looking at the store.
- Reflashing the card (`scripts/apu-image.sh`) wipes the store, stored
  kernels included.

## 6. Hardware watchdog across kernels
Probing the watchdog (i6300esb, AMD FCH) never stops a timer the previous
kernel left running; it reloads it. `watchdog::arm_early` arms it right
after the probe (also on normal boots: a hang while bringing up the NICs
resets), the loader re-arms it right before the jump, and
`watchdog::start` arms it for good once the boot is done. With
`watchdog=0`, `start` stops a timer the previous kernel left running.

## 7. Tests
`scripts/persist-test.sh` (x86_64, QEMU; `QEMU_STORE_BUS=sd` for the SD
card path): QEMU's `-kernel` plays the boot partition's kernel (every
reset boots it again).
- Empty store → the loader boots itself; refusals (401, 422 for garbage
  and for `X-Cmdline`, 409 for confirm without a trial) store nothing.
- Persistent upload → trial, booted bit set, 409 for config saves and
  upgrades during the trial, 401 for confirm without password; confirm →
  flags cleared, entered again after a reboot. An in-RAM upgrade from a
  stored kernel does not chain-load.
- Rollbacks, each with a validity check that the bad kernel was entered
  as a trial and failed as intended: a `fault-panic` kernel, a
  `fault-hang` kernel, no confirm, roll back now, QEMU killed during the
  trial. Each ends on the confirmed kernel with the trial slot erased.
- Negative controls: `image=golden` ignores stored kernels; a corrupt
  record → the boot partition's kernel; `PERSIST_TEST_CONTROL=no-confirm`
  makes the "entered again after a reboot" check fail.
