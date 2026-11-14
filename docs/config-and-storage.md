# Configuration and persistent storage

How rrouter keeps its configuration (and later, other state) across
reboots, and how the management web interface changes it. Part of M8.

## 1. Principles
- **No filesystem for writes.** The kernel never writes the FAT32 boot
  partition. Persistent data lives in a separate raw partition with a
  small, power-fail-safe record format.
- **Every write is atomic.** A power cut at any moment leaves either the
  old or the new version, never a mix, and never requires repair.
- **Config never prevents booting.** No store, a corrupt store or an
  unparsable config means compiled-in defaults plus a log line.
- **Config is intent, state is separate.** Things the user sets
  (addresses, reservations, firewall rules) and things the router learns
  (dynamic leases) live in different areas, written at different rates.
- **Sans-IO.** The format, slot selection and write planning are in
  `crates/config-store`; the schema and validation in `crates/config`.
  The kernel only moves sectors.

## 2. Disk layout
`scripts/apu-image.sh` (and the QEMU scripts) create a second MBR
partition next to the boot partition:

```
p1  FAT32, 1–64 MiB    Limine + kernel (read-only for the kernel)
p2  type 0xda, 16 MiB  rrouter store (64–80 MiB; formatted by tools/rrstore)
```

The store starts with a **store header** (sector 0) that lists the
**areas**. Each area has two equal **slots**, A and B:

| Area | Offset | Slot size | Contents | Written |
|---|---|---|---|---|
| `config` | 4 KiB | 256 KiB | `config.toml` (UTF-8 TOML) | on Save |
| `leases` | 1 MiB | 128 KiB | dynamic DHCP leases (binary) | in batches (e.g. every 10 min) and on shutdown |
| `images` | 2 MiB | rest / 2 | kernel images for persistent upgrades (later) | on persistent upgrade |

The slot size is stored in the header, so areas can grow in a later
layout without reformatting the logic. Sector size is 512 bytes.

### Store header (sector 0)
| Bytes | Field |
|---|---|
| 0..8 | magic `RRSTORE1` |
| 8..10 | layout version (1) |
| 10..12 | sector size (512) |
| 12..14 | number of areas (≤ 16) |
| 16..24 | partition size in sectors when formatted |
| 24..280 | areas, 16 bytes each: name (8, NUL-padded), first sector (u32), slot size in sectors (u32) |
| 508..512 | CRC-32 of bytes 0..508 |

All integers little endian. Areas must lie inside the partition, after
sector 0, and must not overlap.

### Record (one per slot)
A slot is one header sector followed by the payload:

| Bytes | Field |
|---|---|
| 0..4 | magic `RREC` |
| 4..6 | record format (1) |
| 8..16 | area name (a record copied to the wrong place is rejected) |
| 16..24 | `seq`: sequence number, higher = newer |
| 24..28 | payload schema version (e.g. config `version`) |
| 28..32 | payload length in bytes |
| 32..36 | CRC-32 of the payload |
| 36..40 | flags: bit 0 trial, bit 1 trial booted (§6); 0 = confirmed |
| 508..512 | CRC-32 of bytes 0..508 |

## 3. Reading
For each area: read both header sectors, then each payload. A slot is
**valid** if both CRCs match, the magic and area name are right and the
payload fits the slot. The **current** record is the valid one with the
highest `seq` **whose schema version this kernel understands**. A slot
with a newer schema than the kernel supports is skipped, so a kernel
rollback lands on the last config it can read instead of on defaults.

Neither slot valid: the area is empty (defaults, no leases).

## 4. Writing
1. Validate the payload in RAM (for config: size ≤ 64 KiB, TOML parses,
   `deny_unknown_fields`, `validate()`). On failure, nothing is written.
2. Target = the slot that is **not current** (never overwrite what the
   router booted with). New `seq` = highest valid `seq` + 1.
3. Write the payload sectors, flush.
4. Write the header sector, flush. Read back and verify.

The header goes last, so a slot becomes valid only when everything else
is on disk:

| Power cut during... | Result at the next boot |
|---|---|
| payload write | target payload CRC fails → previous record |
| header write | header CRC fails → previous record |
| after the header | new record |

`crates/config-store` tests cut power after every sector of a write and
tear every sector in half, and check that the result is always exactly
the old or exactly the new record.

**Safety:** the kernel writes only a partition with type 0xda **and** a
valid store header. It never formats; only the image and QEMU scripts
do. A wrong disk or a foreign USB stick is never written.

**Wear:** one config save writes at most 513 sectors; areas alternate
between two slots. Negligible for SD cards and SSDs.

**Known limit (schema versions):** the previous slot survives one save.
After two saves with a new schema, a rollback to an old kernel finds no
config it can read and uses defaults. During a kernel trial (persistent
upgrades, later), the kernel therefore saves at most once until the
image is confirmed.

## 5. Configuration
### Format
One TOML document, `config.toml`, parsed with the `toml` crate (no_std,
`serde`, `#![forbid(unsafe_code)]` except for code paths we do not
enable). Unknown fields are errors, so typos are reported instead of
ignored. Nesting depth is bounded by the parser; size is bounded (64 KiB)
before parsing.

```toml
version = 1

[lan]
ipv4 = "10.10.0.1/24"
domain = "lan"

[lan.dhcp]
range = ["10.10.0.100", "10.10.0.199"]   # optional: default .100–.199
lease_secs = 43200

[[lan.dhcp.static]]
mac = "52:54:00:00:00:05"
ip = "10.10.0.10"
hostname = "nas"

[dns]
cache_entries = 4096
rebind_protection = true

[shaping]
up_kbit = 18000          # optional: unset = not shaped
down_kbit = 90000
overhead = 20
ecn_up = false
ecn_down = true
qdisc = "cake"           # cake | fq_codel | codel
isolation = "triple-isolate"

[mgmt]
on_wan = false
```

Schema version 1 (`crates/config`) has the sections above. Every field
has a default, so a file may set only what it changes. Later versions add
`[wan]`, `[firewall]` (rules, `[[firewall.forward]]`), VLANs and the
management password hash, as the kernel implements them:

```toml
[[firewall.forward]]     # later
name = "nas-https"
proto = "tcp"
wan_port = 8443
to = "10.10.0.10:443"
```

The full target schema is in `docs/soho-features.md`. List entries
(reservations, rules, forwards) carry a stable key (`name`, `mac`) so the
web interface can edit or delete one entry. The bounds the validation
enforces (version 1): prefix 8–29, lease 60 s–30 days, ≤ 1024
reservations, DNS cache 16–65536 entries, rates 64 kbit/s–10 Gbit/s,
overhead ≤ 256 bytes. Validation problems carry a path
(`lan.dhcp.static[2].ip`, indices from 0) for the web interface.

### Layering
```
compiled-in defaults ← stored config.toml ← boot arguments
```
Boot arguments (`lan=`, `shape_up=`, ...) still override, for
development and recovery. `config=defaults` ignores the store entirely
(recovery: add it in the Limine menu over serial).

### Moving boot arguments into the config
Boot arguments override the stored config, field by field. `/api/status`
lists them (`overrides`: field path → argument), and the form marks each
such field. `GET /api/config/effective` returns the config in effect;
saving it ("Use values in effect" on the page) and then removing the
arguments leaves the router with the same settings from the store. For a
new SD image: `scripts/apu-image.sh --mgmt-pass --config FILE` writes
FILE (validated) into the store, and the command line keeps only
`mgmt_pass=` (no password field in the schema yet). Lab fixtures (the
`nas` reservation) are added to the defaults on virtual machines only,
so they never end up in a hardware config.

### Validation
`crates/config` checks across sections before anything is saved: the
DHCP pool and reservations lie inside the LAN subnet, no two reservations
share an address or MAC, forward targets are on a LAN, names are unique.
Settings the kernel does not implement yet are rejected as unsupported.

### Schema versions
`version` in the document. A newer kernel migrates older documents on
load and writes the new version only on the next save. See §4 for
rollbacks.

### Secrets
- The management password is stored as a PBKDF2-SHA256 hash.
- Secrets that must be usable in clear (PPPoE password) are stored as
  is, like on other SOHO routers.
- `GET /api/config` and the TOML export omit secret fields; an upload
  without a secret field keeps the current value.

### Comments
The web interface writes the document from the parsed structs, so
comments and custom ordering in an uploaded file are not kept. The file
is UI-managed, with import/export.

## 6. Management interface
The status page has a **Configuration** section: a form for LAN (address,
domain, DHCP pool, lease time), DHCP reservations, DNS, shaping and
management, with Save, Discard, Export (`config.toml`) and Import. Fields
named by validation issues are highlighted.

- `GET /api/config`: current config as TOML (secrets omitted), without
  boot-argument overrides (what a save starts from). `GET
  /api/config.json`: the same as JSON (the form).
- `POST /api/config` (Basic auth): TOML, or JSON with `Content-Type:
  application/json` (the form). Validate, save, reboot. Errors: 422 with
  the parser or validation message (line and column) and, for
  inconsistencies, `issues: [{path, msg}]`; 409 while a trial is pending;
  501 without a store. The kernel stores the canonical TOML of the parsed
  structs. The save runs in the services task and yields while the disk
  works.
- `POST /api/config/confirm`, `POST /api/config/revert` (Basic auth; 409
  without a pending trial). `/api/status` has `config` (where it came
  from), `store` and `trial` (`{seq, remaining_s}` or `null`).
- Shaper rates apply live; Save makes them persistent. (Not yet: a change
  reboots.)

### Confirm or revert
A save that changes the LAN address or the management settings
(`Config::needs_trial`) could cut the user off, so it is written as a
**trial** (record flag bit 0):

1. Boot finds a trial without the booted bit: rewrites its header with
   the booted bit (one sector) and runs it. The web interface shows a
   banner with a countdown; Confirm rewrites the header with flags 0.
2. No Confirm within 120 s (boot argument `trial_secs=` for tests), or
   Revert: the trial's header sector is zeroed (the slot becomes empty)
   and the router reboots into the previous record.
3. Boot finds a trial **with** the booted bit: the last boot never
   confirmed it (power cut, crash, reset). It is erased the same way
   before anything uses it.

Every step writes one header sector. A torn write fails the CRC, so the
previous record wins: the outcome is always the trial or the previous
config. No save is accepted while a trial is pending, since it would
overwrite the previous record, the only confirmed one. Without a previous
record, a revert lands on the defaults.

## 7. Drivers
- QEMU: virtio-blk (`drivers::virtio_blk` over `virtio-drivers`
  `VirtIOBlk`), aarch64 and x86_64. Polled, one request in flight; the
  request's buffers belong to the driver until the device completes it,
  so a dropped caller never leaves the device writing freed memory.
  Requests are at most 64 KiB (`crate::store` splits). Known limit:
  `virtio-drivers` has only a blocking flush, so each flush (two per
  record) spins until QEMU answers.
- Host tool `tools/rrstore` (`cargo run -p rrstore -- create|format|show|put|get|corrupt`):
  creates and formats store images, writes and reads records through the
  same `config-store` code, and flips payload bytes for negative controls.
  `QEMU_STORE=img scripts/qemu-run.sh` attaches an image as virtio-blk.
- apu4: the SD slot, `drivers::sdhci` (any standard SDHCI 2.0/3.0, PCI
  class 08:05). On the apu4 (checked 2026-11-14): AMD FCH SD host at
  00:14.7, SDHCI 2.00, base clock 50 MHz; an 8 GB SDHC card initialises
  and its MBR reads. PIO through the buffer data port, polled, no DMA and
  no interrupts. SD v1/v2, SDSC (byte addresses) and SDHC/SDXC (block
  addresses), 4-bit bus at 25 MHz, multi-block transfers with Auto CMD12.
  A write completes only after the card has programmed it, so the store's
  flush is a no-op there. Every wait yields. A transfer abandoned midway
  is cleaned up (line reset + CMD12) before the next one. Card detect
  that is not wired is overridden, and the commands decide whether a card
  is there. AHCI if an mSATA SSD is used.
- QEMU: `QEMU_STORE_BUS=sd` attaches the store image as an SD card behind
  `sdhci-pci` (image size a power of two; QEMU emulates SDSC up to 2 GiB
  and SDHC above). `scripts/store-test.sh` runs over it too.
- `/api/status` lists what the store probe found on each block device
  (`disks`): model, size, partitions, store or why not.
- Drivers are async and run at service priority: a store write never
  blocks the datapath.

## 8. Tests
- `crates/config-store`: layout and record round trips, every corruption
  case, slot selection with schema versions, power cuts and torn sectors
  at every point of a write.
- `scripts/store-test.sh` (`RROUTER_ARCH=x86_64` too): empty store →
  defaults; stored config used; a stored config that fails validation →
  defaults; `config=defaults` ignores the store; save through the web
  interface (401 without password, 422 for invalid or inconsistent
  configs, store unchanged after them), reboot, the router uses the new
  record. Trials: a LAN change boots as a trial, 409 for saves meanwhile,
  confirm keeps it across a reboot; controls: no confirm → reverted after
  `trial_secs`, Revert → reverted, router killed during the trial → the
  next boot reverts. Negative controls: corrupt the new record → the previous one;
  corrupt both → `config: defaults`.

## 9. Status
| Step | Status |
|---|---|
| `crates/config-store`: layout, records, MBR lookup, write plans | ✅ host-tested |
| `crates/config`: schema v1 (LAN, DHCP + reservations, DNS, shaping, mgmt), defaults, validation, TOML | ✅ host-tested |
| Kernel: one `Config` loaded at boot (refactor, no behaviour change) | ✅ `config::load()`; boot arguments overlay it |
| virtio-blk + store partition in QEMU, lab check | ✅ `drivers::virtio_blk`, `store`, `tools/rrstore`, `GET`/`POST /api/config`, `scripts/store-test.sh` (aarch64 + x86_64) |
| Web interface: config pages, save + reboot, confirm/revert | ✅ form + import/export on the status page, JSON API, trial records (flags), `scripts/store-test.sh` covers confirm, timeout, revert and a kill during the trial (aarch64 + x86_64) |
| apu4: SD driver, store partition in `apu-image.sh` | ✅ in QEMU (`sdhci-pci`, SDSC + SDHC, both arches, full `store-test.sh`) and SeaBIOS → Limine with the apu4 image as the SD card; on the apu4 the card initialises and reads (no store partition on the old image yet). Pending: write test on the apu4 after flashing the new image |
