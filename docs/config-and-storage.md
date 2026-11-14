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
p1  FAT32, 64 MiB      Limine + kernel (read-only for the kernel)
p2  type 0xda, 16 MiB  rrouter store
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
range = ["10.10.0.100", "10.10.0.199"]
lease_secs = 43200

[[lan.dhcp.static]]
mac = "52:54:00:00:00:05"
ip = "10.10.0.10"
hostname = "nas"

[[firewall.forward]]
name = "nas-https"
proto = "tcp"
wan_port = 8443
to = "10.10.0.10:443"

[shaping]
up_kbit = 18000
down_kbit = 90000
overhead = 20

[mgmt]
password_hash = "pbkdf2-sha256$..."
```

The full target schema is in `docs/soho-features.md`. List entries
(reservations, rules, forwards) carry a stable key (`name`, `mac`) so the
web interface can edit or delete one entry.

### Layering
```
compiled-in defaults ← stored config.toml ← boot arguments
```
Boot arguments (`lan=`, `shape_up=`, ...) still override, for
development and recovery. `config=defaults` ignores the store entirely
(recovery: add it in the Limine menu over serial).

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
- `GET /api/config`: current config as TOML (secrets omitted).
- `POST /api/config`: validate, save, reboot. Errors: 422 with the parser
  or validation message (line and column).
- Shaper rates apply live; Save makes them persistent.
- **Confirm or revert:** a change to the LAN address or management
  settings boots as a trial. Without Confirm from the web interface within
  120 s, the router reboots into the previous record.

## 7. Drivers
- QEMU: virtio-blk (`virtio-drivers` `VirtIOBlk`), aarch64 and x86_64.
- apu4: the SD slot (expected: FCH SDHCI, PCI class 08:05; to be
  confirmed from the PCI scan), PIO first. AHCI if an mSATA SSD is used.
- Drivers are async and run at service priority: a store write never
  blocks the datapath.

## 8. Tests
- `crates/config-store`: layout and record round trips, every corruption
  case, slot selection with schema versions, power cuts and torn sectors
  at every point of a write.
- Lab: save a config through the web interface, reboot, check the router
  uses it. Negative control: flip a payload byte; the router must report
  `config: defaults`.

## 9. Status
| Step | Status |
|---|---|
| `crates/config-store`: layout, records, MBR lookup, write plans | ✅ host-tested |
| `crates/config`: schema, defaults, validation, TOML | |
| Kernel: one `Config` loaded at boot (refactor, no behaviour change) | |
| virtio-blk + store partition in QEMU, lab check | |
| Web interface: config pages, save + reboot, confirm/revert | |
| apu4: SD driver, store partition in `apu-image.sh` | |
