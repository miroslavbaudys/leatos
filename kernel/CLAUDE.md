# kernel/ in detail

`leatos-kernel`, binary `leatos`. The networking code has its own file: `src/net/CLAUDE.md`.
Boot arguments: docs/boot-arguments.md.

## Boot, arch, platform

- `src/main.rs`: the arch-neutral boot order (`kmain`). `#![deny(unsafe_code)]` applies crate-wide.
- `src/arch/`: **all** CPU-specific code. `arch/mod.rs` documents the API every backend provides.
  - `aarch64/`: boot.S, cpu, exceptions + IRQ entry, irqchip = GICv3, timer, mmu descriptors,
    power = PSCI, console = PL011, smp = PSCI `CPU_ON`; kexec, rtc and watchdog are stubs.
  - `x86_64/`: boot.S = PVH + Multiboot2 entry → long mode, AP trampoline; isr.S; exceptions =
    IDT/TSS/IST; irqchip = local APIC + MSI-X (+ IOAPIC entries for ISA IRQs from the MADT only:
    COM1's IRQ 4, the keyboard's IRQ 1);
    timer = TSC + LAPIC one-shot; power = ACPI S5; console = 16550; port I/O; rtc = CMOS clock (time
    registers only); smp = INIT-SIPI-SIPI; kexec (+ kexec.S); watchdog = AMD FCH; kbd = PS/2 on
    the i8042 (ISA IRQ 1 → vector 35, decoded by `crates/ps2-kbd` into the console's receive
    ring: the screen's keyboard types into the CLI; none where port 0x64 reads 0xff; `kbd=0`).
- `src/platform/`: the neutral `BootInfo` (no allocation); `dtb.rs` (aarch64); `pvh.rs` /
  `multiboot2.rs` + `acpi.rs` over `phys.rs` (x86_64: one unsafe byte-view constructor, safe
  parsers). `BootInfo.framebuffer`: Multiboot2 tag 8 (`drivers::screen`). `BootInfo.module`:
  the first boot module (Multiboot2 tag 3, PVH modlist = QEMU `-initrd`), the installer's image
  (docs/install.md; `src/install.rs` checks it at boot).
- `linker.ld` (aarch64, kernel at `0x4020_0000`) / `linker-x86_64.ld` (at 1 MiB, keeps the PVH
  note): page-aligned sections, guard pages, 16 KiB exception stack + 256 KiB kernel stack.

## Ports

`wan0` + LAN ports `lan0`–`lan2` (NICs in PCI order, `config::PORTS`, at most `shared::MAX_PORTS`).
Routed ports, no bridge: each network is on one port (`network.ports`), `LinkShared::port` is set
live with the VID; networks on a port the machine lacks are left out (`config::missing_networks`).

## Cores, memory, interrupts

- `src/smp.rs`: multicore (docs/smp.md): `start` (secondary cores via `arch::smp::start`: aarch64
  PSCI `CPU_ON`, x86_64 INIT-SIPI-SIPI into the `boot.S` trampoline at 0x8000), `secondary_main`,
  `current()`, `wake(core)` (IPI), `stop_others`; boot argument `cores=N`.
  - Tasks are pinned (`executor::spawn_on`; `net::stack::layout`): with ≥ 3 cores `dp_down` on 0,
    `dp_up` on 1, `svc` on 2; with 2 both directions on 0 and `svc` on 1.
  - `dp_down` receives on wan0 and sends on every LAN port, `dp_up` the reverse
    (`stack::PortSet`).
- `src/mm/`:
  - `stacks`: secondary cores' stacks from `__ap_stacks`, guard pages.
  - `heap`: `talc`; boot argument `heap=list` = the old first-fit linked list, whose alloc/free walk
    every hole. Every alloc/free is timed: `/api/status` `heap.allocator`/`fragments`/`live`/
    `alloc`/`dealloc`/`lock_wait`, soak CSV columns. `heap::region`: the heap takes the larger
    side of RAM around a boot module (Limine puts it right after the kernel; `module_carve=0` is
    the negative control), `mmu` maps the module read-only, `heap::module` hands it out.
  - `mmu`: neutral page-table builder; arch supplies the encoding.
  - `dma`: virtio `Hal`. `sym`: linker symbols.
- `src/mmio.rs`: `Region` = safe, bounds-checked MMIO over `safe-mmio`.
- `src/irq.rs`: dispatch + `IrqEvent`; shared INTx lines: sharers, `line_done`.
- `src/timer.rs` (tickless, `sleep`), `src/executor.rs` (priority async; accounts idle and
  per-priority poll time), `src/cpuload.rs` (1 s CPU load samples, 5 min history, shown on the mgmt
  page).
- `src/pci.rs`: via `virtio-drivers` `PciRoot`. `src/selftest.rs`.

## Robustness, entropy, time, console

- `src/fatal.rs`: every fatal path: stop the other cores, 3 s, reset; `panic=halt` halts.
- `src/watchdog.rs`: cross-core check: a `watchdog` task per core; a core unseen for 5 s is reported
  and reset. Pets the hardware watchdog `drivers::watchdog` = i6300esb in QEMU, AMD FCH on the apu4
  in `arch/x86_64/watchdog.rs`.
- `src/entropy.rs`: SHA-256 pool from timing jitter, boot data, MACs, request arrival times, and the
  apu4's AMD CCP TRNG via `drivers/ccp.rs` (registers at BAR2 + 0x20000, health-checked, extra
  input only). RDRAND is not used.
- `src/wallclock.rs`: UTC from SNTP; the RTC is read at boot as a hint only and set after each sync
  (`arch::rtc`).
- `src/console.rs`: `println!`, `fatal_println!` (also drawn by `drivers::screen`). The CLI's input
  line is redrawn after other output; UART RX interrupt and the PS/2 keyboard (`arch::kbd`) → one
  lock-free ring. Once the CLI is up, log messages go to a 64 KiB RAM log (`log=console` keeps them
  on the UART; fatal paths dump its tail).
- `src/cli.rs`: the console CLI inside `svc` (serial, or the screen's keyboard): reads `console`'s
  RX ring line by line. `status`, `leases`, `routes`, `log [N|all|clear]`, `config show
  [running|stored|pending]`, `config set/unset/diff/save/discard` as TOML assignments on a pending
  copy, `reboot`.

## Drivers (`src/drivers/`)

- `Nic`: the one NIC interface the stack uses. `Disk`: the one block interface the store uses
  (`open` gives every disk of a PCI function: one, or one per AHCI port; `flush` is async).
- `virtio_net.rs`: slot-owned DMA buffers, pull-based TX with a byte limit.
- `igb.rs`: i210/i211 + QEMU's 82576, same TX contract.
  - Own descriptor rings in `mm::dma::DmaRegion`, 256-entry RX ring.
  - INTx or MSI-X (self-masking via `EIAM`, no `ICR` read). TX completions on vector 1 to the
    transmitting core, armed only while TX is blocked (`arm_tx_irq`). RX moderation `igb_itr_us=`.
  - NIC drops `MPC` + `RQDPC0` → `/api/status` `rx_missed`.
- `virtio_blk.rs`: the store disk in QEMU: polled, one driver-owned request in flight, yields while
  waiting.
- `sdhci.rs`: SD card behind a standard SDHCI (the apu4's slot at 00:14.7): PIO, polled, yields.
- `ahci.rs`: SATA disks on AHCI ports (apu4 mSATA, Proxmox `sata0`, QEMU `-device ahci`): BIOS
  hand-off, one `Ahci` per port with an ATA disk (ATAPI reported, not used), IDENTIFY, READ /
  WRITE DMA (EXT), FLUSH CACHE (EXT); polled, slot 0, yields; DMA only through driver-owned
  `DmaRegion`s (`copy_in` / `copy_out`); an abandoned command → port stop / restart (COMRESET if
  busy). `Disk::open` returns one disk per port, named `<PCI address>/<port>`.
- `ccp.rs`: AMD CCP TRNG, PCI 1022:1537.
- `screen.rs`: the console mirrored on the screen through `crates/text-screen`: the loader's
  framebuffer (Multiboot2 tag 8, requested in `boot.S`, 32 bpp, 7x16 glyphs: 182x50 at
  1280x800; `BootInfo.framebuffer`, passed on by kexec) or VGA text 80x25
  (`arch::console::TEXT_SCREEN`, cursor via `text_cursor`). Collected from the first boot line
  (`early` sizes it), drawn once `init` (after PCI) finds a display controller (class 03), else
  off for good (the apu4); `screen=0`. Only changed cells are redrawn. Proxmox noVNC
  (docs/proxmox.md §8); its input is `arch::kbd`.
- `watchdog.rs` (`HwWatchdog` + probe), `i6300esb.rs` (QEMU's PCI watchdog).
- `cputemp.rs`: AMD family 16h die temperature from PCI 00:18.3 D18F3xA4 + HTC limit x64 (k10temp's
  decoding); sampled with `cpuload`; `/api/status` `temp` (null without a sensor, e.g. QEMU),
  overview tile + chart, CLI `status`.

## Configuration, store, upgrades

- `src/config.rs`: one `config::Config` (`crates/config`) built at boot by `config::load(store)`
  (after PCI, so it can read the disk): defaults ← stored `config.toml` ← boot arguments
  (`config=defaults` ignores the store).
  - `lan()`/`dns()`/`qos()`/`mgmt()` are views of it; `base()` is it without boot arguments;
    `overrides()` lists the fields boot arguments set (shown on the form).
  - Without a stored config, on virtual machines only, the lab's `nas` reservation (host .10) is
    added.
- `src/store.rs`: the store partition (MBR type 0xda + valid store header, never formatted by the
  kernel) on a block device: async record read/write via `crates/config-store`; boot reads go
  through `executor::block_on`; saves run in `svc`. `open` probes every disk; `store_id=` (from
  the boot partition's `limine.conf`) picks the store with that ID, none if no disk has it;
  without it the first, with a warning when there are several.
  - DHCP leases live in the `leases` area (`net/svc.rs` `LeaseStore`): restored at boot, written
    when the bound set changes (checked every 60 s) and before reboot/upgrade; format
    `proto_dhcp::v4::persist`.
- `src/install.rs`: the installer (docs/install.md): `install=1` → `install::run` right after
  PCI, instead of the router: disks listed, target by PCI address (typed or `install_target=`),
  config kept (`store::probe` + `Store::into_disk`; an unconfirmed trial aborts,
  `install_keep=0`), `install_image::Image::plan` written and read back, reset. The only code
  that writes a whole disk. `check_module` logs the module's state on every boot.
- `src/upgrade.rs`: kernel upgrades (docs/upgrades.md; x86_64 only).
  - In RAM: validate + flatten an uploaded kernel in the staging area at the top of RAM
    (`mm::heap::take_staging`); `arch::kexec` copies it into place and enters it like a Multiboot2
    loader.
  - Persistent: kernels in the store's `images` area as trial records. `upgrade::boot` (in `kmain`
    after the store, before `config::load`) makes the boot partition's kernel the loader: it enters
    the current stored kernel (`image=<slot>:<seq>` added), marks trials booted and rolls back one
    found already booted. `image=golden` skips it, `image=ram` marks an in-RAM upgrade.
  - Confirm/revert via `/api/upgrade/confirm|revert`, else reverted after `trial_secs`.
