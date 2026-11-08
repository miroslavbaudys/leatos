# CLAUDE.md

rrouter is a SOHO router OS in Rust: a **bare-metal aarch64 unikernel** for
QEMU `virt` (HVF on Apple Silicon). Its goals are PPPoE, DHCP (v4 server/client,
DHCPv6-PD, RA), a DNS forwarder, NAT, a firewall, and IPv4 plus IPv6.

## Layout
- `kernel/`: the bare-metal kernel (`rrouter-kernel`, binary `rrouter`), target `aarch64-unknown-none`
  - `src/boot.S`: entry, EL2→EL1, stack, .bss, identity-map MMU, vectors (included via `global_asm!`, so **no braces** in that file)
  - `src/main.rs` (`kernel_main`), `dtb.rs` (hardware discovery), `console.rs` (PL011, `print!`/`println!`), `heap.rs`, `timer.rs`, `psci.rs`, `exceptions.rs`, `arch.rs`
  - `linker.ld`: kernel linked at `0x4020_0000` (the DTB occupies the start of RAM)
- `crates/proto-pppoe`, `crates/proto-dhcp`, `crates/proto-dns`, `crates/fwd`: protocol and forwarding logic (skeletons for now)
- `scripts/qemu-run.sh` (cargo runner), `scripts/smoke-test.sh`
- `docs/`: architecture.md, boot-and-memory.md, qemu.md, soho-features.md, roadmap.md

## Commands
- `cargo kbuild [--release]`: build the kernel
- `cargo krun`: boot in QEMU (`Ctrl-A X` quits). Environment knobs are in `docs/qemu.md` (`QEMU_ACCEL`, `QEMU_GDB=1`, `QEMU_NET=user`, …)
- `scripts/smoke-test.sh`: automated boot check (prints `SMOKE TEST: PASS`). Also run it with `QEMU_ACCEL=tcg` after touching boot, MMU or exception code
- `cargo test`: host tests for `crates/*` (default-members exclude the kernel)
- `cargo kclippy`: clippy for the kernel

## Rules
- **Never set `build.target` in `.cargo/config.toml`.** The `crates/*` crates must stay host-testable. Use the `k*` aliases for the kernel.
- `crates/*` are `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`, and **sans-IO**: no sockets, clocks or async runtime inside. Pass in bytes and `now`, and return bytes and events. Put the logic there, not in the kernel.
- Dependencies must be `no_std`-compatible (no tokio, hickory, dhcproto, …). Check before adding one.
- `unsafe` only in `kernel/` (arch, MMIO, drivers). Every `unsafe` block needs a `// SAFETY:` comment (the clippy lint is on). `unsafe_op_in_unsafe_fn` is denied.
- Edition 2024: `#[unsafe(no_mangle)]`, `unsafe extern "C" { … }`, `&raw const` for linker symbols.
- Read hardware addresses from the DTB (`dtb::BootInfo`) instead of hard-coding them. Constants are only fallbacks.
- The MMU identity map currently covers RAM only up to 4 GiB, so keep `QEMU_MEM` ≤ 3G.
- Update the status column in `docs/roadmap.md` when a milestone is completed.
