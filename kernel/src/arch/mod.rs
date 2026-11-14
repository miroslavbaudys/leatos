//! Architecture backends. Neutral code may only use the API below, never
//! `core::arch`, `asm!` or arch-specific crates (see
//! docs/safety-and-portability.md). Each backend provides:
//!
//! - `discover(boot_arg) -> Result<BootInfo, &str>`: firmware → platform info
//! - `cpu`: `privilege_level`, `core_id` (this core's `smp` index), `irq_enable`,
//!   `irq_disable`, `wait_for_interrupt`, `halt`,
//!   `dma_barrier` (order descriptor accesses against device DMA and MMIO)
//! - `console`: `init(base)`, `write_str`, `emergency_write_str`
//! - `irqchip`: `init(&BootInfo)`, `enable(intid, Trigger)`, `disable(intid)`;
//!   the backend's IRQ entry calls `crate::irq::dispatch(intid)`. MSI-X:
//!   `msi_vector(n)` (the n-th device vector, if the platform delivers
//!   MSI-X), `msi_message(vector)` (address/data to program), and
//!   `attach_msix(vector, entry)` (the table entry that enable/disable
//!   unmask/mask). SMP: `IPI_INTID`, `init_secondary()` (this core's
//!   interface), `send_ipi(core)` (wake/stop IPI)
//! - `smp`: `start(core, hw_id, exc_stack_top, stack_top)` (start a
//!   secondary core, which then calls `crate::smp::secondary_main`)
//! - `timer`: `frequency`, `ticks`, `set_deadline`, `stop`, `mask_from_irq`
//! - `mmu`: descriptor encoding (`LEVELS`, `TOP_LEVEL_SHIFT`, `VA_BITS`,
//!   `block_allowed`, `is_valid`, `is_table`, `desc_addr`, `table_desc`,
//!   `leaf_desc`), `PLATFORM_MMIO`, `unsafe fn activate(root)`,
//!   `sync_tables` (after adding entries to the live tables)
//! - `power`: `init(PowerMethod)`, `off() -> !`, `reset() -> !`
//! - `kexec`: `SUPPORTED`, `SCRATCH_SIZE`, `exec(flat, dst, entry, cmdline, scratch) -> !`
//!   (enter a new kernel in RAM; x86_64 only)
//!
//! `cargo kcheck-x86` type-checks neutral code against the x86_64 stubs.

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)] // the arch backend is the main unsafe audit surface
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)] // the arch backend is the main unsafe audit surface
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
