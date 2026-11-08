//! Architecture backends. Neutral code may only use the API below, never
//! `core::arch`, `asm!` or arch-specific crates (see
//! docs/safety-and-portability.md). Each backend provides:
//!
//! - `discover(boot_arg) -> Result<BootInfo, &str>`: firmware → platform info
//! - `cpu`: `privilege_level`, `irq_enable`, `irq_disable`, `wait_for_interrupt`, `halt`
//! - `console`: `init(base)`, `write_str`, `emergency_write_str`
//! - `irqchip`: `init(&BootInfo)`, `enable(intid, Trigger)`, `disable(intid)`;
//!   the backend's IRQ entry calls `crate::irq::dispatch(intid)`
//! - `timer`: `frequency`, `ticks`, `set_deadline`, `stop`, `mask_from_irq`
//! - `mmu`: descriptor encoding (`LEVELS`, `TOP_LEVEL_SHIFT`, `VA_BITS`,
//!   `block_allowed`, `is_valid`, `is_table`, `desc_addr`, `table_desc`,
//!   `leaf_desc`), `PLATFORM_MMIO`, `unsafe fn activate(root)`
//! - `power`: `init(PowerMethod)`, `off() -> !`
//!
//! `cargo kcheck-x86` type-checks neutral code against the x86_64 stubs.

#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)] // the arch backend is the main unsafe audit surface
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)] // x86_64 backend skeleton (port I/O, CPU flags)
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
