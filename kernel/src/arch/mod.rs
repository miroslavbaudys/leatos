//! Architecture backends. Neutral code may only use the API below, never
//! `core::arch`, `asm!` or arch-specific crates (see
//! docs/safety-and-portability.md). Each backend provides:
//!
//! - `discover(boot_arg) -> Result<BootInfo, &str>`: firmware → platform info
//! - `cpu`: `privilege_level`, `core_id` (this core's `smp` index), `irq_enable`,
//!   `irq_disable`, `wait_for_interrupt`, `halt` (smoke builds: power off),
//!   `park` (stop this core only),
//!   `dma_barrier` (order descriptor accesses against device DMA and MMIO)
//! - `console`: `init(base)`, `write_str`, `emergency_write_str`; receive:
//!   `rx_irq_setup(&BootInfo) -> Option<(intid, Trigger)>` (route the UART's
//!   RX interrupt, masked), `rx_irq_enable`, `rx_drain_irq(push)` (IRQ
//!   context: FIFO → `push`, try-lock only), `rx_drain_thread(push)` (the
//!   polled fallback, IRQs masked); `TEXT_SCREEN` (the legacy VGA text
//!   buffer's address, x86_64 only) and `text_cursor(pos)`
//! - `kbd`: the screen's keyboard (x86_64: PS/2 on the i8042; aarch64: none):
//!   `init() -> bool` (found), `irq_setup(&BootInfo)`, `irq_enable`,
//!   `drain_irq(push)` / `drain_thread(push)` (typed bytes → `push`, as the
//!   console's receive side)
//! - `irqchip`: `init(&BootInfo)`, `enable(intid, Trigger)`, `disable(intid)`;
//!   the backend's IRQ entry calls `crate::irq::dispatch(intid)`. MSI-X:
//!   `msi_vector(n)` (the n-th device vector, if the platform delivers
//!   MSI-X), `msi_message(vector, core)` (address/data to program, delivered to `core`), and
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
//! - `rtc`: `read() -> Option<wallclock::DateTime>`, `write(&DateTime)`: the
//!   battery-backed clock in UTC (x86_64: CMOS; aarch64: none)
//! - `watchdog`: `probe(smbus_rev) -> Option<Box<dyn HwWatchdog>>`: a
//!   chipset watchdog (x86_64: the AMD FCH's, given the revision of its
//!   SMBus function; aarch64: none)
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
