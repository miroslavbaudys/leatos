//! Stacks of the secondary cores: carved from `__ap_stacks` in the linker
//! script, one slot per core 1..[`MAX_CORES`], each laid out like core 0's:
//!
//! ```text
//! [guard] exception stack (16 KiB)  [guard] kernel stack (256 KiB)
//! ```
//!
//! `mm::mmu::init` maps the stacks and leaves the guard pages unmapped, so
//! an overflow faults ([`guard_name`]).

use crate::mm::sym;
use crate::smp::MAX_CORES;

const PAGE: usize = 4096;
/// Must match `STACK_SIZE` / `EXC_STACK_SIZE` in the linker scripts
/// (checked against core 0's stacks in [`check_layout`]).
pub const STACK_SIZE: usize = 0x40000;
pub const EXC_STACK_SIZE: usize = 0x4000;
const SLOT: usize = 2 * PAGE + EXC_STACK_SIZE + STACK_SIZE;

/// One core's stacks: guard pages and `[bottom, top)` ranges.
#[derive(Clone, Copy, Debug)]
pub struct CoreStacks {
    pub exc_guard: usize,
    pub exc: (usize, usize),
    pub guard: usize,
    pub stack: (usize, usize),
}

fn slot(core: usize) -> CoreStacks {
    assert!(
        (1..MAX_CORES).contains(&core),
        "stacks: no slot for core {core}"
    );
    let base = sym::ap_stacks() + (core - 1) * SLOT;
    let exc_bottom = base + PAGE;
    let guard = exc_bottom + EXC_STACK_SIZE;
    let bottom = guard + PAGE;
    CoreStacks {
        exc_guard: base,
        exc: (exc_bottom, guard),
        guard,
        stack: (bottom, bottom + STACK_SIZE),
    }
}

/// The linker script reserved what this module assumes.
pub fn check_layout() {
    assert_eq!(
        sym::stack_top() - sym::stack_bottom(),
        STACK_SIZE,
        "stacks: STACK_SIZE"
    );
    assert_eq!(
        sym::exc_stack_top() - sym::exc_stack_bottom(),
        EXC_STACK_SIZE,
        "stacks: EXC_STACK_SIZE"
    );
    assert_eq!(
        sym::ap_stacks_end() - sym::ap_stacks(),
        (MAX_CORES - 1) * SLOT,
        "stacks: __ap_stacks size"
    );
}

/// Every secondary core's stacks (for mapping).
pub fn all_secondary() -> impl Iterator<Item = CoreStacks> {
    (1..MAX_CORES).map(slot)
}

/// (exception stack top, kernel stack top) of `core` (1..MAX_CORES).
pub fn secondary(core: usize) -> (usize, usize) {
    let s = slot(core);
    (s.exc.1, s.stack.1)
}

/// Which guard page `addr` is in, if it is a secondary core's.
pub fn guard_name(addr: usize) -> Option<&'static str> {
    let in_page = |base: usize| addr >= base && addr < base + PAGE;
    all_secondary().find_map(|s| {
        if in_page(s.guard) {
            Some("kernel stack overflow (guard page, secondary core)")
        } else if in_page(s.exc_guard) {
            Some("exception stack overflow (guard page, secondary core)")
        } else {
            None
        }
    })
}
