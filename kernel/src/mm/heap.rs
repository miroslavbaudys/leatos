//! Kernel heap: everything from the end of the kernel image to the end of
//! the RAM bank, minus the **staging area** at the very top (where an
//! uploaded kernel waits for the in-RAM upgrade, `crate::upgrade`: the
//! copy into place must never overwrite it). Packet buffers come from
//! `net::packet`'s pool, not ad-hoc allocations.
//!
//! A **boot module** (the install image, docs/install.md §3.2) lies in RAM
//! the loader calls available, often inside that range: [`region`] gives
//! the heap the larger side of the range around it, and [`module`] hands
//! out the module's bytes (mapped read-only by `mm::mmu`).
//!
//! The allocator is `talc` (free blocks binned by size, boundary tags:
//! allocation and free cost do not grow with fragmentation). Boot argument
//! `heap=list` selects the first-fit linked list used before 2026-11-22,
//! whose every allocation and free walks the free holes: on the apu4 the
//! conntrack pass slowed from 75 to 1186 µs over a day (`heap_bench=N`
//! measures it). It stays as the benchmark's control and a fallback.
//!
//! Every allocation and free is timed ([`stats`]): the time spent waiting
//! for the one heap lock (other cores) and the time holding it. The
//! counters live under the same lock, so they cost no atomics.

use crate::mm::sym;
use crate::platform::BootInfo;
use crate::println;
use core::sync::atomic::{AtomicBool, Ordering};
use core::alloc::{GlobalAlloc, Layout as AllocLayout};
use core::ptr::{self, NonNull};
use linked_list_allocator::Heap;
use talc::{ErrOnOom, Span, Talc};
use spin::{Mutex, Once};

/// Staging area size, where the arch supports the in-RAM upgrade and RAM allows.
pub const STAGING_SIZE: usize = 32 << 20;
static STAGING: Once<(usize, usize)> = Once::new();
static STAGING_TAKEN: AtomicBool = AtomicBool::new(false);
/// The boot module (start, length), kept out of the heap.
static MODULE: Once<(usize, usize)> = Once::new();

#[global_allocator]
static HEAP: TimedHeap = TimedHeap(Mutex::new(Inner {
    talc: Talc::new(ErrOnOom),
    list: Heap::empty(),
    use_list: false,
    alloc: Op::ZERO,
    free: Op::ZERO,
    wait: Op::ZERO,
    live: 0,
}));

/// Counts and timer ticks of one kind of heap operation.
#[derive(Clone, Copy)]
struct Op {
    n: u64,
    ticks: u64,
    max: u64,
}

impl Op {
    const ZERO: Self = Self { n: 0, ticks: 0, max: 0 };

    fn record(&mut self, dt: u64) {
        self.n += 1;
        self.ticks += dt;
        self.max = self.max.max(dt);
    }
}

struct Inner {
    talc: Talc<ErrOnOom>,
    /// `heap=list`: the one claimed at boot; the other stays empty.
    list: Heap,
    use_list: bool,
    /// Lock held by `allocate_first_fit` / `deallocate`.
    alloc: Op,
    free: Op,
    /// Lock wait, both kinds.
    wait: Op,
    /// Allocations not yet freed (the free list has at most one more hole).
    live: u64,
}

/// `talc` or `linked_list_allocator` under one lock, timed.
struct TimedHeap(Mutex<Inner>);

// SAFETY: allocation and deallocation go straight to the allocator chosen
// at boot (`talc::Talc` or `linked_list_allocator::Heap`) under a lock, as
// their own locked wrappers do; the timing only reads the clock and updates
// counters.
unsafe impl GlobalAlloc for TimedHeap {
    unsafe fn alloc(&self, layout: AllocLayout) -> *mut u8 {
        let t0 = crate::timer::ticks();
        let mut g = self.0.lock();
        let t1 = crate::timer::ticks();
        let p = if g.use_list {
            g.list.allocate_first_fit(layout)
        } else {
            // SAFETY: `GlobalAlloc::alloc`'s contract: `layout` has a
            // non-zero size (talc's only requirement).
            unsafe { g.talc.malloc(layout) }
        };
        let p = p.map_or(ptr::null_mut(), |p| p.as_ptr());
        let t2 = crate::timer::ticks();
        g.wait.record(t1 - t0);
        g.alloc.record(t2 - t1);
        if !p.is_null() {
            g.live += 1;
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: AllocLayout) {
        let Some(p) = NonNull::new(ptr) else { return };
        let t0 = crate::timer::ticks();
        let mut g = self.0.lock();
        let t1 = crate::timer::ticks();
        if g.use_list {
            // SAFETY: the caller's `GlobalAlloc::dealloc` contract: `ptr`
            // came from `alloc` above (this allocator) with this `layout`.
            unsafe { g.list.deallocate(p, layout) };
        } else {
            // SAFETY: as above, for talc.
            unsafe { g.talc.free(p, layout) };
        }
        let t2 = crate::timer::ticks();
        g.wait.record(t1 - t0);
        g.free.record(t2 - t1);
        g.live -= 1;
    }
}

/// One kind of heap operation since boot, in nanoseconds.
#[derive(Clone, Copy, Debug)]
pub struct OpTimes {
    pub count: u64,
    pub total_ns: u64,
    pub max_ns: u64,
}

/// Heap operation costs since boot ([`stats`]).
#[derive(Clone, Copy, Debug)]
pub struct Stats {
    /// `"talc"` or `"list"` (`heap=list`).
    pub allocator: &'static str,
    /// Free holes between allocations (talc only).
    pub fragments: Option<usize>,
    /// Allocations not yet freed.
    pub live: u64,
    /// Time holding the lock to allocate (the list: the first-fit walk).
    pub alloc: OpTimes,
    /// Time holding the lock to free (the list: the walk to the insertion point).
    pub free: OpTimes,
    /// Time waiting for the lock (contention between cores).
    pub wait: OpTimes,
}

/// The heap's operation costs. Call it only after `timer::init`.
pub fn stats() -> Stats {
    let (alloc, free, wait, live, use_list, fragments) = {
        let g = HEAP.0.lock();
        let frags = g.talc.get_counters().fragment_count;
        (g.alloc, g.free, g.wait, g.live, g.use_list, frags)
    };
    let ns = |t: u64| crate::timer::ticks_to_duration(t).as_nanos() as u64;
    let times = |o: Op| OpTimes {
        count: o.n,
        total_ns: ns(o.ticks),
        max_ns: ns(o.max),
    };
    Stats {
        allocator: if use_list { "list" } else { "talc" },
        fragments: (!use_list).then_some(fragments),
        live,
        alloc: times(alloc),
        free: times(free),
        wait: times(wait),
    }
}

/// How the RAM region the kernel runs in is split (bytes), for the
/// management page.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub ram: usize,
    /// Kernel image, stacks and whatever lies below it in the region.
    pub kernel: usize,
    pub staging: usize,
    pub heap: usize,
}

static LAYOUT: Once<Layout> = Once::new();

pub fn layout() -> Option<Layout> {
    LAYOUT.get().copied()
}

fn align_down(x: usize) -> usize {
    x & !0xfff
}
fn align_up(x: usize) -> usize {
    (x + 0xfff) & !0xfff
}

/// The heap's range before the staging area is taken off its top: from
/// the kernel's end to the end of its RAM bank, or, when the boot module
/// lies inside that, the larger side of the module (whole pages, so the
/// module shares no page with the heap). Also used by `mm::mmu::init`.
pub fn region(info: &BootInfo) -> (usize, usize) {
    let (start, end) = (sym::kernel_end(), info.ram.0 + info.ram.1);
    let Some((m, len)) = info.module.filter(|_| crate::config::module_carve()) else {
        return (start, end);
    };
    let (lo, hi) = (align_down(m), align_up(m + len));
    if hi <= start || lo >= end {
        return (start, end);
    }
    let below = (start, lo.max(start));
    let above = (hi.min(end), end);
    let size = |(s, e): (usize, usize)| e - s;
    if size(above) > size(below) { (align_up(above.0), above.1) } else { below }
}

pub fn init(info: &BootInfo) {
    let (start, end) = region(info);
    assert!(end > start, "no RAM left for the heap");
    let mut end = end;
    if let Some(m) = info.module {
        MODULE.call_once(|| m);
    }
    if crate::arch::kexec::SUPPORTED && end - start >= 4 * STAGING_SIZE {
        let s = (end - STAGING_SIZE) & !0xfff;
        STAGING.call_once(|| (s, end - s));
        end = s;
    }
    let size = end - start;
    LAYOUT.call_once(|| Layout {
        ram: info.ram.1,
        kernel: start - info.ram.0,
        staging: STAGING.get().map_or(0, |&(_, l)| l),
        heap: size,
    });
    let list = crate::config::heap_list();
    {
        let mut g = HEAP.0.lock();
        g.use_list = list;
        if list {
            // SAFETY: [start, end) is RAM after the kernel image, mapped
            // Normal RW (boot map, later mm::mmu), used by nothing else;
            // called exactly once.
            unsafe { g.list.init(start as *mut u8, size) };
        } else {
            let span = Span::from_base_size(start as *mut u8, size);
            // SAFETY: as above: talc gets sole use of [start, end).
            let claimed = unsafe { g.talc.claim(span) };
            claimed.expect("heap: talc could not claim the heap");
        }
    }
    println!(
        "  heap            : {start:#x}..{end:#x} ({} MiB, {}){}",
        size >> 20,
        if list { "linked list" } else { "talc" },
        STAGING
            .get()
            .map(|&(s, l)| alloc::format!(", upgrade staging {s:#x}..{:#x}", s + l))
            .unwrap_or_default()
    );
}

/// The boot module's bytes (docs/install.md §3.2): `None` without one, or
/// before `mm::mmu::init` mapped it.
pub fn module() -> Option<&'static [u8]> {
    let &(start, len) = MODULE.get()?;
    if !crate::mm::mmu::module_mapped() {
        return None;
    }
    // SAFETY: [start, start + len) is the loader's module: kept out of the
    // heap and the staging area by `region` (whole pages), mapped
    // read-only by mm::mmu::init (checked above), never written or freed
    // by the kernel, so shared references to it stay valid for ever.
    Some(unsafe { core::slice::from_raw_parts(start as *const u8, len) })
}

/// The staging area, handed out once at a time (to the boot loader in
/// `crate::upgrade`, then the management server).
pub fn take_staging() -> Option<&'static mut [u8]> {
    let &(start, len) = STAGING.get()?;
    if STAGING_TAKEN.swap(true, Ordering::AcqRel) {
        return None;
    }
    // SAFETY: [start, start + len) is RAM excluded from the heap above,
    // mapped RW by mm::mmu (its heap mapping runs to the end of RAM),
    // and this is the only reference ever created (STAGING_TAKEN).
    Some(unsafe { core::slice::from_raw_parts_mut(start as *mut u8, len) })
}

/// Hand the staging area back (the boot loader in `crate::upgrade` did not
/// use it), so [`take_staging`] can give it out again. Taking the slice by
/// value ends the caller's only reference to it.
pub fn return_staging(staging: &'static mut [u8]) {
    let ours = STAGING
        .get()
        .is_some_and(|&(start, len)| staging.as_ptr() as usize == start && staging.len() == len);
    assert!(ours, "return_staging: not the staging area");
    STAGING_TAKEN.store(false, Ordering::Release);
}

/// (used, free) bytes.
pub fn usage() -> (usize, usize) {
    let g = HEAP.0.lock();
    if g.use_list {
        (g.list.used(), g.list.free())
    } else {
        let c = g.talc.get_counters();
        (c.allocated_bytes, c.available_bytes)
    }
}
