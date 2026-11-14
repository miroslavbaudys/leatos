//! Secondary cores on x86_64 (INIT-SIPI-SIPI): not implemented yet
//! (M11 step 2b), so the kernel runs on the boot core only.

pub fn start(
    _core: usize,
    _hw_id: u64,
    _exc_top: usize,
    _stack_top: usize,
) -> Result<(), &'static str> {
    Err("x86_64 SMP not implemented yet")
}
