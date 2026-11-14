//! In-RAM upgrade: not implemented on aarch64 (QEMU `virt` is the test
//! platform there, rebooted by the scripts instead).

pub const SUPPORTED: bool = false;
pub const SCRATCH_SIZE: usize = 0;

pub fn exec(_flat: &[u8], _dst: u64, _entry: u64, _cmdline: &str, _scratch: &mut [u8]) -> ! {
    panic!("kexec: not supported on aarch64")
}
