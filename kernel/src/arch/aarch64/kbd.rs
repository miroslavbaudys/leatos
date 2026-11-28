//! No PS/2 keyboard on aarch64 (QEMU `virt`): the console's input is the
//! UART only.

pub fn init() -> bool {
    false
}

pub fn irq_setup(_info: &crate::platform::BootInfo) -> Option<(u32, crate::irq::Trigger)> {
    None
}

pub fn irq_enable() {}

pub fn drain_irq(_push: fn(u8)) {}

pub fn drain_thread(_push: fn(u8)) -> usize {
    0
}
