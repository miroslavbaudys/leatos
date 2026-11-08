//! Device drivers (arch-neutral).

#[allow(unsafe_code)] // DMA buffer hand-off (begin/complete pairs)
pub mod virtio_net;
