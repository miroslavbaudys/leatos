//! The installer (docs/install.md): leatos booted from a USB stick or an
//! ISO writes the install image Limine (or QEMU `-initrd`) loaded as a boot
//! module to a disk it has a driver for.
//!
//! Step 1 (this file so far): the module is found, kept out of the heap
//! (`mm::heap::region`) and checked as an install image
//! (`crates/install-image`: header, extent table, SHA-256).

use crate::println;

/// Check the boot module, if there is one, and log the result. Runs after
/// the heap and the packet pool are in use: a module the heap overlapped
/// fails its hash here.
pub fn check_module() {
    let Some(bytes) = crate::mm::heap::module() else {
        return;
    };
    match install_image::parse(bytes) {
        Ok(img) => {
            let h = img.sha256();
            println!(
                "  install image   : ok, {} MiB disk image, {} extents, {} KiB of data, \
                 sha256 {:02x}{:02x}{:02x}{:02x}…",
                img.sectors() >> 11,
                img.extents().count(),
                img.data_len() >> 10,
                h[0],
                h[1],
                h[2],
                h[3]
            );
        }
        Err(e) => println!("  install image   : invalid ({e})"),
    }
}
