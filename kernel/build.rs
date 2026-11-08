fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let target = std::env::var("TARGET").unwrap_or_default();
    // Only apply the linker script for the bare-metal target.
    if target == "aarch64-unknown-none" {
        println!("cargo:rustc-link-arg-bins=-T{dir}/linker.ld");
    }
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=src/boot.S");
}
