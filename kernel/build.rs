fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let target = std::env::var("TARGET").unwrap_or_default();
    // Only apply the linker script for the bare-metal target.
    match target.as_str() {
        "aarch64-unknown-none" => println!("cargo:rustc-link-arg-bins=-T{dir}/linker.ld"),
        "x86_64-unknown-none" => println!("cargo:rustc-link-arg-bins=-T{dir}/linker-x86_64.ld"),
        _ => {}
    }
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=linker-x86_64.ld");
    println!("cargo:rerun-if-changed=src/arch/aarch64/boot.S");
    println!("cargo:rerun-if-changed=src/arch/x86_64/boot.S");
    println!("cargo:rerun-if-changed=src/arch/x86_64/isr.S");
}
