fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let target = std::env::var("TARGET").unwrap_or_default();
    // Only apply the linker script for the bare-metal target.
    match target.as_str() {
        "aarch64-unknown-none" => println!("cargo:rustc-link-arg-bins=-T{dir}/linker.ld"),
        "x86_64-unknown-none" => println!("cargo:rustc-link-arg-bins=-T{dir}/linker-x86_64.ld"),
        _ => {}
    }
    // Which build runs (`/api/status` `build`, the boot banner): commit,
    // `-dirty` for uncommitted changes. Re-run on any source change, so a
    // rebuild never keeps a stale id.
    let id = std::process::Command::new("git")
        .args(["describe", "--always", "--dirty", "--abbrev=10"])
        .current_dir(&dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=RROUTER_BUILD={id}");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=../crates");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=linker-x86_64.ld");
    println!("cargo:rerun-if-changed=src/arch/aarch64/boot.S");
    println!("cargo:rerun-if-changed=src/arch/x86_64/boot.S");
    println!("cargo:rerun-if-changed=src/arch/x86_64/isr.S");
}
