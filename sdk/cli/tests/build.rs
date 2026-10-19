//! `cargo pico build`, driven through the binary. Real guest builds are
//! `build_flags_acceptance.sh`, by hand: they need the guest toolchain.

use std::process::Command;

#[path = "../../prover/src/tests/scratch.rs"]
mod scratch;
use scratch::scratch_dir;

#[test]
fn a_missing_pico_toolchain_is_refused_naming_the_installer() {
    let dir = scratch_dir("build_no_toolchain");
    // A rustup with no toolchain at all, so `pico` is absent whatever this machine has.
    let rustup_home = dir.join("rustup");

    let out = Command::new(env!("CARGO_BIN_EXE_cargo-pico"))
        .args(["pico", "build"])
        .current_dir(&*dir)
        .env("RUSTUP_HOME", &rustup_home)
        .env_remove("RUST_LOG")
        .output()
        .expect("run cargo-pico");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("the `pico` toolchain is not installed"),
        "{stderr}"
    );
    assert!(stderr.contains("run `cargo pico install`"), "{stderr}");
}
