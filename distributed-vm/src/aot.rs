use std::sync::atomic::{AtomicBool, Ordering};

use pico_aot_dispatch::AOT;
use pico_aot_runtime::AotError;
use sha2::{Digest, Sha256};

/// Whether [`register`] installed this binary's own generated program.
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Registers the generated AOT program. A refused one (the bootstrap stub, or code generated
/// against another codegen stamp) installs no factory, and `EmulatorOpts::bench_riscv_ops` then
/// leaves the snapshot thread on the interpreter, so the run is slower but its records the same.
/// A conflict leaves the program registered first in place, with AOT emulation on.
pub fn register() {
    match pico_aot_runtime::register(&AOT) {
        Ok(()) => REGISTERED.store(true, Ordering::Release),
        Err(err @ AotError::Conflict { .. }) => {
            tracing::warn!("AOT emulation runs the program registered first, not this one: {err}")
        }
        Err(err) => tracing::warn!("AOT emulation is off, the snapshot thread interprets: {err}"),
    }
}

/// Refuses to prove `elf` with compiled code generated from another ELF.
///
/// The registered program runs every block of whatever ELF the process proves: the runtime
/// does not hold it against that ELF. A guest swapped without regenerating the AOT crates would
/// run its PCs through code compiled for other instructions and fail somewhere inside a proof;
/// this makes it fail when the ELF is loaded, saying what to do.
pub(crate) fn ensure_generated_from(elf: &[u8], source: &str) {
    if !REGISTERED.load(Ordering::Acquire) {
        return;
    }
    let generated_from = AOT.elf_sha256();
    let loaded: [u8; 32] = Sha256::digest(elf).into();
    let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert!(
        loaded == generated_from,
        "this binary's AOT program was generated from the ELF with SHA-256 {}, but {source} has \
         SHA-256 {}: regenerate the AOT crates from this ELF (`cargo run -r -p pico-aot-codegen \
         --bin generate_crates -- <elf>`) and rebuild, or build without `aot-emulator`",
        hex(generated_from),
        hex(loaded),
    );
}
