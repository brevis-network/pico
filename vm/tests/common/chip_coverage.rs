//! The chip-coverage guest's shipped ELF and its pin, for every harness that runs it.
//!
//! The digest moves whenever the ELF is rebuilt, the source unchanged included: the guest compiles
//! `pico-vm` through `pico-sdk`, and cargo hashes the build directory into the image. Rebuild only
//! to change what the guest runs, then re-pin it here and re-record its golden heights.

use sha2::{Digest, Sha256};

// Relative to this file: the crates compiling it sit in different directories.
const ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/chip-coverage-elf");
const ELF_SHA256: &str = "c3f410f055d39662a4cfab3551e065b820fbe552a4fe955be4281d412008c27c";

/// The guest's ELF, refused unless it is the pinned one: traces and heights read off another image
/// say nothing about this guest's.
pub fn elf() -> &'static [u8] {
    assert_eq!(
        hex::encode(Sha256::digest(ELF)),
        ELF_SHA256,
        "perf/bench_data/rv64/chip-coverage-elf changed: re-pin it and re-record its golden heights"
    );
    ELF
}
