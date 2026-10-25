//! Emulation with explicit options, for the deferred examples.
//!
//! `riscv::emulate` takes its chunk size from `CHUNK_SIZE`, which it sets once per process, so a
//! run that varies the chunk size between emulations drives the emulator itself.

use std::sync::Arc;

use pico_vm::{
    compiler::riscv::program::Program,
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
    mle::machine::riscv::{self, EmulationOutput},
};

/// Default options with `CHUNK_SIZE`, or `default_chunk_size` when it is unset, as the chunk
/// size. The pinned CPU/ALU event buffers size themselves from `CHUNK_SIZE` on first use, so it is
/// set here when absent: every later chunk in this process must fit what the first one sized.
pub fn opts_from_env_chunk_size(default_chunk_size: u32) -> EmulatorOpts {
    if std::env::var_os("CHUNK_SIZE").is_none() {
        std::env::set_var("CHUNK_SIZE", default_chunk_size.to_string());
    }
    EmulatorOpts::default()
}

/// [`riscv::emulate_with_opts`], aborting on failure.
pub fn emulate_with_opts(
    program: Arc<Program>,
    stdin: &EmulatorStdin<Program, Vec<u8>>,
    opts: EmulatorOpts,
) -> EmulationOutput {
    riscv::emulate_with_opts(program, stdin, opts).expect("emulation")
}
