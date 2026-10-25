//! AOT-compiled emulator for reth example
//!
//! This crate re-exports AotEmulatorCore from pico-aot-dispatch when the 'aot' feature is enabled.

use std::sync::Arc;

pub use aot_common::{AotOnlyBenchSummary, PipelineBenchSummary};

// Common Pico types used by binaries.
pub use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::{config::StarkGenericConfig, stark_config::KoalaBearPoseidon2 as RiscvKBSC},
    emulator::opts::{EmulatorOpts, SnapshotMainMode},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::witness::ProvingWitness,
};
pub use reth_lib::{
    create_stdin, load_block_input, load_reth_elf, parse_block_arg, validate_block,
};

// AOT-only runtime surface.
#[cfg(feature = "aot")]
pub use pico_aot_dispatch::AotEmulatorCore;

#[cfg(feature = "aot")]
pub use aot_common::{recycle_snapshot_memory, AotRun};
#[cfg(feature = "aot")]
pub use pico_aot_dispatch::run_aot as run_aot_dispatch;

#[cfg(feature = "aot")]
pub fn register_snapshot_aot_factory() {
    pico_aot_runtime::register_snapshot_aot_factory(run_aot_dispatch);
}

pub type RethWitness =
    ProvingWitness<RiscvKBSC, RiscvChipType<<RiscvKBSC as StarkGenericConfig>::Val>, Vec<u8>>;

pub fn build_witness(elf_bytes: &[u8], opts: EmulatorOpts, block_input: &[u8]) -> RethWitness {
    let compiler =
        Compiler::new(SourceType::RISCV, elf_bytes).expect("Failed to create RISC-V compiler");
    let program = compiler.compile();
    let stdin = create_stdin::<RiscvKBSC>(block_input).expect("Failed to create stdin");

    ProvingWitness {
        program: Some(program),
        vk_root: None,
        stdin: Some(stdin),
        flag_empty_stdin: false,
        config: None,
        opts: Some(opts),
        records: vec![],
    }
}

#[cfg(feature = "aot")]
pub fn run_pipeline_once(label: &'static str, witness: &RethWitness) -> PipelineBenchSummary {
    aot_common::run_pipeline_once(label, |callback| {
        pico_vm::proverchain::riscv::emulate_snapshot_pipeline(witness, move |record, done| {
            callback(record, done);
        })
    })
}

#[cfg(feature = "aot")]
pub fn run_pipeline_benchmark(
    label: &'static str,
    witness: &RethWitness,
    warmup_runs: usize,
    bench_runs: usize,
) -> Vec<PipelineBenchSummary> {
    aot_common::run_pipeline_benchmark(label, warmup_runs, bench_runs, |callback| {
        pico_vm::proverchain::riscv::emulate_snapshot_pipeline(witness, move |record, done| {
            callback(record, done);
        })
    })
}

#[cfg(feature = "aot")]
pub fn run_aot_only_once(
    label: &'static str,
    program: Arc<Program>,
    input_stream: &[Vec<u8>],
    opts: EmulatorOpts,
) -> AotOnlyBenchSummary {
    aot_common::run_aot_only_once(
        label,
        || AotEmulatorCore::new(program, input_stream.to_vec()),
        |emu| emu.next_state_batch(opts),
    )
}

#[cfg(feature = "aot")]
pub fn run_aot_only_benchmark(
    label: &'static str,
    program: Arc<Program>,
    input_stream: &[Vec<u8>],
    opts: EmulatorOpts,
    warmup_runs: usize,
    bench_runs: usize,
) -> Vec<AotOnlyBenchSummary> {
    aot_common::run_aot_only_benchmark(
        label,
        || AotEmulatorCore::new(program.clone(), input_stream.to_vec()),
        |emu| emu.next_state_batch(opts),
        warmup_runs,
        bench_runs,
    )
}

pub fn interpreter_snapshot_opts() -> EmulatorOpts {
    EmulatorOpts::bench_riscv_ops().with_snapshot_main(SnapshotMainMode::Interpreter)
}

#[cfg(feature = "aot")]
pub fn aot_snapshot_opts() -> EmulatorOpts {
    EmulatorOpts::bench_riscv_ops().with_snapshot_main(SnapshotMainMode::Aot)
}
