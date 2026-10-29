//! AOT-compiled emulator for Fibonacci example
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
    emulator::{
        opts::{EmulatorOpts, SnapshotMainMode},
        stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::witness::ProvingWitness,
};

// AOT-only runtime surface.
#[cfg(feature = "aot")]
pub use pico_aot_dispatch::AotEmulatorCore;

#[cfg(feature = "aot")]
pub use aot_common::{recycle_snapshot_memory, register_with_vm, AotRun};
#[cfg(feature = "aot")]
pub use pico_aot_dispatch::run_aot as run_aot_dispatch;

#[cfg(feature = "aot")]
pub fn register_snapshot_aot_factory() {
    pico_aot_runtime::register_snapshot_aot_factory(run_aot_dispatch);
}

pub const INPUT_VALUE: u32 = 9_000_000u32;
// The fixture `aot-generated` is generated from: AOT dispatch is keyed by pc alone, so blocks
// compiled from one ELF must never run under another.
pub const ELF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../perf/bench_data/rv64/fib-elf"
);

pub type FibonacciWitness =
    ProvingWitness<RiscvKBSC, RiscvChipType<<RiscvKBSC as StarkGenericConfig>::Val>, Vec<u8>>;

pub fn load_elf_bytes() -> Vec<u8> {
    std::fs::read(ELF_PATH).expect("Failed to read ELF file")
}

pub fn build_stdin(n: u32) -> EmulatorStdin<Program, Vec<u8>> {
    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<RiscvKBSC>();
    stdin_builder.write(&n);
    stdin_builder.finalize::<Program>()
}

pub fn build_witness(elf_bytes: &[u8], opts: EmulatorOpts, n: u32) -> FibonacciWitness {
    let compiler =
        Compiler::new(SourceType::RISCV, elf_bytes).expect("Failed to create RISC-V compiler");
    let program = compiler.compile();
    let stdin = build_stdin(n);

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
pub fn run_pipeline_once(label: &'static str, witness: &FibonacciWitness) -> PipelineBenchSummary {
    aot_common::run_pipeline_once(label, |callback| {
        pico_vm::proverchain::riscv::emulate_snapshot_pipeline(witness, move |record, done| {
            callback(record, done);
        })
    })
}

#[cfg(feature = "aot")]
pub fn run_pipeline_benchmark(
    label: &'static str,
    witness: &FibonacciWitness,
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
