//! The ed25519 guest runs the same under the AOT runtime as under pico-vm's interpreter.
//!
//! `perf/bench_data/rv64/ed25519-elf` decompresses two points, which asks the `FD_EDDECOMPRESS`
//! hook first and then calls `ED_DECOMPRESS`, and adds points with `ED_ADD`. The hook's answer
//! decides how many more values the guest reads, so an AOT hook that answers differently shows up
//! here as a run that stops on missing input rather than as a wrong value.
//!
//! The AOT side interprets every block, the way the bootstrap dispatch does before any chunk is
//! generated, so this needs no code generation; the hooks and syscalls it reaches are the ones
//! generated code reaches.

use std::sync::Arc;

use p3_koala_bear::KoalaBear;
use pico_aot_runtime::{AotEmulatorCore, NextStep};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::{EmulatorOpts, SnapshotMainMode, SplitOpts},
        riscv::{
            chunk_split::ChunkSplitConfig, public_values::RecordFinalPvsState,
            riscv_emulator::RiscvEmulator,
        },
        stdin::EmulatorStdin,
    },
};

const ED25519_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../perf/bench_data/rv64/ed25519-elf"
));

/// What `--elf ed25519 --n 10` writes in `vm/examples/common/parse_args.rs`: the basepoint, its
/// negation, and two scalars.
fn stdin() -> EmulatorStdin<Program, Vec<u8>> {
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    stdin.write(&basepoint);
    let mut neg_basepoint = basepoint;
    neg_basepoint[31] |= 0x80;
    stdin.write(&neg_basepoint);
    let mut scalar = [0u8; 32];
    scalar[..4].copy_from_slice(&10u32.to_le_bytes());
    stdin.write(&scalar);
    scalar[4] = 1;
    stdin.write(&scalar);
    stdin.finalize()
}

/// Every field set, since `EmulatorOpts::default` reads the environment.
fn opts() -> EmulatorOpts {
    let chunk_size = 1 << 22;
    EmulatorOpts {
        chunk_size,
        chunk_batch_size: 1,
        split_opts: SplitOpts::new(chunk_size as usize >> 2),
        max_cycles: Some(1 << 32),
        cycle_tracker: false,
        cost_estimator: false,
        snapshot_main: SnapshotMainMode::Interpreter,
    }
}

#[test]
fn the_ed25519_guest_runs_the_same_under_aot() {
    let program: Arc<Program> = Compiler::new(SourceType::RISCV, ED25519_ELF)
        .expect("the ed25519 ELF parses")
        .compile();
    let stdin = stdin();

    let mut interpreter = RiscvEmulator::new_single::<KoalaBear>(
        program.clone(),
        Arc::new(RecordFinalPvsState::default()),
        opts(),
        None,
    );
    interpreter.write_stdin(&stdin);
    loop {
        let report = interpreter
            .emulate_batch(&mut |_| {})
            .expect("the ed25519 guest runs under the interpreter");
        if report.done {
            break;
        }
    }

    let mut aot = AotEmulatorCore::new(program, stdin.inputs.to_vec());
    aot.batch_chunk_target = 0;
    aot.batch_chunks_emulated = 0;
    aot.batch_stop = false;
    aot.chunk_split_config = ChunkSplitConfig::disabled(aot.max_syscall_cycles);
    let mut next = NextStep::Dynamic(aot.pc);
    while !aot.should_yield() {
        next = match next {
            NextStep::Direct(block) => block(&mut aot),
            NextStep::Dynamic(pc) => {
                aot.pc = pc;
                aot.interpret_from_current_pc()
            }
            NextStep::Halt => break,
        }
        .expect("the ed25519 guest runs under the AOT runtime");
    }

    assert_eq!(aot.pc, 0, "the guest did not halt under the AOT runtime");
    assert_eq!(
        aot.public_values_stream, interpreter.state.public_values_stream,
        "the committed values differ"
    );
    // The hook answers are spliced into the input stream, so equal streams mean every hook
    // answered alike, and the guest read all of them in both.
    assert_eq!(
        aot.input_stream, interpreter.state.input_stream,
        "the input streams differ"
    );
    assert_eq!(aot.input_stream_ptr, interpreter.state.input_stream_ptr);
    assert_eq!(
        aot.insn_count, interpreter.state.global_clk,
        "the two emulators ran a different number of instructions"
    );
}
