//! Common test functions for RISC-V chips: emulation helpers, event counters and the CUDA test
//! stream. The FRI prove-and-verify helpers (`run_test`, `test_rv64_prove_and_verify*`) were
//! removed with the FRI proving path (tag `legacy-fri-last`); the chip tests that were built on
//! them went with it and are to be rewritten on the MLE engine.

use crate::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    cuda_adaptor::resource_pool::{
        mem_pool::create_ctx,
        stream_pool::{create_stream, get_global_stream_pool},
    },
    emulator::{
        emulator::MetaEmulator,
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            emulator::RiscvEmulator, public_values::RecordFinalPvsState, record::EmulationRecord,
        },
        stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{
        chip::{ChipBehavior, MetaChip},
        witness::ProvingWitness,
    },
};
use cudart::{memory::CudaHostAllocFlags, stream::CudaStream};
use p3_koala_bear::KoalaBear;
use std::{fs, path::PathBuf, sync::Arc};

/// Initialise the global CPU event buffer pool if nothing else has yet.
///
/// A `std::sync::Once` is not enough: it only covers this call site, while the same pool is also
/// initialised from chip and emulator code. Guarding on the pool's own state matches the other call
/// sites and is correct whoever got there first.
#[allow(dead_code)] // kept for the chip tests to be rewritten on the MLE engine
fn init_cpu_event_pool_once() {
    use crate::emulator::riscv::cpu_event_pool::{init_cpu_event_buffer_pool, is_pool_initialized};
    if !is_pool_initialized() {
        init_cpu_event_buffer_pool(50, CudaHostAllocFlags::DEFAULT);
    }
}

/// Run emulation and return all records.
#[allow(dead_code)] // kept for the chip tests to be rewritten on the MLE engine
pub(crate) fn test_rv64_emulate(
    program: Arc<Program>,
    stdin: EmulatorStdin<Program, Vec<u8>>,
) -> Vec<crate::emulator::riscv::record::EmulationRecord> {
    test_rv64_emulate_with_opts(program, stdin, EmulatorOpts::default())
}

/// Run emulation with custom opts and return all records.
#[allow(dead_code)] // kept for the chip tests to be rewritten on the MLE engine
pub(crate) fn test_rv64_emulate_with_opts(
    program: Arc<Program>,
    stdin: EmulatorStdin<Program, Vec<u8>>,
    opts: EmulatorOpts,
) -> Vec<crate::emulator::riscv::record::EmulationRecord> {
    init_cpu_event_pool_once();

    println!("Setting up emulator (chunk_size={})", opts.chunk_size);
    let final_pvs_state = Arc::new(RecordFinalPvsState::default());
    let mut emulator =
        RiscvEmulator::new_single::<KoalaBear>(program.clone(), final_pvs_state, opts, None);

    emulator.write_stdin(&stdin);

    println!("Emulating");
    let mut all_records = vec![];
    loop {
        let report = emulator
            .emulate_batch(&mut |record| {
                all_records.push(record);
            })
            .unwrap();
        if report.done {
            break;
        }
    }

    all_records
}

/// Run extra_record for all active chips to populate derived events
/// (e.g. global_lookup_events from MemoryInitFinalize, byte_lookups from GlobalChip).
pub(crate) fn run_extra_records(
    chips: &[MetaChip<KoalaBear, RiscvChipType<KoalaBear>>],
    record: &mut EmulationRecord,
) {
    let mut extra = EmulationRecord::default();
    for chip in chips {
        if chip.is_active(record) {
            chip.extra_record(record, &mut extra);
        }
    }
    record.append(&mut extra);
}

/// Find the first record containing events for the given syscall code.
#[allow(dead_code)] // kept for the chip tests to be rewritten on the MLE engine
pub(crate) fn find_record_with_events(
    records: Vec<EmulationRecord>,
    syscall_code: crate::emulator::riscv::syscalls::SyscallCode,
) -> EmulationRecord {
    records
        .into_iter()
        .find(|r| {
            r.precompile_events
                .get_events(syscall_code)
                .is_some_and(|evts| !evts.is_empty())
        })
        .unwrap_or_else(|| panic!("No record contains {:?} events", syscall_code))
}

/// Count precompile events of a given syscall code in a record.
#[allow(dead_code)] // kept for the chip tests to be rewritten on the MLE engine
pub(crate) fn count_events(
    record: &EmulationRecord,
    syscall_code: crate::emulator::riscv::syscalls::SyscallCode,
) -> usize {
    record.get_precompile_events(syscall_code).len()
}

/// Count total precompile events across all records.
#[allow(dead_code)] // kept for the chip tests to be rewritten on the MLE engine
pub(crate) fn count_total_events(
    records: &[EmulationRecord],
    syscall_code: crate::emulator::riscv::syscalls::SyscallCode,
) -> usize {
    records.iter().map(|r| count_events(r, syscall_code)).sum()
}

#[allow(dead_code)]
type F = KoalaBear;

#[allow(dead_code)]
pub(crate) enum TestElf {
    Fib,
    Reth,
}

impl TestElf {
    #[allow(dead_code)]
    fn elf(&self) -> Vec<u8> {
        let filename = match self {
            Self::Fib => "rv64/fib-elf",
            Self::Reth => "rv64/reth-elf",
        };
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ["..", "perf", "bench_data", filename]
            .iter()
            .for_each(|dir| path.push(dir));

        fs::read(path).unwrap()
    }
}

#[allow(dead_code)]
pub(crate) enum TestInput {
    Fib(u32),
    Reth171,
    Reth188,
}

impl TestInput {
    #[allow(dead_code)]
    fn input_bytes(&self) -> Vec<u8> {
        let filename = match self {
            Self::Fib(n) => return bincode::serialize(n).unwrap(),
            Self::Reth171 => "rv64/reth-17106222.bin",
            Self::Reth188 => "rv64/reth-18884864.bin",
        };

        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ["..", "perf", "bench_data", filename]
            .iter()
            .for_each(|dir| path.push(dir));

        fs::read(path).unwrap()
    }
}

pub(crate) fn init_test_stream() -> &'static CudaStream {
    create_ctx(0);
    create_stream(0);
    let sync_stream = get_global_stream_pool(0);
    &sync_stream.0
}

#[allow(dead_code)]
pub(crate) fn generate_test_chunks(elf: TestElf, input: TestInput) -> Vec<EmulationRecord> {
    let elf = elf.elf();

    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let input_bytes = input.input_bytes();
    stdin_builder.write_slice(&input_bytes);
    let stdin = stdin_builder.finalize();

    let program = Compiler::new(SourceType::RISCV, &elf).unwrap().compile();
    let chips = RiscvChipType::<F>::all_chips();
    let witness = ProvingWitness::<KoalaBearPoseidon2, RiscvChipType<F>, _>::setup_for_mle_riscv(
        program,
        stdin,
        EmulatorOpts::bench_riscv_ops(),
    );
    let final_pvs_state = Arc::new(RecordFinalPvsState::default());
    let mut emulator = MetaEmulator::setup_riscv(&witness, final_pvs_state, None);
    let mut records = vec![];
    loop {
        let done = emulator.next_record_batch(&mut |r| records.push(r)).done;
        println!("generated records: {}, done: {done}", records.len());
        if done {
            break;
        }
    }
    // What `RiscvMachine::complement_record` used to do: let every active chip derive its extra
    // events (global lookups, byte lookups, ...) into the record.
    for record in &mut records {
        run_extra_records(&chips, record);
    }

    records
}

/// Number of constraint-DAG nodes reachable from an AIR's constraint roots. This is the zerocheck
/// rule count the MLE keygen derives: one rule per node in the sub-edge closure of
/// `constraint_idx`, leaves (variables, constants, selectors) included, interaction-only nodes
/// excluded. Pinning it in a unit test localises any change in constraint expression shape.
pub(crate) fn reachable_constraint_nodes<F: p3_field::Field>(
    dag: &pico_mle_core::air::symbolic::SymbolicExpressionDag<F>,
) -> usize {
    use pico_mle_core::air::symbolic::SymbolicExpressionNode;

    let mut seen = vec![false; dag.nodes.len()];
    let mut stack = dag.constraint_idx.clone();
    let mut count = 0;
    while let Some(idx) = stack.pop() {
        if seen[idx] {
            continue;
        }
        seen[idx] = true;
        count += 1;
        match &dag.nodes[idx] {
            SymbolicExpressionNode::Add {
                left_idx,
                right_idx,
                ..
            }
            | SymbolicExpressionNode::Sub {
                left_idx,
                right_idx,
                ..
            }
            | SymbolicExpressionNode::Mul {
                left_idx,
                right_idx,
                ..
            } => {
                stack.push(*left_idx);
                stack.push(*right_idx);
            }
            SymbolicExpressionNode::Neg { idx: child, .. } => stack.push(*child),
            SymbolicExpressionNode::Variable(_)
            | SymbolicExpressionNode::IsFirstRow
            | SymbolicExpressionNode::IsLastRow
            | SymbolicExpressionNode::IsTransition
            | SymbolicExpressionNode::Constant(_) => {}
        }
    }
    count
}
