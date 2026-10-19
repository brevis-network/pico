//! Common test functions for RISC-V chips: emulation helpers and event counters. The FRI
//! prove-and-verify helpers (`run_test`, `test_rv64_prove_and_verify*`) were removed with the FRI
//! proving path (tag `legacy-fri-last`); the chip tests that were built on them went with it and
//! are to be rewritten on the MLE engine.

use crate::{
    compiler::riscv::program::Program,
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{emulator::RiscvEmulator, record::EmulationRecord},
        stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::{ChipBehavior, MetaChip},
};
use p3_koala_bear::KoalaBear;
use std::sync::Arc;

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
    println!("Setting up emulator (chunk_size={})", opts.chunk_size);
    let mut emulator = RiscvEmulator::new_single::<KoalaBear>(program.clone(), opts, None);

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
#[allow(dead_code)] // kept for the chip tests to be rewritten on the MLE engine
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

/// Pins the zerocheck rule count of `GcsBindAir`: one rule per DAG node reachable from the
/// constraint roots. A different septic expression shape changes this number.
#[test]
fn gcs_bind_reachable_rule_count() {
    use crate::{
        mle::machine::air::{GcsBindAir, GCS_DIGEST_LEN},
        primitives::consts::MAX_NUM_PVS,
    };
    use p3_air::BaseAir;
    use p3_koala_bear::KoalaBear;
    use pico_mle_core::{
        air::symbolic::{get_symbolic_builder_with_public_values, SymbolicConstraintsDag},
        keygen::types::TraceWidth,
    };

    let width = TraceWidth {
        preprocessed: None,
        cached_mains: vec![],
        common_main: BaseAir::<KoalaBear>::width(&GcsBindAir::<KoalaBear>::default()),
    };
    let builder = get_symbolic_builder_with_public_values::<KoalaBear, _>(
        &GcsBindAir::<KoalaBear>::default(),
        &width,
        GCS_DIGEST_LEN + MAX_NUM_PVS,
    );
    let constraints = builder.constraints();
    // The degree fixes the round-0 zerocheck coset count and the interaction count fixes the
    // LogUp side; neither is reachable from the constraint roots, so the rule count below would
    // not notice a change in either.
    assert_eq!(constraints.max_constraint_degree(), 3);
    assert_eq!(constraints.interactions.len(), 8);
    let dag: SymbolicConstraintsDag<KoalaBear> = constraints.into();
    assert_eq!(reachable_constraint_nodes(&dag.constraints), 836);
}
