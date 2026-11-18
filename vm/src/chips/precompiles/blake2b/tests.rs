//! The `BLAKE2B_ROUNDS` precompile: the emulator against the reference, both chips' rows against
//! their AIRs, the shape a BLAKE2b chunk selects, and a proof of the records end to end.

use super::{
    control::NUM_BLAKE2B_CONTROL_COLS,
    g,
    round::{mix_steps, NUM_BLAKE2B_ROUND_COLS},
    rounds, Blake2bControlChip, Blake2bRoundChip, MESSAGE_DWORDS, MIX_INDICES, STATE_DWORDS,
};
use crate::{
    chips::tests::test_rv64_emulate,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        riscv::{
            record::EmulationRecord,
            syscalls::{precompiles::PrecompileEvent, SyscallCode},
        },
        stdin::EmulatorStdin,
    },
    machine::{chip::ChipBehavior, debug_folder::DebugConstraintFolder, septic::SepticDigest},
};
use core::borrow::BorrowMut;
use p3_air::{Air, RowWindow};
use p3_field::{extension::QuinticTrinomialExtensionField, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use rand::{rngs::StdRng, RngExt, SeedableRng};
use std::{collections::BTreeMap, sync::Arc};

type F = KoalaBear;
type EF = QuinticTrinomialExtensionField<KoalaBear>;

/// The syscall buffer: `v` then `m`, clear of the test program's few instructions.
const BUFFER: u64 = 0x10_0000;

fn li(rd: u8, imm: u64) -> Instruction {
    Instruction::new(Opcode::ADD, rd, 0, imm, true, true)
}

/// A program of one `BLAKE2B_ROUNDS` call per entry of `calls`, each on the buffer, then a halt,
/// over a buffer holding `v` and `m`.
fn program(calls: &[u32], v: &[u64; 16], m: &[u64; 16]) -> Arc<Program> {
    let mut instructions = Vec::new();
    for &n in calls {
        instructions.extend([
            li(10, BUFFER),
            li(11, u64::from(n)),
            li(5, u64::from(SyscallCode::BLAKE2B_ROUNDS as u32)),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ]);
    }
    instructions.extend([
        li(10, 0),
        li(5, u64::from(SyscallCode::HALT as u32)),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
    ]);
    let mut image = BTreeMap::new();
    for (i, word) in v.iter().chain(m).enumerate() {
        image.insert(BUFFER + 8 * i as u64, *word);
    }
    Arc::new(Program {
        instructions: instructions.into(),
        pc_start: 0,
        pc_base: 0,
        memory_image: Arc::new(image),
        preprocessed_shape: None,
        profiled_functions: Default::default(),
    })
}

fn random_words<const N: usize>(rng: &mut StdRng) -> [u64; N] {
    core::array::from_fn(|_| rng.random())
}

/// Every record of the run, and the one that holds its BLAKE2b calls.
fn emulate(program: Arc<Program>) -> (Vec<EmulationRecord>, EmulationRecord) {
    let stdin = EmulatorStdin::new_builder::<KoalaBearPoseidon2>().finalize();
    let records = test_rv64_emulate(program, stdin);
    let blake2b = records
        .iter()
        .find(|record| {
            record
                .precompile_events
                .get_events(SyscallCode::BLAKE2B_ROUNDS)
                .is_some_and(|events| !events.is_empty())
        })
        .expect("the run raised no BLAKE2b event")
        .clone();
    (records, blake2b)
}

/// The constraints `chip`'s AIR reports violated on `row`; the folder does not see lookups.
fn failures<C>(chip: &C, row: &[F]) -> Vec<String>
where
    C: for<'a> Air<DebugConstraintFolder<'a, F, EF>>,
{
    let dummy = [F::ZERO];
    let mut folder = DebugConstraintFolder::<F, EF> {
        preprocessed: RowWindow::from_two_rows(&dummy, &dummy),
        main: RowWindow::from_two_rows(row, row),
        global_cumulative_sum: SepticDigest::<F>::zero(),
        is_first_row: F::ZERO,
        is_last_row: F::ZERO,
        is_transition: F::ONE,
        public_values: &[],
        failures: Vec::new(),
        scopes: Vec::new(),
        constraint_count: 0,
    };
    chip.eval(&mut folder);
    folder
        .failures
        .iter()
        .map(|(scopes, failure)| format!("{scopes:?} {failure:?}"))
        .collect()
}

/// The mix the round chip lays out is the reference's G, value for value.
#[test]
fn the_mix_steps_are_g() {
    let mut rng = StdRng::seed_from_u64(7);
    for _ in 0..1000 {
        let v0: [u64; 16] = random_words(&mut rng);
        let (x, y) = (rng.random(), rng.random());
        for idx in MIX_INDICES {
            let (mut a, mut b) = (v0, v0);
            g(&mut a, idx, x, y);
            mix_steps(&mut b, idx, x, y);
            assert_eq!(a, b);
        }
    }
}

/// Calls of several lengths, one of them the most a call runs: each event holds what the
/// reference computes, the round chip has a row per round and the control chip one per call, and
/// every real and padding row of both satisfies its AIR.
#[test]
fn every_row_of_a_run_satisfies_the_airs() {
    let mut rng = StdRng::seed_from_u64(11);
    let v: [u64; STATE_DWORDS] = random_words(&mut rng);
    let m: [u64; MESSAGE_DWORDS] = random_words(&mut rng);
    let calls = [12, super::MAX_ROUNDS_PER_CALL, 23, 1, 10];
    let (_, record) = emulate(program(&calls, &v, &m));

    let events = record
        .get_precompile_events(SyscallCode::BLAKE2B_ROUNDS)
        .clone();
    assert_eq!(events.len(), calls.len());
    let mut expected = v;
    for ((_, event), &n) in events.iter().zip(&calls) {
        let PrecompileEvent::Blake2bRounds(event) = event else {
            unreachable!()
        };
        assert_eq!(event.v_in, expected);
        rounds(&mut expected, &m, n);
        assert_eq!(event.rounds, n);
        assert_eq!(event.v_out, expected);
        assert_eq!(event.m, m);
    }

    let round_chip = Blake2bRoundChip::<F>::default();
    let trace = round_chip.generate_main(&record, &mut EmulationRecord::default());
    let total: usize = calls.iter().map(|&n| n as usize).sum();
    assert_eq!(trace.width(), NUM_BLAKE2B_ROUND_COLS);
    assert_eq!(trace.height(), total.next_power_of_two());
    for (i, row) in trace.values.chunks(NUM_BLAKE2B_ROUND_COLS).enumerate() {
        let failures = failures(&round_chip, row);
        assert!(failures.is_empty(), "round row {i}: {failures:?}");
    }

    let control_chip = Blake2bControlChip::<F>::default();
    let trace = control_chip.generate_main(&record, &mut EmulationRecord::default());
    assert_eq!(trace.width(), NUM_BLAKE2B_CONTROL_COLS);
    for (i, row) in trace.values.chunks(NUM_BLAKE2B_CONTROL_COLS).enumerate() {
        let failures = failures(&control_chip, row);
        assert!(failures.is_empty(), "control row {i}: {failures:?}");
    }
}

/// A round row whose adder output is off by one in a byte fails its carry constraint: the
/// carries are expressions, so a wrong sum has no carry to hide behind.
#[test]
fn a_wrong_sum_fails_the_round_air() {
    let mut rng = StdRng::seed_from_u64(13);
    let (_, record) = emulate(program(
        &[12],
        &random_words(&mut rng),
        &random_words(&mut rng),
    ));
    let chip = Blake2bRoundChip::<F>::default();
    let trace = chip.generate_main(&record, &mut EmulationRecord::default());
    let mut row = trace.values[..NUM_BLAKE2B_ROUND_COLS].to_vec();
    let cols: &mut super::round::Blake2bRoundCols<F> = row.as_mut_slice().borrow_mut();
    cols.mix[3].c1[5] += F::ONE;
    assert!(!failures(&chip, &row).is_empty());
}

/// A BLAKE2b chunk selects a whitelist shape, its control chip and syscall table padded to the
/// call height its rounds allow.
#[test]
fn a_blake2b_chunk_selects_a_whitelist_shape() {
    use crate::mle::machine::shape::{
        blake2b_call_log_height, mle_natural_heights, select_riscv_shape,
    };
    let mut rng = StdRng::seed_from_u64(17);
    let calls = [super::MAX_ROUNDS_PER_CALL; 3];
    let (_, record) = emulate(program(
        &calls,
        &random_words(&mut rng),
        &random_words(&mut rng),
    ));
    let natural = mle_natural_heights(&record);
    assert_eq!(natural["Blake2bRound"], 3000);
    assert_eq!(natural["Blake2bControl"], 3);
    let mut present: Vec<String> = natural.keys().cloned().collect();
    present.extend(["Byte".to_string(), "Program".to_string()]);
    let shape: BTreeMap<String, usize> = select_riscv_shape(&present, &natural, false)
        .into_iter()
        .collect();
    assert_eq!(shape["Blake2bRound"], 12);
    assert_eq!(shape["Blake2bControl"], blake2b_call_log_height(12));
    assert_eq!(shape["SyscallPrecompile"], blake2b_call_log_height(12));
}

/// The run's records prove and verify: the round chain, the message offers and the byte lookups
/// all balance. On the CPU at natural heights; with `cuda`, on the GPU at natural heights and at
/// the whitelist's, which pads the control chip and the syscall table to the call height.
#[test]
fn a_blake2b_run_proves_and_verifies() {
    use crate::{compiler::program::ProgramBehavior, mle::machine::riscv::RiscvMachine};
    let mut rng = StdRng::seed_from_u64(19);
    let program = program(
        &[12, 37, 10],
        &random_words(&mut rng),
        &random_words(&mut rng),
    );
    let (records, _) = emulate(program.clone());
    #[cfg(not(feature = "cuda"))]
    let modes = [(20, false)];
    #[cfg(feature = "cuda")]
    let modes = {
        use crate::mle::machine::riscv::{init_mle_gpu_pool, MLE_GPU_DEVICE};
        init_mle_gpu_pool(MLE_GPU_DEVICE);
        [
            (20, false),
            (crate::mle::machine::riscv::DEFAULT_LOG_STACKED_HEIGHT, true),
        ]
    };
    for (log_stacked_height, bucket) in modes {
        let machine =
            RiscvMachine::new(program.clone(), log_stacked_height, bucket).expect("riscv keygen");
        let proof = machine.prove(&records).expect("the run proves");
        machine
            .verify(&proof, program.initial_global_cumulative_sum())
            .unwrap_or_else(|e| panic!("bucket {bucket}: the run does not verify: {e:?}"));
    }
}

/// Full blocks: 1100 calls of 1000 rounds split into two records of 524 calls (2^19 round rows,
/// the split's block) and a remainder of 52, and the run proves and verifies under the whitelist.
/// Two 2^19-row round chips are minutes of CPU proving, so it runs with `cuda` only.
#[cfg(feature = "cuda")]
#[test]
#[ignore = "two full BLAKE2b blocks on the GPU; run explicitly"]
fn full_blake2b_blocks_prove_under_the_whitelist() {
    use crate::{
        compiler::program::ProgramBehavior,
        mle::machine::riscv::{
            init_mle_gpu_pool, RiscvMachine, DEFAULT_LOG_STACKED_HEIGHT, MLE_GPU_DEVICE,
        },
    };
    let mut rng = StdRng::seed_from_u64(23);
    let program = program(
        &[super::MAX_ROUNDS_PER_CALL; 1100],
        &random_words(&mut rng),
        &random_words(&mut rng),
    );
    let (records, _) = emulate(program.clone());
    let blocks: Vec<usize> = records
        .iter()
        .filter_map(|r| r.precompile_events.get_events(SyscallCode::BLAKE2B_ROUNDS))
        .map(|events| events.len())
        .filter(|&n| n > 0)
        .collect();
    assert_eq!(blocks, [524, 524, 52], "the split's BLAKE2b records");
    init_mle_gpu_pool(MLE_GPU_DEVICE);
    let machine =
        RiscvMachine::new(program.clone(), DEFAULT_LOG_STACKED_HEIGHT, true).expect("riscv keygen");
    let started = std::time::Instant::now();
    let proof = machine.prove(&records).expect("the run proves");
    println!(
        "{} chunks proved in {} ms",
        records.len(),
        started.elapsed().as_millis()
    );
    machine
        .verify(&proof, program.initial_global_cumulative_sum())
        .expect("the run verifies");
}
