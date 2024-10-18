use hashbrown::HashMap;
use itertools::enumerate;
use log::{debug, info, warn};
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_field::{AbstractField, Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_vm::{
    compiler::{
        recursion::{config::InnerConfig, program_builder::hints::hintable::Hintable},
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    configs::{bb_poseidon2::BabyBearPoseidon2, config::StarkGenericConfig},
    emulator::{
        context::EmulatorContext,
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            record::EmulationRecord,
            riscv_emulator::{EmulationError, EmulatorMode, RiscvEmulator},
        },
        stdin::EmulatorStdin,
    },
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::riscv_recursion::{builder::RiscvVerifierCircuit, stdin::RiscvRecursionStdin},
        machine::{riscv_machine::RiscvMachine, simple_recursion_machine::SimpleRecursionMachine},
    },
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        logger::setup_logger,
        machine::MachineBehavior,
        witness::ProvingWitness,
    },
    primitives::consts::{RECURSION_NUM_PVS, RISCV_NUM_PVS},
    recursion::runtime::Runtime as RecursionRuntime,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{
    env,
    hash::{DefaultHasher, Hash, Hasher},
    time::Instant,
};

const TEST_BATCH_SIZE: usize = 100;

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();

    // run with default fibo
    let (elf, stdin, _, _) = parse_args::parse_args(env::args().collect());
    let start = Instant::now();

    info!("Being RiscV..");

    info!("\n Creating Program..");
    let compiler = Compiler::new(SourceType::RiscV, elf);
    let program = compiler.compile();

    // Setup config and chips.
    info!("\n Creating BaseMachine (at {:?})..", start.elapsed());
    let config = BabyBearPoseidon2::new();
    let chips = RiscvChipType::all_chips();

    // Create a new machine based on config and chips
    let riscv_machine = RiscvMachine::new(config, RISCV_NUM_PVS, chips);
    info!("{} created.", riscv_machine.name());

    // Setup machine prover, verifier, pk and vk.
    info!("\n Setup machine (at {:?})..", start.elapsed());
    let (pk, vk) = riscv_machine.setup_keys(&program);

    info!("\n Construct riscv proving witness..");
    let witness = ProvingWitness::new_with_program(
        program,
        stdin,
        EmulatorOpts::test_opts(),
        EmulatorContext::default(),
    );

    // Generate the proof.
    info!("\n Generating proof (at {:?})..", start.elapsed());
    let proof = riscv_machine.prove(&pk, &witness);
    info!("{} generated.", proof.name());

    let proof_size = bincode::serialize(&proof).unwrap().len();
    info!("Riscv proof size: {}", proof_size);

    // Verify the proof.
    info!("\n Verifying Riscv proof (at {:?})..", start.elapsed());
    let result = riscv_machine.verify(&vk, &proof);
    info!(
        "The proof is verified: {} (at {:?})..",
        result.is_ok(),
        start.elapsed()
    );
    assert_eq!(result.is_ok(), true);

    //////////////////////////////////////

    info!("\n Begin Recursion..");

    info!("Build recursion program (at {:?})..", start.elapsed());
    let recursion_program =
        RiscvVerifierCircuit::<InnerConfig, BabyBearPoseidon2>::build(&riscv_machine);

    let serialized_program = bincode::serialize(&recursion_program).unwrap();
    let mut hasher = DefaultHasher::new();
    serialized_program.hash(&mut hasher);
    let hash = hasher.finish();
    info!("recursion program hash: {}", hash);
    // todo: check program hash
    assert_eq!(hash, 9369494871096519575);

    let mut challenger = DuplexChallenger::new(riscv_machine.config().perm.clone());
    let recursion_stdin = RiscvRecursionStdin::construct(
        &vk,
        &riscv_machine,
        &proof.proofs(),
        &mut challenger,
        TEST_BATCH_SIZE,
    );
    assert_eq!(recursion_stdin.len(), 1);

    // Execute the runtime.
    let recursion_record = tracing::debug_span!("execute runtime").in_scope(|| {
        let mut witness_stream = Vec::new();
        witness_stream.extend(recursion_stdin[0].write());

        let mut runtime = RecursionRuntime::<
            <BabyBearPoseidon2 as StarkGenericConfig>::Val,
            <BabyBearPoseidon2 as StarkGenericConfig>::Challenge,
            _,
        >::new(&recursion_program, riscv_machine.config().perm.clone());
        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        runtime.record
    });

    let stats = recursion_record.stats();
    debug!("recursion record stats:");
    for (key, value) in &stats {
        debug!("|- {:<28}: {}", key, value);
    }

    // check expected record stats
    // todo: check why cpu events keep changing
    let mut expected_stats = HashMap::<String, usize>::new();
    expected_stats.insert("poseidon2_hash_events".to_string(), 10600);
    expected_stats.insert("poseidon2_compress_events".to_string(), 47347);
    expected_stats.insert("fri_fold_events".to_string(), 384800);
    expected_stats.insert("range_check_events".to_string(), 67605);
    expected_stats.insert("exp_reverse_bits_len_events".to_string(), 91200);
    assert_eq!(
        stats.get("poseidon2_hash_events"),
        expected_stats.get("poseidon2_hash_events")
    );
    assert_eq!(
        stats.get("poseidon2_compress_events"),
        expected_stats.get("poseidon2_compress_events")
    );
    assert_eq!(
        stats.get("fri_fold_event"),
        expected_stats.get("fri_fold_event")
    );
    assert_eq!(
        stats.get("range_check_events"),
        expected_stats.get("range_check_events")
    );
    assert_eq!(
        stats.get("exp_reverse_bits_len_events"),
        expected_stats.get("exp_reverse_bits_len_events")
    );

    // Setup recursion machine
    info!("\n Setup recursion machine (at {:?})..", start.elapsed());
    let riscv_recursion_machine = SimpleRecursionMachine::new(
        BabyBearPoseidon2::new(),
        RECURSION_NUM_PVS,
        RecursionChipType::<BabyBear, 3>::all_chips(),
    );
    let (recursion_pk, recursion_vk) = riscv_recursion_machine.setup_keys(&recursion_program);

    info!(
        "\n Complement recursion records (at {:?})..",
        start.elapsed()
    );
    let mut recursion_records = vec![recursion_record.clone()];
    riscv_recursion_machine.complement_record(&mut recursion_records);

    info!("\n Construct proving witness..");
    let recursion_witness = ProvingWitness::new_with_records(recursion_records);

    // Generate the proof.
    info!("\n Generating recursion proof (at {:?})..", start.elapsed());
    let recursion_proof = riscv_recursion_machine.prove(&recursion_pk, &recursion_witness);
    info!("{} generated.", recursion_proof.name());

    let proof_size = bincode::serialize(&recursion_proof).unwrap().len();
    info!("Recursion proof size: {}", proof_size);

    // Verify the proof.
    info!("\n Verifying recursion proof (at {:?})..", start.elapsed());
    let recursion_result = riscv_recursion_machine.verify(&recursion_vk, &recursion_proof);
    info!(
        "The proof is verified: {} (at {:?})",
        recursion_result.is_ok(),
        start.elapsed()
    );
    assert_eq!(recursion_result.is_ok(), true);
}
