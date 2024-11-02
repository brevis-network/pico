use hashbrown::HashMap;
use log::{debug, info, warn};
use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, DuplexChallenger};
use pico_vm::{
    compiler::{
        recursion::program_builder::hints::hintable::Hintable,
        riscv::compiler::{Compiler, SourceType},
    },
    configs::config::StarkGenericConfig,
    emulator::{opts::EmulatorOpts, record::RecordBehavior, riscv::riscv_emulator::RiscvEmulator},
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::simple_circuit::{builder::SimpleVerifierCircuit, stdin::SimpleRecursionStdin},
        configs::{recur_config as rcf, riscv_config::StarkConfig as RiscvSC},
        machine::simple_machine::SimpleMachine,
    },
    machine::{
        keys::BaseVerifyingKey, logger::setup_logger, machine::MachineBehavior, proof::BaseProof,
        witness::ProvingWitness,
    },
    primitives::consts::{MAX_NUM_PVS, RISCV_NUM_PVS, RISCV_SIMPLE_DEGREE},
    recursion::runtime::Runtime as RecursionRuntime,
};
use std::{
    env,
    hash::{DefaultHasher, Hash, Hasher},
    time::Instant,
};

#[path = "common/parse_args.rs"]
mod parse_args;

// todo: refactor the whole test

pub fn get_simple_recursion_stdin<'a, SC: StarkGenericConfig>(
    machine: &'a SimpleMachine<RiscvSC, RiscvChipType<BabyBear>>,
    reconstruct_challenger: &mut <RiscvSC as StarkGenericConfig>::Challenger,
    vk: &'a BaseVerifyingKey<RiscvSC>,
    base_challenger: &'a mut <RiscvSC as StarkGenericConfig>::Challenger,
    base_proof: BaseProof<RiscvSC>,
) -> SimpleRecursionStdin<'a, RiscvSC, RiscvChipType<BabyBear>> {
    let num_public_values = machine.num_public_values();

    vk.observed_by(reconstruct_challenger);
    vk.observed_by(base_challenger);

    base_challenger.observe(base_proof.commitments.main_commit);
    base_challenger.observe_slice(&base_proof.public_values[0..num_public_values]);

    let stdin = SimpleRecursionStdin {
        vk,
        machine: machine.base_machine(),
        base_proofs: vec![base_proof.clone()],
        base_challenger,
        initial_reconstruct_challenger: reconstruct_challenger.clone(),
        flag_complete: true,
    };

    stdin
}

fn main() {
    setup_logger();

    let (elf, stdin, test_case, input_n) = parse_args::parse_args(env::args().collect());
    let start = Instant::now();

    info!("\n Creating Program..");
    let compiler = Compiler::new(SourceType::RiscV, elf);
    let program = compiler.compile();

    info!("\n Creating emulator (at {:?})..", start.elapsed());
    let mut emulator = RiscvEmulator::new(program, EmulatorOpts::default());
    emulator.run_with_stdin(stdin).unwrap();

    // TRICKY: We copy the memory initialize and finalize events from the second (last)
    // record to this record, since the memory lookups could only work if has the
    // full lookups in the all records.
    assert_eq!(
        emulator.records.len(),
        2,
        "We could only test for one record for now and the last is the final one",
    );
    let mut record = emulator.records[0].clone();
    assert!(record.memory_initialize_events.is_empty());
    assert!(record.memory_finalize_events.is_empty());
    emulator.records[1]
        .memory_initialize_events
        .clone_into(&mut record.memory_initialize_events);
    emulator.records[1]
        .memory_finalize_events
        .clone_into(&mut record.memory_finalize_events);
    let program = record.program.clone();

    let mut records = vec![record];

    debug!("first record stats:");
    for (key, value) in &records[0].stats() {
        debug!("|- {:<25}: {}", key, value);
    }

    // Setup config and chips.
    info!("\n Creating BaseMachine (at {:?})..", start.elapsed());
    let config = RiscvSC::new();
    let fib_chips = RiscvChipType::all_chips();

    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, fib_chips, RISCV_NUM_PVS);

    // Setup machine prover, verifier, pk and vk.
    info!("\n Setup machine (at {:?})..", start.elapsed());
    let (pk, vk) = simple_machine.setup_keys(&program);

    info!("\n Complement records (at {:?})..", start.elapsed());
    simple_machine.complement_record(&mut records);

    info!("\n Construct proving witness..");
    let witness = ProvingWitness::setup_with_records(records);

    // Generate the proof.
    info!("\n Generating proof (at {:?})..", start.elapsed());
    let proof = simple_machine.prove(&pk, &witness);
    let base_proof = proof.proofs()[0].clone();
    info!("{} generated.", proof.name());

    // Verify the proof.
    info!("\n Verifying proof (at {:?})..", start.elapsed());
    let result = simple_machine.verify(&vk, &proof);
    info!("The proof is verified: {}", result.is_ok());
    assert_eq!(result.is_ok(), true);

    // Get field_config program
    // Note that simple_machine is used as input for recursive verifier to build the program
    info!("\n Build field_config program (at {:?})..", start.elapsed());
    let recursion_program =
        SimpleVerifierCircuit::<rcf::FieldConfig, _>::build(simple_machine.base_machine());

    let serialized_program = bincode::serialize(&recursion_program).unwrap();
    let mut hasher = DefaultHasher::new();
    serialized_program.hash(&mut hasher);
    let hash = hasher.finish();
    info!("field_config program hash: {}", hash);
    assert_eq!(hash, 5148864530479490320);

    // Get field_config input
    let mut reconstruct_challenger = DuplexChallenger::new(simple_machine.config().perm.clone());
    let mut base_challenger = DuplexChallenger::new(simple_machine.config().perm.clone());

    let recursion_stdin = SimpleRecursionStdin::construct(
        &simple_machine.base_machine(),
        &mut reconstruct_challenger,
        &vk,
        &mut base_challenger,
        base_proof.clone(),
    );

    // Execute the runtime.
    let recursion_record = tracing::debug_span!("execute runtime").in_scope(|| {
        let mut witness_stream = Vec::new();
        witness_stream.extend(recursion_stdin.write());

        let mut runtime = RecursionRuntime::<
            <rcf::StarkConfig as StarkGenericConfig>::Val,
            <rcf::StarkConfig as StarkGenericConfig>::Challenge,
            _,
        >::new(&recursion_program, simple_machine.config().perm.clone());
        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        runtime.record
    });

    let stats = recursion_record.stats();
    debug!("field_config record stats:");
    for (key, value) in &stats {
        debug!("|- {:<28}: {}", key, value);
    }

    // TODO: The number of CPU and range_check events keeps changing
    let mut expected_stats = HashMap::<String, usize>::new();
    expected_stats.insert("poseidon2_hash_events".to_string(), 8000);
    expected_stats.insert("poseidon2_compress_events".to_string(), 24598);
    expected_stats.insert("fri_fold_events".to_string(), 280000);
    // expected_stats.insert("range_check_events".to_string(), 67000);
    expected_stats.insert("exp_reverse_bits_len_events".to_string(), 660);
    assert_eq!(
        stats.get("poseidon2_events"),
        expected_stats.get("poseidon2_events")
    );
    assert_eq!(
        stats.get("fri_fold_event"),
        expected_stats.get("fri_fold_event")
    );
    if test_case == "fibonacci" && input_n == 20 {
        info!("check event stats for fib-20");
        // assert_eq!(
        //     stats.get("range_check_events"),
        //     expected_stats.get("range_check_events")
        // );
        // assert_eq!(
        //     stats.get("exp_reverse_bits_len_events"),
        //     expected_stats.get("exp_reverse_bits_len_events")
        // );
    } else {
        warn!("skip certain event stats checking for non-fib-20");
    }

    // Setup field_config machine
    info!("\n Setup field_config machine (at {:?})..", start.elapsed());
    // Note that here we use SimpleMachine to build the recursion machine
    // Note that it should only accept witnesses initialized from records
    let recursion_machine = SimpleMachine::new(
        rcf::StarkConfig::new(),
        RecursionChipType::<BabyBear, RISCV_SIMPLE_DEGREE>::all_chips(),
        MAX_NUM_PVS,
    );
    let (recursion_pk, recursion_vk) = recursion_machine.setup_keys(&recursion_program);

    info!(
        "\n Complement field_config records (at {:?})..",
        start.elapsed()
    );
    let mut recursion_records = vec![recursion_record.clone()];
    recursion_machine.complement_record(&mut recursion_records);

    info!("\n Construct proving witness..");
    let recursion_witness = ProvingWitness::setup_with_records(recursion_records);

    // Generate the proof.
    info!(
        "\n Generating field_config proof (at {:?})..",
        start.elapsed()
    );
    let recursion_proof = recursion_machine.prove(&recursion_pk, &recursion_witness);
    info!("{} generated.", recursion_proof.name());

    // Verify the proof.
    info!(
        "\n Verifying field_config proof (at {:?})..",
        start.elapsed()
    );
    let recursion_result = recursion_machine.verify(&recursion_vk, &recursion_proof);
    info!(
        "The proof is verified: {} (at {:?})",
        recursion_result.is_ok(),
        start.elapsed()
    );
    assert_eq!(recursion_result.is_ok(), true);
}
