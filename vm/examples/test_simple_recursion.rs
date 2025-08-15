use hashbrown::HashMap;
use p3_challenger::DuplexChallenger;
use pico_vm::{
    compiler::{
        recursion::circuit::witness::Witnessable,
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    configs::{
        config::{StarkGenericConfig, Val},
        field_config::{BabyBearSimple, KoalaBearSimple},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    emulator::{
        opts::EmulatorOpts, record::RecordBehavior,
        recursion::emulator::Runtime as RecursionRuntime, riscv::riscv_emulator::RiscvEmulator,
        stdin::EmulatorStdin,
    },
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::simple_circuit::{builder::SimpleVerifierCircuit, stdin::SimpleRecursionStdin},
        machine::simple::SimpleMachine,
    },
    machine::{logger::setup_logger, machine::MachineBehavior, witness::ProvingWitness},
    primitives::consts::{
        BABYBEAR_S_BOX_DEGREE, KOALABEAR_S_BOX_DEGREE, MAX_NUM_PVS, RISCV_NUM_PVS,
    },
};
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    time::Instant,
};
use tracing::{debug, info};

#[path = "common/parse_args.rs"]
mod parse_args;

macro_rules! run {
    ($func_name:ident, $riscv_sc:ident, $recur_cc:ident, $recur_sc:ident, $s_box_degree:ident) => {
        fn $func_name(
            elf: &'static [u8],
            stdin: EmulatorStdin<Program, Vec<u8>>,
            step_name: String,
        ) {
            let start = Instant::now();

            info!("\n Creating Program..");
            let compiler = Compiler::new(SourceType::RISCV, elf);
            let program = compiler.compile();

            info!("\n Creating emulator (at {:?})..", start.elapsed());
            let mut emulator =
                RiscvEmulator::new_single::<Val<$riscv_sc>>(program, EmulatorOpts::default(), None);
            let records = emulator.run(Some(stdin)).unwrap();

            // TRICKY: We copy the memory initialize and finalize events from the second (last)
            // record to this record, since the memory lookups could only work if has the
            // full lookups in the all records.

            for record in &records {
                debug!("record events: {:?}", record.stats());
            }

            assert_eq!(
                records.len(),
                2,
                "We could only test for one record for now and the last is the final one",
            );

            let mut record = records[0].clone();
            assert!(record.memory_initialize_events.is_empty());
            assert!(record.memory_finalize_events.is_empty());
            records[1]
                .memory_initialize_events
                .clone_into(&mut record.memory_initialize_events);
            records[1]
                .memory_finalize_events
                .clone_into(&mut record.memory_finalize_events);
            records[1]
                .public_values
                .last_initialize_addr_bits
                .clone_into(&mut record.public_values.last_initialize_addr_bits);
            records[1]
                .public_values
                .last_finalize_addr_bits
                .clone_into(&mut record.public_values.last_finalize_addr_bits);
            let program = record.program.clone();

            let stats = record.stats();
            debug!("final record stats:");
            for (key, value) in &stats {
                debug!("|- {:<25}: {}", key, value);
            }

            let mut records = vec![record];

            // Setup config and chips.
            info!("\n Creating BaseMachine (at {:?})..", start.elapsed());
            let config = $riscv_sc::new();
            let chips = RiscvChipType::all_chips();

            // Create a new machine based on config and chips
            let simple_machine = SimpleMachine::new(config, chips, RISCV_NUM_PVS);

            // Setup machine prover, verifier, pk and vk.
            info!("\n Setup machine (at {:?})..", start.elapsed());
            let (pk, vk) = simple_machine.setup_keys(&program);

            info!("\n Complement records (at {:?})..", start.elapsed());
            simple_machine.complement_record(&mut records);

            for (i, record) in records.iter().enumerate() {
                let stats = record.stats();
                debug!("post complement record stats[{}]:", i);
                for (key, value) in &stats {
                    debug!("|- {:<25}: {}", key, value);
                }
            }

            info!("\n Construct proving witness..");
            let witness = ProvingWitness::setup_with_keys_and_records(pk, vk.clone(), records);

            // Generate the proof.
            info!("\n Generating proof (at {:?})..", start.elapsed());
            let proof = simple_machine.prove(&witness);
            info!("{} generated.", proof.name());

            debug!(
                "|- Commitment size: {}",
                bincode::serialize(&proof.proofs()[0].commitments)
                    .unwrap()
                    .len()
            );
            debug!(
                "|- Opened values size: {}",
                bincode::serialize(&proof.proofs()[0].opened_values)
                    .unwrap()
                    .len()
            );
            debug!(
                "|- Opening proof size: {}",
                bincode::serialize(&proof.proofs()[0].opening_proof)
                    .unwrap()
                    .len()
            );
            debug!(
                "|- Log main degrees size: {}",
                bincode::serialize(&proof.proofs()[0].log_main_degrees)
                    .unwrap()
                    .len()
            );
            debug!(
                "|- Log quotient degrees size: {}",
                bincode::serialize(&proof.proofs()[0].log_quotient_degrees)
                    .unwrap()
                    .len()
            );
            debug!(
                "|- Chip ordering size: {}",
                bincode::serialize(&proof.proofs()[0].main_chip_ordering)
                    .unwrap()
                    .len()
            );
            debug!(
                "|- Public values size: {}",
                bincode::serialize(&proof.proofs()[0].public_values)
                    .unwrap()
                    .len()
            );

            // Verify the proof.
            info!("\n Verifying proof (at {:?})..", start.elapsed());
            let result = simple_machine.verify(&proof, &vk);
            info!(
                "The proof is verified: {} (at {:?})",
                result.is_ok(),
                start.elapsed()
            );
            assert!(result.is_ok());

            if step_name == "riscv" {
                return;
            }

            // ------------------ start recursion ------------------

            let base_proof = proof.proofs()[0].clone();

            // Get recursion input
            let mut base_challenger = DuplexChallenger::new(simple_machine.config().perm.clone());

            let recursion_stdin = SimpleRecursionStdin::construct(
                simple_machine.base_machine(),
                &vk,
                &mut base_challenger,
                base_proof.clone(),
            );

            // Get recursion program
            // Note that simple_machine is used as input for recursive verifier to build the program
            info!("\n Build recursion program (at {:?})..", start.elapsed());
            let recursion_program = SimpleVerifierCircuit::<$recur_cc, $recur_sc>::build(
                simple_machine.base_machine(),
                &recursion_stdin,
            );

            let serialized_program = bincode::serialize(&recursion_program).unwrap();
            let mut hasher = DefaultHasher::new();
            serialized_program.hash(&mut hasher);
            let hash = hasher.finish();
            info!("Recursion program hash: {}", hash);

            // Emulation.
            let recursion_record = tracing::debug_span!("Recursion Emulator").in_scope(|| {
                let mut witness_stream = Vec::new();
                Witnessable::<$recur_cc>::write(&recursion_stdin, &mut witness_stream);

                let mut runtime = RecursionRuntime::<
                    <$recur_sc as StarkGenericConfig>::Val,
                    <$recur_sc as StarkGenericConfig>::Challenge,
                    _,
                    _,
                    $s_box_degree,
                >::new(
                    recursion_program.clone().into(),
                    simple_machine.config().perm.clone(),
                );
                runtime.witness_stream = witness_stream.into();
                runtime.run().unwrap();
                runtime.record
            });

            let stats = recursion_record.stats();
            info!("Simple recursion record stats:");
            for (key, value) in &stats {
                info!("|- {:<28}: {}", key, value);
            }

            let mut expected_stats = HashMap::<String, usize>::new();
            expected_stats.insert("poseidon2_events".to_string(), 602);
            // assert!([727, 660].contains(stats.get("poseidon2_events").unwrap()));

            // Setup field_config machine
            info!(
                "\n Setup simple recursion machine (at {:?})..",
                start.elapsed()
            );
            // Note that here we use SimpleMachine to build the recursion machine
            // Note that it should only accept witnesses initialized from records
            let recursion_machine = SimpleMachine::new(
                $recur_sc::new(),
                RecursionChipType::<Val<$recur_sc>>::all_chips(),
                MAX_NUM_PVS,
            );
            let (recursion_pk, recursion_vk) = recursion_machine.setup_keys(&recursion_program);

            info!(
                "\n Complement simple recursion records (at {:?})..",
                start.elapsed()
            );
            let mut recursion_records = vec![recursion_record.clone()];
            recursion_machine.complement_record(&mut recursion_records);

            info!("\n Construct proving witness..");
            let recursion_witness = ProvingWitness::setup_with_keys_and_records(
                recursion_pk,
                recursion_vk,
                recursion_records,
            );

            // Generate the proof.
            info!(
                "\n Generating simple recursion proof (at {:?})..",
                start.elapsed()
            );
            let recursion_proof = recursion_machine.prove(&recursion_witness);

            // Verify the proof.
            info!(
                "\n Verifying simple recursion proof (at {:?})..",
                start.elapsed()
            );
            let recursion_result = recursion_machine.verify(&recursion_proof, &vk);
            info!(
                "The proof is verified: {} (at {:?})",
                recursion_result.is_ok(),
                start.elapsed()
            );
            assert!(recursion_result.is_ok());
        }
    };
}

run!(
    run_babybear,
    BabyBearPoseidon2,
    BabyBearSimple,
    BabyBearPoseidon2,
    BABYBEAR_S_BOX_DEGREE
);
run!(
    run_koalabear,
    KoalaBearPoseidon2,
    KoalaBearSimple,
    KoalaBearPoseidon2,
    KOALABEAR_S_BOX_DEGREE
);

fn main() {
    setup_logger();

    let (elf, stdin, args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    match args.field.as_str() {
        "bb" => run_babybear(elf, stdin, args.step),
        "kb" => run_koalabear(elf, stdin, args.step),
        _ => unreachable!("Unsupported field for simple recursion: {}", args.field),
    }
}
