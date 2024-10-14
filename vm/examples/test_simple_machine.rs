use log::{debug, info};
use p3_air::{Air, BaseAir};
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::bb_poseidon2::BabyBearPoseidon2,
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{record::EmulationRecord, riscv_emulator::RiscvEmulator},
        stdin::EmulatorStdin,
    },
    instances::{chiptype::riscv_chiptype::FibChipType, machine::simple_machine::SimpleMachine},
    machine::{machine::MachineBehavior, witness::ProvingWitness},
    primitives::consts::{RECURSION_NUM_PVS, RISCV_NUM_PVS},
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{env, time::Instant};

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    env_logger::init();
    let (elf, stdin, _, _) = parse_args::parse_args(env::args().collect());
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
    for record in &emulator.records {
        debug!("record events: {:?}", record.stats());
    }
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

    let stats = record.stats();
    debug!("final record stats:");
    for (key, value) in &stats {
        debug!("|- {:<25}: {}", key, value);
    }

    let mut records = vec![record];

    // Setup config and chips.
    info!("\n Creating BaseMachine (at {:?})..", start.elapsed());
    let config = BabyBearPoseidon2::new();
    let chips = FibChipType::all_chips();

    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, RISCV_NUM_PVS, chips);
    info!("{} created.", simple_machine.name());

    // Setup machine prover, verifier, pk and vk.
    info!("\n Setup machine (at {:?})..", start.elapsed());
    let (pk, vk) = simple_machine.setup_keys(&program);

    info!("\n Complement records (at {:?})..", start.elapsed());
    simple_machine.complement_record(&mut records);

    info!("\n Construct proving witness..");
    let witness = ProvingWitness::new_with_records(records);

    // Generate the proof.
    info!("\n Generating proof (at {:?})..", start.elapsed());
    let proof = simple_machine.prove(&pk, &witness);
    info!("{} generated.", proof.name());

    let proof_size = bincode::serialize(&proof).unwrap().len();
    info!("Proof size: {}", proof_size);
    debug!(
        "|- Commitment size: {}",
        bincode::serialize(&proof.proof.proof[0].commitments)
            .unwrap()
            .len()
    );
    debug!(
        "|- Opened values size: {}",
        bincode::serialize(&proof.proof.proof[0].opened_values)
            .unwrap()
            .len()
    );
    debug!(
        "|- Opening proof size: {}",
        bincode::serialize(&proof.proof.proof[0].opening_proof)
            .unwrap()
            .len()
    );
    debug!(
        "|- Log main degrees size: {}",
        bincode::serialize(&proof.proof.proof[0].log_main_degrees)
            .unwrap()
            .len()
    );
    debug!(
        "|- Log quotient degrees size: {}",
        bincode::serialize(&proof.proof.proof[0].log_quotient_degrees)
            .unwrap()
            .len()
    );
    debug!(
        "|- Chip ordering size: {}",
        bincode::serialize(&proof.proof.proof[0].main_chip_ordering)
            .unwrap()
            .len()
    );
    debug!(
        "|- Public values size: {}",
        bincode::serialize(&proof.proof.proof[0].public_values)
            .unwrap()
            .len()
    );

    // Verify the proof.
    info!("\n Verifying proof (at {:?})..", start.elapsed());
    let result = simple_machine.verify(&vk, &proof);
    info!(
        "The proof is verified: {} (at {:?})",
        result.is_ok(),
        start.elapsed()
    );
    assert_eq!(result.is_ok(), true);
}
