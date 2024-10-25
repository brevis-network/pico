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
        recursion::{ir::Felt, program_builder::hints::hintable::Hintable},
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
        word::Word,
    },
    configs::config::StarkGenericConfig,
    emulator::{
        context::EmulatorContext,
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            public_values::PublicValues,
            record::EmulationRecord,
            riscv_emulator::{EmulationError, EmulatorMode, RiscvEmulator},
            stdin::EmulatorStdin,
        },
    },
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::riscv_circuit::{
            compress::builder::RiscvCompressVerifierCircuit, stdin::RiscvRecursionStdin,
        },
        configs::{
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvSC,
        },
        machine::{riscv_machine::RiscvMachine, riscv_recursion::RiscvRecursionMachine},
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
    borrow::Borrow,
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

    info!("Begin RiscV..");

    info!("\n Creating Program..");
    let compiler = Compiler::new(SourceType::RiscV, elf);
    let program = compiler.compile();

    // Setup config and chips.
    info!("\n Creating BaseMachine (at {:?})..", start.elapsed());
    let config = RiscvSC::new();
    let chips = RiscvChipType::all_chips();

    // Create a new machine based on config and chips
    let riscv_machine = RiscvMachine::new(config, RISCV_NUM_PVS, chips);
    info!("{} created.", riscv_machine.name());

    // Setup machine prover, verifier, pk and vk.
    info!("\n Setup machine (at {:?})..", start.elapsed());
    let (pk, vk) = riscv_machine.setup_keys(&program);

    info!("\n Construct riscv proving witness..");
    let witness = ProvingWitness::setup_for_riscv(
        program,
        &stdin,
        EmulatorOpts::test_opts(),
        EmulatorContext::default(),
    );

    // Generate the proof.
    info!("\n Generating proof (at {:?})..", start.elapsed());
    let proof = riscv_machine.prove(&pk, &witness);
    info!("{} generated.", proof.name());

    // for each_proof in proof.proofs() {
    //     let public_values: &PublicValues<Word<_>, _> = each_proof.public_values.as_slice().borrow();
    //     info!("public values: {:?}", public_values);
    // }

    let proof_size = bincode::serialize(&proof).unwrap().len();
    info!("PERF-step=proof_size-{}", proof_size);

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

    info!("Build field_config program (at {:?})..", start.elapsed());
    let recursion_program =
        RiscvCompressVerifierCircuit::<RecursionFC, RiscvSC>::build(&riscv_machine);

    // Setup machine
    info!("\n Setup recursion machine (at {:?})..", start.elapsed());
    let recursion_machine = RiscvRecursionMachine::new(
        RecursionSC::new(),
        RECURSION_NUM_PVS,
        RecursionChipType::<BabyBear, 3>::all_chips(),
    );
    let (recursion_pk, recursion_vk) = recursion_machine.setup_keys(&recursion_program);

    // Setup stdin and witnesses
    info!("\n Construct riscv_compress recursion stdin and witnesses..");
    let mut challenger = DuplexChallenger::new(riscv_machine.config().perm.clone());
    let recursion_stdin = EmulatorStdin::construct_for_compress(
        &vk,
        &riscv_machine,
        &proof.proofs(),
        &mut challenger,
    );

    let recursion_witness = ProvingWitness::setup_for_riscv_recursion(
        recursion_program,
        &recursion_stdin,
        recursion_machine.config(),
    );

    // Generate the proof.
    info!("\n Generating recursion proof (at {:?})..", start.elapsed());
    let recursion_proof = recursion_machine.prove(&recursion_pk, &recursion_witness);
    info!("{} generated.", proof.name());

    let proof_size = bincode::serialize(&recursion_proof).unwrap().len();
    info!("PERF-step=proof_size-{}", proof_size);

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
