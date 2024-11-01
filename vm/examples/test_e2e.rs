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
    configs::config::{Challenge, StarkGenericConfig, Val},
    emulator::{
        context::EmulatorContext,
        emulator::RecursionEmulator,
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
        compiler::{
            recursion_circuit::combine::builder::RecursionCombineVerifierCircuit,
            riscv_circuit::{
                compress::builder::RiscvCompressVerifierCircuit, stdin::RiscvRecursionStdin,
            },
        },
        configs::{
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvSC,
        },
        machine::{
            combine_recursion::RecursionCombineMachine, riscv_machine::RiscvMachine,
            riscv_recursion::RiscvRecursionMachine,
        },
    },
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        keys::HashableKey,
        logger::setup_logger,
        machine::MachineBehavior,
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{
        COMBINE_DEGREE, COMBINE_SIZE, RECURSION_NUM_PVS, RISCV_COMPRESS_DEGREE, RISCV_NUM_PVS,
    },
    recursion::runtime::{Runtime as RecursionRuntime, Runtime},
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{
    borrow::Borrow,
    env,
    hash::{DefaultHasher, Hash, Hasher},
    time::Instant,
};

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();

    /*
    Riscv Machine
     */

    info!("\n Begin RiscV..");

    let (elf, riscv_stdin, _, _) = parse_args::parse_args(env::args().collect());
    let start = Instant::now();

    info!("Creating Program..");
    let riscv_compiler = Compiler::new(SourceType::RiscV, elf);
    let riscv_program = riscv_compiler.compile();

    // Setup config and chips.
    info!("Creating RiscVMachine (at {:?})..", start.elapsed());
    let riscv_machine =
        RiscvMachine::new(RiscvSC::new(), RiscvChipType::all_chips(), RISCV_NUM_PVS);

    // Setup machine prover, verifier, pk and vk.
    info!("Setup RiscV machine (at {:?})..", start.elapsed());
    let (riscv_pk, riscv_vk) = riscv_machine.setup_keys(&riscv_program);

    info!("Construct RiscV proving witness..");
    let riscv_witness = ProvingWitness::setup_for_riscv(
        riscv_program,
        &riscv_stdin,
        EmulatorOpts::test_opts(),
        EmulatorContext::default(),
    );

    // Generate the proof.
    info!("Generating RiscV proof (at {:?})..", start.elapsed());
    let riscv_proof = riscv_machine.prove(&riscv_pk, &riscv_witness);

    // Verify the proof.
    info!("Verifying RiscV proof (at {:?})..", start.elapsed());
    let riscv_result = riscv_machine.verify(&riscv_vk, &riscv_proof);
    info!(
        "The proof is verified: {} (at {:?})..",
        riscv_result.is_ok(),
        start.elapsed()
    );
    assert_eq!(riscv_result.is_ok(), true);

    /*
    Riscv Compression Recursion Machine
     */

    info!("\n Begin Riscv Recursion..");

    info!("Build riscv_compress program (at {:?})..", start.elapsed());
    let riscv_compress_program =
        RiscvCompressVerifierCircuit::<RecursionFC, RiscvSC>::build(riscv_machine.base_machine());

    // Setup machine
    info!("Setup recursion machine (at {:?})..", start.elapsed());
    let riscv_compress_machine = RiscvRecursionMachine::new(
        RecursionSC::new(),
        RecursionChipType::<BabyBear, RISCV_COMPRESS_DEGREE>::all_chips(),
        RECURSION_NUM_PVS,
    );
    let (riscv_compress_pk, riscv_compress_vk) =
        riscv_compress_machine.setup_keys(&riscv_compress_program);

    // Setup stdin and witnesses
    info!("Construct recursion stdin and witnesses..");
    let mut riscv_challenger = DuplexChallenger::new(riscv_machine.config().perm.clone());
    let riscv_compress_stdin = EmulatorStdin::setup_for_riscv_compress(
        &riscv_vk,
        riscv_machine.base_machine(),
        &riscv_proof.proofs(),
        &mut riscv_challenger,
    );

    let riscv_compress_witness = ProvingWitness::setup_for_riscv_recursion(
        riscv_compress_program,
        &riscv_compress_stdin,
        riscv_compress_machine.config(),
    );

    // Generate the proof.
    info!("Generating recursion proof (at {:?})..", start.elapsed());
    let riscv_compress_proof =
        riscv_compress_machine.prove(&riscv_compress_pk, &riscv_compress_witness);

    // Verify the proof.
    info!("Verifying recursion proof (at {:?})..", start.elapsed());
    let riscv_compress_result =
        riscv_compress_machine.verify(&riscv_compress_vk, &riscv_compress_proof);
    info!(
        "The proof is verified: {} (at {:?})",
        riscv_compress_result.is_ok(),
        start.elapsed()
    );
    assert_eq!(riscv_compress_result.is_ok(), true);

    /*
    Combine Recursion Machine
     */

    info!("\n Begin Combine..");

    info!("Build combine program (at {:?})..", start.elapsed());
    let combine_program = RecursionCombineVerifierCircuit::<RecursionFC, RecursionSC>::build(
        riscv_compress_machine.base_machine(),
    );

    // Setup machine
    info!("Setup combine machine (at {:?})..", start.elapsed());
    let combine_machine = RecursionCombineMachine::new(
        RecursionSC::new(),
        RecursionChipType::<BabyBear, COMBINE_DEGREE>::all_chips(),
        RECURSION_NUM_PVS,
        riscv_vk,
    );

    let (combine_pk, combine_vk) = combine_machine.setup_keys(&combine_program);

    // Setup stdin and witnesses
    info!("Construct combine stdin and witnesses..");
    let combine_stdin = EmulatorStdin::setup_for_combine(
        &riscv_compress_vk,
        riscv_compress_machine.base_machine(),
        riscv_compress_proof.proofs(),
        COMBINE_SIZE,
        false,
    );

    let combine_witness = ProvingWitness::setup_for_recursion(
        combine_program,
        &combine_stdin,
        combine_machine.config(),
        &combine_vk,
    );

    // Generate the proof.
    info!("Generating combine proof (at {:?})..", start.elapsed());
    let combine_proof = combine_machine.prove(&combine_pk, &combine_witness);

    // Verify the proof.
    info!("Verifying combine proof (at {:?})..", start.elapsed());
    let combine_result = combine_machine.verify(&combine_vk, &combine_proof);
    info!(
        "The combine proof is verified: {} (at {:?})",
        combine_result.is_ok(),
        start.elapsed()
    );
    assert_eq!(combine_result.is_ok(), true);
}
