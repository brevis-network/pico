use itertools::enumerate;
use log::{debug, info};
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    emulator::{
        context::EmulatorContext,
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            record::EmulationRecord,
            riscv_emulator::{EmulationError, EmulatorMode, RiscvEmulator},
            stdin::EmulatorStdin,
        },
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        configs::riscv_config::StarkConfig as RiscvSC,
        machine::{riscv_machine::RiscvMachine, simple_machine::SimpleMachine},
    },
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        logger::setup_logger,
        machine::MachineBehavior,
        witness::ProvingWitness,
    },
    primitives::consts::{RECURSION_NUM_PVS, RISCV_NUM_PVS},
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{env, time::Instant};

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();

    let (elf, stdin, _, _) = parse_args::parse_args(env::args().collect());

    let start = Instant::now();

    info!("\n Creating Program..");
    let compiler = Compiler::new(SourceType::RiscV, elf);
    let program = compiler.compile();

    // Setup config and chips.
    info!("\n Creating BaseMachine (at {:?})..", start.elapsed());
    let config = RiscvSC::new();
    let chips = RiscvChipType::all_chips();

    // Create a new machine based on config and chips
    let riscv_machine = RiscvMachine::new(config, RISCV_NUM_PVS, chips);

    // Setup machine prover, verifier, pk and vk.
    info!("\n Setup machine (at {:?})..", start.elapsed());
    let (pk, vk) = riscv_machine.setup_keys(&program);

    info!("\n Construct proving witness..");
    let witness = ProvingWitness::setup_for_riscv(
        program,
        &stdin,
        EmulatorOpts::test_opts(),
        EmulatorContext::default(),
    );

    // Generate the proof.
    info!("\n Generating proof (at {:?})..", start.elapsed());
    let proof = riscv_machine.prove(&pk, &witness);

    // Verify the proof.
    info!("\n Verifying proof (at {:?})..", start.elapsed());
    let result = riscv_machine.verify(&vk, &proof);
    info!(
        "The proof is verified: {} (at {:?})..",
        result.is_ok(),
        start.elapsed()
    );
    assert_eq!(result.is_ok(), true);
}
