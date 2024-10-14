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
    configs::bb_poseidon2::BabyBearPoseidon2,
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
        chiptype::riscv_chiptype::FibChipType,
        machine::{riscv_machine::RiscvMachine, simple_machine::SimpleMachine},
    },
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        machine::MachineBehavior,
    },
    primitives::consts::{RECURSION_NUM_PVS, RISCV_NUM_PVS},
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{env, time::Instant};

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    env_logger::init();

    // run with default fibo, in which n = 40000
    let (elf, stdin, _, _) = parse_args::parse_args(env::args().collect());

    let start = Instant::now();

    info!("\n Creating Program..");
    let compiler = Compiler::new(SourceType::RiscV, elf);
    let program = compiler.compile();

    // Setup config and chips.
    info!("\n Creating BaseMachine (at {:?})..", start.elapsed());
    let config = BabyBearPoseidon2::new();
    let chips = FibChipType::all_chips();

    // Create a new machine based on config and chips
    let riscv_machine = RiscvMachine::new(config, RISCV_NUM_PVS, chips);
    info!("{} created.", riscv_machine.name());

    // Setup machine prover, verifier, pk and vk.
    info!("\n Setup machine (at {:?})..", start.elapsed());
    let (pk, vk) = riscv_machine.setup_keys(&program);

    // Generate the proof.
    info!("\n Generating proof (at {:?})..", start.elapsed());
    let proof = riscv_machine.emulate_and_prove(
        &pk,
        program,
        &stdin,
        EmulatorOpts::test_opts(),
        EmulatorContext::default(),
    );
    info!("{} generated.", proof.name());

    let proof_size = bincode::serialize(&proof).unwrap().len();
    info!("Proof size: {}", proof_size);

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
