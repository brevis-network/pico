use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    emulator::{context::EmulatorContext, opts::EmulatorOpts, riscv::stdin::EmulatorStdin},
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::riscv_circuit::combine::builder::RiscvCombineVerifierCircuit,
        configs::{
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvSC,
        },
        machine::{riscv_machine::RiscvMachine, riscv_recursion::RiscvRecursionMachine},
    },
    machine::{logger::setup_logger, machine::MachineBehavior, witness::ProvingWitness},
    primitives::consts::{RECURSION_NUM_PVS, RISCV_COMBINE_DEGREE, RISCV_NUM_PVS},
};
use std::time::Instant;
use tracing::info;

const TEST_COMBINE_SIZE: usize = 10;

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();

    // run with default fibo
    let (elf, stdin, _) = parse_args::parse_args();
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
    let riscv_machine = RiscvMachine::new(config, chips, RISCV_NUM_PVS);

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

    // Verify the proof.
    info!("\n Verifying Riscv proof (at {:?})..", start.elapsed());
    let result = riscv_machine.verify(&vk, &proof);
    info!(
        "The proof is verified: {} (at {:?})..",
        result.is_ok(),
        start.elapsed()
    );
    assert!(result.is_ok());

    //////////////////////////////////////

    info!("\n Begin Recursion..");

    info!("Build field_config program (at {:?})..", start.elapsed());
    let recursion_program =
        RiscvCombineVerifierCircuit::<RecursionFC, RiscvSC>::build(riscv_machine.base_machine());

    // Setup recursion machine
    info!("\n Setup recursion machine (at {:?})..", start.elapsed());
    let recursion_machine = RiscvRecursionMachine::new(
        RecursionSC::new(),
        RecursionChipType::<BabyBear, RISCV_COMBINE_DEGREE>::all_chips(),
        RECURSION_NUM_PVS,
    );
    let (recursion_pk, recursion_vk) = recursion_machine.setup_keys(&recursion_program);

    // Setup stdin and witnesses
    info!("\n Construct riscv_combine recursion stdin and witnesses..");
    let mut challenger = DuplexChallenger::new(riscv_machine.config().perm.clone());
    let recursion_stdin = EmulatorStdin::setup_for_riscv_combine(
        &vk,
        riscv_machine.base_machine(),
        proof.proofs(),
        &mut challenger,
        TEST_COMBINE_SIZE,
    );
    assert_eq!(recursion_stdin.buffer.len(), 1);

    let recursion_witness = ProvingWitness::setup_for_riscv_recursion(
        recursion_program,
        &recursion_stdin,
        recursion_machine.config(),
        EmulatorOpts::test_opts(),
    );

    // Generate the proof.
    info!("\n Generating recursion proof (at {:?})..", start.elapsed());
    let recursion_proof = recursion_machine.prove(&recursion_pk, &recursion_witness);

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
    assert!(recursion_result.is_ok());
}
