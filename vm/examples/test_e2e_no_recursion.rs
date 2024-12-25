use p3_field::PrimeField32;
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::config::{Com, PcsProverData, StarkGenericConfig},
    emulator::{opts::EmulatorOpts, riscv::stdin::EmulatorStdin},
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        configs::{
            riscv_config::StarkConfig as RiscvBBSC, riscv_kb_config::StarkConfig as RiscvKBSC,
        },
        machine::riscv::RiscvMachine,
    },
    machine::{
        logger::setup_logger, machine::MachineBehavior, proof::BaseProof, witness::ProvingWitness,
    },
    primitives::consts::RISCV_NUM_PVS,
};
use serde::Serialize;
use std::time::Instant;
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

fn run<SC>(config: SC, elf: &'static [u8], riscv_stdin: EmulatorStdin<Program, Vec<u8>>)
where
    SC: StarkGenericConfig + Serialize + Send,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    SC::Val: PrimeField32,
    BaseProof<SC>: Send + Sync,
    SC::Domain: Send + Sync,
{
    info!("\n Begin RiscV..");
    let start = Instant::now();

    info!("Creating Program..");
    let riscv_compiler = Compiler::new(SourceType::RiscV, elf);
    let riscv_program = riscv_compiler.compile();

    let riscv_machine = RiscvMachine::new(config, RiscvChipType::all_chips(), RISCV_NUM_PVS);
    // Setup config and chips.
    info!("Creating RiscVMachine (at {:?})..", start.elapsed());

    // Setup machine prover, verifier, pk and vk.
    info!("Setup RiscV machine (at {:?})..", start.elapsed());
    let (riscv_pk, riscv_vk) = riscv_machine.setup_keys(&riscv_program.clone());

    info!("Construct RiscV proving witness..");
    let riscv_witness = ProvingWitness::setup_for_riscv(
        riscv_program,
        riscv_stdin,
        EmulatorOpts::default(),
        riscv_pk,
        riscv_vk,
    );

    // Generate the proof.
    info!("Generating RiscV proof (at {:?})..", start.elapsed());
    let timer = Instant::now();
    let riscv_proof = riscv_machine.prove(&riscv_witness);
    println!("Proof-generation-time: {:?}", timer.elapsed());

    // Verify the proof.
    info!("Verifying RiscV proof (at {:?})..", start.elapsed());
    let timer = Instant::now();
    let riscv_result = riscv_machine.verify(&riscv_proof);
    println!("Proof-verification-time: {:?}", timer.elapsed());
    info!(
        "The proof is verified: {} (at {:?})..",
        riscv_result.is_ok(),
        start.elapsed()
    );
    assert!(riscv_result.is_ok());
}

fn main() {
    setup_logger();
    let (elf, riscv_stdin, args) = parse_args::parse_args();

    // -------- Riscv Machine --------

    if args.field == "bb" {
        run(RiscvBBSC::new(), elf, riscv_stdin);
    } else if args.field == "kb" {
        run(RiscvKBSC::new(), elf, riscv_stdin);
    } else {
        panic!("unsupported field: {}", args.field);
    };
}
