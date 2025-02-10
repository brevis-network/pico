use p3_air::Air;
use p3_field::PrimeField32;
use pico_vm::{
    chips::chips::riscv_poseidon2::FieldSpecificPoseidon2Chip,
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::config::{Com, PcsProverData, StarkGenericConfig, Val},
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        configs::{
            riscv_config::StarkConfig as RiscvBBSC, riscv_kb_config::StarkConfig as RiscvKBSC,
            riscv_m31_config::StarkConfig as RiscvM31SC,
        },
        machine::riscv::RiscvMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        folder::{ProverConstraintFolder, SymbolicConstraintFolder, VerifierConstraintFolder},
        logger::setup_logger,
        machine::MachineBehavior,
        proof::BaseProof,
        witness::ProvingWitness,
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
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    BaseProof<SC>: Send + Sync,
    SC::Domain: Send + Sync,
    FieldSpecificPoseidon2Chip<Val<SC>>: Air<SymbolicConstraintFolder<Val<SC>>>
        + Air<ProverConstraintFolder<SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    info!("╔═══════════════════════╗");
    info!("║      RISCV PHASE      ║");
    info!("╚═══════════════════════╝");
    let start = Instant::now();

    let riscv_compiler = Compiler::new(SourceType::RiscV, elf);
    let riscv_program = riscv_compiler.compile();

    let riscv_machine = RiscvMachine::new(config, RiscvChipType::all_chips(), RISCV_NUM_PVS);
    // Setup config and chips.

    // Setup machine prover, verifier, pk and vk.
    let (riscv_pk, riscv_vk) = riscv_machine.setup_keys(&riscv_program.clone());

    let riscv_witness = ProvingWitness::setup_for_riscv(
        riscv_program,
        riscv_stdin,
        EmulatorOpts::default(),
        riscv_pk,
        riscv_vk,
    );

    // Generate the proof.
    info!("Generating RISCV proof (at {:?})..", start.elapsed());
    let riscv_proof = riscv_machine.prove(&riscv_witness);

    // Verify the proof.
    info!("Verifying RISCV proof (at {:?})..", start.elapsed());
    let riscv_result = riscv_machine.verify(&riscv_proof);
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
    match args.field.as_str() {
        "bb" => run(RiscvBBSC::new(), elf, riscv_stdin),
        "kb" => run(RiscvKBSC::new(), elf, riscv_stdin),
        "m31" => run(RiscvM31SC::new(), elf, riscv_stdin),
        _ => panic!("unsupported field for RISCV: {}", args.field),
    }
}
