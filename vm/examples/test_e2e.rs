use log::info;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use pico_vm::{
    compiler::{
        recursion::program_builder::hints::hintable::Hintable,
        riscv::compiler::{Compiler, SourceType},
    },
    configs::config::{Challenge, Val},
    emulator::{context::EmulatorContext, opts::EmulatorOpts, riscv::stdin::EmulatorStdin},
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::{
            recursion_circuit::{
                combine::builder::RecursionCombineVerifierCircuit,
                compress::builder::RecursionCompressVerifierCircuit,
                embed::builder::RecursionEmbedVerifierCircuit, stdin::RecursionStdin,
            },
            riscv_circuit::compress::builder::RiscvCompressVerifierCircuit,
        },
        configs::{
            embed_config::StarkConfig as EmbedSC,
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvSC,
        },
        machine::{
            recursion_combine::RecursionCombineMachine,
            recursion_compress::RecursionCompressMachine, recursion_embed::RecursionEmbedMachine,
            riscv_machine::RiscvMachine, riscv_recursion::RiscvRecursionMachine,
        },
    },
    machine::{logger::setup_logger, machine::MachineBehavior, witness::ProvingWitness},
    primitives::consts::{
        COMBINE_DEGREE, COMBINE_SIZE, COMPRESS_DEGREE, EMBED_DEGREE, RECURSION_NUM_PVS,
        RISCV_COMPRESS_DEGREE, RISCV_NUM_PVS,
    },
    recursion::runtime::Runtime,
};
use std::{env, time::Instant};

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
    let (riscv_pk, riscv_vk) = riscv_machine.setup_keys(&riscv_program.clone());

    info!("Construct RiscV proving witness..");
    let riscv_witness = ProvingWitness::setup_for_riscv(
        riscv_program,
        &riscv_stdin,
        EmulatorOpts::default(),
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
    assert!(riscv_result.is_ok());

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
        riscv_proof.proofs(),
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
    assert!(riscv_compress_result.is_ok());

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
    assert!(combine_result.is_ok());

    /*
    Compress Recursion Machine
     */

    info!("\n Begin Compress..");

    info!("Build comopress program (at {:?})..", start.elapsed());
    let compress_program = RecursionCompressVerifierCircuit::<RecursionFC, RecursionSC>::build(
        combine_machine.base_machine(),
    );

    // Setup machine
    info!("Setup compress machine (at {:?})..", start.elapsed());

    let (_, riscv_vk) = riscv_machine.setup_keys(&riscv_compiler.compile().clone());
    let compress_machine = RecursionCompressMachine::new(
        RecursionSC::compress(),
        RecursionChipType::<BabyBear, COMPRESS_DEGREE>::compress_chips(),
        RECURSION_NUM_PVS,
        riscv_vk,
    );

    let (compress_pk, compress_vk) = compress_machine.setup_keys(&compress_program);

    // Setup stdin and witnesses
    info!("Construct compress stdin and witnesses..");

    let compress_record = {
        let stdin = RecursionStdin {
            vk: &combine_vk,
            machine: combine_machine.base_machine(),
            proofs: combine_proof.proofs().to_vec(),
            flag_complete: true,
        };

        let mut witness_stream = Vec::new();
        witness_stream.extend(stdin.write());

        let mut runtime = Runtime::<Val<RecursionSC>, Challenge<RecursionSC>, _>::new(
            &compress_program,
            compress_machine.config().perm.clone(),
        );
        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        tracing::debug!("Compress program stats");
        runtime.print_stats();
        runtime.record
    };
    let compress_witness = ProvingWitness::setup_with_records(vec![compress_record]);

    // Generate the proof.
    info!("Generating compress proof (at {:?})..", start.elapsed());
    let compress_proof = compress_machine.prove(&compress_pk, &compress_witness);

    // Verify the proof.
    info!("Verifying compress proof (at {:?})..", start.elapsed());
    let compress_result = compress_machine.verify(&compress_vk, &compress_proof);
    info!(
        "The compress proof is verified: {} (at {:?})",
        compress_result.is_ok(),
        start.elapsed()
    );
    assert!(compress_result.is_ok());

    /*
    Embed Recursion Machine
     */

    info!("\n Begin Embed..");

    info!("Build embed program (at {:?})..", start.elapsed());
    let embed_program = RecursionEmbedVerifierCircuit::<RecursionFC, RecursionSC>::build(
        compress_machine.base_machine(),
    );

    let embed_record = {
        let stdin = RecursionStdin {
            vk: &compress_vk,
            machine: compress_machine.base_machine(),
            proofs: compress_proof.proofs().to_vec(),
            flag_complete: true,
        };

        let mut witness_stream = Vec::new();
        witness_stream.extend(stdin.write());

        let mut runtime = Runtime::<Val<RecursionSC>, Challenge<RecursionSC>, _>::new(
            &embed_program,
            compress_machine.config().perm.clone(),
        );
        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        tracing::debug!("Embed program stats");
        runtime.print_stats();

        runtime.record
    };

    // todo: consider simplify in the future. currently Vec<u8> is not necessary
    let embed_witness: ProvingWitness<
        '_,
        EmbedSC,
        RecursionChipType<BabyBear, EMBED_DEGREE>,
        Vec<u8>,
    > = ProvingWitness::setup_with_records(vec![embed_record]);

    // Setup machine
    info!("Setup embed machine (at {:?})..", start.elapsed());
    let (_, riscv_vk) = riscv_machine.setup_keys(&riscv_compiler.compile().clone());
    let embed_machine = RecursionEmbedMachine::new(
        EmbedSC::new(),
        RecursionChipType::<BabyBear, EMBED_DEGREE>::embed_chips(),
        RECURSION_NUM_PVS,
        riscv_vk,
    );

    let (embed_pk, embed_vk) = embed_machine.setup_keys(&embed_program);

    // Generate the proof.
    info!("Generating embed proof (at {:?})..", start.elapsed());
    let embed_proof = embed_machine.prove(&embed_pk, &embed_witness);

    // Verify the proof.
    info!("Verifying embed proof (at {:?})..", start.elapsed());
    let embed_result = embed_machine.verify(&embed_vk, &embed_proof);
    info!(
        "The embed proof is verified: {} (at {:?})",
        embed_result.is_ok(),
        start.elapsed()
    );
    assert!(embed_result.is_ok());
}
