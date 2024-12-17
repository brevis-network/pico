use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_field::FieldAlgebra;
use p3_matrix::dense::DenseStorage;
use pico_vm::{
    compiler::{
        recursion_v2::circuit::witness::Witnessable,
        riscv::compiler::{Compiler, SourceType},
    },
    configs::config::{Challenge, Val},
    emulator::{opts::EmulatorOpts, riscv::stdin::EmulatorStdin},
    instances::{
        chiptype::{recursion_chiptype_v2::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler_v2::{
            recursion_circuit::{
                combine::builder::RecursionCombineVerifierCircuit,
                compress::builder::RecursionCompressVerifierCircuit,
                embed::builder::RecursionEmbedVerifierCircuit, stdin::RecursionStdin,
            },
            riscv_circuit::{
                challenger::RiscvRecursionChallengers,
                compress::builder::RiscvCompressVerifierCircuit, stdin::RiscvRecursionStdin,
            },
        },
        configs::{
            embed_config::StarkConfig as EmbedSC,
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvBBSC,
        },
        machine::{
            recursion_combine::RecursionCombineMachine,
            recursion_compress::RecursionCompressMachine, recursion_embed::RecursionEmbedMachine,
            riscv_machine::RiscvMachine, riscv_recursion::RiscvRecursionMachine,
        },
    },
    machine::{
        logger::setup_logger, machine::MachineBehavior, proof::MetaProof, witness::ProvingWitness,
    },
    primitives::{
        consts::{
            BABYBEAR_S_BOX_DEGREE, COMBINE_DEGREE, COMBINE_SIZE, COMPRESS_DEGREE, DIGEST_SIZE,
            EMBED_DEGREE, PERMUTATION_WIDTH, RISCV_COMPRESS_DEGREE, RISCV_NUM_PVS,
        },
        consts_v2::RECURSION_NUM_PVS_V2,
    },
    recursion_v2::runtime::Runtime,
};
use std::{sync::Arc, time::Instant};
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();

    // -------- Riscv Machine --------

    info!("\n Begin RISCV..");

    let (elf, riscv_stdin, step, _) = parse_args::parse_args();
    let start = Instant::now();

    info!("Creating RiscV Program..");
    let riscv_compiler = Compiler::new(SourceType::RiscV, elf);
    let riscv_program = riscv_compiler.compile();

    // Setup config and chips.
    info!("Creating RiscVMachine (at {:?})..", start.elapsed());

    let riscv_machine = RiscvMachine::new(
        RiscvBBSC::new(),
        RiscvChipType::<BabyBear>::all_chips(),
        RISCV_NUM_PVS,
    );

    // Setup machine prover, verifier, pk and vk.
    info!("Setup RiscV machine (at {:?})..", start.elapsed());
    let (riscv_pk, riscv_vk) = riscv_machine.setup_keys(&riscv_program.clone());

    info!("Construct RiscV proving witness..");
    let riscv_witness = ProvingWitness::setup_for_riscv(
        riscv_program.clone(),
        riscv_stdin,
        EmulatorOpts::default(),
        riscv_pk,
        riscv_vk,
    );

    // Generate the proof.
    info!("Generating RiscV proof (at {:?})..", start.elapsed());
    let riscv_proof = riscv_machine.prove(&riscv_witness);

    // Verify the proof.
    info!("Verifying RiscV proof (at {:?})..", start.elapsed());
    let riscv_result = riscv_machine.verify(&riscv_proof);
    info!(
        "The proof is verified: {} (at {:?})..",
        riscv_result.is_ok(),
        start.elapsed()
    );
    assert!(riscv_result.is_ok());
    if step == "riscv" {
        return;
    }

    // -------- Riscv Compression Recursion Machine --------

    info!("\n Begin CONVERT..");

    // TODO: Initialize the VK root.
    let vk_root = [BabyBear::ZERO; DIGEST_SIZE];
    let riscv_vk = riscv_witness.vk();

    info!("Initializing RiscV compression machine");
    let riscv_compress_machine = RiscvRecursionMachine::new(
        RecursionSC::new(),
        RecursionChipType::<BabyBear, RISCV_COMPRESS_DEGREE>::all_chips(),
        RECURSION_NUM_PVS_V2,
    );

    // Setup stdin and witness
    info!("Construct recursion stdin and witnesses..");
    let riscv_compress_stdin = EmulatorStdin::setup_for_convert(
        &riscv_vk,
        vk_root,
        riscv_machine.base_machine(),
        riscv_proof.proofs(),
    );

    let riscv_compress_witness = ProvingWitness::setup_for_riscv_recursion(
        riscv_compress_stdin,
        riscv_compress_machine.config(),
        EmulatorOpts::default(),
    );

    // Generate the proof.
    info!("Generating CONVERT proof (at {:?})..", start.elapsed());
    let riscv_compress_proof = riscv_compress_machine.prove(&riscv_compress_witness);

    // Verify the proof.
    info!("Verifying CONVERT proof (at {:?})..", start.elapsed());
    let riscv_compress_result = riscv_compress_machine.verify(&riscv_compress_proof);
    info!(
        "The CONVERT proof is verified: {} (at {:?})",
        riscv_compress_result.is_ok(),
        start.elapsed()
    );
    assert!(riscv_compress_result.is_ok());

    if step == "riscv_compress" {
        return;
    }

    // -------- Combine Recursion Machine --------

    info!("\n Begin COMBINE");

    // TODO: Initialize the VK root.
    let vk_root = [BabyBear::ZERO; DIGEST_SIZE];

    info!("Initializing COMBINE machine");
    let combine_machine = RecursionCombineMachine::new(
        RecursionSC::new(),
        RecursionChipType::<BabyBear, COMBINE_DEGREE>::all_chips(),
        RECURSION_NUM_PVS_V2,
    );

    // Setup stdin and witnesses
    info!("Construct COMBINE stdin and witnesses..");
    let combine_stdin = EmulatorStdin::setup_for_combine(
        vk_root,
        riscv_compress_proof.vks(),
        riscv_compress_proof.proofs(),
        riscv_compress_machine.base_machine(),
        COMBINE_SIZE,
        false,
    );

    let combine_witness = ProvingWitness::setup_for_recursion(
        vk_root,
        combine_stdin,
        combine_machine.config(),
        EmulatorOpts::default(),
    );

    // Generate the proof.
    info!("Generating COMBINE proof (at {:?})..", start.elapsed());
    let combine_proof = combine_machine.prove(&combine_witness);

    // Verify the proof.
    info!("Verifying COMBINE proof (at {:?})..", start.elapsed());
    let combine_result = combine_machine.verify(&combine_proof);
    info!(
        "The COMBINE proof is verified: {} (at {:?})",
        combine_result.is_ok(),
        start.elapsed()
    );
    assert!(combine_result.is_ok());

    if step == "recur_combine" {
        return;
    }

    // -------- Compress Recursion Machine --------

    info!("\n Begin COMPRESS..");

    // TODO: Initialize the VK root.
    let vk_root = [BabyBear::ZERO; DIGEST_SIZE];

    info!("Initializing COMPRESS machine");
    let compress_machine = RecursionCompressMachine::new(
        RecursionSC::compress(),
        RecursionChipType::<BabyBear, COMPRESS_DEGREE>::compress_chips(),
        RECURSION_NUM_PVS_V2,
    );

    info!("Generating COMPRESS vks and proofs");
    let compress_stdin = RecursionStdin::new(
        compress_machine.base_machine(),
        combine_proof.vks().to_vec(),
        combine_proof.proofs().to_vec(),
        true,
        vk_root,
    );

    info!("Building COMPRESS program");
    let compress_program = RecursionCompressVerifierCircuit::<RecursionFC, RecursionSC>::build(
        combine_machine.base_machine(),
        &compress_stdin,
    );

    info!("Generating COMPRESS keys");
    let (compress_pk, compress_vk) = compress_machine.setup_keys(&compress_program);

    let record = {
        let mut witness_stream = Vec::new();
        Witnessable::<RecursionFC>::write(&compress_stdin, &mut witness_stream);
        let mut runtime = Runtime::<
            Val<RecursionSC>,
            Challenge<RecursionSC>,
            _,
            _,
            PERMUTATION_WIDTH,
            BABYBEAR_S_BOX_DEGREE,
        >::new(
            Arc::new(compress_program),
            combine_machine.config().perm.clone(),
        );
        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        runtime.record
    };
    let compress_witness =
        ProvingWitness::setup_with_keys_and_records(compress_pk, compress_vk, vec![record]);

    info!("Proving COMPRESS");
    let mut compress_proof = compress_machine.prove(&compress_witness);

    info!("Verifying COMPRESS proof");
    let compress_result = compress_machine.verify(&compress_proof);

    info!(
        "The COMPRESS proof is verified: {} (at {:?})",
        compress_result.is_ok(),
        start.elapsed()
    );
    assert!(compress_result.is_ok());

    if step == "recur_compress" {
        return;
    }

    // -------- Embed Recursion Machine --------

    info!("\n Begin Embed..");

    // TODO: Initialize the VK root.
    let vk_root = [BabyBear::ZERO; DIGEST_SIZE];

    info!("Initializing EMBED machine");
    let embed_machine = RecursionEmbedMachine::<_, _, Vec<u8>>::new(
        EmbedSC::new(),
        RecursionChipType::<BabyBear, EMBED_DEGREE>::embed_chips(),
        RECURSION_NUM_PVS_V2,
    );

    info!("Generating EMBED vks and proofs");
    let embed_stdin = RecursionStdin::new(
        compress_machine.base_machine(),
        compress_proof.vks().to_vec(),
        compress_proof.proofs().to_vec(),
        true,
        vk_root,
    );

    info!("Building EMBED program");
    let embed_program = RecursionEmbedVerifierCircuit::<RecursionFC, RecursionSC>::build(
        compress_machine.base_machine(),
        &embed_stdin,
    );

    info!("Generating EMBED keys");
    let (embed_pk, embed_vk) = embed_machine.setup_keys(&embed_program);

    let record = {
        let mut witness_stream = Vec::new();
        Witnessable::<RecursionFC>::write(&embed_stdin, &mut witness_stream);
        let mut runtime = Runtime::<
            Val<RecursionSC>,
            Challenge<RecursionSC>,
            _,
            _,
            PERMUTATION_WIDTH,
            BABYBEAR_S_BOX_DEGREE,
        >::new(
            Arc::new(embed_program),
            compress_machine.config().perm.clone(),
        );
        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        runtime.record
    };

    let embed_witness =
        ProvingWitness::setup_with_keys_and_records(embed_pk, embed_vk, vec![record]);

    info!("Proving EMBED");
    let mut embed_proof = embed_machine.prove(&embed_witness);

    info!("\n Verifying EMBED proof");
    let embed_result = embed_machine.verify(&embed_proof);

    info!(
        "The EMBED proof is verified: {} (at {:?})",
        compress_result.is_ok(),
        start.elapsed()
    );
    assert!(embed_result.is_ok());
}
