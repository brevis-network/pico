use p3_baby_bear::BabyBear;
use pico_vm::{
    compiler::{
        recursion_v2::circuit::witness::Witnessable,
        riscv::compiler::{Compiler, SourceType},
    },
    configs::{
        config::{Challenge, StarkGenericConfig, Val},
        field_config::bb_simple::BabyBearSimple,
        stark_config::bb_poseidon2::BabyBearPoseidon2,
    },
    emulator::{opts::EmulatorOpts, recursion::emulator::Runtime, riscv::stdin::EmulatorStdin},
    instances::{
        chiptype::{recursion_chiptype_v2::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler_v2::{
            recursion_circuit::stdin::RecursionStdin,
            shapes::{compress_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
            vk_merkle::{
                builder::{CompressVkVerifierCircuit, EmbedVkVerifierCircuit},
                HasStaticVkManager, VkMerkleManager, VK_MANAGER_BB,
            },
        },
        configs::{
            embed_bb_bn254_poseidon2::StarkConfig as EmbedBBBN254PoseidonConfig,
            embed_config::{BabyBearBn254Poseidon2, StarkConfig as EmbedSC},
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvBBSC,
        },
        machine::{
            combine_vk::CombineVkMachine, compress_vk::CompressVkMachine, convert::ConvertMachine,
            embed::EmbedMachine, riscv::RiscvMachine,
        },
    },
    machine::{
        keys::{BaseVerifyingKey, HashableKey},
        logger::setup_logger,
        machine::MachineBehavior,
        witness::ProvingWitness,
    },
    primitives::consts::{
        BABYBEAR_S_BOX_DEGREE, COMBINE_DEGREE, COMBINE_SIZE, COMPRESS_DEGREE, CONVERT_DEGREE,
        EMBED_DEGREE, RECURSION_NUM_PVS, RISCV_NUM_PVS,
    },
};
use std::{sync::Arc, time::Instant};
use tracing::{debug, info};

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();

    // TODO: build vk_map_bb.bin
    let riscv_shape_config = RiscvShapeConfig::<BabyBear>::default();
    // COMBINE_DEGREE == COMPRESS_DEGREE == CONVERT_DEGREE == 3
    let recursion_shape_config =
        RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear, COMBINE_DEGREE>>::default();
    let vk_manager = <BabyBearPoseidon2 as HasStaticVkManager>::static_vk_manager();

    // -------- Riscv Machine --------

    info!("\n Begin RISCV..");

    let (elf, riscv_stdin, args) = parse_args::parse_args();

    debug!("PERF-machine=riscv");
    let start = Instant::now();
    let riscv_start = Instant::now();

    info!("Setting up RISCV..");
    let riscv_compiler = Compiler::new(SourceType::RiscV, elf);
    let mut riscv_program = riscv_compiler.compile();

    if let Some(program) = Arc::get_mut(&mut riscv_program) {
        riscv_shape_config
            .padding_preprocessed_shape(program)
            .expect("cannot padding preprocessed shape");
    } else {
        panic!("cannot get_mut arc");
    }

    let riscv_machine = RiscvMachine::new(
        RiscvBBSC::new(),
        RiscvChipType::<BabyBear>::all_chips(),
        RISCV_NUM_PVS,
    );

    // Setup machine prover, verifier, pk and vk.
    let (riscv_pk, riscv_vk) = riscv_machine.setup_keys(&riscv_program.clone());

    let core_opts = if args.bench {
        info!("use benchmark options");
        EmulatorOpts::bench_riscv_ops()
    } else {
        EmulatorOpts::default()
    };
    info!("core_opts: {:?}", core_opts);

    let riscv_witness = ProvingWitness::setup_for_riscv(
        riscv_program.clone(),
        riscv_stdin,
        core_opts,
        riscv_pk,
        riscv_vk,
    );

    // Generate the proof.
    info!("Generating RISCV proof (at {:?})..", start.elapsed());
    let riscv_proof = riscv_machine
        .prove_with_shape(&riscv_witness, Some(&riscv_shape_config))
        .0;
    debug!(
        "PERF-step=prove-user_time={}",
        riscv_start.elapsed().as_millis()
    );

    let riscv_proof_size = bincode::serialize(&riscv_proof.proofs()).unwrap().len();
    debug!("PERF-step=proof_size-{}", riscv_proof_size);

    // Verify the proof.
    info!("Verifying RISCV proof (at {:?})..", start.elapsed());
    let riscv_result = riscv_machine.verify(&riscv_proof);
    info!(
        "The proof is verified: {} (at {:?})..",
        riscv_result.is_ok(),
        start.elapsed()
    );
    assert!(riscv_result.is_ok());
    if args.step == "riscv" {
        info!("Proof duration:");
        // info!("|- riscv {:?}", riscv_duration);

        info!("Proof size:");
        info!("|- riscv {:?}K", (riscv_proof_size as f64) / 1000.0);
        return;
    }

    // -------- Riscv Convert Recursion Machine --------

    info!("\n Begin CONVERT..");
    let recursion_opts = if args.bench {
        EmulatorOpts::bench_recursion_opts()
    } else {
        EmulatorOpts::default()
    };
    info!("recursion_opts: {:?}", recursion_opts);

    debug!("PERF-machine=convert");
    let convert_start = Instant::now();

    let vk_root = vk_manager.merkle_root;
    let riscv_vk = riscv_witness.vk();

    info!("Setting up CONVERT..");
    let convert_machine = ConvertMachine::new(
        RecursionSC::new(),
        RecursionChipType::<BabyBear, CONVERT_DEGREE>::all_chips(),
        RECURSION_NUM_PVS,
    );

    // Setup stdin and witness
    let convert_stdin = EmulatorStdin::setup_for_convert::<BabyBear, BabyBearSimple>(
        riscv_vk,
        vk_root,
        riscv_machine.base_machine(),
        &riscv_proof.proofs(),
        &Some(recursion_shape_config),
    );

    let convert_witness =
        ProvingWitness::setup_for_convert(convert_stdin, convert_machine.config(), recursion_opts);

    // Generate the proof.
    info!("Generating CONVERT proof (at {:?})..", start.elapsed());
    let convert_proof = convert_machine.prove(&convert_witness);
    debug!(
        "PERF-step=prove-user_time={}",
        convert_start.elapsed().as_millis()
    );

    let convert_proof_size = bincode::serialize(&convert_proof.proofs()).unwrap().len();
    debug!("PERF-step=proof_size-{}", convert_proof_size);

    // Verify the proof.
    info!("Verifying CONVERT proof (at {:?})..", start.elapsed());
    let convert_result = convert_machine.verify(&convert_proof);
    info!(
        "The CONVERT proof is verified: {} (at {:?})",
        convert_result.is_ok(),
        start.elapsed()
    );
    assert!(convert_result.is_ok());

    if args.step == "convert" {
        return;
    }

    // -------- Combine Recursion Machine --------

    info!("\n Begin COMBINE..");

    let recursion_shape_config =
        RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear, COMBINE_DEGREE>>::default();

    debug!("PERF-machine=combine");
    let combine_start = Instant::now();

    let vk_root = vk_manager.merkle_root;

    info!("Setting up COMBINE");
    let combine_machine = CombineVkMachine::new(
        RecursionSC::new(),
        RecursionChipType::<BabyBear, COMBINE_DEGREE>::all_chips(),
        RECURSION_NUM_PVS,
    );

    for (i, vk) in convert_proof.vks().iter().enumerate() {
        println!(
            "vk_digest for the {}-th convert proof: {:?}",
            i,
            vk.hash_field()
        );
    }
    // Setup stdin and witnesses
    let (combine_stdin, last_vk, last_proof) =
        EmulatorStdin::setup_for_combine_vk::<BabyBear, BabyBearSimple>(
            vk_root,
            convert_proof.vks(),
            &convert_proof.proofs(),
            convert_machine.base_machine(),
            COMBINE_SIZE,
            convert_proof.proofs().len() <= COMBINE_SIZE,
            &vk_manager,
            &recursion_shape_config,
        );

    let combine_witness = ProvingWitness::setup_for_recursion_vk(
        vk_root,
        combine_stdin,
        last_vk,
        last_proof,
        combine_machine.config(),
        recursion_opts,
    );

    // Generate the proof.
    info!("Generating COMBINE proof (at {:?})..", start.elapsed());
    let combine_proof = combine_machine.prove(&combine_witness);
    debug!(
        "PERF-step=prove-user_time={}",
        combine_start.elapsed().as_millis(),
    );

    let combine_proof_size = bincode::serialize(&combine_proof.proofs()).unwrap().len();
    debug!("PERF-step=proof_size-{}", combine_proof_size);

    // Verify the proof.
    info!("Verifying COMBINE proof (at {:?})..", start.elapsed());
    let combine_result = combine_machine.verify(&combine_proof);
    info!(
        "The COMBINE proof is verified: {} (at {:?})",
        combine_result.is_ok(),
        start.elapsed()
    );
    assert!(combine_result.is_ok());

    if args.step == "combine" {
        return;
    }

    // -------- Compress Recursion Machine --------

    info!("\n Begin COMPRESS..");

    debug!("PERF-machine=compress");
    let compress_start = Instant::now();

    let vk_root = vk_manager.merkle_root;

    info!("Setting up COMPRESS");
    let compress_machine = CompressVkMachine::new(
        RecursionSC::compress(),
        RecursionChipType::<BabyBear, COMPRESS_DEGREE>::compress_chips(),
        RECURSION_NUM_PVS,
    );

    let compress_stdin = RecursionStdin::new(
        compress_machine.base_machine(),
        combine_proof.vks.clone(),
        combine_proof.proofs.clone(),
        true,
        vk_root,
    );

    let compress_vk_stdin = vk_manager.add_vk_merkle_proof(compress_stdin);

    let mut compress_program = CompressVkVerifierCircuit::<RecursionFC, RecursionSC>::build(
        combine_machine.base_machine(),
        &compress_vk_stdin,
    );

    let compress_pad_shape = RecursionChipType::<BabyBear, COMPRESS_DEGREE>::compress_shape();

    compress_program.shape = Some(compress_pad_shape);

    let (compress_pk, compress_vk) = compress_machine.setup_keys(&compress_program);

    let record = {
        let mut witness_stream = Vec::new();
        Witnessable::<RecursionFC>::write(&compress_vk_stdin, &mut witness_stream);
        let mut runtime =
            Runtime::<Val<RecursionSC>, Challenge<RecursionSC>, _, _, BABYBEAR_S_BOX_DEGREE>::new(
                Arc::new(compress_program),
                combine_machine.config().perm.clone(),
            );
        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        runtime.record
    };
    let compress_witness =
        ProvingWitness::setup_with_keys_and_records(compress_pk, compress_vk, vec![record]);

    info!("Generating COMPRESS proof (at {:?})..", start.elapsed());
    let compress_proof = compress_machine.prove(&compress_witness);
    debug!(
        "PERF-step=prove-user_time={}",
        compress_start.elapsed().as_millis()
    );

    let compress_proof_size = bincode::serialize(&compress_proof.proofs()).unwrap().len();
    debug!("PERF-step=proof_size-{}", compress_proof_size);

    info!("Verifying COMPRESS proof (at {:?})..", start.elapsed());
    let compress_result = compress_machine.verify(&compress_proof);

    info!(
        "The COMPRESS proof is verified: {} (at {:?})",
        compress_result.is_ok(),
        start.elapsed()
    );
    assert!(compress_result.is_ok());

    if args.step == "compress" {
        return;
    }

    // -------- Embed Machine --------

    info!("\n Begin EMBED..");
    debug!("PERF-machine=embed");
    let embed_start = Instant::now();

    let vk_root = vk_manager.merkle_root;

    info!("Setting up EMBED");
    let embed_machine = EmbedMachine::<RecursionSC, _, _, Vec<u8>>::new(
        EmbedSC::new(),
        RecursionChipType::<BabyBear, EMBED_DEGREE>::embed_chips(),
        RECURSION_NUM_PVS,
    );

    let embed_stdin = RecursionStdin::new(
        combine_machine.base_machine(),
        compress_proof.vks,
        compress_proof.proofs,
        true,
        vk_root,
    );

    let embed_vk_stdin = vk_manager.add_vk_merkle_proof(embed_stdin);

    let embed_vk_program = EmbedVkVerifierCircuit::<RecursionFC, RecursionSC>::build(
        compress_machine.base_machine(),
        &embed_vk_stdin,
        &vk_manager,
    );

    embed_vk_program.print_stats();

    let (embed_pk, embed_vk) = embed_machine.setup_keys(&embed_vk_program);

    let record = {
        let mut witness_stream = Vec::new();
        Witnessable::<RecursionFC>::write(&embed_vk_stdin, &mut witness_stream);
        let mut runtime =
            Runtime::<Val<RecursionSC>, Challenge<RecursionSC>, _, _, BABYBEAR_S_BOX_DEGREE>::new(
                Arc::new(embed_vk_program),
                compress_machine.config().perm.clone(),
            );
        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        runtime.record
    };

    // for all workloads of pico zkvm, the embed_vk.bin should be the same
    let embed_vk_bytes = bincode::serialize(&embed_vk).unwrap();
    std::fs::write("embed_vk.bin", embed_vk_bytes).unwrap();

    let new_embed_vk_bytes = std::fs::read("embed_vk.bin").unwrap();
    let new_embed_vk: BaseVerifyingKey<EmbedBBBN254PoseidonConfig> =
        bincode::deserialize(&new_embed_vk_bytes).unwrap();

    let embed_witness =
        ProvingWitness::setup_with_keys_and_records(embed_pk, new_embed_vk, vec![record]);

    info!("Generating EMBED proof (at {:?})..", start.elapsed());
    let embed_proof = embed_machine.prove(&embed_witness);
    debug!(
        "PERF-step=prove-user_time={}",
        embed_start.elapsed().as_millis()
    );

    let embed_proof_size = bincode::serialize(&embed_proof.proofs()).unwrap().len();
    debug!("PERF-step=proof_size-{}", embed_proof_size);

    info!("Verifying EMBED proof (at {:?})..", start.elapsed());
    let embed_result = embed_machine.verify(&embed_proof);

    info!(
        "The EMBED proof is verified: {} (at {:?})",
        compress_result.is_ok(),
        start.elapsed()
    );
    assert!(embed_result.is_ok());
}
