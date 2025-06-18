use p3_field::FieldAlgebra;
use pico_vm::{
    compiler::{
        recursion::circuit::{hash::FieldHasher, witness::Witnessable},
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    configs::{
        config::{Challenge, FieldGenericConfig, StarkGenericConfig, Val},
        field_config::{BabyBearBn254, BabyBearSimple, KoalaBearBn254, KoalaBearSimple},
        stark_config::{
            BabyBearBn254Poseidon2, BabyBearPoseidon2, KoalaBearBn254Poseidon2, KoalaBearPoseidon2,
        },
    },
    emulator::{
        emulator::MetaEmulator, opts::EmulatorOpts, recursion::emulator::Runtime,
        stdin::EmulatorStdin,
    },
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::{
            onchain_circuit::{
                gnark::builder::OnchainVerifierCircuit, stdin::OnchainStdin,
                utils::build_gnark_config,
            },
            recursion_circuit::{
                compress::builder::CompressVerifierCircuit, embed::builder::EmbedVerifierCircuit,
                stdin::RecursionStdin,
            },
            shapes::{recursion_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
            vk_merkle::{
                builder::{CompressVkVerifierCircuit, EmbedVkVerifierCircuit},
                stdin::RecursionStdinVariant,
                HasStaticVkManager, VkMerkleManager,
            },
        },
        machine::{
            combine::CombineMachine, compress::CompressMachine, convert::ConvertMachine,
            embed::EmbedMachine, riscv::RiscvMachine,
        },
    },
    machine::{
        keys::BaseVerifyingKey, logger::setup_logger, machine::MachineBehavior,
        witness::ProvingWitness,
    },
    primitives::consts::{
        BABYBEAR_S_BOX_DEGREE, COMBINE_SIZE, DIGEST_SIZE, KOALABEAR_S_BOX_DEGREE,
        RECURSION_NUM_PVS, RISCV_NUM_PVS,
    },
};
use std::{fs::File, io::Write, path::PathBuf, sync::Arc, time::Instant};
use tracing::{debug, info};

#[path = "common/parse_args.rs"]
mod parse_args;
use parse_args::parse_args;
#[path = "common/print_utils.rs"]
mod print_utils;
use print_utils::{log_section, timed_run, PhaseStats};

fn get_vk_root<SC>(vk_manager: &VkMerkleManager<SC>) -> [Val<SC>; DIGEST_SIZE]
where
    SC: StarkGenericConfig + FieldHasher<Val<SC>, Digest = [Val<SC>; DIGEST_SIZE]>,
    Val<SC>: Ord,
{
    if vk_manager.vk_verification_enabled() {
        vk_manager.merkle_root
    } else {
        [Val::<SC>::ZERO; DIGEST_SIZE]
    }
}

macro_rules! run {
    ($func_name:ident, $riscv_sc:ident, $recur_cc:ident, $recur_sc:ident,
    $embed_cc:ident, $embed_sc:ident, $s_box_degree:ident) => {
        fn $func_name(
            elf: &'static [u8],
            riscv_stdin: EmulatorStdin<Program, Vec<u8>>,
            step_name: String,
            bench: bool,
        ) {
            // === Common Setup ===
            let start = Instant::now();
            let mut stats = PhaseStats::new();
            let vk_manager = <$riscv_sc as HasStaticVkManager>::static_vk_manager();
            let vk_enabled = vk_manager.vk_verification_enabled();

            let riscv_shape_config =
                vk_enabled.then(|| RiscvShapeConfig::<Val<$riscv_sc>>::default());
            let recursion_shape_config = vk_enabled.then(|| {
                RecursionShapeConfig::<Val<$recur_sc>, RecursionChipType<Val<$recur_sc>>>::default()
            });

            // Compile RISCV program and apply padding if VK_VERIFICATION is enabled.
            let riscv_compiler = Compiler::new(SourceType::RISCV, elf);
            let mut riscv_program = riscv_compiler.compile();
            if let Some(ref shape_config) = riscv_shape_config {
                let program = Arc::get_mut(&mut riscv_program).expect("cannot get_mut arc");
                shape_config
                    .padding_preprocessed_shape(program)
                    .expect("cannot padding preprocessed shape");
            }

            // === RISCV Phase: RISCV Machine ===
            log_section("RISCV PHASE");
            // Setup the RISCV machine and keys.
            let riscv_machine = RiscvMachine::new(
                $riscv_sc::new(),
                RiscvChipType::<Val<$riscv_sc>>::all_chips(),
                RISCV_NUM_PVS,
            );
            let (riscv_pk, riscv_vk) = riscv_machine.setup_keys(&riscv_program.clone());
            let riscv_opts = if bench {
                info!("use benchmark options");
                EmulatorOpts::bench_riscv_ops()
            } else {
                EmulatorOpts::default()
            };
            debug!("riscv_opts: {:?}", riscv_opts);

            // Getting public values stream.
            debug!(
                "Generating public values stream (at {:?})..",
                start.elapsed()
            );
            let riscv_witness = ProvingWitness::<
                                                                $riscv_sc,
                                                                RiscvChipType<Val<$riscv_sc>>,
                                                                Vec<u8>
                                                            >::setup_for_riscv(
                                                                riscv_program.clone(),
                                                                riscv_stdin.clone(),
                                                                riscv_opts.clone(),
                                                                riscv_pk.clone(),
                                                                riscv_vk.clone()
                                                            );
            let mut emulator = MetaEmulator::setup_riscv(&riscv_witness, None);
            let pv_stream = emulator.get_pv_stream_with_dryrun();
            debug!("Public values stream: {:?}", pv_stream);

            info!("Generating RISCV proof (at {:?})..", start.elapsed());
            let (riscv_proof, riscv_time) = timed_run(|| {
                let riscv_witness = ProvingWitness::setup_for_riscv(
                    riscv_program.clone(),
                    riscv_stdin,
                    riscv_opts,
                    riscv_pk,
                    riscv_vk.clone(),
                );

                riscv_machine
                .prove_with_shape_cycles(&riscv_witness, riscv_shape_config.as_ref())
                .0
            });

            // Assert pv_stream is the same as dryrun.
            assert_eq!(riscv_proof.pv_stream.clone().unwrap(), pv_stream);
            let riscv_proof_size = bincode::serialize(&riscv_proof.proofs()).unwrap().len();

            // RISCV proof verificaiton.
            info!("Verifying RISCV proof (at {:?})..", start.elapsed());
            let riscv_result = riscv_machine.verify(&riscv_proof, &riscv_vk);
            info!(
                "The proof is verified: {} (at {:?})..",
                riscv_result.is_ok(),
                start.elapsed()
            );
            assert!(riscv_result.is_ok());

            stats.riscv = (riscv_time, riscv_proof_size);
            if step_name == "riscv" {
                stats.print_up_to(&step_name);
                return;
            }

            // === Convert Phase: Convert Recursion Machine ===
            log_section("CONVERT PHASE");
            let recursion_opts = if bench {
                EmulatorOpts::bench_recursion_opts()
            } else {
                EmulatorOpts::default()
            };
            debug!("recursion_opts: {:?}", recursion_opts);

            let vk_root = get_vk_root(&vk_manager);
            let convert_machine = ConvertMachine::new(
                $recur_sc::new(),
                RecursionChipType::<Val<$recur_sc>>::all_chips(),
                RECURSION_NUM_PVS,
            );

            info!("Generating CONVERT proof (at {:?})..", start.elapsed());
            let (convert_proof, convert_time) = timed_run(|| {
                let convert_stdin = EmulatorStdin::setup_for_convert::<
                    <$recur_cc as FieldGenericConfig>::F,
                    $recur_cc,
                >(
                    &riscv_vk,
                    vk_root,
                    riscv_machine.base_machine(),
                    &riscv_proof.proofs(),
                    &recursion_shape_config,
                );
                let convert_witness = ProvingWitness::setup_for_convert(
                    convert_stdin,
                    convert_machine.config(),
                    recursion_opts,
                );

                convert_machine.prove(&convert_witness)
            });
            let convert_proof_size = bincode::serialize(&convert_proof.proofs()).unwrap().len();

            // Convert proof verificaiton.
            info!("Verifying CONVERT proof (at {:?})..", start.elapsed());
            let convert_result = convert_machine.verify(&convert_proof, &riscv_vk);
            info!(
                "The CONVERT proof is verified: {} (at {:?})",
                convert_result.is_ok(),
                start.elapsed()
            );
            assert!(convert_result.is_ok());

            stats.convert = (convert_time, convert_proof_size);
            if step_name == "convert" {
                stats.print_up_to(&step_name);
                return;
            }

            // === Combine Phase: Combine Recursion Machine ===
            convert_proof.split_into_individuals();
            log_section("COMBINE PHASE");
            let vk_root = get_vk_root(&vk_manager);
            let combine_machine = CombineMachine::<_, _>::new(
                $recur_sc::new(),
                RecursionChipType::<Val<$recur_sc>>::all_chips(),
                RECURSION_NUM_PVS,
            );

            info!("Generating COMBINE proof (at {:?})..", start.elapsed());
            let (combine_proof, combine_time) = timed_run(|| {
                let (combine_stdin, last_vk, last_proof) = EmulatorStdin::setup_for_combine::<
                    <$recur_cc as FieldGenericConfig>::F,
                    $recur_cc,
                >(
                    vk_root,
                    convert_proof.vks(),
                    &convert_proof.proofs(),
                    convert_machine.base_machine(),
                    COMBINE_SIZE,
                    convert_proof.proofs().len() <= COMBINE_SIZE,
                    vk_manager,
                    recursion_shape_config.as_ref(),
                );
                let combine_witness = ProvingWitness::setup_for_combine(
                    vk_root,
                    combine_stdin,
                    last_vk,
                    last_proof,
                    combine_machine.config(),
                    recursion_opts,
                );

                combine_machine.prove(&combine_witness)
            });

            let combine_proof_size = bincode::serialize(&combine_proof.proofs()).unwrap().len();

            // Combine proof verificaiton.
            info!("Verifying COMBINE proof (at {:?})..", start.elapsed());
            let combine_result = combine_machine.verify(&combine_proof, &riscv_vk);
            info!(
                "The COMBINE proof is verified: {} (at {:?})",
                combine_result.is_ok(),
                start.elapsed()
            );
            assert!(combine_result.is_ok());

            stats.combine = (combine_time, combine_proof_size);
            if step_name == "combine" {
                stats.print_up_to(&step_name);
                return;
            }

            // === Compress Phase: Compress Recursion Machine ===
            log_section("COMPRESS PHASE");
            let vk_root = get_vk_root(&vk_manager);
            let compress_machine = CompressMachine::new(
                $recur_sc::compress(),
                RecursionChipType::<Val<$recur_sc>>::compress_chips(),
                RECURSION_NUM_PVS,
            );

            info!("Generating COMPRESS proof (at {:?})..", start.elapsed());
            let (compress_proof, compress_time) = timed_run(|| {
                let compress_stdin = RecursionStdin::new(
                    combine_machine.base_machine(),
                    combine_proof.vks.clone(),
                    combine_proof.proofs.clone(),
                    true,
                    vk_root,
                );

                let (compress_program, compress_stdin_variant) = if vk_enabled {
                    let compress_vk_stdin = vk_manager.add_vk_merkle_proof(compress_stdin);
                    let mut compress_program =
                        CompressVkVerifierCircuit::<$recur_cc, $recur_sc>::build(
                            combine_machine.base_machine(),
                            &compress_vk_stdin,
                        );
                    compress_program.shape =
                        Some(RecursionChipType::<Val<$recur_sc>>::compress_shape());

                    (
                        compress_program,
                        RecursionStdinVariant::WithVk(compress_vk_stdin),
                    )
                } else {
                    let compress_program = CompressVerifierCircuit::<$recur_cc, $recur_sc>::build(
                        combine_machine.base_machine(),
                        &compress_stdin,
                    );

                    (
                        compress_program,
                        RecursionStdinVariant::NoVk(compress_stdin),
                    )
                };

                compress_program.print_stats();

                let (compress_pk, compress_vk) = compress_machine.setup_keys(&compress_program);
                let record = {
                    let mut witness_stream = Vec::new();
                    Witnessable::<$recur_cc>::write(&compress_stdin_variant, &mut witness_stream);
                    let mut runtime =
                        Runtime::<Val<$recur_sc>, Challenge<$recur_sc>, _, _, $s_box_degree>::new(
                            Arc::new(compress_program),
                            combine_machine.config().perm.clone(),
                        );
                    runtime.witness_stream = witness_stream.into();
                    runtime.run().unwrap();
                    runtime.record
                };
                let compress_witness = ProvingWitness::setup_with_keys_and_records(
                    compress_pk,
                    compress_vk,
                    vec![record],
                );

                compress_machine.prove(&compress_witness)
            });

            let compress_proof_size = bincode::serialize(&compress_proof.proofs()).unwrap().len();

            // Compress proof verificaiton.
            info!("Verifying COMPRESS proof (at {:?})..", start.elapsed());
            let compress_result = compress_machine.verify(&compress_proof, &riscv_vk);
            info!(
                "The COMPRESS proof is verified: {} (at {:?})",
                compress_result.is_ok(),
                start.elapsed()
            );
            assert!(compress_result.is_ok());

            stats.compress = (compress_time, compress_proof_size);
            if step_name == "compress" {
                stats.print_up_to(&step_name);
                return;
            }

            // === Embed Phase: Embed Machine ===
            log_section("EMBED PHASE");
            let vk_root = get_vk_root(&vk_manager);
            let embed_machine = EmbedMachine::<$recur_sc, _, _, Vec<u8>>::new(
                $embed_sc::new(),
                RecursionChipType::<Val<$embed_sc>>::embed_chips(),
                RECURSION_NUM_PVS,
            );

            info!("Generating EMBED proof (at {:?})..", start.elapsed());
            let (embed_proof, embed_time) = timed_run(|| {
                let embed_stdin = RecursionStdin::new(
                    compress_machine.base_machine(),
                    compress_proof.vks,
                    compress_proof.proofs,
                    true,
                    vk_root,
                );
                let (embed_program, embed_stdin_variant) = if vk_enabled {
                    let embed_vk_stdin = vk_manager.add_vk_merkle_proof(embed_stdin);
                    let embed_program = EmbedVkVerifierCircuit::<$recur_cc, $recur_sc>::build(
                        compress_machine.base_machine(),
                        &embed_vk_stdin,
                        vk_manager,
                    );

                    (embed_program, RecursionStdinVariant::WithVk(embed_vk_stdin))
                } else {
                    let embed_program = EmbedVerifierCircuit::<$recur_cc, $recur_sc>::build(
                        compress_machine.base_machine(),
                        &embed_stdin,
                    );

                    (embed_program, RecursionStdinVariant::NoVk(embed_stdin))
                };

                embed_program.print_stats();

                let (embed_pk, embed_vk) = embed_machine.setup_keys(&embed_program);
                let record = {
                    let mut witness_stream = Vec::new();
                    Witnessable::<$recur_cc>::write(&embed_stdin_variant, &mut witness_stream);
                    let mut runtime =
                        Runtime::<Val<$recur_sc>, Challenge<$recur_sc>, _, _, $s_box_degree>::new(
                            Arc::new(embed_program),
                            compress_machine.config().perm.clone(),
                        );
                    runtime.witness_stream = witness_stream.into();
                    runtime.run().unwrap();

                    runtime.record
                };

                // Persist and re-read the embed_vk to ensure consistency.
                let embed_vk_bytes = bincode::serialize(&embed_vk).unwrap();
                std::fs::write("embed_vk.bin", embed_vk_bytes).unwrap();
                let new_embed_vk_bytes = std::fs::read("embed_vk.bin").unwrap();
                let new_embed_vk: BaseVerifyingKey<$embed_sc> =
                    bincode::deserialize(&new_embed_vk_bytes).unwrap();

                let embed_witness = ProvingWitness::setup_with_keys_and_records(
                    embed_pk,
                    new_embed_vk,
                    vec![record],
                );

                embed_machine.prove(&embed_witness)
            });
            let embed_proof_size = bincode::serialize(&embed_proof.proofs()).unwrap().len();

            let serialized_proofs = bincode::serialize(&embed_proof.proofs()).unwrap();
            let mut file = File::create("embed_proof_proofs.bin").expect("cannot create file");
            file.write_all(&serialized_proofs).expect("failed to write to file");

            info!("Verifying EMBED proof (at {:?})..", start.elapsed());
            let embed_result = embed_machine.verify(&embed_proof, &riscv_vk);
            info!(
                "The EMBED proof is verified: {} (at {:?})",
                embed_result.is_ok(),
                start.elapsed()
            );
            assert!(embed_result.is_ok());

            // === Onchain Phase ===
            log_section("ONCHAIN PHASE");
            let onchain_stdin = OnchainStdin {
                machine: embed_machine.base_machine().clone(),
                vk: embed_proof.vks().first().unwrap().clone(),
                proof: embed_proof.proofs().first().unwrap().clone(),
                flag_complete: true,
            };
            let (constraints, witness) =
                OnchainVerifierCircuit::<$embed_cc, $embed_sc>::build(&onchain_stdin);

            build_gnark_config(constraints, witness, PathBuf::from("./"));
            info!("Finished exporting gnark data");

            stats.embed = (embed_time, embed_proof_size);
            stats.print_all();
        }
    };
}

run!(
    run_babybear,
    BabyBearPoseidon2,
    BabyBearSimple,
    BabyBearPoseidon2,
    BabyBearBn254,
    BabyBearBn254Poseidon2,
    BABYBEAR_S_BOX_DEGREE
);

run!(
    run_koalabear,
    KoalaBearPoseidon2,
    KoalaBearSimple,
    KoalaBearPoseidon2,
    KoalaBearBn254,
    KoalaBearBn254Poseidon2,
    KOALABEAR_S_BOX_DEGREE
);

fn main() {
    setup_logger();

    let (elf, riscv_stdin, args) = parse_args();
    match args.field.as_str() {
        "bb" => run_babybear(elf, riscv_stdin, args.step, args.bench),
        "kb" => run_koalabear(elf, riscv_stdin, args.step, args.bench),
        _ => unreachable!("Unsupported field for e2e test"),
    }
}
