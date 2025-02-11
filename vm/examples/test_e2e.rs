use cpu_time::ProcessTime;
use p3_field::FieldAlgebra;
use pico_vm::{
    compiler::{
        recursion::circuit::witness::Witnessable,
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    configs::{
        config::{Challenge, FieldGenericConfig, StarkGenericConfig, Val},
        field_config::{
            bb_bn254::BabyBearBn254, bb_simple::BabyBearSimple, kb_bn254::KoalaBearBn254,
            kb_simple::KoalaBearSimple,
        },
        stark_config::{
            bb_bn254_poseidon2::BabyBearBn254Poseidon2, bb_poseidon2::BabyBearPoseidon2,
            kb_bn254_poseidon2::KoalaBearBn254Poseidon2, kb_poseidon2::KoalaBearPoseidon2,
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
        },
        machine::{
            combine::CombineMachine, compress::CompressMachine, convert::ConvertMachine,
            embed::EmbedMachine, riscv::RiscvMachine,
        },
    },
    machine::{logger::setup_logger, machine::MachineBehavior, witness::ProvingWitness},
    primitives::consts::{
        BABYBEAR_S_BOX_DEGREE, COMBINE_SIZE, DIGEST_SIZE, KOALABEAR_S_BOX_DEGREE,
        RECURSION_NUM_PVS, RISCV_NUM_PVS,
    },
};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{debug, info};

#[path = "common/parse_args.rs"]
mod parse_args;

#[rustfmt::skip]
macro_rules! run {
    ($func_name:ident, $riscv_sc:ident, $recur_cc:ident, $recur_sc:ident, $embed_cc:ident, $embed_sc:ident, $s_box_degree:ident) => {
        fn $func_name(
            elf: &'static [u8],
            riscv_stdin: EmulatorStdin<Program, Vec<u8>>,
            step_name: String,
            bench: bool,
        ) {
            let start = Instant::now();

            let riscv_compiler = Compiler::new(SourceType::RISCV, elf);
            let riscv_program = riscv_compiler.compile();

            let riscv_machine = RiscvMachine::new(
                $riscv_sc::new(),
                RiscvChipType::<Val<$riscv_sc>>::all_chips(),
                RISCV_NUM_PVS,
            );

            // Setup machine prover, verifier, pk and vk.
            let (riscv_pk, riscv_vk) = riscv_machine.setup_keys(&riscv_program.clone());

            let riscv_opts = if bench {
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
            let riscv_witness = ProvingWitness::<$riscv_sc, RiscvChipType<Val<$riscv_sc>>, Vec<u8>>
                ::setup_for_riscv(
                    riscv_program.clone(),
                    riscv_stdin.clone(),
                    riscv_opts.clone(),
                    riscv_pk.clone(),
                    riscv_vk.clone()
                );
            let mut emulator = MetaEmulator::setup_riscv(&riscv_witness);
            let pv_stream = emulator.get_pv_stream_with_dryrun();
            debug!("Public values stream: {:?}", pv_stream);

            // Generate the proof.
            info!("╔═══════════════════════╗");
            info!("║      RISCV PHASE      ║");
            info!("╚═══════════════════════╝");
            info!("Generating RISCV proof (at {:?})..", start.elapsed());
            let (riscv_proof, riscv_time) = timed_run(|| {
                let riscv_witness = ProvingWitness::setup_for_riscv(
                    riscv_program.clone(),
                    riscv_stdin,
                    riscv_opts,
                    riscv_pk,
                    riscv_vk.clone(),
                );

                riscv_machine.prove(&riscv_witness)
            });

            // assert pv_stream is the same as dryrun
            assert_eq!(riscv_proof.pv_stream.clone().unwrap(), pv_stream);

            let riscv_proof_size = bincode::serialize(&riscv_proof.proofs()).unwrap().len();

            // Verify the proof.
            info!("Verifying RISCV proof (at {:?})..", start.elapsed());
            let riscv_result = riscv_machine.verify(&riscv_proof, &riscv_vk);
            info!(
                "The proof is verified: {} (at {:?})..",
                riscv_result.is_ok(),
                start.elapsed()
            );
            assert!(riscv_result.is_ok());
            if step_name == "riscv" {
                print_stats(
                    riscv_time,
                    TIME_ZERO,
                    TIME_ZERO,
                    TIME_ZERO,
                    TIME_ZERO,
                    riscv_proof_size,
                    0,
                    0,
                    0,
                    0,
                );
                return;
            }

            // -------- Riscv Convert Recursion Machine --------

            info!("╔═══════════════════════╗");
            info!("║     CONVERT PHASE     ║");
            info!("╚═══════════════════════╝");

            let recursion_opts = if bench {
                EmulatorOpts::bench_recursion_opts()
            } else {
                EmulatorOpts::default()
            };
            debug!("recursion_opts: {:?}", recursion_opts);

            let vk_root = [Val::<$riscv_sc>::ZERO; DIGEST_SIZE];

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
                    &None,
                );

                let convert_witness = ProvingWitness::setup_for_convert(
                    convert_stdin,
                    convert_machine.config(),
                    recursion_opts,
                );

                convert_machine.prove(&convert_witness)
            });

            let convert_proof_size = bincode::serialize(&convert_proof.proofs()).unwrap().len();

            // Verify the proof.
            info!("Verifying CONVERT proof (at {:?})..", start.elapsed());
            let convert_result = convert_machine.verify(&convert_proof, &riscv_vk);
            info!(
                "The CONVERT proof is verified: {} (at {:?})",
                convert_result.is_ok(),
                start.elapsed()
            );
            assert!(convert_result.is_ok());

            if step_name == "convert" {
                print_stats(
                    riscv_time,
                    convert_time,
                    TIME_ZERO,
                    TIME_ZERO,
                    TIME_ZERO,
                    riscv_proof_size,
                    convert_proof_size,
                    0,
                    0,
                    0,
                );
                return;
            }

            // -------- Combine Recursion Machine --------

            info!("╔═══════════════════════╗");
            info!("║     COMBINE PHASE     ║");
            info!("╚═══════════════════════╝");

            let vk_root = [Val::<$recur_sc>::ZERO; DIGEST_SIZE];

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
                );

                let combine_witness = ProvingWitness::setup_for_recursion(
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

            // Verify the proof.
            info!("Verifying COMBINE proof (at {:?})..", start.elapsed());
            let combine_result = combine_machine.verify(&combine_proof, &riscv_vk);
            info!(
                "The COMBINE proof is verified: {} (at {:?})",
                combine_result.is_ok(),
                start.elapsed()
            );
            assert!(combine_result.is_ok());

            if step_name == "combine" {
                print_stats(
                    riscv_time,
                    convert_time,
                    combine_time,
                    TIME_ZERO,
                    TIME_ZERO,
                    riscv_proof_size,
                    convert_proof_size,
                    combine_proof_size,
                    0,
                    0,
                );
                return;
            }

            // -------- Compress Recursion Machine --------

            info!("╔═══════════════════════╗");
            info!("║    COMPRESS PHASE     ║");
            info!("╚═══════════════════════╝");

            let vk_root = [Val::<$recur_sc>::ZERO; DIGEST_SIZE];

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

                let compress_program = CompressVerifierCircuit::<$recur_cc, $recur_sc>::build(
                    combine_machine.base_machine(),
                    &compress_stdin,
                );
                compress_program.print_stats();
                let (compress_pk, compress_vk) = compress_machine.setup_keys(&compress_program);
                let record = {
                    let mut witness_stream = Vec::new();
                    Witnessable::<$recur_cc>::write(&compress_stdin, &mut witness_stream);
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

            info!("Verifying COMPRESS proof (at {:?})..", start.elapsed());
            let compress_result = compress_machine.verify(&compress_proof, &riscv_vk);

            info!(
                "The COMPRESS proof is verified: {} (at {:?})",
                compress_result.is_ok(),
                start.elapsed()
            );
            assert!(compress_result.is_ok());

            if step_name == "compress" {
                print_stats(
                    riscv_time,
                    convert_time,
                    combine_time,
                    compress_time,
                    TIME_ZERO,
                    riscv_proof_size,
                    convert_proof_size,
                    combine_proof_size,
                    compress_proof_size,
                    0,
                );
                return;
            }

            // -------- Embed Machine --------

            info!("╔═══════════════════════╗");
            info!("║      EMBED PHASE      ║");
            info!("╚═══════════════════════╝");

            let vk_root = [Val::<$embed_sc>::ZERO; DIGEST_SIZE];

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
                let embed_program = EmbedVerifierCircuit::<$recur_cc, $recur_sc>::build(
                    compress_machine.base_machine(),
                    &embed_stdin,
                );

                embed_program.print_stats();
                let (embed_pk, embed_vk) = embed_machine.setup_keys(&embed_program);
                let record = {
                    let mut witness_stream = Vec::new();
                    Witnessable::<$recur_cc>::write(&embed_stdin, &mut witness_stream);
                    let mut runtime =
                        Runtime::<Val<$recur_sc>, Challenge<$recur_sc>, _, _, $s_box_degree>::new(
                            Arc::new(embed_program),
                            compress_machine.config().perm.clone(),
                        );
                    runtime.witness_stream = witness_stream.into();
                    runtime.run().unwrap();
                    runtime.record
                };
                let embed_witness =
                    ProvingWitness::setup_with_keys_and_records(embed_pk, embed_vk, vec![record]);
                embed_machine.prove(&embed_witness)
            });

            let embed_proof_size = bincode::serialize(&embed_proof.proofs()).unwrap().len();

            info!("Verifying EMBED proof (at {:?})..", start.elapsed());
            let embed_result = embed_machine.verify(&embed_proof, &riscv_vk);

            info!(
                "The EMBED proof is verified: {} (at {:?})",
                compress_result.is_ok(),
                start.elapsed()
            );
            assert!(embed_result.is_ok());

            info!("╔═══════════════════════╗");
            info!("║     ONCHAIN PHASE     ║");
            info!("╚═══════════════════════╝");
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

            print_stats(
                riscv_time,
                convert_time,
                combine_time,
                compress_time,
                embed_time,
                riscv_proof_size,
                convert_proof_size,
                combine_proof_size,
                compress_proof_size,
                embed_proof_size,
            );
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

struct TimeStats {
    pub wall_time: Duration,
    pub cpu_time: Duration,
    pub parallelism: f64,
}
const TIME_ZERO: TimeStats = TimeStats {
    wall_time: Duration::from_secs(0),
    cpu_time: Duration::from_secs(0),
    parallelism: 0.0,
};

fn timed_run<T, F: FnOnce() -> T>(operation: F) -> (T, TimeStats) {
    let start = Instant::now();
    let start_cpu = ProcessTime::now();
    let result = operation();
    let wall_time = start.elapsed();
    let cpu_time = start_cpu.elapsed();
    let parallelism = cpu_time.as_secs_f64() / wall_time.as_secs_f64();
    (
        result,
        TimeStats {
            wall_time,
            cpu_time,
            parallelism,
        },
    )
}
#[allow(clippy::too_many_arguments)]
fn print_stats(
    riscv_time: TimeStats,
    convert_time: TimeStats,
    combine_time: TimeStats,
    compress_time: TimeStats,
    embed_time: TimeStats,
    riscv_proof_size: usize,
    convert_proof_size: usize,
    combine_proof_size: usize,
    compress_proof_size: usize,
    embed_proof_size: usize,
) {
    let recursion_time = convert_time.wall_time
        + combine_time.wall_time
        + compress_time.wall_time
        + embed_time.wall_time;
    let recursion_cpu_time = convert_time.cpu_time
        + combine_time.cpu_time
        + compress_time.cpu_time
        + embed_time.cpu_time;
    let recursion_parallelism = recursion_cpu_time.as_secs_f64() / recursion_time.as_secs_f64();
    let total_time = riscv_time.wall_time + recursion_time;
    let total_cpu_time = riscv_time.cpu_time + recursion_cpu_time;
    let total_parallelism = total_cpu_time.as_secs_f64() / total_time.as_secs_f64();

    info!("╔═══════════════════════╗");
    info!("║ PERFORMANCE SUMMARY   ║");
    info!("╚═══════════════════════╝");
    info!("Time Metrics (wall time | CPU time | parallelism)");
    info!("----------------------------------------");
    info!(
        "RISCV:     {:>10} | {:>10} | {:>6.2}x",
        format_duration(riscv_time.wall_time.as_secs_f64()),
        format_duration(riscv_time.cpu_time.as_secs_f64()),
        riscv_time.parallelism
    );
    info!("Recursion Steps:");
    info!(
        "  CONVERT: {:>10} | {:>10} | {:>6.2}x",
        format_duration(convert_time.wall_time.as_secs_f64()),
        format_duration(convert_time.cpu_time.as_secs_f64()),
        convert_time.parallelism
    );
    info!(
        "  COMBINE: {:>10} | {:>10} | {:>6.2}x",
        format_duration(combine_time.wall_time.as_secs_f64()),
        format_duration(combine_time.cpu_time.as_secs_f64()),
        combine_time.parallelism
    );
    info!(
        "  COMPRESS:{:>10} | {:>10} | {:>6.2}x",
        format_duration(compress_time.wall_time.as_secs_f64()),
        format_duration(compress_time.cpu_time.as_secs_f64()),
        compress_time.parallelism
    );
    info!(
        "  EMBED:   {:>10} | {:>10} | {:>6.2}x",
        format_duration(embed_time.wall_time.as_secs_f64()),
        format_duration(embed_time.cpu_time.as_secs_f64()),
        embed_time.parallelism
    );
    info!("  ----------------------------------------");
    info!(
        "  TOTAL:   {:>10} | {:>10} | {:>6.2}x",
        format_duration(recursion_time.as_secs_f64()),
        format_duration(recursion_cpu_time.as_secs_f64()),
        recursion_parallelism
    );
    info!("----------------------------------------");
    info!(
        "TOTAL:     {:>10} | {:>10} | {:>6.2}x",
        format_duration(total_time.as_secs_f64()),
        format_duration(total_cpu_time.as_secs_f64()),
        total_parallelism
    );

    info!("╔═══════════════════════╗");
    info!("║      PROOF SIZES      ║");
    info!("╚═══════════════════════╝");
    info!("----------------------------------------");
    info!("RISCV:     {:>10.2} KB", (riscv_proof_size as f64) / 1024.0);
    info!(
        "CONVERT:   {:>10.2} KB",
        (convert_proof_size as f64) / 1024.0
    );
    info!(
        "COMBINE:   {:>10.2} KB",
        (combine_proof_size as f64) / 1024.0
    );
    info!(
        "COMPRESS:  {:>10.2} KB",
        (compress_proof_size as f64) / 1024.0
    );
    info!("EMBED:     {:>10.2} KB", (embed_proof_size as f64) / 1024.0);
    info!("----------------------------------------");
}

fn main() {
    setup_logger();

    let (elf, riscv_stdin, args) = parse_args::parse_args();
    match args.field.as_str() {
        "bb" => run_babybear(elf, riscv_stdin, args.step, args.bench),
        "kb" => run_koalabear(elf, riscv_stdin, args.step, args.bench),
        _ => unreachable!("Unsupported field for e2e test"),
    }
}

fn format_duration(duration: f64) -> String {
    let secs = duration.round() as u64;
    let minutes = secs / 60;
    let seconds = secs % 60;

    if minutes > 0 {
        format!("{}m:{}s", minutes, seconds)
    } else if seconds > 0 {
        format!(
            "{}s:{}ms",
            seconds,
            ((duration - seconds as f64) * 1000.0).round() as u64
        )
    } else {
        format!("{}ms", (duration * 1000.0).round() as u64)
    }
}
