// Benchmark as:
// export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"
// RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512ifma,+avx512vl" SPLIT_THRESHOLD=1048576 CHUNK_SIZE=4194304 CHUNK_BATCH_SIZE=32 RUST_LOG=info cargo run --profile perf --bin bench --features jemalloc --features nightly-features -- --programs reth-17106222 --field kb_vk

use anyhow::Result;
use clap::{
    builder::{NonEmptyStringValueParser, TypedValueParser},
    Parser,
};
use log::info;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_symmetric::Permutation;
use pico_perf::common::{
    bench_field::BenchField,
    bench_program::{load, BenchProgram, PROGRAMS},
    gnark_utils::send_gnark_prove_task,
    print_utils::{
        format_duration, format_results, log_performance_summary, log_section, PerformanceReport,
    },
};
use pico_vm::{
    chips::{
        chips::riscv_poseidon2::FieldSpecificPoseidon2Chip,
        precompiles::poseidon2::FieldSpecificPrecompilePoseidon2Chip,
    },
    configs::{
        config::{Com, Dom, PcsProverData, StarkGenericConfig, Val},
        field_config::{BabyBearBn254, KoalaBearBn254},
        stark_config::{
            bb_bn254_poseidon2::BabyBearBn254Poseidon2,
            kb_bn254_poseidon2::KoalaBearBn254Poseidon2, BabyBearPoseidon2, KoalaBearPoseidon2,
        },
    },
    emulator::opts::EmulatorOpts,
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            onchain_circuit::{
                gnark::builder::OnchainVerifierCircuit, stdin::OnchainStdin,
                utils::build_gnark_config_with_str,
            },
            shapes::{recursion_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
            vk_merkle::HasStaticVkManager,
        },
        configs::{
            riscv_config::StarkConfig as RiscvBBSC, riscv_kb_config::StarkConfig as RiscvKBSC,
        },
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        folder::ProverConstraintFolder,
        keys::{BaseVerifyingKey, HashableKey},
        logger::setup_logger,
        proof::BaseProof,
    },
    primitives::Poseidon2Init,
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
};
use std::{
    path::PathBuf,
    str::FromStr,
    time::{Duration, Instant},
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about=None)]
struct Args {
    #[clap(long, use_value_delimiter = true, value_delimiter = ',', value_parser = NonEmptyStringValueParser::new().map(|x| x.to_lowercase()))]
    programs: Vec<String>,

    #[clap(long, use_value_delimiter = true, default_value = "bb")]
    field: String,

    #[clap(long, default_value = "false")]
    noprove: bool,
}

fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}

fn bench_bb(bench_program: &BenchProgram) -> Result<PerformanceReport> {
    let vk_manager = <BabyBearPoseidon2 as HasStaticVkManager>::static_vk_manager();
    let vk_enabled = vk_manager.vk_verification_enabled();

    let (elf, stdin) = load(bench_program)?;
    let riscv_opts = EmulatorOpts::bench_riscv_ops();
    let recursion_opts = EmulatorOpts::bench_recursion_opts();

    info!(
        "RISCV Chunk Size: {}, RISCV Chunk Batch Size: {}",
        riscv_opts.chunk_size, riscv_opts.chunk_batch_size
    );
    info!(
        "Recursion Chunk Size: {}, Recursion Chunk Batch Size: {}",
        recursion_opts.chunk_size, recursion_opts.chunk_batch_size
    );

    // Conditionally create shape configs if VK is enabled.
    let riscv_shape_config = vk_enabled.then(RiscvShapeConfig::<BabyBear>::default);
    let recursion_shape_config =
        vk_enabled.then(RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear>>::default);

    let riscv =
        RiscvProver::new_initial_prover((RiscvBBSC::new(), &elf), riscv_opts, riscv_shape_config);
    let convert = ConvertProver::new_with_prev(&riscv, recursion_opts, recursion_shape_config);

    let recursion_shape_config =
        vk_enabled.then(RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear>>::default);
    let combine = CombineProver::new_with_prev(&convert, recursion_opts, recursion_shape_config);
    let compress = CompressProver::new_with_prev(&combine, (), None);
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);

    let riscv_vk = riscv.vk();

    // RISCV Phase
    log_section("RISCV PHASE");
    info!("Generating RISCV proof");
    let ((proof, cycles), riscv_duration) = time_operation(|| riscv.prove_cycles(stdin));
    info!("Verifying RISCV proof..");
    assert!(riscv.verify(&proof, riscv_vk));

    // Convert Phase
    log_section("CONVERT PHASE");
    info!("Generating CONVERT proof");
    let (proof, convert_duration) = time_operation(|| convert.prove(proof));
    info!("Verifying CONVERT proof..");
    assert!(convert.verify(&proof, riscv_vk));

    // Combine Phase
    log_section("COMBINE PHASE");
    info!("Generating COMBINE proof");
    let (proof, combine_duration) = time_operation(|| combine.prove(proof));
    info!("Verifying COMBINE proof..");
    assert!(combine.verify(&proof, riscv_vk));

    // Compress Phase
    log_section("COMPRESS PHASE");
    info!("Generating COMPRESS proof");
    let (proof, compress_duration) = time_operation(|| compress.prove(proof));
    info!("Verifying COMPRESS proof..");
    assert!(compress.verify(&proof, riscv_vk));

    // Embed Phase
    log_section("EMBED PHASE");
    info!("Generating EMBED proof");
    let (proof, embed_duration) = time_operation(|| embed.prove(proof));
    info!("Verifying EMBED proof..");
    assert!(embed.verify(&proof, riscv_vk));

    // Onchain Phase (only if VK enabled)
    let evm_duration_opt = vk_enabled.then(|| {
        log_section("ONCHAIN PHASE");
        let (_, evm_duration) = time_operation(|| {
            let onchain_stdin = OnchainStdin {
                machine: embed.machine().clone(),
                vk: proof.vks().first().unwrap().clone(),
                proof: proof.proofs().first().unwrap().clone(),
                flag_complete: true,
            };

            // Generate gnark data
            let (constraints, witness) = OnchainVerifierCircuit::<
                BabyBearBn254,
                BabyBearBn254Poseidon2,
            >::build(&onchain_stdin);
            let gnark_witness =
                build_gnark_config_with_str(constraints, witness, PathBuf::from("./"));
            let gnark_proof_data = send_gnark_prove_task(gnark_witness);
            info!(
                "gnark prove success with proof data {}",
                gnark_proof_data.unwrap_or_else(|e| format!("Error: {}", e))
            );

            1_u32
        });

        evm_duration
    });

    let (recursion_duration, total_duration) = log_performance_summary(
        riscv_duration,
        convert_duration,
        combine_duration,
        compress_duration,
        embed_duration,
        evm_duration_opt,
    );

    Ok(PerformanceReport {
        program: bench_program.name.to_string(),
        cycles,
        riscv_duration,
        convert_duration,
        combine_duration,
        compress_duration,
        embed_duration,
        recursion_duration,
        evm_duration: evm_duration_opt.unwrap_or_default(),
        total_duration,
        success: true,
    })
}

fn bench_kb(bench_program: &BenchProgram) -> Result<PerformanceReport> {
    let vk_manager = <KoalaBearPoseidon2 as HasStaticVkManager>::static_vk_manager();
    let vk_enabled = vk_manager.vk_verification_enabled();

    let (elf, stdin) = load(bench_program)?;
    let riscv_opts = EmulatorOpts::bench_riscv_ops();
    let recursion_opts = EmulatorOpts::bench_recursion_opts();

    info!(
        "RISCV Chunk Size: {}, RISCV Chunk Batch Size: {}",
        riscv_opts.chunk_size, riscv_opts.chunk_batch_size
    );
    info!(
        "Recursion Chunk Size: {}, Recursion Chunk Batch Size: {}",
        recursion_opts.chunk_size, recursion_opts.chunk_batch_size
    );

    // Conditionally create shape configs if VK is enabled.
    let riscv_shape_config = vk_enabled.then(RiscvShapeConfig::<KoalaBear>::default);
    let recursion_shape_config =
        vk_enabled.then(RecursionShapeConfig::<KoalaBear, RecursionChipType<KoalaBear>>::default);

    let riscv =
        RiscvProver::new_initial_prover((RiscvKBSC::new(), &elf), riscv_opts, riscv_shape_config);
    let convert = ConvertProver::new_with_prev(&riscv, recursion_opts, recursion_shape_config);

    let recursion_shape_config =
        vk_enabled.then(RecursionShapeConfig::<KoalaBear, RecursionChipType<KoalaBear>>::default);
    let combine = CombineProver::new_with_prev(&convert, recursion_opts, recursion_shape_config);
    let compress = CompressProver::new_with_prev(&combine, (), None);
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);

    let riscv_vk = riscv.vk();

    // RISCV Phase
    log_section("RISCV PHASE");
    info!("Generating RISCV proof");
    let ((proof, cycles), riscv_duration) = time_operation(|| riscv.prove_cycles(stdin));
    info!("Verifying RISCV proof..");
    assert!(riscv.verify(&proof, riscv_vk));

    // Convert Phase
    log_section("CONVERT PHASE");
    info!("Generating CONVERT proof");
    let (proof, convert_duration) = time_operation(|| convert.prove(proof));
    info!("Verifying CONVERT proof..");
    assert!(convert.verify(&proof, riscv_vk));

    // Combine Phase
    log_section("COMBINE PHASE");
    info!("Generating COMBINE proof");
    let (proof, combine_duration) = time_operation(|| combine.prove(proof));
    info!("Verifying COMBINE proof..");
    assert!(combine.verify(&proof, riscv_vk));

    // Compress Phase
    log_section("COMPRESS PHASE");
    info!("Generating COMPRESS proof");
    let (proof, compress_duration) = time_operation(|| compress.prove(proof));
    info!("Verifying COMPRESS proof..");
    assert!(compress.verify(&proof, riscv_vk));

    // Embed Phase
    log_section("EMBED PHASE");
    info!("Generating EMBED proof");
    let (proof, embed_duration) = time_operation(|| embed.prove(proof));
    info!("Verifying EMBED proof..");
    assert!(embed.verify(&proof, riscv_vk));

    // Onchain Phase (only if VK enabled)
    let evm_duration_opt = vk_enabled.then(|| {
        log_section("ONCHAIN PHASE");
        let (_, evm_duration) = time_operation(|| {
            let onchain_stdin = OnchainStdin {
                machine: embed.machine().clone(),
                vk: proof.vks().first().unwrap().clone(),
                proof: proof.proofs().first().unwrap().clone(),
                flag_complete: true,
            };

            // Generate gnark data
            let (constraints, witness) = OnchainVerifierCircuit::<
                KoalaBearBn254,
                KoalaBearBn254Poseidon2,
            >::build(&onchain_stdin);
            let gnark_witness =
                build_gnark_config_with_str(constraints, witness, PathBuf::from("./"));
            let gnark_proof_data = send_gnark_prove_task(gnark_witness);
            info!(
                "gnark prove success with proof data {}",
                gnark_proof_data.unwrap_or_else(|e| format!("Error: {}", e))
            );

            1_u32
        });

        evm_duration
    });

    let (recursion_duration, total_duration) = log_performance_summary(
        riscv_duration,
        convert_duration,
        combine_duration,
        compress_duration,
        embed_duration,
        evm_duration_opt,
    );

    Ok(PerformanceReport {
        program: bench_program.name.to_string(),
        cycles,
        riscv_duration,
        convert_duration,
        combine_duration,
        compress_duration,
        embed_duration,
        recursion_duration,
        evm_duration: evm_duration_opt.unwrap_or_default(),
        total_duration,
        success: true,
    })
}

fn bench_tracegen<SC>(bench_program: &BenchProgram) -> Result<PerformanceReport>
where
    SC: Send + StarkGenericConfig + 'static,
    Com<SC>: Send + Sync,
    Dom<SC>: Send + Sync,
    PcsProverData<SC>: Clone + Send + Sync,
    BaseProof<SC>: Send + Sync,
    BaseVerifyingKey<SC>: HashableKey<Val<SC>>,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config + Poseidon2Init,
    <Val<SC> as Poseidon2Init>::Poseidon2: Permutation<[Val<SC>; 16]>,
    FieldSpecificPoseidon2Chip<Val<SC>>: Air<ProverConstraintFolder<SC>>,
    FieldSpecificPrecompilePoseidon2Chip<Val<SC>>: Air<ProverConstraintFolder<SC>>,
{
    let (elf, stdin) = load(bench_program)?;
    let riscv_opts = EmulatorOpts::bench_riscv_ops();

    info!(
        "RISCV Chunk Size: {}, RISCV Chunk Batch Size: {}",
        riscv_opts.chunk_size, riscv_opts.chunk_batch_size
    );

    let riscv = RiscvProver::new_initial_prover((SC::new(), &elf), riscv_opts, None);

    log_section("RISCV PHASE");
    info!("Running RISCV");
    let (cycles, riscv_duration) = time_operation(|| riscv.emulate(stdin));

    log_section("PERFORMANCE SUMMARY");
    info!("Time Metrics (wall time)");
    info!("----------------------------------------");
    info!("RISCV:     {}", format_duration(riscv_duration));

    Ok(PerformanceReport {
        program: bench_program.name.to_string(),
        cycles,
        riscv_duration,
        convert_duration: Duration::default(),
        combine_duration: Duration::default(),
        compress_duration: Duration::default(),
        embed_duration: Duration::default(),
        recursion_duration: Duration::default(),
        evm_duration: Duration::default(),
        total_duration: riscv_duration,
        success: true,
    })
}

fn run_benchmark(
    bench_program: &BenchProgram,
    bench_field: BenchField,
) -> Result<PerformanceReport> {
    match bench_field {
        BenchField::BabyBear => bench_bb(bench_program),
        BenchField::KoalaBear => bench_kb(bench_program),
    }
}

fn run_tracegen_benchmark(
    bench_program: &BenchProgram,
    bench_type: BenchField,
) -> Result<PerformanceReport> {
    match bench_type {
        BenchField::BabyBear => bench_tracegen::<RiscvBBSC>(bench_program),
        BenchField::KoalaBear => bench_tracegen::<RiscvKBSC>(bench_program),
    }
}

fn main() -> Result<()> {
    setup_logger();

    let args = Args::parse();
    let bench_type = BenchField::from_str(&args.field)?;

    let mut programs: Vec<_> = args
        .programs
        .iter()
        .filter_map(|name| PROGRAMS.iter().find(|p| p.name == name).copied())
        .collect();

    if programs.is_empty() {
        programs = PROGRAMS.to_vec();
    }

    // Run benchmarks.
    let mut results = Vec::with_capacity(programs.len());

    if args.noprove {
        for bench_program in &programs {
            results.push(run_tracegen_benchmark(bench_program, bench_type)?);
        }
    } else {
        for bench_program in programs {
            results.push(run_benchmark(&bench_program, bench_type)?);
        }
    }

    // Print results.
    let output = format_results(&results);
    println!("{}", output.join("\n"));

    Ok(())
}
