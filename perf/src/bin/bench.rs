// Benchmark as:
// export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"
// RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512ifma,+avx512vl" SPLIT_THRESHOLD=1048576 CHUNK_SIZE=4194304 CHUNK_BATCH_SIZE=32 RUST_LOG=info cargo run --profile perf --bin bench --features jemalloc --features nightly-features -- --programs reth-17106222 --field kb_vk

use anyhow::{Context, Result};
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
use pico_vm::{
    chips::{
        chips::riscv_poseidon2::FieldSpecificPoseidon2Chip,
        precompiles::poseidon2::FieldSpecificPrecompilePoseidon2Chip,
    },
    configs::{
        config::{Com, Dom, PcsProverData, StarkGenericConfig, Val},
        field_config::{BabyBearBn254, KoalaBearBn254},
        stark_config::{
            bb_bn254_poseidon2::BabyBearBn254Poseidon2, kb_bn254_poseidon2::KoalaBearBn254Poseidon2,
        },
    },
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            onchain_circuit::{
                gnark::builder::OnchainVerifierCircuit, stdin::OnchainStdin,
                utils::build_gnark_config_with_str,
            },
            shapes::{recursion_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
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
        CombineProver, CombineVkProver, CompressProver, CompressVkProver, ConvertProver,
        EmbedProver, EmbedVkProver, InitialProverSetup, MachineProver, ProverChain, RiscvProver,
    },
};
use reqwest::blocking::Client;
use serde::Serialize;
use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    thread::sleep,
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

#[derive(Clone, Copy)]
struct Benchmark {
    pub name: &'static str,
    pub elf: &'static str,
    pub input: Option<&'static str>,
}

const PROGRAMS: &[Benchmark] = &[
    Benchmark {
        name: "fibonacci-300kn",
        elf: "./perf/bench_data/fibonacci-elf",
        input: Some("fibonacci-300kn"),
    },
    Benchmark {
        name: "tendermint",
        elf: "./perf/bench_data/tendermint-elf",
        input: None,
    },
    Benchmark {
        name: "reth-17106222",
        elf: "./perf/bench_data/reth-elf",
        input: Some("./perf/bench_data/reth-17106222.bin"),
    },
    Benchmark {
        name: "reth-22059900",
        elf: "./perf/bench_data/reth-elf",
        input: Some("./perf/bench_data/reth-22059900.bin"),
    },
    Benchmark {
        name: "reth-20528709",
        elf: "./perf/bench_data/reth-elf",
        input: Some("./perf/bench_data/reth-20528709.bin"),
    },
];

#[allow(clippy::type_complexity)]
fn load<P>(bench: &Benchmark) -> Result<(Vec<u8>, EmulatorStdin<P, Vec<u8>>)> {
    let elf = std::fs::read(bench.elf)?;
    let mut stdin_builder = EmulatorStdin::<P, Vec<u8>>::new_builder();

    match bench.input {
        None => {}
        Some("fibonacci-300kn") => {
            let input_bytes = bincode::serialize(&300_000u32).expect("failed to serialize");
            stdin_builder.write_slice(&input_bytes);
        }
        Some(input_path) => {
            let mut file = File::open(input_path).expect("Failed to open file");
            let mut buffer: Vec<u8> = Vec::new();
            file.read_to_end(&mut buffer).expect("Failed to read file");
            stdin_builder.write_slice(&buffer);
        }
    }

    let stdin = stdin_builder.finalize();

    Ok((elf, stdin))
}

fn prepare_kb_gnark() {
    clean_gnark_env();

    let mut setup_cmd_setup = Command::new("sh");
    setup_cmd_setup.arg("-c").arg(
        "rm -f vm_pk vm_vk Groth16Verifier.sol && \
        curl -O https://picobench.s3.us-west-2.amazonaws.com/koalabear_gnark/vm_pk && \
        curl -O https://picobench.s3.us-west-2.amazonaws.com/koalabear_gnark/vm_vk && \
        curl -O https://picobench.s3.us-west-2.amazonaws.com/koalabear_gnark/vm_ccs",
    );
    execute_command(setup_cmd_setup);

    let mut setup_cmd_start_gnark_server = Command::new("sh");
    setup_cmd_start_gnark_server.arg("-c")
        .arg("docker run --rm -d -v `pwd`:/data -p 9099:9099 --name pico_bench brevishub/pico_gnark_server:1.1 -field kb");
    execute_command(setup_cmd_start_gnark_server);

    check_gnark_prover_ready()
}

fn prepare_bb_gnark() {
    clean_gnark_env();

    let mut setup_cmd_setup = Command::new("sh");
    setup_cmd_setup.arg("-c").arg(
        "rm -f vm_pk vm_vk Groth16Verifier.sol && \
        curl -O https://picobench.s3.us-west-2.amazonaws.com/babybear_gnark/vm_pk && \
        curl -O https://picobench.s3.us-west-2.amazonaws.com/babybear_gnark/vm_vk && \
        curl -O https://picobench.s3.us-west-2.amazonaws.com/babybear_gnark/vm_ccs",
    );
    execute_command(setup_cmd_setup);

    let mut setup_cmd_start_gnark_server = Command::new("sh");
    setup_cmd_start_gnark_server.arg("-c")
        .arg("docker run --rm -d -v `pwd`:/data -p 9099:9099 --name pico_bench brevishub/pico_gnark_server:1.1 -field bb");
    execute_command(setup_cmd_start_gnark_server);

    check_gnark_prover_ready()
}

fn clean_gnark_env() {
    let mut setup_cmd_clean = Command::new("sh");
    setup_cmd_clean.arg("-c").arg("docker rm -f pico_bench");
    execute_command(setup_cmd_clean);
}

fn format_duration(duration: Duration) -> String {
    let duration = duration.as_secs_f64();
    let secs = duration.round() as u64;
    let minutes = secs / 60;
    let seconds = secs % 60;

    if minutes > 0 {
        format!("{}m{}s", minutes, seconds)
    } else if seconds > 0 {
        format!("{}s", seconds)
    } else {
        format!("{}ms", (duration * 1000.0).round() as u64)
    }
}

#[derive(Debug, Serialize)]
pub struct PerformanceReport {
    program: String,
    cycles: u64,
    riscv_duration: Duration,
    convert_duration: Duration,
    combine_duration: Duration,
    compress_duration: Duration,
    embed_duration: Duration,
    recursion_duration: Duration,
    evm_duration: Duration,
    total_duration: Duration,
    success: bool,
}

fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}

fn bench_bb(bench: &Benchmark) -> Result<PerformanceReport> {
    let (elf, stdin) = load(bench)?;
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

    let riscv = RiscvProver::new_initial_prover((RiscvBBSC::new(), &elf), riscv_opts, None);
    let convert = ConvertProver::new_with_prev(&riscv, recursion_opts, None);
    let combine = CombineProver::new_with_prev(&convert, recursion_opts, None);
    let compress = CompressProver::new_with_prev(&combine, (), None);
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);

    let riscv_vk = riscv.vk();

    info!("╔═══════════════════════╗");
    info!("║      RISCV PHASE      ║");
    info!("╚═══════════════════════╝");
    info!("Generating RISCV proof");
    let ((proof, cycles), riscv_duration) = time_operation(|| riscv.prove_cycles(stdin));
    info!("Verifying RISCV proof..");
    assert!(riscv.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║     CONVERT PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating CONVERT proof");
    let (proof, convert_duration) = time_operation(|| convert.prove(proof));
    info!("Verifying CONVERT proof..");
    assert!(convert.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║     COMBINE PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating COMBINE proof");
    let (proof, combine_duration) = time_operation(|| combine.prove(proof));
    info!("Verifying COMBINE proof..");
    assert!(combine.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║    COMPRESS PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating COMPRESS proof");
    let (proof, compress_duration) = time_operation(|| compress.prove(proof));
    info!("Verifying COMPRESS proof..");
    assert!(compress.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║      EMBED PHASE      ║");
    info!("╚═══════════════════════╝");
    info!("Generating EMBED proof");
    let (proof, embed_duration) = time_operation(|| embed.prove(proof));
    info!("Verifying EMBED proof..");
    assert!(embed.verify(&proof, riscv_vk));

    let recursion_duration =
        convert_duration + combine_duration + compress_duration + embed_duration;
    let total_duration = riscv_duration + recursion_duration;

    info!("╔═══════════════════════╗");
    info!("║ PERFORMANCE SUMMARY   ║");
    info!("╚═══════════════════════╝");
    info!("Time Metrics (wall time)");
    info!("----------------------------------------");
    info!("RISCV:     {}", format_duration(riscv_duration));
    info!("Recursion Steps:");
    info!("  CONVERT: {}", format_duration(convert_duration));
    info!("  COMBINE: {}", format_duration(combine_duration));
    info!("  COMPRESS:{}", format_duration(compress_duration));
    info!("  EMBED:   {}", format_duration(embed_duration));
    info!("  ----------------------------------------");
    info!("  TOTAL:   {}", format_duration(recursion_duration));
    info!("----------------------------------------");
    info!("TOTAL:     {}", format_duration(total_duration));

    Ok(PerformanceReport {
        program: bench.name.to_string(),
        cycles,
        riscv_duration,
        convert_duration,
        combine_duration,
        compress_duration,
        embed_duration,
        recursion_duration,
        evm_duration: Duration::default(),
        total_duration,
        success: true,
    })
}

fn bench_bb_vk(bench: &Benchmark) -> Result<PerformanceReport> {
    let (elf, stdin) = load(bench)?;
    let riscv_opts = EmulatorOpts::bench_riscv_ops();
    let recursion_opts = EmulatorOpts::bench_recursion_opts();
    let riscv_shape_config = RiscvShapeConfig::<BabyBear>::default();
    let recursion_shape_config =
        RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear>>::default();

    info!(
        "RISCV Chunk Size: {}, RISCV Chunk Batch Size: {}",
        riscv_opts.chunk_size, riscv_opts.chunk_batch_size
    );
    info!(
        "Recursion Chunk Size: {}, Recursion Chunk Batch Size: {}",
        recursion_opts.chunk_size, recursion_opts.chunk_batch_size
    );

    let riscv = RiscvProver::new_initial_prover(
        (RiscvBBSC::new(), &elf),
        riscv_opts,
        Some(riscv_shape_config),
    );
    let convert =
        ConvertProver::new_with_prev(&riscv, recursion_opts, Some(recursion_shape_config));
    let recursion_shape_config =
        RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear>>::default();
    let combine =
        CombineVkProver::new_with_prev(&convert, recursion_opts, Some(recursion_shape_config));
    let compress = CompressVkProver::new_with_prev(&combine, (), None);
    let embed = EmbedVkProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);

    let riscv_vk = riscv.vk();

    info!("╔═══════════════════════╗");
    info!("║      RISCV PHASE      ║");
    info!("╚═══════════════════════╝");
    info!("Generating RISCV proof");
    let ((proof, cycles), riscv_duration) = time_operation(|| riscv.prove_cycles(stdin));
    info!("Verifying RISCV proof..");
    assert!(riscv.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║     CONVERT PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating CONVERT proof");
    let (proof, convert_duration) = time_operation(|| convert.prove(proof));
    info!("Verifying CONVERT proof..");
    assert!(convert.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║     COMBINE PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating COMBINE proof");
    let (proof, combine_duration) = time_operation(|| combine.prove(proof));
    info!("Verifying COMBINE proof..");
    assert!(combine.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║    COMPRESS PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating COMPRESS proof");
    let (proof, compress_duration) = time_operation(|| compress.prove(proof));
    info!("Verifying COMPRESS proof..");
    assert!(compress.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║      EMBED PHASE      ║");
    info!("╚═══════════════════════╝");
    info!("Generating EMBED proof");
    let (proof, embed_duration) = time_operation(|| embed.prove(proof));
    info!("Verifying EMBED proof..");
    assert!(embed.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║     ONCHAIN PHASE     ║");
    info!("╚═══════════════════════╝");
    let (_, evm_duration) = time_operation(|| {
        let onchain_stdin = OnchainStdin {
            machine: embed.machine().clone(),
            vk: proof.vks().first().unwrap().clone(),
            proof: proof.proofs().first().unwrap().clone(),
            flag_complete: true,
        };

        // generate gnark data
        let (constraints, witness) =
            OnchainVerifierCircuit::<BabyBearBn254, BabyBearBn254Poseidon2>::build(&onchain_stdin);
        let gnark_witness = build_gnark_config_with_str(constraints, witness, PathBuf::from("./"));

        let gnark_proof_data = send_gnark_prove_task(gnark_witness);
        info!("gnark prove success with proof data {}", gnark_proof_data);

        1_u32
    });

    let recursion_duration =
        convert_duration + combine_duration + compress_duration + embed_duration;
    let total_duration = riscv_duration + recursion_duration + evm_duration;

    info!("╔═══════════════════════╗");
    info!("║ PERFORMANCE SUMMARY   ║");
    info!("╚═══════════════════════╝");
    info!("Time Metrics (wall time)");
    info!("----------------------------------------");
    info!("RISCV:     {}", format_duration(riscv_duration));
    info!("Recursion Steps:");
    info!("  CONVERT: {}", format_duration(convert_duration));
    info!("  COMBINE: {}", format_duration(combine_duration));
    info!("  COMPRESS:{}", format_duration(compress_duration));
    info!("  EMBED:   {}", format_duration(embed_duration));
    info!("  ----------------------------------------");
    info!("  TOTAL:   {}", format_duration(recursion_duration));
    info!("----------------------------------------");
    info!("EVM:       {}", format_duration(evm_duration));
    info!("----------------------------------------");
    info!("TOTAL:     {}", format_duration(total_duration));

    Ok(PerformanceReport {
        program: bench.name.to_string(),
        cycles,
        riscv_duration,
        convert_duration,
        combine_duration,
        compress_duration,
        embed_duration,
        recursion_duration,
        evm_duration,
        total_duration,
        success: true,
    })
}

fn bench_kb_vk(bench: &Benchmark) -> Result<PerformanceReport> {
    let (elf, stdin) = load(bench)?;
    let riscv_opts = EmulatorOpts::bench_riscv_ops();
    let recursion_opts = EmulatorOpts::bench_recursion_opts();
    let riscv_shape_config = RiscvShapeConfig::<KoalaBear>::default();
    let recursion_shape_config =
        RecursionShapeConfig::<KoalaBear, RecursionChipType<KoalaBear>>::default();

    info!(
        "RISCV Chunk Size: {}, RISCV Chunk Batch Size: {}",
        riscv_opts.chunk_size, riscv_opts.chunk_batch_size
    );
    info!(
        "Recursion Chunk Size: {}, Recursion Chunk Batch Size: {}",
        recursion_opts.chunk_size, recursion_opts.chunk_batch_size
    );

    let riscv = RiscvProver::new_initial_prover(
        (RiscvKBSC::new(), &elf),
        riscv_opts,
        Some(riscv_shape_config),
    );
    let convert =
        ConvertProver::new_with_prev(&riscv, recursion_opts, Some(recursion_shape_config));
    let recursion_shape_config =
        RecursionShapeConfig::<KoalaBear, RecursionChipType<KoalaBear>>::default();
    let combine =
        CombineVkProver::new_with_prev(&convert, recursion_opts, Some(recursion_shape_config));
    let compress = CompressVkProver::new_with_prev(&combine, (), None);
    let embed = EmbedVkProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);

    let riscv_vk = riscv.vk();

    info!("╔═══════════════════════╗");
    info!("║      RISCV PHASE      ║");
    info!("╚═══════════════════════╝");
    info!("Generating RISCV proof");
    let ((proof, cycles), riscv_duration) = time_operation(|| riscv.prove_cycles(stdin));
    info!("Verifying RISCV proof..");
    assert!(riscv.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║     CONVERT PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating CONVERT proof");
    let (proof, convert_duration) = time_operation(|| convert.prove(proof));
    info!("Verifying CONVERT proof..");
    assert!(convert.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║     COMBINE PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating COMBINE proof");
    let (proof, combine_duration) = time_operation(|| combine.prove(proof));
    info!("Verifying COMBINE proof..");
    assert!(combine.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║    COMPRESS PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating COMPRESS proof");
    let (proof, compress_duration) = time_operation(|| compress.prove(proof));
    info!("Verifying COMPRESS proof..");
    assert!(compress.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║      EMBED PHASE      ║");
    info!("╚═══════════════════════╝");
    info!("Generating EMBED proof");
    let (proof, embed_duration) = time_operation(|| embed.prove(proof));
    info!("Verifying EMBED proof..");
    assert!(embed.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║     ONCHAIN PHASE     ║");
    info!("╚═══════════════════════╝");
    let (_, evm_duration) = time_operation(|| {
        let onchain_stdin = OnchainStdin {
            machine: embed.machine().clone(),
            vk: proof.vks().first().unwrap().clone(),
            proof: proof.proofs().first().unwrap().clone(),
            flag_complete: true,
        };

        // generate gnark data
        let (constraints, witness) = OnchainVerifierCircuit::<
            KoalaBearBn254,
            KoalaBearBn254Poseidon2,
        >::build(&onchain_stdin);
        let gnark_witness = build_gnark_config_with_str(constraints, witness, PathBuf::from("./"));
        let gnark_proof_data = send_gnark_prove_task(gnark_witness);
        info!("gnark prove success with proof data {}", gnark_proof_data);

        1_u32
    });

    let recursion_duration =
        convert_duration + combine_duration + compress_duration + embed_duration;
    let total_duration = riscv_duration + recursion_duration + evm_duration;

    info!("╔═══════════════════════╗");
    info!("║ PERFORMANCE SUMMARY   ║");
    info!("╚═══════════════════════╝");
    info!("Time Metrics (wall time)");
    info!("----------------------------------------");
    info!("RISCV:     {}", format_duration(riscv_duration));
    info!("Recursion Steps:");
    info!("  CONVERT: {}", format_duration(convert_duration));
    info!("  COMBINE: {}", format_duration(combine_duration));
    info!("  COMPRESS:{}", format_duration(compress_duration));
    info!("  EMBED:   {}", format_duration(embed_duration));
    info!("  ----------------------------------------");
    info!("  TOTAL:   {}", format_duration(recursion_duration));
    info!("----------------------------------------");
    info!("EVM:       {}", format_duration(evm_duration));
    info!("----------------------------------------");
    info!("TOTAL:     {}", format_duration(total_duration));

    Ok(PerformanceReport {
        program: bench.name.to_string(),
        cycles,
        riscv_duration,
        convert_duration,
        combine_duration,
        compress_duration,
        embed_duration,
        recursion_duration,
        evm_duration,
        total_duration,
        success: true,
    })
}

fn bench_kb(bench: &Benchmark) -> Result<PerformanceReport> {
    let (elf, stdin) = load(bench)?;
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

    let riscv = RiscvProver::new_initial_prover((RiscvKBSC::new(), &elf), riscv_opts, None);
    let convert = ConvertProver::new_with_prev(&riscv, recursion_opts, None);
    let combine = CombineProver::new_with_prev(&convert, recursion_opts, None);
    let compress = CompressProver::new_with_prev(&combine, (), None);
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);

    let riscv_vk = riscv.vk();

    info!("╔═══════════════════════╗");
    info!("║      RISCV PHASE      ║");
    info!("╚═══════════════════════╝");
    info!("Generating RISCV proof");
    let ((proof, cycles), riscv_duration) = time_operation(|| riscv.prove_cycles(stdin));
    info!("Verifying RISCV proof..");
    assert!(riscv.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║     CONVERT PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating CONVERT proof");
    let (proof, convert_duration) = time_operation(|| convert.prove(proof));
    info!("Verifying CONVERT proof..");
    assert!(convert.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║     COMBINE PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating COMBINE proof");
    let (proof, combine_duration) = time_operation(|| combine.prove(proof));
    info!("Verifying COMBINE proof..");
    assert!(combine.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║    COMPRESS PHASE     ║");
    info!("╚═══════════════════════╝");
    info!("Generating COMPRESS proof");
    let (proof, compress_duration) = time_operation(|| compress.prove(proof));
    info!("Verifying COMPRESS proof..");
    assert!(compress.verify(&proof, riscv_vk));

    info!("╔═══════════════════════╗");
    info!("║      EMBED PHASE      ║");
    info!("╚═══════════════════════╝");
    info!("Generating EMBED proof");
    let (proof, embed_duration) = time_operation(|| embed.prove(proof));
    info!("Verifying EMBED proof..");
    assert!(embed.verify(&proof, riscv_vk));

    let recursion_duration =
        convert_duration + combine_duration + compress_duration + embed_duration;
    let total_duration = riscv_duration + recursion_duration;

    info!("╔═══════════════════════╗");
    info!("║ PERFORMANCE SUMMARY   ║");
    info!("╚═══════════════════════╝");
    info!("Time Metrics (wall time)");
    info!("----------------------------------------");
    info!("RISCV:     {}", format_duration(riscv_duration));
    info!("Recursion Steps:");
    info!("  CONVERT: {}", format_duration(convert_duration));
    info!("  COMBINE: {}", format_duration(combine_duration));
    info!("  COMPRESS:{}", format_duration(compress_duration));
    info!("  EMBED:   {}", format_duration(embed_duration));
    info!("  ----------------------------------------");
    info!("  TOTAL:   {}", format_duration(recursion_duration));
    info!("----------------------------------------");
    info!("TOTAL:     {}", format_duration(total_duration));

    Ok(PerformanceReport {
        program: bench.name.to_string(),
        cycles,
        riscv_duration,
        convert_duration,
        combine_duration,
        compress_duration,
        embed_duration,
        recursion_duration,
        evm_duration: Duration::default(),
        total_duration,
        success: true,
    })
}

fn bench_tracegen<SC>(bench: &Benchmark) -> Result<PerformanceReport>
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
    let (elf, stdin) = load(bench)?;
    let riscv_opts = EmulatorOpts::bench_riscv_ops();

    info!(
        "RISCV Chunk Size: {}, RISCV Chunk Batch Size: {}",
        riscv_opts.chunk_size, riscv_opts.chunk_batch_size
    );

    let riscv = RiscvProver::new_initial_prover((SC::new(), &elf), riscv_opts, None);

    info!("╔═══════════════════════╗");
    info!("║      RISCV PHASE      ║");
    info!("╚═══════════════════════╝");
    info!("Running RISCV");
    let (cycles, riscv_duration) = time_operation(|| riscv.run_tracegen(stdin));

    info!("╔═══════════════════════╗");
    info!("║ PERFORMANCE SUMMARY   ║");
    info!("╚═══════════════════════╝");
    info!("Time Metrics (wall time)");
    info!("----------------------------------------");
    info!("RISCV:     {}", format_duration(riscv_duration));

    Ok(PerformanceReport {
        program: bench.name.to_string(),
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

fn format_results(_args: &Args, results: &[PerformanceReport]) -> Vec<String> {
    let mut table_text = String::new();
    table_text.push_str("```\n");
    table_text.push_str(
        "| program     | cycles      | riscv_d     | recursion_d | total_d    | success |\n",
    );
    table_text.push_str(
        "|-------------|-------------|-------------|-------------|------------|---------|",
    );

    for result in results.iter() {
        table_text.push_str(&format!(
            "\n| {:<11} | {:>11} | {:>11} | {:>11} | {:>10} | {:<7} |",
            result.program,
            result.cycles,
            format_duration(result.riscv_duration),
            format_duration(result.recursion_duration),
            format_duration(result.total_duration),
            if result.success { "✅" } else { "❌" }
        ));
    }
    table_text.push_str("\n```");

    vec![
        "*Pico Performance Benchmark Results*\n".to_string(),
        String::new(),
        table_text,
    ]
}

fn main() -> Result<()> {
    setup_logger();

    let args = Args::parse();
    let programs = if args.programs.is_empty() {
        PROGRAMS.to_vec()
    } else {
        PROGRAMS
            .iter()
            .copied()
            .filter(|p| args.programs.iter().any(|name| name == p.name))
            .collect()
    };

    if args.noprove {
        let mut results = Vec::with_capacity(programs.len());
        let run_bench = match args.field.as_str() {
            "bb" | "bb_vk" => |bench| bench_tracegen::<RiscvBBSC>(bench),
            "kb" | "kb_vk" => |bench| bench_tracegen::<RiscvKBSC>(bench),
            _ => panic!("bad field, use bb or kb"),
        };

        for bench in programs.iter() {
            results.push(run_bench(bench)?);
        }

        let output = format_results(&args, &results);
        println!("{}", output.join("\n"));
    } else {
        if args.field.as_str() == "kb_vk" {
            prepare_kb_gnark()
        } else if args.field.as_str() == "bb_vk" {
            prepare_bb_gnark()
        }

        let run_bench: fn(&Benchmark) -> _ = match args.field.as_str() {
            "bb" => bench_bb,
            "kb" => bench_kb,
            "kb_vk" => bench_kb_vk,
            "bb_vk" => bench_bb_vk,
            _ => panic!("bad field, use bb or kb"),
        };

        let mut results = Vec::with_capacity(programs.len());
        for bench in programs {
            results.push(run_bench(&bench)?);
        }

        let output = format_results(&args, &results);
        println!("{}", output.join("\n"));

        // stop and rm the docker server
        if args.field.as_str() == "kb_vk" || args.field.as_str() == "bb_vk" {
            clean_gnark_env()
        }
    }

    Ok(())
}

pub fn execute_command(mut command: Command) {
    println!("Start to execute command...");
    log_command(&command);
    // Add necessary tags for stdout and stderr from the command.
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn command")
        .expect("cargo build failed");
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let stderr = BufReader::new(child.stderr.take().unwrap());

    // Add prefix to the output of the process depending on the context.
    let msg = "[pico]";

    // Pipe stdout and stderr to the parent process with [docker] prefix
    let stdout_handle = thread::spawn(move || {
        stdout.lines().for_each(|line| {
            println!("{} {}", msg, line.unwrap());
        });
    });
    stderr.lines().for_each(|line| {
        eprintln!("{} {}", msg, line.unwrap());
    });
    stdout_handle.join().unwrap();

    let _ = child.wait().expect("failed to wait for child process");
}

fn log_command(command: &Command) {
    let command_string = format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("Command: {:?}", command_string);
}

fn send_gnark_prove_task(json_req: String) -> String {
    let client = Client::new();
    tracing::info!("start send witness to gnark prover");
    let response = client
        .post("http://127.0.0.1:9099/prove")
        .body(json_req.to_string())
        .header("Content-Type", "application/json")
        .send()
        .unwrap();

    if !response.status().is_success() {
        panic!(
            "fail to prove task: {:?} {:?}",
            response.status(),
            response.text()
        );
    }
    tracing::info!("gnark prover successful");
    response.text().unwrap()
}

fn check_gnark_prover_ready() {
    let client = Client::new();
    let start = Instant::now();
    loop {
        let response = client
            .post("http://127.0.0.1:9099/ready")
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(2))
            .send();

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    tracing::info!("gnark prover is ready");
                    break;
                }
            }
            Err(_e) => {}
        }
        if start.elapsed() > Duration::from_secs(120) {
            panic!("wait for docker prover timeout")
        }
        tracing::info!("docker prover not ready for conn, waiting...");
        sleep(Duration::from_secs(2));
    }
}
