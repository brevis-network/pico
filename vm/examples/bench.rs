use anyhow::Result;
use clap::{
    builder::{NonEmptyStringValueParser, TypedValueParser},
    Parser,
};
use log::info;
use p3_baby_bear::BabyBear;
use p3_koala_bear::KoalaBear;
use pico_vm::{
    configs::config::StarkGenericConfig,
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::shapes::{compress_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
        configs::{
            riscv_config::StarkConfig as RiscvBBSC, riscv_kb_config::StarkConfig as RiscvKBSC,
        },
    },
    machine::logger::setup_logger,
    proverchain::{
        CombineProver, CombineVkProver, CompressProver, CompressVkProver, ConvertProver,
        EmbedProver, EmbedVkProver, InitialProverSetup, MachineProver, ProverChain, RiscvProver,
    },
};
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about=None)]
struct Args {
    #[clap(long, use_value_delimiter = true, value_delimiter = ',', value_parser = NonEmptyStringValueParser::new().map(|x| x.to_lowercase()))]
    programs: Vec<String>,

    #[clap(long, use_value_delimiter = true, default_value = "bb")]
    field: String,
}

#[derive(Clone, Copy)]
struct Benchmark {
    pub name: &'static str,
    pub elf: &'static str,
    pub input: Option<&'static str>,
}

const PROGRAMS: &[Benchmark] = &[
    Benchmark {
        name: "fibonacci",
        elf: "./vm/src/compiler/test_data/bench/fib",
        input: None,
    },
    Benchmark {
        name: "f",
        elf: "./vm/src/compiler/test_data/bench/fibo-small",
        input: None,
    },
    Benchmark {
        name: "tendermint",
        elf: "./vm/src/compiler/test_data/bench/tendermint",
        input: Some("./vm/src/compiler/test_data/bench/tendermint.in"),
    },
    Benchmark {
        name: "reth",
        elf: "./vm/src/compiler/test_data/bench/reth",
        input: Some("./vm/src/compiler/test_data/bench/reth.in"),
    },
    Benchmark {
        name: "reth-17106222",
        elf: "./vm/src/compiler/test_data/bench/reth",
        input: Some("./vm/src/compiler/test_data/bench/reth-17106222.in"),
    },
    Benchmark {
        name: "reth-19409768",
        elf: "./vm/src/compiler/test_data/bench/reth",
        input: Some("./vm/src/compiler/test_data/bench/reth-19409768.in"),
    },
];

#[allow(clippy::type_complexity)]
fn load<P>(bench: &Benchmark) -> Result<(Vec<u8>, EmulatorStdin<P, Vec<u8>>)> {
    let elf = std::fs::read(bench.elf)?;
    let stdin = match bench.input {
        None => Vec::new(),
        Some(path) => bincode::deserialize(&std::fs::read(path)?)?,
    };
    let stdin = EmulatorStdin::new_riscv(&stdin);

    Ok((elf, stdin))
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
        total_duration,
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

    Ok(())
}
