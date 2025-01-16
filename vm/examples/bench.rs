use anyhow::Result;
use bincode;
use clap::{
    builder::{NonEmptyStringValueParser, TypedValueParser},
    Parser,
};
use log::info;
use pico_vm::{
    configs::config::StarkGenericConfig,
    emulator::{opts::EmulatorOpts, riscv::stdin::EmulatorStdin},
    instances::configs::{
        riscv_config::StarkConfig as RiscvBBSC, riscv_kb_config::StarkConfig as RiscvKBSC,
    },
    machine::logger::setup_logger,
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
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
    exec_khz: f64,
    exec_duration: Duration,
    core_khz: f64,
    core_duration: Duration,
    compressed_khz: f64,
    compressed_duration: Duration,
    time: Duration,
    success: bool,
}

fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}
fn to_khz(cycles: u64, duration: Duration) -> f64 {
    let duration_secs = duration.as_secs_f64();
    if duration_secs > 0.0 {
        (cycles as f64 / duration_secs) / 1_000.0
    } else {
        0.0
    }
}

fn bench_bb(bench: &Benchmark) -> Result<PerformanceReport> {
    let (elf, stdin) = load(bench)?;
    let core_opts = EmulatorOpts::bench_riscv_ops();
    let recursion_opts = EmulatorOpts::bench_recursion_opts();

    let riscv = RiscvProver::new_initial_prover((RiscvBBSC::new(), &elf), core_opts);
    let convert = ConvertProver::new_with_prev(&riscv, recursion_opts);
    let combine = CombineProver::new_with_prev(&convert, recursion_opts);
    let compress = CompressProver::new_with_prev(&combine, ());
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, ());

    info!("Generating RiscV proof");
    let ((proof, cycles), core_duration) = time_operation(|| riscv.prove_cycles(stdin));
    assert!(riscv.verify(&proof));

    info!("Generating convert proof");
    let (proof, convert_duration) = time_operation(|| convert.prove(proof));
    assert!(convert.verify(&proof));

    info!("Generating combine proof");
    let (proof, combine_duration) = time_operation(|| combine.prove(proof));
    assert!(combine.verify(&proof));

    info!("Generating compress proof");
    let (proof, compress_duration) = time_operation(|| compress.prove(proof));
    assert!(compress.verify(&proof));

    info!("Generating embed proof");
    let (proof, embed_duration) = time_operation(|| embed.prove(proof));
    assert!(embed.verify(&proof));

    let total_recursion_duration =
        convert_duration + combine_duration + compress_duration + embed_duration;
    let total_duration = core_duration + total_recursion_duration;

    info!("core duration: {}", format_duration(core_duration));
    info!("convert duration: {}", format_duration(convert_duration));
    info!("combine duration: {}", format_duration(combine_duration));
    info!("compress duration: {}", format_duration(compress_duration));
    info!("embed duration: {}", format_duration(embed_duration));
    info!(
        "total recursion duration: {}",
        format_duration(total_recursion_duration)
    );
    info!("total duration: {}", format_duration(total_duration));

    Ok(PerformanceReport {
        program: bench.name.to_string(),
        cycles,
        exec_khz: to_khz(cycles, Duration::ZERO),
        exec_duration: Duration::ZERO,
        core_khz: to_khz(cycles, core_duration),
        core_duration,
        compressed_khz: to_khz(cycles, total_recursion_duration + core_duration),
        compressed_duration: total_recursion_duration,
        time: total_duration,
        success: true,
    })
}

fn bench_kb(bench: &Benchmark) -> Result<PerformanceReport> {
    let (elf, stdin) = load(bench)?;
    let core_opts = EmulatorOpts::bench_riscv_ops();
    let recursion_opts = EmulatorOpts::bench_recursion_opts();

    let riscv = RiscvProver::new_initial_prover((RiscvKBSC::new(), &elf), core_opts);
    let convert = ConvertProver::new_with_prev(&riscv, recursion_opts);
    let combine = CombineProver::new_with_prev(&convert, recursion_opts);
    let compress = CompressProver::new_with_prev(&combine, ());
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, ());

    info!("Generating RiscV proof");
    let ((proof, cycles), core_duration) = time_operation(|| riscv.prove_cycles(stdin));
    assert!(riscv.verify(&proof));

    info!("Generating convert proof");
    let (proof, convert_duration) = time_operation(|| convert.prove(proof));
    assert!(convert.verify(&proof));

    info!("Generating combine proof");
    let (proof, combine_duration) = time_operation(|| combine.prove(proof));
    assert!(combine.verify(&proof));

    info!("Generating compress proof");
    let (proof, compress_duration) = time_operation(|| compress.prove(proof));
    assert!(compress.verify(&proof));

    info!("Generating embed proof");
    let (proof, embed_duration) = time_operation(|| embed.prove(proof));
    assert!(embed.verify(&proof));

    let total_recursion_duration =
        convert_duration + combine_duration + compress_duration + embed_duration;
    let total_duration = core_duration + total_recursion_duration;

    info!("core duration: {}", format_duration(core_duration));
    info!("convert duration: {}", format_duration(convert_duration));
    info!("combine duration: {}", format_duration(combine_duration));
    info!("compress duration: {}", format_duration(compress_duration));
    info!("embed duration: {}", format_duration(embed_duration));
    info!(
        "total recursion duration: {}",
        format_duration(total_recursion_duration)
    );
    info!("total duration: {}", format_duration(total_duration));

    Ok(PerformanceReport {
        program: bench.name.to_string(),
        cycles,
        exec_khz: to_khz(cycles, Duration::ZERO),
        exec_duration: Duration::ZERO,
        core_khz: to_khz(cycles, core_duration),
        core_duration,
        compressed_khz: to_khz(cycles, total_recursion_duration + core_duration),
        compressed_duration: total_recursion_duration,
        time: total_duration,
        success: true,
    })
}

fn format_results(_args: &Args, results: &[PerformanceReport]) -> Vec<String> {
    let mut table_text = String::new();
    table_text.push_str("```\n");
    table_text.push_str("| program     | cycles      | execute (mHz)  | execute_d      | core (kHZ)     | core_d     | compress (KHz) | compressed_d | time   | success  |\n");
    table_text.push_str("|-------------|-------------|----------------|--------------- |----------------|------------|----------------|--------------|--------|----------|");

    for result in results.iter() {
        table_text.push_str(&format!(
            "\n| {:<11} | {:>11} | {:>14.2} | {:>14} | {:>14.2} | {:>10} | {:>14.2} | {:>12} | {:>6} | {:<7} |",
            result.program,
            result.cycles,
            result.exec_khz / 1000.0,
            format_duration(result.exec_duration),
            result.core_khz,
            format_duration(result.core_duration),
            result.compressed_khz,
            format_duration(result.compressed_duration),
            format_duration(result.time),
            if result.success { "✅" } else { "❌" }
        ));
    }
    table_text.push_str("\n```");

    vec![
        "*Pico Performance Test Results*\n".to_string(),
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
