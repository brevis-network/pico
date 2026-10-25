//! Benchmark the full snapshot pipeline with the AOT snapshot-main enabled.

#[cfg(not(feature = "aot"))]
compile_error!(
    "This binary requires the 'aot' feature. Build with: cargo run --features aot --bin pipeline_bench"
);

use reth_aot::{
    aot_snapshot_opts, build_witness, load_block_input, load_reth_elf, parse_block_arg,
    register_snapshot_aot_factory, run_aot_only_benchmark, run_pipeline_benchmark, validate_block,
    AotOnlyBenchSummary, PipelineBenchSummary,
};

const DEFAULT_WARMUP_RUNS: usize = 1;
const DEFAULT_BENCH_RUNS: usize = 5;
const PIPELINE_LABEL: &str = "AOT snapshot pipeline";
const AOT_ONLY_LABEL: &str = "AOT snapshot-main only";
const TARGET: &str = "reth";

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn print_run_summary(run_idx: usize, summary: &PipelineBenchSummary) {
    println!(
        "  Run {}: {:?}, cycles={}, reports={}, emitted_records={}, final_done={}, pv_stream_len={}, throughput={:.2} Mcyc/s",
        run_idx,
        summary.wall_duration,
        summary.total_cycles,
        summary.report_count,
        summary.emitted_record_count,
        summary.final_done,
        summary.pv_stream.len(),
        summary.throughput_mcycles_per_sec(),
    );
    println!(
        "PIPELINE_BENCH target={} mode=aot run={} secs={:.6} cycles={} reports={} emitted_records={} final_done={} throughput_mcyc={:.2} pv_len={}",
        TARGET,
        run_idx,
        summary.wall_duration.as_secs_f64(),
        summary.total_cycles,
        summary.report_count,
        summary.emitted_record_count,
        summary.final_done,
        summary.throughput_mcycles_per_sec(),
        summary.pv_stream.len(),
    );
}

fn print_aot_only_run_summary(run_idx: usize, summary: &AotOnlyBenchSummary) {
    println!(
        "  Run {}: {:?}, cycles={}, batches={}, throughput={:.2} Mcyc/s",
        run_idx,
        summary.wall_duration,
        summary.total_cycles,
        summary.batch_count,
        summary.throughput_mcycles_per_sec(),
    );
    println!(
        "AOT_ONLY_BENCH target={} mode=aot-only run={} secs={:.6} cycles={} batches={} throughput_mcyc={:.2}",
        TARGET,
        run_idx,
        summary.wall_duration.as_secs_f64(),
        summary.total_cycles,
        summary.batch_count,
        summary.throughput_mcycles_per_sec(),
    );
}

fn assert_consistent(results: &[PipelineBenchSummary]) {
    let first = results.first().expect("at least one benchmark result");
    for (idx, summary) in results.iter().enumerate().skip(1) {
        assert_eq!(
            summary.total_cycles,
            first.total_cycles,
            "run {} total_cycles mismatch",
            idx + 1
        );
        assert_eq!(
            summary.report_count,
            first.report_count,
            "run {} report_count mismatch",
            idx + 1
        );
        assert_eq!(
            summary.emitted_record_count,
            first.emitted_record_count,
            "run {} emitted_record_count mismatch",
            idx + 1
        );
        assert_eq!(
            summary.final_done,
            first.final_done,
            "run {} final_done mismatch",
            idx + 1
        );
        assert_eq!(
            summary.pv_stream,
            first.pv_stream,
            "run {} pv_stream mismatch",
            idx + 1
        );
    }
}

fn assert_aot_only_consistent(results: &[AotOnlyBenchSummary]) {
    let first = results
        .first()
        .expect("at least one AOT-only benchmark result");
    for (idx, summary) in results.iter().enumerate().skip(1) {
        assert_eq!(
            summary.total_cycles,
            first.total_cycles,
            "AOT-only run {} total_cycles mismatch",
            idx + 1
        );
        assert_eq!(
            summary.batch_count,
            first.batch_count,
            "AOT-only run {} batch_count mismatch",
            idx + 1
        );
    }
}

fn main() {
    let block_number = parse_block_arg();
    let warmup_runs = env_usize("PIPELINE_BENCH_WARMUP_RUNS", DEFAULT_WARMUP_RUNS);
    let bench_runs = env_usize("PIPELINE_BENCH_RUNS", DEFAULT_BENCH_RUNS);
    assert!(
        bench_runs > 0,
        "PIPELINE_BENCH_RUNS must be greater than zero"
    );

    println!("Reth Snapshot Pipeline Benchmark");
    println!("===============================\n");
    println!("Mode: AOT snapshot-main");
    println!("Block number: {}", block_number);
    println!("Warmup runs: {}", warmup_runs);
    println!("Benchmark runs: {}", bench_runs);

    if let Err(err) = validate_block(block_number) {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }

    let elf_bytes = load_reth_elf().expect("Failed to load reth ELF");
    let block_input = load_block_input(block_number).expect("Failed to load block input");
    let opts = aot_snapshot_opts();
    println!(
        "Opts: chunk_size={}, chunk_batch_size={}, split_threshold={}, num_threads={}",
        opts.chunk_size,
        opts.chunk_batch_size,
        opts.split_opts.deferred,
        std::env::var("NUM_THREADS").unwrap_or_else(|_| "1".to_string()),
    );
    println!("Block input size: {} bytes", block_input.len());

    let witness = build_witness(&elf_bytes, opts, &block_input);
    let program = witness
        .program
        .as_ref()
        .expect("witness.program not set")
        .clone();
    let input_stream = witness
        .stdin
        .as_ref()
        .expect("witness.stdin not set")
        .inputs
        .to_vec();
    register_snapshot_aot_factory();

    println!("\nAOT-only timed runs:");
    let aot_only_results = run_aot_only_benchmark(
        AOT_ONLY_LABEL,
        program,
        &input_stream,
        opts,
        warmup_runs,
        bench_runs,
    );
    for (idx, summary) in aot_only_results.iter().enumerate() {
        print_aot_only_run_summary(idx + 1, summary);
    }

    println!("\nFull pipeline timed runs:");
    let results = run_pipeline_benchmark(PIPELINE_LABEL, &witness, warmup_runs, bench_runs);

    for (idx, summary) in results.iter().enumerate() {
        print_run_summary(idx + 1, summary);
    }

    assert_aot_only_consistent(&aot_only_results);
    assert_consistent(&results);
    let aot_only_avg_secs = aot_only_results
        .iter()
        .map(|summary| summary.wall_duration.as_secs_f64())
        .sum::<f64>()
        / aot_only_results.len() as f64;
    let avg_secs = results
        .iter()
        .map(|summary| summary.wall_duration.as_secs_f64())
        .sum::<f64>()
        / results.len() as f64;
    let aot_only_first = &aot_only_results[0];
    let first = &results[0];

    assert_eq!(
        aot_only_first.total_cycles, first.total_cycles,
        "AOT-only and pipeline total_cycles mismatch"
    );

    let aot_only_avg_throughput =
        aot_only_first.total_cycles as f64 / aot_only_avg_secs / 1_000_000.0;
    let pipeline_avg_throughput = first.total_cycles as f64 / avg_secs / 1_000_000.0;
    let runtime_ratio = avg_secs / aot_only_avg_secs;
    let throughput_ratio = pipeline_avg_throughput / aot_only_avg_throughput;

    println!("\nSummary:");
    println!("  AOT-only label: {}", aot_only_first.label);
    println!("  AOT-only avg wall time: {:.3}s", aot_only_avg_secs);
    println!("  AOT-only batches: {}", aot_only_first.batch_count);
    println!(
        "  AOT-only avg throughput: {:.2} Mcyc/s",
        aot_only_avg_throughput
    );
    println!("  Pipeline label: {}", first.label);
    println!("  Avg wall time: {:.3}s", avg_secs);
    println!("  Total cycles: {}", first.total_cycles);
    println!("  Report count: {}", first.report_count);
    println!("  Emitted records: {}", first.emitted_record_count);
    println!("  Final done: {}", first.final_done);
    println!("  PV stream len: {}", first.pv_stream.len());
    println!(
        "  Pipeline avg throughput: {:.2} Mcyc/s",
        pipeline_avg_throughput
    );

    println!("\nAnalysis:");
    println!("  Pipeline/AOT-only runtime ratio: {:.2}x", runtime_ratio);
    println!(
        "  Pipeline/AOT-only throughput ratio: {:.2}",
        throughput_ratio
    );
    println!(
        "AOT_ANALYSIS target={} aot_only_secs={:.6} pipeline_secs={:.6} aot_only_throughput_mcyc={:.2} pipeline_throughput_mcyc={:.2} runtime_ratio={:.2} throughput_ratio={:.2}",
        TARGET,
        aot_only_avg_secs,
        avg_secs,
        aot_only_avg_throughput,
        pipeline_avg_throughput,
        runtime_ratio,
        throughput_ratio,
    );
}
