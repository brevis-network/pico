use log::info;
use serde::Serialize;
use std::time::Duration;

pub fn log_section(title: &str) {
    info!("╔═══════════════════════╗");
    info!("║{:^23}║", title);
    info!("╚═══════════════════════╝");
}

pub fn log_performance_summary(
    riscv_duration: Duration,
    convert_duration: Duration,
    combine_duration: Duration,
    compress_duration: Duration,
    embed_duration: Duration,
    evm_duration: Option<Duration>,
) -> (Duration, Duration) {
    let recursion_duration =
        convert_duration + combine_duration + compress_duration + embed_duration;
    let total_duration = riscv_duration + recursion_duration + evm_duration.unwrap_or_default();

    log_section("PERFORMANCE SUMMARY");
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

    if let Some(evm_dur) = evm_duration {
        info!("EVM:       {}", format_duration(evm_dur));
        info!("----------------------------------------");
    }

    info!("TOTAL:     {}", format_duration(total_duration));

    (recursion_duration, total_duration)
}
pub fn format_duration(duration: Duration) -> String {
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
    pub program: String,
    pub cycles: u64,
    pub riscv_duration: Duration,
    pub convert_duration: Duration,
    pub combine_duration: Duration,
    pub compress_duration: Duration,
    pub embed_duration: Duration,
    pub recursion_duration: Duration,
    pub evm_duration: Duration,
    pub total_duration: Duration,
    pub success: bool,
}

pub fn format_results(results: &[PerformanceReport]) -> Vec<String> {
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
