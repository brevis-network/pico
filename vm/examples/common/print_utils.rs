#![allow(dead_code)] // The utility functions here are used in macros, so they are detected as unused
use cpu_time::ProcessTime;
use std::time::{Duration, Instant};
use tracing::info;

pub fn log_section(title: &str) {
    info!("╔═══════════════════════╗");
    info!("║{:^23}║", title);
    info!("╚═══════════════════════╝");
}

#[derive(Copy, Clone)]
pub struct TimeStats {
    pub wall_time: Duration,
    pub cpu_time: Duration,
    pub parallelism: f64,
}

impl TimeStats {
    /// Returns a new zeroed TimeStats.
    pub fn zero() -> Self {
        Self {
            wall_time: Duration::from_secs(0),
            cpu_time: Duration::from_secs(0),
            parallelism: 0.0,
        }
    }
}

pub fn timed_run<T, F: FnOnce() -> T>(operation: F) -> (T, TimeStats) {
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

    log_section("PERFORMANCE SUMMARY");
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

    log_section("PROOF SIZES");
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

pub struct PhaseStats {
    pub riscv: (TimeStats, usize),
    pub convert: (TimeStats, usize),
    pub combine: (TimeStats, usize),
    pub compress: (TimeStats, usize),
    pub embed: (TimeStats, usize),
}

impl PhaseStats {
    pub fn new() -> Self {
        Self {
            riscv: (TimeStats::zero(), 0),
            convert: (TimeStats::zero(), 0),
            combine: (TimeStats::zero(), 0),
            compress: (TimeStats::zero(), 0),
            embed: (TimeStats::zero(), 0),
        }
    }

    pub fn print_up_to(&self, step: &str) {
        // Define the phases in order
        let phases = [
            ("riscv", self.riscv),
            ("convert", self.convert),
            ("combine", self.combine),
            ("compress", self.compress),
            ("embed", self.embed),
        ];

        // Build time and size arrays
        let mut times = Vec::with_capacity(phases.len());
        let mut sizes = Vec::with_capacity(phases.len());
        let mut reached_step = false;

        for (phase_name, (time, size)) in phases.iter() {
            if reached_step {
                times.push(TimeStats::zero());
                sizes.push(0);
            } else {
                times.push(*time);
                sizes.push(*size);
            }
            if *phase_name == step {
                reached_step = true;
            }
        }

        print_stats(
            times[0], times[1], times[2], times[3], times[4], sizes[0], sizes[1], sizes[2],
            sizes[3], sizes[4],
        );
    }

    pub fn print_all(&self) {
        print_stats(
            self.riscv.0,
            self.convert.0,
            self.combine.0,
            self.compress.0,
            self.embed.0,
            self.riscv.1,
            self.convert.1,
            self.combine.1,
            self.compress.1,
            self.embed.1,
        );
    }
}
