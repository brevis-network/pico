use pico_perf::common::{
    bench_field::BenchField,
    bench_program::{BenchProgram, PROGRAMS},
};
use std::str::FromStr;

pub fn parse_field(s: &str) -> Result<BenchField, String> {
    BenchField::from_str(s).map_err(|e| e.to_string())
}

pub fn parse_program(s: &str) -> Result<BenchProgram, String> {
    PROGRAMS
        .iter()
        .copied()
        .find(|p| p.name == s)
        .ok_or_else(|| format!("unknown program: {}", s))
}

pub fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// `FRI_RISCV_ONLY` (cached): riscv-only benchmark mode — prove each chunk and report it
/// terminally, skipping convert/recursion. Cached so the per-chunk prover path doesn't
/// re-read the environment, and truthy-checked (via `env_flag`) so `FRI_RISCV_ONLY=0` disables.
pub fn fri_riscv_only() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| env_flag("FRI_RISCV_ONLY"))
}
pub fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok().and_then(|s| s.parse().ok())
}
