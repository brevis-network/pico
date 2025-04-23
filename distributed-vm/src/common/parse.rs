use pico_perf::common::{
    bench_field::BenchField,
    bench_program::{BenchProgram, PROGRAMS},
};
use std::str::FromStr;

pub(crate) fn parse_field(s: &str) -> Result<BenchField, String> {
    BenchField::from_str(s).map_err(|e| e.to_string())
}

pub(crate) fn parse_program(s: &str) -> Result<BenchProgram, String> {
    PROGRAMS
        .iter()
        .copied()
        .find(|p| p.name == s)
        .ok_or_else(|| format!("unknown program: {}", s))
}
