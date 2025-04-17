use pico_perf::common::{bench_field::BenchField, bench_program::BenchProgram};

#[derive(Debug)]
pub struct CoordinatorConfig {
    pub program: BenchProgram,
    pub field: BenchField,
}
