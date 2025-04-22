use pico_perf::common::{bench_field::BenchField, bench_program::BenchProgram};

#[derive(Debug)]
pub struct WorkerConfig {
    pub field: BenchField,
    pub program: BenchProgram,
}
