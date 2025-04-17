use pico_perf::common::bench_field::BenchField;
use pico_vm::configs::config::StarkGenericConfig;

#[derive(Debug)]
pub struct WorkerConfig<SC: StarkGenericConfig> {
    pub field: BenchField,
    pub stark_cfg: SC,
}
