use std::{
    fmt::Debug,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use pico_vm::{
    emulator::riscv::{
        record::EmulationRecord, riscv_emulator::EmulationError, state::RiscvEmulationState,
    },
    machine::report::EmulationReport,
};

use crate::recycle_snapshot_memory;

#[derive(Debug, Clone)]
pub struct PipelineBenchSummary {
    pub label: &'static str,
    pub wall_duration: Duration,
    pub total_cycles: u64,
    pub report_count: usize,
    pub emitted_record_count: usize,
    pub final_done: bool,
    pub pv_stream: Vec<u8>,
}

impl PipelineBenchSummary {
    pub fn throughput_mcycles_per_sec(&self) -> f64 {
        self.total_cycles as f64 / self.wall_duration.as_secs_f64() / 1_000_000.0
    }
}

#[derive(Debug, Clone)]
pub struct AotOnlyBenchSummary {
    pub label: &'static str,
    pub wall_duration: Duration,
    pub total_cycles: u64,
    pub batch_count: u32,
}

impl AotOnlyBenchSummary {
    pub fn throughput_mcycles_per_sec(&self) -> f64 {
        self.total_cycles as f64 / self.wall_duration.as_secs_f64() / 1_000_000.0
    }
}

pub fn run_pipeline_once<F>(label: &'static str, run_pipeline: F) -> PipelineBenchSummary
where
    F: FnOnce(
        Box<dyn Fn(EmulationRecord, bool) + Send + Sync>,
    ) -> Result<(Vec<EmulationReport>, u64, Vec<u8>), EmulationError>,
{
    let emitted_record_count = Arc::new(AtomicUsize::new(0));
    let callback_done = Arc::new(AtomicBool::new(false));

    let started_at = Instant::now();
    let (reports, total_cycles, pv_stream) = run_pipeline(Box::new({
        let emitted_record_count = Arc::clone(&emitted_record_count);
        let callback_done = Arc::clone(&callback_done);
        move |_record, done| {
            emitted_record_count.fetch_add(1, Ordering::Relaxed);
            callback_done.store(done, Ordering::Relaxed);
        }
    }))
    .expect("snapshot pipeline failed");
    let wall_duration = started_at.elapsed();

    PipelineBenchSummary {
        label,
        wall_duration,
        total_cycles,
        report_count: reports.len(),
        emitted_record_count: emitted_record_count.load(Ordering::Relaxed),
        final_done: callback_done.load(Ordering::Relaxed),
        pv_stream,
    }
}

pub fn run_pipeline_benchmark<F>(
    label: &'static str,
    warmup_runs: usize,
    bench_runs: usize,
    mut run_pipeline: F,
) -> Vec<PipelineBenchSummary>
where
    F: FnMut(
        Box<dyn Fn(EmulationRecord, bool) + Send + Sync>,
    ) -> Result<(Vec<EmulationReport>, u64, Vec<u8>), EmulationError>,
{
    for _ in 0..warmup_runs {
        let _ = run_pipeline_once(label, &mut run_pipeline);
    }

    let mut summaries = Vec::with_capacity(bench_runs);
    for _ in 0..bench_runs {
        summaries.push(run_pipeline_once(label, &mut run_pipeline));
    }
    summaries
}

pub fn run_aot_only_once<Emu, BuildEmu, RunBatch, E>(
    label: &'static str,
    build_emu: BuildEmu,
    mut run_batch: RunBatch,
) -> AotOnlyBenchSummary
where
    BuildEmu: FnOnce() -> Emu,
    RunBatch: FnMut(&mut Emu) -> Result<(RiscvEmulationState, EmulationReport), E>,
    E: Debug,
    Emu: AotBenchCycles,
{
    let mut emu = build_emu();
    let started_at = Instant::now();
    let mut batch_count = 0;

    loop {
        let (snapshot, report) = run_batch(&mut emu).expect("AOT next_state_batch failed");
        recycle_snapshot_memory(snapshot);
        batch_count += 1;
        if report.done {
            break;
        }
    }

    AotOnlyBenchSummary {
        label,
        wall_duration: started_at.elapsed(),
        total_cycles: run_batch_total_cycles(&emu),
        batch_count,
    }
}

pub fn run_aot_only_benchmark<Emu, BuildEmu, RunBatch, E>(
    label: &'static str,
    mut build_emu: BuildEmu,
    run_batch: RunBatch,
    warmup_runs: usize,
    bench_runs: usize,
) -> Vec<AotOnlyBenchSummary>
where
    BuildEmu: FnMut() -> Emu,
    RunBatch: FnMut(&mut Emu) -> Result<(RiscvEmulationState, EmulationReport), E> + Copy,
    E: Debug,
    Emu: AotBenchCycles,
{
    for _ in 0..warmup_runs {
        let _ = run_aot_only_once(label, &mut build_emu, run_batch);
    }

    let mut summaries = Vec::with_capacity(bench_runs);
    for _ in 0..bench_runs {
        summaries.push(run_aot_only_once(label, &mut build_emu, run_batch));
    }
    summaries
}

pub trait AotBenchCycles {
    fn total_cycles(&self) -> u64;
}

impl<T: AotBenchCycles + ?Sized> AotBenchCycles for &mut T {
    fn total_cycles(&self) -> u64 {
        (**self).total_cycles()
    }
}

fn run_batch_total_cycles<Emu: AotBenchCycles>(emu: &Emu) -> u64 {
    emu.total_cycles()
}

#[cfg(feature = "aot")]
impl AotBenchCycles for pico_aot_dispatch::AotEmulatorCore {
    fn total_cycles(&self) -> u64 {
        self.insn_count
    }
}
