//! The emitting arm: the AOT snapshot thread with its sink on, its records compared with the
//! interpreter's through `check_guest`.
//!
//! The pipeline cannot take its records from the AOT core yet: its replay workers are interpreters.
//! So the arm runs the AOT pipeline as the plain AOT arm does, takes the records the AOT core cut
//! on the snapshot thread, and puts each in the place of the CPU chunk record the workers made for
//! the same chunk. It keeps the workers' record only for what the pipeline writes after a chunk is
//! cut, the public values, `is_last` and the shape, so every other field compared is the AOT core's.
//! Of the public values, the AOT core writes the chunk's boundary at the cut and the digest words
//! its `COMMIT`s store, which have to be the workers' before theirs replace them.
//! The precompile events the pipeline moves out of a chunk into deferred records it takes from the
//! workers too, and compares the AOT core's against them.
//!
//! Per chunk, because one chunk that fell back to interpreting hides inside a run's totals, the
//! audit reads what ran each chunk against what the code was expected to run.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, PoisonError,
    },
};

use pico_aot_runtime::{emulator::EmittedChunk, AotEmulatorCore};
use pico_vm::{
    compiler::riscv::program::Program,
    emulator::{
        opts::{EmulatorOpts, SnapshotMainMode},
        record::RecordBehavior,
        riscv::{record::EmulationRecord, syscalls::SyscallCode},
        stdin::EmulatorStdin,
    },
    mle::machine::riscv::{emulate_with_pipeline, EmulateError, EmulationOutput},
};
use sha2::{Digest, Sha256};

/// Whether the AOT run in progress writes records.
static EMIT: AtomicBool = AtomicBool::new(false);
/// The chunks the AOT run in progress has cut.
// TODO: every chunk's full record, held beside the pipeline's own until the splice, so the
// at-scale pass peaks at two copies of the run's CPU records where `check_at_scale` holds one
// arm's. Reduce each chunk as it is cut once that pass outgrows the host.
static EMITTED: Mutex<Vec<EmittedChunk>> = Mutex::new(Vec::new());
/// What the last emitting run found, for its audit.
static LAST: Mutex<Option<Spliced>> = Mutex::new(None);

/// What ran a chunk of the emitting arm.
struct ChunkRun {
    cycles: u64,
    dispatches: u64,
    fallback_insns: u64,
}

impl ChunkRun {
    /// The chunk's instructions compiled code ran. A dispatch alone does not show it: a block
    /// that does not fit what is left of the chunk, or that is entered inside an unconstrained
    /// block, hands its first instruction straight to the fallback.
    fn compiled_insns(&self) -> u64 {
        self.cycles - self.fallback_insns
    }
}

struct Spliced {
    chunks: Vec<ChunkRun>,
    problems: Vec<String>,
}

/// Which code the emitting arm runs, and so what its chunks have to show.
#[derive(Clone, Copy)]
pub enum Expect {
    /// Generated code on the harness's short chunks: compiled code ran some instruction of the run.
    /// No per-chunk bound: a block that does not fit a short chunk runs in the fallback by design.
    Compiled,
    /// Generated code at production chunk size: on every chunk but the last, which can be short,
    /// compiled code ran some instruction, the fallback at most 1 % of the cycles, and cycles per
    /// dispatch at most 2 times the median over those chunks. The fallback is not required to run:
    /// a cut can land on a block boundary, and the stub's code proves the fallback's records.
    CompiledAtScale,
    /// The bootstrap stub's code, which interprets every instruction.
    AllFallback,
}

/// Runs one batch of `run` on `emu`, writing records while the emitting arm asks for them: the
/// sink goes on before the run's first instruction, and the chunk the guest halts in is closed once
/// it has.
pub fn run_emitting(
    emu: &mut AotEmulatorCore,
    run: impl FnOnce(&mut AotEmulatorCore) -> Result<(), String>,
) -> Result<(), String> {
    let emit = EMIT.load(Ordering::Relaxed);
    if emit && !emu.is_emitting() {
        emu.emit_records();
    }
    let result = run(emu);
    if emit {
        if emu.is_program_done() {
            emu.finish_emitted_chunk();
        }
        EMITTED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(emu.take_emitted_chunks());
    }
    result
}

/// The emitting arm's `emulate`: the AOT pipeline, its CPU chunk records the AOT core's own.
pub fn emulate(
    program: Arc<Program>,
    stdin: &EmulatorStdin<Program, Vec<u8>>,
    opts: EmulatorOpts,
    workers: NonZeroUsize,
) -> Result<EmulationOutput, EmulateError> {
    EMITTED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    EMIT.store(true, Ordering::Relaxed);
    let output = emulate_with_pipeline(
        program,
        stdin,
        opts.with_snapshot_main(SnapshotMainMode::Aot),
        workers,
    );
    EMIT.store(false, Ordering::Relaxed);
    let chunks = std::mem::take(&mut *EMITTED.lock().unwrap_or_else(PoisonError::into_inner));
    let mut output = output?;
    let spliced = splice(&mut output, chunks);
    *LAST.lock().unwrap_or_else(PoisonError::into_inner) = Some(spliced);
    Ok(output)
}

/// Puts the AOT core's records in place of the workers' CPU chunk records, in chunk order, and
/// compares the precompile events it moved out of them with the workers' deferred records.
fn splice(output: &mut EmulationOutput, chunks: Vec<EmittedChunk>) -> Spliced {
    let mut problems = Vec::new();
    let mut records: Vec<_> = output
        .records
        .iter_mut()
        .filter(|record| record.is_cpu_chunk)
        .collect();
    if records.len() != chunks.len() {
        problems.push(format!(
            "the AOT core cut {} chunk(s), and the pipeline made {} CPU chunk record(s)",
            chunks.len(),
            records.len()
        ));
    }
    let mut runs = Vec::with_capacity(chunks.len());
    let mut aot_deferred: Option<EmulationRecord> = None;
    for (index, (piped, chunk)) in records.iter_mut().zip(chunks).enumerate() {
        runs.push(ChunkRun {
            cycles: chunk.cycles,
            dispatches: chunk.compiled_block_dispatches,
            fallback_insns: chunk.fallback_insns,
        });
        let mut record = chunk.record;
        // What the pipeline moves out of a CPU chunk into the deferred records, which this arm
        // takes from the workers: the precompile events are compared below, and no memory
        // initialize or finalize event may be lost unread.
        let mut deferred = record.defer();
        let unread =
            deferred.memory_initialize_events.len() + deferred.memory_finalize_events.len();
        if unread > 0 {
            problems.push(format!(
                "chunk {}: the AOT record carries {unread} memory initialize or finalize \
                 event(s), which this arm does not compare",
                index + 1
            ));
        }
        let written = |record: &EmulationRecord| {
            let public_values = &record.public_values;
            (
                public_values.start_pc,
                public_values.next_pc,
                public_values.exit_code,
                public_values.committed_value_digest,
                public_values.deferred_proofs_digest,
            )
        };
        if written(&record) != written(piped) {
            problems.push(format!(
                "chunk {}: (start_pc, next_pc, exit_code, committed, deferred proofs) {:?} in the \
                 AOT core's record, {:?} in the pipeline's",
                index + 1,
                written(&record),
                written(piped)
            ));
        }
        match &mut aot_deferred {
            Some(all) => all.append(&mut deferred),
            None => aot_deferred = Some(deferred),
        }
        record.public_values = piped.public_values;
        record.is_last = piped.is_last;
        record.shape = std::mem::take(&mut piped.shape);
        **piped = record;
    }
    drop(records);

    // The pipeline splits the deferred precompile events into blocks, and within a block joins
    // the local-memory windows that chain from one event to the next; the AOT core's go through
    // the same split. Splitting once at the end cuts the blocks the pipeline cut as it went: each
    // is a run of one code's events in order, of the same size.
    let aot_blocks = aot_deferred
        .map(|mut all| all.split(true, u32::MAX))
        .unwrap_or_default();
    let aot = precompile_streams(&aot_blocks);
    let piped = precompile_streams(output.records.iter().filter(|r| !r.is_cpu_chunk));
    for code in aot.keys().chain(piped.keys()).collect::<BTreeSet<_>>() {
        let (left, right) = (piped.get(code), aot.get(code));
        if left != right {
            let count = |stream: Option<&(usize, [u8; 32])>| stream.map_or(0, |(n, _)| *n);
            problems.push(format!(
                "precompile events filed under {code}: {} in the pipeline's deferred records, {} \
                 from the AOT core{}",
                count(left),
                count(right),
                if count(left) == count(right) {
                    ", which differ"
                } else {
                    ""
                }
            ));
        }
    }
    Spliced {
        chunks: runs,
        problems,
    }
}

/// Per syscall code, how many precompile events `records` hold and a digest of them in order.
fn precompile_streams<'a>(
    records: impl IntoIterator<Item = &'a EmulationRecord>,
) -> BTreeMap<SyscallCode, (usize, [u8; 32])> {
    let mut streams: BTreeMap<SyscallCode, (usize, Sha256)> = BTreeMap::new();
    for record in records {
        for (code, events) in record.precompile_events.sorted_groups() {
            let (count, hasher) = streams.entry(*code).or_default();
            *count += events.len();
            for event in events {
                bincode::serialize_into(&mut *hasher, event).expect("serialize a precompile event");
            }
        }
    }
    streams
        .into_iter()
        .map(|(code, (count, hasher))| (code, (count, hasher.finalize().into())))
        .collect()
}

/// Adds to `problems` what the last emitting run found, prints what ran each of its chunks, and
/// returns a suffix for the run's line.
pub fn audit(expect: Expect, problems: &mut Vec<String>) -> String {
    let Some(Spliced {
        chunks,
        problems: found,
    }) = LAST.lock().unwrap_or_else(PoisonError::into_inner).take()
    else {
        problems.push("the emitting arm produced no output".to_string());
        return String::new();
    };
    problems.extend(found);
    if chunks.is_empty() {
        problems.push("the AOT core cut no chunk".to_string());
    }

    let per_dispatch = |run: &ChunkRun| run.cycles as f64 / run.dispatches as f64;
    let barred = match expect {
        Expect::CompiledAtScale => &chunks[..chunks.len().saturating_sub(1)],
        _ => &[][..],
    };
    let mut cycles_per_dispatch: Vec<f64> = barred
        .iter()
        .filter(|run| run.dispatches > 0)
        .map(per_dispatch)
        .collect();
    cycles_per_dispatch.sort_by(f64::total_cmp);
    let median = cycles_per_dispatch
        .get(cycles_per_dispatch.len() / 2)
        .copied();

    for (index, run) in chunks.iter().enumerate() {
        let chunk = index + 1;
        let share = 100.0 * run.fallback_insns as f64 / run.cycles.max(1) as f64;
        println!(
            "    chunk {chunk}: {} cycle(s), {} compiled-block dispatch(es), {} fallback \
             instruction(s) ({share:.1} %), {:.1} cycles per dispatch",
            run.cycles,
            run.dispatches,
            run.fallback_insns,
            per_dispatch(run),
        );
        if let Expect::AllFallback = expect {
            if run.dispatches != 0 || run.fallback_insns != run.cycles {
                problems.push(format!(
                    "chunk {chunk}: {} dispatch(es) and {} of {} cycle(s) interpreted, where the \
                     stub's code interprets them all",
                    run.dispatches, run.fallback_insns, run.cycles
                ));
            }
        }
    }
    if let Expect::Compiled = expect {
        if chunks.iter().all(|run| run.compiled_insns() == 0) {
            problems.push("compiled code ran no instruction of the run".to_string());
        }
    }
    for (index, run) in barred.iter().enumerate() {
        let chunk = index + 1;
        if run.compiled_insns() == 0 {
            problems.push(format!("chunk {chunk}: compiled code ran none of it"));
        }
        if run.fallback_insns * 100 > run.cycles {
            problems.push(format!(
                "chunk {chunk}: the fallback ran {:.1} % of its cycles, over 1 %",
                100.0 * run.fallback_insns as f64 / run.cycles.max(1) as f64
            ));
        }
        // One-sided: many cycles per dispatch is what a chunk the fallback ran mostly looks like,
        // while few only means short blocks, which compiled code ran all the same.
        if let (true, Some(median)) = (run.dispatches > 0, median) {
            if per_dispatch(run) > 2.0 * median {
                problems.push(format!(
                    "chunk {chunk}: {:.1} cycles per dispatch, over 2× the median {median:.1}",
                    per_dispatch(run)
                ));
            }
        }
    }
    let fallback: u64 = chunks.iter().map(|run| run.fallback_insns).sum();
    format!(
        "; {} chunk(s) cut by the AOT core, {fallback} instruction(s) interpreted by its fallback",
        chunks.len()
    )
}
