//! A chunk replayed in several segments and folded, against the same chunk replayed whole, on the
//! record-parity guests: the execution history table by table and by its digest, every compared
//! field of `record_digest::field_digests`, and every chip's main trace cell by cell.
//!
//! Only the AOT snapshot thread cuts a chunk into segments, and no AOT program is registered here,
//! so the tests cut them as the pipeline's workers would replay them: the interpreter's snapshot
//! thread hands out each chunk's state, a worker replays the chunk's first stretch as a segment
//! that does not end it, and each later stretch starts where the one before stopped, the worker
//! recovered in place as it is between batches. `merge_segments` folds the segments' records as
//! the pipeline's segment collector does. Each arm keeps one worker across a run's chunks.
//!
//! One field differs by construction and is taken from the whole replay before the chips are
//! traced: `cpu_local_memory_access`. A split leaves an address touched on both sides of a cut two
//! chained windows where the whole replay leaves one, so the local-memory chip's rows, and the
//! global interactions and byte lookups its `extra_record` adds, differ. The compared
//! `cpu_local_memory_chain` is what says the chains span the same accesses.

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
};

use p3_matrix::dense::RowMajorMatrix;
use pico_vm::{
    compiler::riscv::program::Program,
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            history::{ChipSteps, ExecutionHistory},
            public_values::RecordFinalPvsState,
            record::EmulationRecord,
            record_digest::{field_digests, is_compared},
            record_merge::merge_segments,
            record_slots::hold_records_unbounded,
            riscv_emulator::{EmulationDeferredState, RiscvEmulator},
            state::RiscvEmulationState,
        },
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::MetaChip,
    mle::machine::riscv::{air_name, build_ctx, Kb},
};

// Only the guests and their runs: the comparison in there is between two emulation paths.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
use record_parity::{opts, program, stdin, GUESTS};

type Chips = [MetaChip<Kb, RiscvChipType<Kb>>];

/// Segments per chunk. Three, so a fold that moved each segment's indices by the first one's rows
/// instead of by everything before it still fails.
const SEGMENTS: u64 = 3;

/// A chunk's problems past this many are counted, not listed: one broken index repeats on every
/// row after it.
const LISTED_PER_CHUNK: usize = 8;

/// The interpreter's snapshot thread: each chunk's start state and the global clock it ends at.
struct Snapshots {
    emulator: RiscvEmulator,
    done: bool,
}

impl Snapshots {
    fn new(program: &Arc<Program>, opts: EmulatorOpts, input: &[Vec<u8>]) -> Self {
        hold_records_unbounded();
        let mut emulator = RiscvEmulator::new_single::<Kb>(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
            opts,
        );
        emulator.write_stdin(&stdin(input));
        Self {
            emulator,
            done: false,
        }
    }
}

impl Iterator for Snapshots {
    type Item = (RiscvEmulationState, u64);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let (state, report) = self
            .emulator
            .emulate_state(true, &mut |_| {})
            .expect("the snapshot thread");
        self.done = report.done;
        Some((state, report.current_cycle))
    }
}

/// A replay worker kept across a run's chunks.
struct Worker {
    emulator: Option<RiscvEmulator>,
}

impl Worker {
    fn new() -> Self {
        Self { emulator: None }
    }

    /// The chunk `state` starts, replayed up to each global clock in `stops` in turn: one segment
    /// per stop, all but the last a segment that does not end the chunk. Each segment's record, if
    /// it produced one.
    fn replay(
        &mut self,
        program: &Arc<Program>,
        opts: EmulatorOpts,
        state: RiscvEmulationState,
        stops: &[u64],
    ) -> Vec<EmulationRecord> {
        let mut state = Some(state);
        let mut records = Vec::new();
        for (index, &stop) in stops.iter().enumerate() {
            let final_segment = index + 1 == stops.len();
            let from = state
                .take()
                .expect("each segment starts where the last one stopped");
            let emulator = self.recover(program, opts, from, stop, final_segment);
            let mut produced = Vec::new();
            emulator
                .emulate_batch(&mut |record: EmulationRecord| produced.push(record))
                .unwrap_or_else(|err| panic!("segment {index} of {}: {err}", stops.len()));
            assert!(
                produced.len() <= 1,
                "segment {index} produced {} records",
                produced.len()
            );
            records.extend(produced);
            if !final_segment {
                state = Some(std::mem::take(&mut emulator.state));
            }
        }
        records
    }

    /// The worker, recovered from `state` to replay to `stop`: fresh for its first segment, as the
    /// pipeline recovers a worker's first batch, and in place for every later one.
    fn recover(
        &mut self,
        program: &Arc<Program>,
        opts: EmulatorOpts,
        state: RiscvEmulationState,
        stop: u64,
        final_segment: bool,
    ) -> &mut RiscvEmulator {
        let deferred = || {
            EmulationDeferredState::shared(
                program.clone(),
                Arc::new(RecordFinalPvsState::default()),
            )
        };
        match &mut self.emulator {
            Some(emulator) => {
                drop(emulator.recover_in_place(state, deferred(), stop, final_segment));
                emulator
            }
            slot @ None => slot.insert(RiscvEmulator::recover::<Kb>(
                program.clone(),
                state,
                opts,
                deferred(),
                stop,
                final_segment,
            )),
        }
    }
}

/// The global clocks a chunk's replay from `start` to `end` stops at: [`SEGMENTS`] stretches of
/// about equal length, or one per cycle in a chunk shorter than that.
fn stops(start: u64, end: u64) -> Vec<u64> {
    let segments = SEGMENTS.min(end - start).max(1);
    (1..=segments)
        .map(|index| start + (end - start) * index / segments)
        .collect()
}

/// Each chip list, by name.
fn lists(chip_steps: &ChipSteps) -> [(&'static str, &[u32]); 11] {
    let ChipSteps {
        add,
        sub,
        mul,
        bitwise,
        shift_left,
        shift_right,
        lt,
        divrem,
        memory,
        ecall,
        branch,
    } = chip_steps;
    [
        ("add", add),
        ("sub", sub),
        ("mul", mul),
        ("bitwise", bitwise),
        ("shift_left", shift_left),
        ("shift_right", shift_right),
        ("lt", lt),
        ("divrem", divrem),
        ("memory", memory),
        ("ecall", ecall),
        ("branch", branch),
    ]
}

/// The first row of the table `what` where the whole replay's and the fold's differ.
fn first_row<T: PartialEq + std::fmt::Debug>(
    what: &str,
    whole: &[T],
    folded: &[T],
    found: &mut Vec<String>,
) {
    if let Some(at) = whole
        .iter()
        .zip(folded)
        .position(|(left, right)| left != right)
    {
        found.push(format!(
            "{what} {at}: {:?} whole, {:?} folded",
            whole[at], folded[at]
        ));
    } else if whole.len() != folded.len() {
        found.push(format!(
            "{what}: {} row(s) whole, {} folded",
            whole.len(),
            folded.len()
        ));
    }
}

/// The differences between the whole replay's history and the fold's, table by table.
fn history_differences(
    whole: &ExecutionHistory,
    folded: &ExecutionHistory,
    found: &mut Vec<String>,
) {
    let before = found.len();
    if whole.chunk != folded.chunk {
        found.push(format!(
            "history chunk {} whole, {} folded",
            whole.chunk, folded.chunk
        ));
    }
    first_row("step", &whole.steps, &folded.steps, found);
    first_row("read", &whole.reads, &folded.reads, found);
    first_row("write", &whole.writes, &folded.writes, found);
    first_row(
        "operand exception",
        &whole.operand_exceptions,
        &folded.operand_exceptions,
        found,
    );
    for ((name, whole), (_, folded)) in lists(&whole.chip_steps)
        .into_iter()
        .zip(lists(&folded.chip_steps))
    {
        first_row(&format!("{name} list entry"), whole, folded, found);
    }
    let syscalls = |history: &ExecutionHistory| -> Vec<(u32, u64, u32, u64, u64)> {
        history
            .syscalls
            .iter()
            .map(|event| {
                (
                    event.chunk,
                    event.clk,
                    event.syscall_id,
                    event.arg1,
                    event.arg2,
                )
            })
            .collect()
    };
    first_row("syscall", &syscalls(whole), &syscalls(folded), found);
    if found.len() == before && whole.digest() != folded.digest() {
        found.push(format!(
            "history digest {:016x} whole, {:016x} folded, with every table equal",
            whole.digest(),
            folded.digest()
        ));
    }
}

/// The compared fields of `field_digests` where the two records differ.
fn field_differences(whole: &EmulationRecord, folded: &EmulationRecord, found: &mut Vec<String>) {
    let compared = |record: &EmulationRecord| {
        field_digests(record)
            .into_iter()
            .filter(|(field, _, _)| is_compared(field))
            .collect::<Vec<_>>()
    };
    for ((field, len, digest), (_, folded_len, folded_digest)) in
        compared(whole).into_iter().zip(compared(folded))
    {
        if (len, digest) == (folded_len, folded_digest) {
            continue;
        }
        if field == "public_values" {
            found.push(format!(
                "public values {:?} whole, {:?} folded",
                whole.public_values, folded.public_values
            ));
        } else {
            found.push(format!(
                "{field}: {len} element(s) {digest:016x} whole, {folded_len} {folded_digest:016x} \
                 folded"
            ));
        }
    }
}

/// Each active chip's air id and main trace, as the prover builds them in dev mode. A history
/// whose indices are wrong can send an accessor past its tables, so a panic is caught and
/// reported against the chunk rather than ending the run unnamed.
fn traces(
    chips: &Chips,
    record: &EmulationRecord,
) -> Result<Vec<(usize, RowMajorMatrix<Kb>)>, String> {
    catch_unwind(AssertUnwindSafe(|| {
        build_ctx(chips, record, false)
            .per_trace
            .into_iter()
            .map(|(id, air)| (id, air.common_main))
            .collect()
    }))
    .map_err(|panic| {
        panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| {
                panic
                    .downcast_ref::<&str>()
                    .map(|message| message.to_string())
            })
            .unwrap_or_default()
    })
}

/// The chips whose main traces differ between the two records.
fn trace_differences(
    chips: &Chips,
    whole: &EmulationRecord,
    folded: &EmulationRecord,
    found: &mut Vec<String>,
) {
    let chip = |id: usize| air_name(id).unwrap_or("an unnamed air");
    let (whole, folded) = match (traces(chips, whole), traces(chips, folded)) {
        (Ok(whole), Ok(folded)) => (whole, folded),
        (whole, folded) => {
            for (which, traced) in [("whole", whole), ("folded", folded)] {
                if let Err(panic) = traced {
                    found.push(format!("tracing the {which} record panicked: {panic}"));
                }
            }
            return;
        }
    };
    let active = |traced: &[(usize, RowMajorMatrix<Kb>)]| -> Vec<&str> {
        traced.iter().map(|&(id, _)| chip(id)).collect()
    };
    if active(&whole) != active(&folded) {
        found.push(format!(
            "active chips {:?} whole, {:?} folded",
            active(&whole),
            active(&folded)
        ));
    }
    for (id, whole) in &whole {
        let Some((_, folded)) = folded.iter().find(|(other, _)| other == id) else {
            continue;
        };
        let height = |trace: &RowMajorMatrix<Kb>| trace.values.len() / trace.width.max(1);
        if (whole.width, whole.values.len()) != (folded.width, folded.values.len()) {
            found.push(format!(
                "{} trace: {} x {} whole, {} x {} folded",
                chip(*id),
                height(whole),
                whole.width,
                height(folded),
                folded.width
            ));
        } else if let Some(at) = whole
            .values
            .iter()
            .zip(&folded.values)
            .position(|(left, right)| left != right)
        {
            found.push(format!(
                "{} trace: row {} column {} is {} whole, {} folded",
                chip(*id),
                at / whole.width,
                at % whole.width,
                whole.values[at],
                folded.values[at]
            ));
        }
    }
}

/// Every run of the guest called `name` in [`GUESTS`], each chunk replayed whole and in
/// [`SEGMENTS`] segments.
fn check(name: &str) {
    let guest = GUESTS
        .iter()
        .find(|guest| guest.name == name)
        .unwrap_or_else(|| panic!("no guest {name}"));
    let chips = RiscvChipType::<Kb>::all_chips();
    let mut problems = Vec::new();
    let mut split_chunks = 0;
    for run in guest.runs() {
        let label = format!("{name} @ {}", run.chunk_size);
        let program = program(guest.elf);
        let opts = opts(run.chunk_size);
        let snapshots = || Snapshots::new(&program, opts, &run.stdin);
        let (mut whole, mut split) = (Worker::new(), Worker::new());
        let (mut chunks, mut segmented, mut steps) = (0, 0, 0);
        let mut example = None;
        for (chunk, ((whole_state, end), (split_state, split_end))) in
            snapshots().zip(snapshots()).enumerate()
        {
            assert_eq!(split_end, end, "[{label}] the snapshot threads diverged");
            let label = format!("{label} chunk {chunk}");
            let stops = stops(whole_state.global_clk, end);
            let first_clock = whole_state.global_clk;
            let whole_records = whole.replay(&program, opts, whole_state, &[end]);
            let split_records = split.replay(&program, opts, split_state, &stops);
            let Some(whole_record) = whole_records.into_iter().next() else {
                if !split_records.is_empty() {
                    problems.push(format!("[{label}] a record from the segments, none whole"));
                }
                continue;
            };
            if split_records.is_empty() {
                problems.push(format!("[{label}] a record whole, none from the segments"));
                continue;
            }
            chunks += 1;
            if split_records.len() > 1 {
                segmented += 1;
                let segments = split_records.len();
                example.get_or_insert_with(|| {
                    format!(
                        "chunk {chunk} replayed in {segments} segments, from global clock \
                         {first_clock} to {stops:?}"
                    )
                });
            }
            let mut found = Vec::new();
            let mut folded = merge_segments(split_records);
            match (&whole_record.history, &folded.history) {
                (Some(whole_history), Some(folded_history)) => {
                    steps += folded_history.steps.len();
                    history_differences(whole_history, folded_history, &mut found);
                }
                (whole_history, folded_history) => found.push(format!(
                    "a history {} whole, {} folded",
                    if whole_history.is_some() {
                        "kept"
                    } else {
                        "missing"
                    },
                    if folded_history.is_some() {
                        "kept"
                    } else {
                        "missing"
                    }
                )),
            }
            field_differences(&whole_record, &folded, &mut found);
            folded.cpu_local_memory_access = whole_record.cpu_local_memory_access.clone();
            trace_differences(&chips, &whole_record, &folded, &mut found);
            let unlisted = found.len().saturating_sub(LISTED_PER_CHUNK);
            problems.extend(
                found
                    .into_iter()
                    .take(LISTED_PER_CHUNK)
                    .map(|problem| format!("[{label}] {problem}")),
            );
            if unlisted > 0 {
                problems.push(format!("[{label}] and {unlisted} more problem(s)"));
            }
        }
        split_chunks += segmented;
        println!(
            "{label}: {chunks} chunk(s), {segmented} folded from more than one segment, {steps} \
             step(s); {}",
            example.as_deref().unwrap_or("no chunk split")
        );
    }
    // Without a chunk folded from several segments the equalities say nothing about the fold.
    if split_chunks == 0 {
        problems.push("no chunk was replayed in more than one segment".to_string());
    }

    for problem in &problems {
        println!("FAIL: {problem}");
    }
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn history_fold_fib() {
    check("fib");
}

#[test]
fn history_fold_ed25519() {
    check("ed25519");
}

#[test]
fn history_fold_poseidon2() {
    check("poseidon2");
}

#[test]
fn history_fold_aggregator() {
    check("aggregator");
}

#[test]
fn history_fold_bls12381_fp() {
    check("bls12381-fp");
}

#[test]
fn history_fold_replays_a_middle_segment() {
    let guest = &GUESTS[0];
    let program = program(guest.elf);
    let run = &guest.runs()[0];
    let opts = opts(run.chunk_size);
    let (state, end) = Snapshots::new(&program, opts, &run.stdin)
        .next()
        .expect("a first chunk");
    let stops = stops(state.global_clk, end);
    assert!(stops.len() > 1, "fib's first chunk is {end} cycles");
    let records = Worker::new().replay(&program, opts, state, &stops);
    assert_eq!(records.len(), stops.len(), "a record per segment");
    let folded = merge_segments(records);
    assert!(folded.history.is_some());
}

/// What the fold cannot fold, and so refuses: segments of which only some carry a history, in
/// either order, and histories of two chunks.
#[test]
fn history_fold_refuses_what_it_cannot_fold() {
    let with_history = |chunk| {
        let history = ExecutionHistory {
            chunk,
            steps: vec![Default::default()].into(),
            reads: vec![Default::default()].into(),
            ..ExecutionHistory::default()
        };
        EmulationRecord {
            history: Some(history),
            ..EmulationRecord::default()
        }
    };
    let refusals = [
        (
            "a history after none",
            vec![EmulationRecord::default(), with_history(1)],
        ),
        (
            "none after a history",
            vec![with_history(1), EmulationRecord::default()],
        ),
        (
            "histories of two chunks",
            vec![with_history(1), with_history(2)],
        ),
    ];
    for (what, segments) in refusals {
        let refused = catch_unwind(AssertUnwindSafe(|| merge_segments(segments)));
        assert!(refused.is_err(), "{what} folded");
    }
    let mut folded = merge_segments(vec![with_history(1), with_history(1)]);
    assert_eq!(
        folded.history.take().map(|history| history.steps.len()),
        Some(2)
    );
}
