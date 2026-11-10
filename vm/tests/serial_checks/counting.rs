//! The counting sink against the execution history, chunk by chunk. The history's counts come
//! from its steps, access slots, chip lists, unaligned table and syscalls, read off the shared
//! stream; the counting sink's from a second emulation of the run, which needs a sink of its own.
//!
//! A precompile's `SyscallContext::postprocess` moves the emulator's window for each address it
//! touched out of the sink's map and into `record.cpu_local_memory_access`, so the sink counts its
//! windows off both.
//!
//! `COUNTING_SINK_RETH_BLOCK=18884864` adds a test of that block of the reth guest at `WHOLE`:
//! minutes of interpreter per emulation and gigabytes per chunk.

use std::{path::PathBuf, sync::Arc};

use pico_vm::{
    compiler::riscv::program::Program,
    emulator::riscv::{
        history::Slots,
        public_values::{PublicValues, RecordFinalPvsState},
        record::EmulationRecord,
        record_slots::hold_records_unbounded,
        riscv_emulator::RiscvEmulator,
        sink::{ChunkCounts, CountingSink, Sink},
    },
    mle::machine::riscv::Kb,
};

use crate::{
    record_parity::{opts, program, stdin, WHOLE},
    trace_source::history_emulation,
};

const RETH_BLOCK: &str = "COUNTING_SINK_RETH_BLOCK";

/// Counts no record-parity guest takes: none of them divides.
const NOT_TAKEN: &[&str] = &["divrem"];

/// What the history side holds of one CPU chunk.
pub type HistorySide = (ChunkCounts, PublicValues<u32, u32>);

/// The counts of a CPU chunk's history, and its public values. A step whose rows do not match its
/// slots is listed into `problems` and its accesses are not counted.
pub fn history_side(record: &EmulationRecord, problems: &mut Vec<String>) -> HistorySide {
    let Some(history) = record.history.as_ref() else {
        problems.push("a CPU chunk has no history to count".to_string());
        return (ChunkCounts::default(), record.public_values);
    };
    let mut accesses = [0; 4];
    for (index, step) in history.steps.iter().enumerate() {
        let instruction = record.program.fetch(u64::from(step.pc));
        let slots = Slots::of(&instruction);
        let (reads, writes) = history.rows_of(index);
        let expected = (slots.len() - slots.write_count(), slots.write_count());
        if (reads.len(), writes.len()) != expected {
            problems.push(format!(
                "step {index}'s read and write counts: {:?}, {expected:?} by its slots",
                (reads.len(), writes.len())
            ));
            continue;
        }
        for (slot, _) in history.accesses_of(index, &instruction) {
            accesses[3 - slot as usize] += 1;
        }
    }
    let chips = &history.chip_steps;
    let counts = ChunkCounts {
        steps: history.steps.len(),
        accesses,
        add: chips.add.len(),
        sub: chips.sub.len(),
        mul: chips.mul.len(),
        bitwise: chips.bitwise.len(),
        shift_left: chips.shift_left.len(),
        shift_right: chips.shift_right.len(),
        lt: chips.lt.len(),
        divrem: chips.divrem.len(),
        syscalls: history.syscalls.len(),
        // A load or store whose address is no multiple of its width is in the unaligned table,
        // not the memory list; the counting sink counts every one.
        memory_instructions: chips.memory.len() + history.unaligned.len(),
        ecalls: chips.ecall.len(),
        windows: record.cpu_local_memory_access.len(),
    };
    (counts, record.public_values)
}

/// Every count of `counts`, named. The destructuring has no `..`, so a new field does not compile
/// until it is named here.
fn named(counts: &ChunkCounts) -> [(&'static str, usize); 17] {
    let ChunkCounts {
        steps,
        accesses: [a, b, c, memory],
        add,
        sub,
        mul,
        bitwise,
        shift_left,
        shift_right,
        lt,
        divrem,
        syscalls,
        memory_instructions,
        ecalls,
        windows,
    } = *counts;
    [
        ("steps", steps),
        ("accesses.a", a),
        ("accesses.b", b),
        ("accesses.c", c),
        ("accesses.memory", memory),
        ("add", add),
        ("sub", sub),
        ("mul", mul),
        ("bitwise", bitwise),
        ("shift_left", shift_left),
        ("shift_right", shift_right),
        ("lt", lt),
        ("divrem", divrem),
        ("syscalls", syscalls),
        ("memory_instructions", memory_instructions),
        ("ecalls", ecalls),
        ("windows", windows),
    ]
}

/// One table line: `label`, then each cell right-aligned under its column's name.
fn line<'a>(label: &str, cells: impl IntoIterator<Item = (&'a str, String)>) -> String {
    let mut line = format!("{label:<22}");
    for (column, cell) in cells {
        line.push_str(&format!(" {cell:>width$}", width = column.len().max(9)));
    }
    line
}

fn columns(counts: &ChunkCounts, chunks: usize) -> impl Iterator<Item = (&'static str, usize)> {
    std::iter::once(("chunks", chunks)).chain(named(counts))
}

fn row(label: &str, chunks: usize, counts: &ChunkCounts) -> String {
    line(
        label,
        columns(counts, chunks).map(|(name, n)| (name, n.to_string())),
    )
}

fn header_row() -> String {
    let counts = ChunkCounts::default();
    line(
        "run",
        columns(&counts, 0).map(|(name, _)| (name, name.to_string())),
    )
}

/// What the counting sink took over some runs: every count, and the two paths equal counts would
/// not show ran, a precompile's window move and the rollback.
#[derive(Default)]
pub struct Taken {
    total: ChunkCounts,
    chunks: usize,
    moved_windows: usize,
    unconstrained_blocks: usize,
}

/// One run compared: its problems, and what the counting sink took.
pub struct Compared {
    pub problems: Vec<String>,
    taken: Taken,
}

/// Emulates `program` on `input` through the counting sink, and compares each CPU chunk's counts
/// and public values with `history`'s, the history side of the same run. A run that commits
/// nothing compares public values that say nothing, so `commits` refuses one.
pub fn compare_run(
    label: &str,
    program: Arc<Program>,
    input: &[Vec<u8>],
    chunk_size: u32,
    history: &[HistorySide],
    commits: bool,
) -> Compared {
    hold_records_unbounded();
    let mut problems = Vec::new();
    let mut taken = Taken::default();
    let mut emulator = RiscvEmulator::new_single::<Kb>(
        program.clone(),
        Arc::new(RecordFinalPvsState::default()),
        opts(chunk_size),
    )
    .with_sink(Sink::Counting(CountingSink::new(EmulationRecord::new(
        program,
    ))));
    emulator.write_stdin(&stdin(input));
    let mut emitted = Vec::new();
    loop {
        let report = emulator
            .emulate_batch(&mut |record: EmulationRecord| {
                if !record.is_cpu_chunk {
                    return;
                }
                taken.moved_windows += record.cpu_local_memory_access.len();
                if record.history.is_some() {
                    problems.push(format!("[{label}] the counting sink wrote a history"));
                }
                if !record.add_events.is_empty() {
                    problems.push(format!("[{label}] the counting sink wrote additions"));
                }
                emitted.push(record.public_values);
            })
            .expect("emulate_batch");
        if report.done {
            break;
        }
    }
    let Sink::Counting(sink) = &mut emulator.sink else {
        unreachable!("the emulator was built with the counting sink");
    };
    let mut cuts = sink.take_counts();
    taken.unconstrained_blocks += sink.unconstrained_blocks();

    if let Some((_, last)) = history.last() {
        if commits && last.committed_value_digest.iter().all(|&w| w == 0) {
            problems.push(format!(
                "[{label}] the history sink's last chunk commits nothing, so the digest \
                 comparison is vacuous"
            ));
        }
    }

    // `postprocess`'s cut comes last and holds no step.
    match cuts.pop() {
        Some(last) if last == ChunkCounts::default() => {}
        Some(last) => problems.push(format!(
            "[{label}] postprocess's cut, after the last step, counted {last:?}"
        )),
        None => problems.push(format!("[{label}] no chunk was cut")),
    }

    if cuts.len() != history.len() {
        problems.push(format!(
            "[{label}] {} chunk(s) counted, {} emitted by the history sink",
            cuts.len(),
            history.len()
        ));
    }
    for (i, (counted, (expected, _))) in cuts.iter().zip(history).enumerate() {
        if counted != expected {
            problems.push(format!(
                "[{label}] chunk {i}: counted {counted:?}, history {expected:?}"
            ));
        }
        if counted.steps == 0 {
            problems.push(format!("[{label}] chunk {i}: no step"));
        }
        taken.total += *counted;
    }

    if emitted.len() != history.len() {
        problems.push(format!(
            "[{label}] {} CPU record(s) emitted, the history sink {}",
            emitted.len(),
            history.len()
        ));
    }
    // `PublicValues` has no `PartialEq`; its `Debug` form prints every field.
    for (i, (counting, (_, history))) in emitted.iter().zip(history).enumerate() {
        if format!("{counting:?}") != format!("{history:?}") {
            problems.push(format!(
                "[{label}] chunk {i}: public values {counting:?}, history {history:?}"
            ));
        }
    }

    if taken.total.steps == 0 {
        problems.push(format!("[{label}] no step in the whole run"));
    }
    taken.chunks = cuts.len();
    println!("{}", row(label, taken.chunks, &taken.total));
    Compared { problems, taken }
}

/// One guest's runs: the history side off the shared stream, then the counting sink's emulation.
#[derive(Default)]
pub struct Check {
    problems: Vec<String>,
    run: Vec<HistorySide>,
    runs: usize,
    taken: Taken,
}

impl Check {
    pub fn record(&mut self, record: &EmulationRecord) {
        if record.is_cpu_chunk {
            let side = history_side(record, &mut self.problems);
            self.run.push(side);
        }
    }

    pub fn end_run(&mut self, label: &str, program: Arc<Program>, input: &[Vec<u8>], chunk: u32) {
        let history = std::mem::take(&mut self.run);
        if self.runs == 0 {
            println!("{}", header_row());
        }
        self.runs += 1;
        let compared = compare_run(label, program, input, chunk, &history, true);
        self.problems.extend(compared.problems);
        let Taken {
            total,
            chunks,
            moved_windows,
            unconstrained_blocks,
        } = compared.taken;
        self.taken.total += total;
        self.taken.chunks += chunks;
        self.taken.moved_windows += moved_windows;
        self.taken.unconstrained_blocks += unconstrained_blocks;
    }

    pub fn finish(self) -> (Vec<String>, Taken) {
        (self.problems, self.taken)
    }
}

/// Every count must have been taken above zero on some guest, or its equality says nothing.
pub fn check_every_count_taken<'a>(guests: impl IntoIterator<Item = (&'a str, &'a Taken)>) {
    let mut total = Taken::default();
    println!("{}", header_row());
    for (guest, taken) in guests {
        println!("{}", row(guest, taken.chunks, &taken.total));
        total.total += taken.total;
        total.chunks += taken.chunks;
        total.moved_windows += taken.moved_windows;
        total.unconstrained_blocks += taken.unconstrained_blocks;
    }
    println!("{}", row("total", total.chunks, &total.total));

    let paths = [
        ("windows a precompile moved", total.moved_windows),
        ("unconstrained blocks", total.unconstrained_blocks),
    ];
    for (name, count) in paths {
        println!("{name}: {count}");
    }
    let mut problems = Vec::new();
    for (name, count) in named(&total.total).into_iter().chain(paths) {
        if count == 0 && NOT_TAKEN.contains(&name) {
            println!("vacuous: no guest took a {name} count above zero");
        } else if count == 0 {
            problems.push(format!("no guest took a {name} count above zero"));
        }
    }
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// Every guest through both sinks, compared chunk by chunk, and every count taken above zero by
/// some guest: the counting comparison a `counting` name filter selects. In a whole run it reads
/// the per-guest results the other tests already computed, so nothing is emulated twice.
#[test]
fn the_counting_sink_counts_every_list_the_history_holds() {
    let summaries: Vec<(&str, &crate::Summary)> = crate::GUESTS
        .iter()
        .map(|guest| (guest.name, crate::checked(guest.name)))
        .collect();
    check_every_count_taken(
        summaries
            .iter()
            .map(|(guest, summary)| (*guest, &summary.taken)),
    );
}

/// The block of the reth guest `COUNTING_SINK_RETH_BLOCK` names, at `WHOLE`, through both sinks.
/// No run without it.
#[test]
fn the_counting_sink_counts_a_reth_block() {
    crate::before_any_emulation();
    let Ok(block) = std::env::var(RETH_BLOCK) else {
        println!("{RETH_BLOCK} is unset: no reth block is run");
        return;
    };
    let data = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../perf/bench_data/rv64");
    let read = |name: String| {
        std::fs::read(data.join(&name)).unwrap_or_else(|err| panic!("{RETH_BLOCK}: {name}: {err}"))
    };
    let program = program(&read("reth-elf".to_string()));
    let input = vec![read(format!("reth-{block}.bin"))];
    let label = format!("reth-{block} @ {WHOLE}");
    let mut problems = Vec::new();
    let mut history = Vec::new();
    history_emulation(program.clone(), &input, WHOLE, |record| {
        if record.is_cpu_chunk {
            history.push(history_side(&record, &mut problems));
        }
    });
    println!("{}", header_row());
    problems.extend(compare_run(&label, program, &input, WHOLE, &history, true).problems);
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}
