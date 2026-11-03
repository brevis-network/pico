//! The counting sink against the execution history on the record-parity guests, chunk by chunk.
//! Counts come from the history's steps, access slots, chip lists and syscalls.
//!
//! A precompile's `SyscallContext::postprocess` moves the emulator's window for each address it
//! touched out of the sink's map and into `record.cpu_local_memory_access`, so the sink counts its
//! windows off both.
//!
//! Needs `--features test-utils`. `COUNTING_SINK_RETH_BLOCK=18884864` adds that block of the reth
//! guest at `WHOLE`: minutes of interpreter per arm and gigabytes per chunk.

use std::{borrow::Cow, path::PathBuf, sync::Arc};

use pico_vm::{
    compiler::riscv::program::Program,
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            history::Slots,
            public_values::RecordFinalPvsState,
            record::EmulationRecord,
            record_slots::hold_records_unbounded,
            riscv_emulator::RiscvEmulator,
            sink::{ChunkCounts, CountingSink, HistorySink, Sink},
        },
        stdin::EmulatorStdin,
    },
    mle::machine::riscv::Kb,
};

// Only the guests and their runs: the comparison in there is between two emulation paths.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
use record_parity::{opts, program, stdin, GUESTS, WHOLE};

const RETH_BLOCK: &str = "COUNTING_SINK_RETH_BLOCK";

/// Counts no record-parity guest takes: none of them divides.
const NOT_TAKEN: &[&str] = &["divrem"];

/// One comparison: a guest, its input and a chunk size.
struct Case {
    label: String,
    elf: Cow<'static, [u8]>,
    stdin: Vec<Vec<u8>>,
    chunk_size: u32,
}

/// Every run of every record-parity guest, and the reth block `COUNTING_SINK_RETH_BLOCK` names.
fn cases() -> Vec<Case> {
    let mut cases: Vec<Case> = GUESTS
        .iter()
        .flat_map(|guest| {
            guest.runs().into_iter().map(|run| Case {
                label: format!("{} @ {}", guest.name, run.chunk_size),
                elf: Cow::Borrowed(guest.elf),
                stdin: run.stdin,
                chunk_size: run.chunk_size,
            })
        })
        .collect();
    if let Ok(block) = std::env::var(RETH_BLOCK) {
        let data = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../perf/bench_data/rv64");
        let read = |name: String| {
            std::fs::read(data.join(&name))
                .unwrap_or_else(|err| panic!("{RETH_BLOCK}: {name}: {err}"))
        };
        cases.push(Case {
            label: format!("reth-{block} @ {WHOLE}"),
            elf: Cow::Owned(read("reth-elf".to_string())),
            stdin: vec![read(format!("reth-{block}.bin"))],
            chunk_size: WHOLE,
        });
    }
    cases
}

fn history_counts(record: &EmulationRecord) -> ChunkCounts {
    let history = record.history.as_ref().expect("a CPU chunk has a history");
    let mut accesses = [0; 4];
    for (index, step) in history.steps.iter().enumerate() {
        let instruction = record.program.fetch(u64::from(step.pc));
        let slots = Slots::of(&instruction);
        let (reads, writes) = history.rows_of(index);
        assert_eq!(
            (reads.len(), writes.len()),
            (slots.len() - slots.write_count(), slots.write_count()),
            "step {index}'s read and write counts"
        );
        for (slot, _) in history.accesses_of(index, &instruction) {
            accesses[3 - slot as usize] += 1;
        }
    }
    let chips = &history.chip_steps;
    ChunkCounts {
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
        memory_instructions: chips.memory.len(),
        ecalls: chips.ecall.len(),
        windows: record.cpu_local_memory_access.len(),
    }
}

/// Runs `emulator` to the end, handing every CPU-chunk record it emits to `on_chunk`.
fn emulate(
    emulator: &mut RiscvEmulator,
    stdin: &EmulatorStdin<Program, Vec<u8>>,
    mut on_chunk: impl FnMut(EmulationRecord),
) {
    emulator.write_stdin(stdin);
    loop {
        let report = emulator
            .emulate_batch(&mut |record: EmulationRecord| {
                if record.is_cpu_chunk {
                    on_chunk(record);
                }
            })
            .expect("emulate_batch");
        if report.done {
            break;
        }
    }
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

fn interpreter(program: Arc<Program>, opts: EmulatorOpts) -> RiscvEmulator {
    RiscvEmulator::new_single::<Kb>(program, Arc::new(RecordFinalPvsState::default()), opts)
}

#[test]
fn the_counting_sink_counts_every_list_the_history_holds() {
    hold_records_unbounded();
    let mut problems = Vec::new();
    let mut rows = Vec::new();
    let mut total = ChunkCounts::default();
    let mut total_chunks = 0;
    // Two paths equal counts would not show ran: a precompile's window move and the rollback.
    let mut moved_windows = 0;
    let mut unconstrained_blocks = 0;
    for case in cases() {
        let label = case.label;
        let program = program(&case.elf);
        let stdin = stdin(&case.stdin);
        let opts = opts(case.chunk_size);

        // Each record is reduced as it comes out: the BLS12-381 field guest's are gigabytes.
        let mut history = Vec::new();
        emulate(
            &mut interpreter(program.clone(), opts).with_sink(Sink::History(HistorySink::new(
                EmulationRecord::new(program.clone()),
            ))),
            &stdin,
            |record| history.push((history_counts(&record), record.public_values)),
        );

        let mut emulator = interpreter(program.clone(), opts).with_sink(Sink::Counting(
            CountingSink::new(EmulationRecord::new(program)),
        ));
        let mut emitted = Vec::new();
        emulate(&mut emulator, &stdin, |record| {
            moved_windows += record.cpu_local_memory_access.len();
            assert!(
                record.history.is_none(),
                "[{label}] the counting sink wrote a history"
            );
            assert!(
                record.add_events.is_empty(),
                "[{label}] the counting sink wrote additions"
            );
            emitted.push(record.public_values);
        });
        let Sink::Counting(sink) = &mut emulator.sink else {
            unreachable!("the emulator was built with the counting sink");
        };
        let mut cuts = sink.take_counts();
        unconstrained_blocks += sink.unconstrained_blocks();

        if let Some((_, last)) = history.last() {
            if last.committed_value_digest.iter().all(|&w| w == 0) {
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
        let mut run_total = ChunkCounts::default();
        for (i, (counted, (expected, _))) in cuts.iter().zip(&history).enumerate() {
            if counted != expected {
                problems.push(format!(
                    "[{label}] chunk {i}: counted {counted:?}, history {expected:?}"
                ));
            }
            if counted.steps == 0 {
                problems.push(format!("[{label}] chunk {i}: no step"));
            }
            run_total += *counted;
        }

        if emitted.len() != history.len() {
            problems.push(format!(
                "[{label}] {} CPU record(s) emitted, the history sink {}",
                emitted.len(),
                history.len()
            ));
        }
        // `PublicValues` has no `PartialEq`; its `Debug` form prints every field.
        for (i, (counting, (_, history))) in emitted.iter().zip(&history).enumerate() {
            if format!("{counting:?}") != format!("{history:?}") {
                problems.push(format!(
                    "[{label}] chunk {i}: public values {counting:?}, history {history:?}"
                ));
            }
        }

        if run_total.steps == 0 {
            problems.push(format!("[{label}] no step in the whole run"));
        }
        rows.push(row(&label, cuts.len(), &run_total));
        total += run_total;
        total_chunks += cuts.len();
    }

    let header = columns(&total, total_chunks).map(|(name, _)| (name, name.to_string()));
    println!("{}", line("run", header));
    for run in &rows {
        println!("{run}");
    }
    println!("{}", row("total", total_chunks, &total));

    // Every count must have been taken on some case, or its equality above says nothing.
    let paths = [
        ("windows a precompile moved", moved_windows),
        ("unconstrained blocks", unconstrained_blocks),
    ];
    for (name, count) in paths {
        println!("{name}: {count}");
    }
    for (name, count) in named(&total).into_iter().chain(paths) {
        if count == 0 && NOT_TAKEN.contains(&name) {
            println!("vacuous: no case took a {name} count above zero");
        } else if count == 0 {
            problems.push(format!("no case took a {name} count above zero"));
        }
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
