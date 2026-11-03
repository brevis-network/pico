//! The execution history's way to the device on the record-parity guests, which needs a card:
//! every CPU chunk's history is copied into an arena slot, uploaded as one fill and read back, and
//! must come back row for row with a clear error word; each table forced past its region alone
//! spills, keeps every row and uploads the same; with spilling refused, an overfilled table stops
//! the fill at its row. The fill header's scan must count what the host's accessors read off the
//! same history: each opcode of the coarse add and sub lists, and the ADD rows div/rem derives, on
//! every record-parity guest, on the chip-coverage guest, whose signed div/rem on negative operands
//! derives ADD rows, and on a reth block's first chunk with div/rem rows.
#![cfg(feature = "cuda")]

use std::{num::NonZeroUsize, sync::Arc};

use pico_vm::{
    chips::chips::alu::divrem::utils::derived_add_rows,
    compiler::riscv::{opcode::Opcode, program::Program},
    emulator::{
        riscv::{
            history::ExecutionHistory,
            history_arena::{HistoryArena, HistoryCapacity, SpillPolicy, Table, TableFull},
            history_fill::DerivedRows,
            public_values::RecordFinalPvsState,
            record::{AluStream, EmulationRecord},
            record_slots::hold_records_unbounded,
            riscv_emulator::RiscvEmulator,
            sink::{HistorySink, Sink},
        },
        stdin::EmulatorStdin,
    },
    instances::preparer::device_history::{plan::CPU_SLICE_STEPS, round_trip},
    mle::machine::riscv::Kb,
};

// Only the guests and their runs: the comparison in there is between two emulation paths.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
use record_parity::{opts, program, stdin, GUESTS, WHOLE};

const CHIP_COVERAGE_ELF: &[u8] = include_bytes!("../../perf/bench_data/rv64/chip-coverage-elf");

const DEVICE: usize = 0;

/// Slices small enough that a test chunk has several, so the slice boundaries are crossed.
const SLICE_STEPS: [u32; 2] = [64, CPU_SLICE_STEPS];

/// Runs `elf` on `stdin` at `chunk_size`, handing each CPU chunk record to `on_chunk` until it
/// returns false or the run ends.
fn cpu_chunks(
    elf: &[u8],
    stdin: &EmulatorStdin<Program, Vec<u8>>,
    chunk_size: u32,
    mut on_chunk: impl FnMut(&Arc<Program>, EmulationRecord) -> bool,
) {
    let program = program(elf);
    hold_records_unbounded();
    let mut emulator = RiscvEmulator::new_single::<Kb>(
        program.clone(),
        Arc::new(RecordFinalPvsState::default()),
        opts(chunk_size),
    )
    .with_sink(Sink::History(HistorySink::new(EmulationRecord::new(
        program.clone(),
    ))));
    emulator.write_stdin(stdin);
    let mut going = true;
    while going {
        let report = emulator
            .emulate_batch(&mut |record: EmulationRecord| {
                if going && record.is_cpu_chunk {
                    going = on_chunk(&program, record);
                }
            })
            .expect("emulate_batch");
        going &= !report.done;
    }
}

/// Every CPU chunk record of `name`'s runs, with its program.
fn chunk_records(name: &str) -> Vec<(Arc<Program>, EmulationRecord)> {
    let guest = GUESTS
        .iter()
        .find(|guest| guest.name == name)
        .unwrap_or_else(|| panic!("no guest {name}"));
    let mut records = Vec::new();
    for run in guest.runs() {
        cpu_chunks(
            guest.elf,
            &stdin(&run.stdin),
            run.chunk_size,
            |program, record| {
                records.push((program.clone(), record));
                true
            },
        );
    }
    assert!(!records.is_empty(), "{name} ran no CPU chunk");
    records
}

fn history(record: &EmulationRecord) -> &ExecutionHistory {
    record
        .history_view()
        .expect("a CPU chunk's history")
        .history
}

/// The header counts the host's accessors read off the record's history.
fn host_counts(record: &EmulationRecord) -> DerivedRows {
    let count = |stream: AluStream, opcode: Opcode| record.alu_ops(stream).count(opcode) as u32;
    let divrem = record.alu_ops(AluStream::DivRem);
    DerivedRows {
        divrem_add: (0..divrem.len())
            .map(|row| {
                let event = divrem.get(row);
                derived_add_rows(event.opcode, event.b, event.c) as u32
            })
            .sum(),
        add: count(AluStream::Add, Opcode::ADD),
        addw: count(AluStream::Add, Opcode::ADDW),
        sub: count(AluStream::Sub, Opcode::SUB),
        subw: count(AluStream::Sub, Opcode::SUBW),
    }
}

fn arena(capacity: HistoryCapacity, policy: SpillPolicy) -> HistoryArena {
    HistoryArena::pin(NonZeroUsize::MIN, 1 << 20, capacity, policy).expect("an arena")
}

/// Every chunk of `name` through a slot and up to the card and back, in slices of each size.
fn check(name: &str) {
    let arena = arena(HistoryCapacity::CENSUS, SpillPolicy::Spill);
    let mut problems = Vec::new();
    let mut divrem_add_rows = 0;
    for (chunk, (program, record)) in chunk_records(name).into_iter().enumerate() {
        let history = history(&record);
        let counts = DerivedRows::of(history, &program);
        divrem_add_rows += counts.divrem_add;
        if counts != host_counts(&record) {
            problems.push(format!(
                "chunk {chunk}: the scan counts {counts:?}, the host {:?}",
                host_counts(&record)
            ));
        }
        let filled = arena.fill(history).expect("room in a census slot");
        if filled.spilled().count() > 0 {
            problems.push(format!("chunk {chunk} spilled a census slot"));
        }
        for slice_steps in SLICE_STEPS {
            let differ = round_trip(DEVICE, &filled, counts, &program, slice_steps)
                .unwrap_or_else(|e| panic!("chunk {chunk}: {e}"));
            if !differ.is_empty() {
                problems.push(format!(
                    "chunk {chunk} in slices of {slice_steps}: {differ:?} differ on the device"
                ));
            }
        }
    }
    println!("{name}: {divrem_add_rows} derived ADD row(s) over its chunks");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// `record`'s header scan against the host's counts, any difference a problem under `label`;
/// the scan.
fn compare_counts(
    label: &str,
    record: &EmulationRecord,
    problems: &mut Vec<String>,
) -> DerivedRows {
    let view = record.history_view().expect("a CPU chunk's history");
    let scanned = DerivedRows::of(view.history, view.program);
    let host = host_counts(record);
    if scanned != host {
        problems.push(format!(
            "{label}: the scan counts {scanned:?}, the host {host:?}"
        ));
    }
    scanned
}

/// Every chunk of every run of every record-parity guest.
#[test]
fn the_header_scan_is_the_hosts_on_every_guest() {
    let mut problems = Vec::new();
    for guest in &GUESTS {
        for run in guest.runs() {
            let mut chunk = 0;
            cpu_chunks(
                guest.elf,
                &stdin(&run.stdin),
                run.chunk_size,
                |_, record| {
                    let label = format!("{} @ {} chunk {chunk}", guest.name, run.chunk_size);
                    compare_counts(&label, &record, &mut problems);
                    chunk += 1;
                    true
                },
            );
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The chip-coverage guest whole and cut fine, its signed div/rem on negative operands deriving
/// ADD rows.
#[test]
fn the_header_scan_is_the_hosts_on_chip_coverage() {
    let mut problems = Vec::new();
    let mut derived = 0;
    for chunk_size in [WHOLE, 1 << 10] {
        let mut chunk = 0;
        cpu_chunks(CHIP_COVERAGE_ELF, &stdin(&[]), chunk_size, |_, record| {
            let label = format!("chip-coverage @ {chunk_size} chunk {chunk}");
            derived += compare_counts(&label, &record, &mut problems).divrem_add;
            chunk += 1;
            true
        });
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(
        derived > 0,
        "no chunk derived an ADD row: no signed div/rem saw a negative operand"
    );
}

/// reth-23993050 at a production chunk size, up to its first chunk with div/rem rows.
#[test]
fn the_header_scan_is_the_hosts_on_a_reth_chunk() {
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/../perf/bench_data/rv64/");
    let read = |file: &str| {
        std::fs::read(format!("{data}{file}")).unwrap_or_else(|e| panic!("{data}{file}: {e}"))
    };
    let (elf, input) = (read("reth-elf"), read("reth-23993050.bin"));
    let mut problems = Vec::new();
    let (mut chunk, mut divrem_rows) = (0, 0);
    cpu_chunks(&elf, &stdin(&[input]), 1 << 22, |_, record| {
        compare_counts(
            &format!("reth-23993050 chunk {chunk}"),
            &record,
            &mut problems,
        );
        chunk += 1;
        divrem_rows = record
            .history_view()
            .map_or(0, |view| view.history.chip_steps.divrem.len());
        divrem_rows == 0
    });
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(
        divrem_rows > 0,
        "reth-23993050 ran {chunk} chunk(s) and none held a div/rem row"
    );
}

#[test]
fn fib() {
    check("fib");
}

#[test]
fn ed25519() {
    check("ed25519");
}

#[test]
fn k256() {
    check("k256");
}

/// The first chunk of `fib` with each table given one row less than it holds: that table alone
/// spills, and the fill uploads row for row from its pageable copy.
#[test]
fn each_spilled_table_uploads_row_for_row() {
    let (program, record) = chunk_records("fib").swap_remove(0);
    let history = history(&record);
    let counts = DerivedRows::of(history, &program);
    let rows = {
        let arena = arena(HistoryCapacity::CENSUS, SpillPolicy::Spill);
        arena.fill(history).expect("room").rows()
    };
    let mut problems = Vec::new();
    for table in Table::ALL {
        let held = rows[table.index()];
        if held == 0 {
            println!("{}: empty in this chunk, so it cannot spill", table.name());
            continue;
        }
        let arena = arena(
            HistoryCapacity::CENSUS.with_rows(table, held - 1),
            SpillPolicy::Spill,
        );
        let filled = arena.fill(history).expect("a spill, not a refusal");
        if filled.spilled().collect::<Vec<_>>() != [table] {
            problems.push(format!(
                "{} forced: {:?} spilled",
                table.name(),
                filled.spilled().map(Table::name).collect::<Vec<_>>()
            ));
        }
        if arena.stats().spills[table.index()] != 1 {
            problems.push(format!("{}'s spill went uncounted", table.name()));
        }
        let differ = round_trip(DEVICE, &filled, counts, &program, 64)
            .unwrap_or_else(|e| panic!("{} forced: {e}", table.name()));
        if !differ.is_empty() {
            problems.push(format!("{} forced: {differ:?} differ", table.name()));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Spilling refused, the steps one row short: the fill stops at that row and keeps nothing.
#[test]
fn a_refused_spill_stops_the_fill() {
    let (_, record) = chunk_records("fib").swap_remove(0);
    let history = history(&record);
    let steps = history.steps.len();
    let arena = arena(
        HistoryCapacity::CENSUS.with_rows(Table::Steps, steps - 1),
        SpillPolicy::Refuse,
    );
    assert_eq!(
        arena.fill(history).err(),
        Some(TableFull {
            table: Table::Steps,
            capacity: steps - 1,
            needed: steps,
        })
    );
    let stats = arena.stats();
    assert_eq!((stats.acquisitions, stats.returns), (1, 1));
}
