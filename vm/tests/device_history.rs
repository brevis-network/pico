//! The execution history's way to the device, which needs a card.
//!
//! `every_history_reader_from_the_history` emulates once each guest that a row of `READERS` or
//! `ROUND_TRIP` names, and hands each CPU chunk to two checks:
//!
//! - the round trip, on `ROUND_TRIP`'s guests: the chunk's history copied into an arena slot,
//!   uploaded as one fill in slices of each size in `SLICE_STEPS` and read back, which must come
//!   back row for row with a clear error word;
//! - the fixed trace oracle (`trace_oracle::generate_and_check`), on every guest a row names: each
//!   air of the chunk's device context against the host's built from the same history, every chip
//!   that read the history with a real row having launched its history kernel. Each row must then
//!   have compared real rows of its chip on its own guests, and taken its `Also` count above zero.
//!
//! The oracle's per-air rules are what let the history's order prove the host's trace: the CPU
//! trace in order with `is_real` telling real rows from padding, the ecall trace in order with its
//! tally columns compared on padding rows too, the program trace cell for cell, and the ALU,
//! less-than, memory read/write and syscall traces as multisets of rows with their opcode flags'
//! sum (div/rem: `is_real`) telling real rows from padding, so the order the device splits the add
//! and sub lists in, and appends div/rem's derived ADD rows in, proves the same trace. The syscall
//! rows feed the global trace, compared in order.
//!
//! Every test that uploads takes the card's turn, and with it arms the poison: every history fill's
//! device region is poisoned before its copies, so a kernel or a read-back of a byte no copy wrote
//! reads poison. The two arena tests take fib's first chunk: each table forced past its region
//! alone spills, keeps every row and uploads the same; with spilling refused, an overfilled table
//! stops the fill at its row.
#![cfg(feature = "cuda")]

use std::{collections::BTreeSet, num::NonZeroUsize, sync::MutexGuard};

use pico_vm::{
    chips::chips::riscv_ecall::traces::commit_tally,
    emulator::{
        record::RecordBehavior,
        riscv::{
            history::ExecutionHistory,
            history_arena::{HistoryArena, HistoryCapacity, SpillPolicy, Table, TableFull},
            history_fill::DerivedRows,
            record::EmulationRecord,
        },
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        preparer::device_history::{plan::CPU_SLICE_STEPS, round_trip},
    },
    machine::chip::MetaChip,
    mle::machine::{
        riscv::{air_id_for, init_mle_gpu_pool, prepare_chunk_shaped, Kb, MLE_GPU_DEVICE},
        trace_oracle::{self, poison, HostSide, HISTORY_READERS},
    },
};

#[path = "common/chip_coverage.rs"]
mod chip_coverage;
// Only the guests, their runs and the card's turn.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
#[path = "common/trace_source.rs"]
mod trace_source;

#[cfg(feature = "drop-ordering-edge")]
#[path = "device_history/ordering.rs"]
mod ordering;

use record_parity::{guest, one_at_a_time, WHOLE};
use trace_source::{history_records, history_run};

const CHIP_COVERAGE: &str = "chip-coverage";

/// The chip-coverage guest runs every opcode of the ALU chips, its signed divisions on negative
/// operands deriving ADD rows; fib runs at every chunk size its runs take.
const ALU_GUESTS: &[&str] = &["fib", CHIP_COVERAGE];
const CPU_GUESTS: &[&str] = &["fib", "ed25519"];

/// A count a row's guests must take above zero over its checked chunks, besides its chip's real
/// rows.
#[derive(Clone, Copy)]
enum Also {
    /// ADD rows derived from divisions, so the append of div/rem's derived rows was compared.
    DerivedAddRows,
    /// Commits tallied, so the running sums down the padding rows were compared.
    Commits,
}

/// A chip of [`HISTORY_READERS`] and the guests its device trace is held to the host's on.
struct Reader {
    chip: &'static str,
    guests: &'static [&'static str],
    also: Option<Also>,
}

const fn reader(chip: &'static str, guests: &'static [&'static str]) -> Reader {
    Reader {
        chip,
        guests,
        also: None,
    }
}

const READERS: [Reader; 15] = [
    reader("Cpu", CPU_GUESTS),
    reader("Program", CPU_GUESTS),
    reader("MemoryReadWrite", CPU_GUESTS),
    reader("LessThan", CPU_GUESTS),
    Reader {
        chip: "Add",
        guests: ALU_GUESTS,
        also: Some(Also::DerivedAddRows),
    },
    reader("Addw", ALU_GUESTS),
    reader("Sub", ALU_GUESTS),
    reader("Subw", ALU_GUESTS),
    reader("DivRem", ALU_GUESTS),
    reader("Mul", ALU_GUESTS),
    reader("Bitwise", ALU_GUESTS),
    reader("ShiftLeft", ALU_GUESTS),
    reader("ShiftRight", ALU_GUESTS),
    // Every guest's halt commits its output and deferred-proofs digests word by word, so the
    // run's last chunks carry a nonzero tally down their padding rows.
    Reader {
        chip: "Ecall",
        guests: &["fib", "aggregator"],
        also: Some(Also::Commits),
    },
    // fib sends no syscall to a precompile table; these two send many.
    reader("SyscallRiscv", &["ed25519", "poseidon2"]),
];

/// The guests whose every CPU chunk goes through the round trip.
const ROUND_TRIP: [&str; 3] = ["fib", "ed25519", "k256"];

/// Slices small enough that a test chunk has several, so the slice boundaries are crossed.
const SLICE_STEPS: [u32; 2] = [64, CPU_SLICE_STEPS];

/// The card's turn, held until it drops, with the history's device region poisoned before every
/// fill and the card's pools up.
fn card() -> MutexGuard<'static, ()> {
    let turn = one_at_a_time();
    poison::arm();
    init_mle_gpu_pool(MLE_GPU_DEVICE);
    turn
}

/// Each record of the guest called `name`, with its run's chunk size: every run of a record-parity
/// guest, or the chip-coverage guest in one chunk of [`WHOLE`].
fn each_record(name: &str, mut on_record: impl FnMut(u32, EmulationRecord)) {
    if name == CHIP_COVERAGE {
        history_run(chip_coverage::elf(), &[], WHOLE, |record| {
            on_record(WHOLE, record)
        });
        return;
    }
    let guest = guest(name);
    for run in guest.runs() {
        history_records(guest.elf, &run, |record| on_record(run.chunk_size, record));
    }
}

fn history(record: &EmulationRecord) -> &ExecutionHistory {
    record
        .history_view()
        .expect("a CPU chunk's history")
        .history
}

fn arena(capacity: HistoryCapacity, policy: SpillPolicy) -> HistoryArena {
    HistoryArena::pin(NonZeroUsize::MIN, 1 << 20, capacity, policy).expect("an arena")
}

/// What a row's guests showed over the chunks it was checked on.
#[derive(Default)]
struct Seen {
    chunks: usize,
    real: usize,
    derived_add_rows: usize,
    commits: u32,
}

#[test]
fn every_history_reader_from_the_history() {
    let _turn = card();
    assert_eq!(
        READERS.iter().map(|reader| reader.chip).collect::<BTreeSet<_>>(),
        BTreeSet::from(HISTORY_READERS),
        "READERS must hold one row for each chip the history feeds, so the launch check covers each"
    );
    let airs: Vec<usize> = READERS
        .iter()
        .map(|reader| {
            air_id_for(reader.chip).unwrap_or_else(|| panic!("{}: no such air", reader.chip))
        })
        .collect();
    let chips: Vec<MetaChip<Kb, RiscvChipType<Kb>>> = RiscvChipType::<Kb>::all_chips();
    let orchestrator = RiscvChipType::<Kb>::gpu_generate_extra_record_and_main_chips();
    let arena = arena(HistoryCapacity::CENSUS, SpillPolicy::Spill);

    let mut guests: Vec<&str> = Vec::new();
    for &name in READERS
        .iter()
        .flat_map(|reader| reader.guests)
        .chain(&ROUND_TRIP)
    {
        if !guests.contains(&name) {
            guests.push(name);
        }
    }
    let mut seen: Vec<Seen> = READERS.iter().map(|_| Seen::default()).collect();
    let mut problems = Vec::new();
    for name in guests {
        let round_trips = ROUND_TRIP.contains(&name);
        let rows: Vec<usize> = (0..READERS.len())
            .filter(|&row| READERS[row].guests.contains(&name))
            .collect();
        let mut round_tripped = 0usize;
        each_record(name, |chunk_size, record| {
            if !record.is_cpu_chunk {
                return;
            }
            let at = format!("{name} @ {chunk_size} chunk {}", record.chunk_index());
            let view = record
                .history_view()
                .unwrap_or_else(|| panic!("{at}: a CPU chunk without a history"));
            let counts = DerivedRows::of(view.history, view.program);
            if round_trips {
                let filled = arena.fill(view.history).expect("room in a census slot");
                if filled.spilled().count() > 0 {
                    problems.push(format!("{at} spilled a census slot"));
                }
                for slice_steps in SLICE_STEPS {
                    let differ =
                        round_trip(MLE_GPU_DEVICE, &filled, counts, view.program, slice_steps)
                            .unwrap_or_else(|e| panic!("{at}: {e}"));
                    if !differ.is_empty() {
                        problems.push(format!(
                            "{at} in slices of {slice_steps}: {differ:?} differ on the device"
                        ));
                    }
                }
                round_tripped += 1;
            }
            if rows.is_empty() {
                return;
            }
            let commits = commit_tally(&record).0;
            let host = HostSide::build(&chips, &record);
            let chunk = prepare_chunk_shaped(&chips, record, false);
            let (verdict, _) = trace_oracle::generate_and_check(&host, &orchestrator, &chunk, &[])
                .unwrap_or_else(|failures| {
                    panic!(
                        "{at}: the device traces from the history:\n{}",
                        trace_oracle::describe(&failures)
                    )
                });
            for &row in &rows {
                let seen = &mut seen[row];
                seen.chunks += 1;
                seen.real += verdict
                    .compared
                    .get(&airs[row])
                    .map_or(0, |report| report.real);
                seen.derived_add_rows += counts.divrem_add as usize;
                seen.commits += commits;
            }
        });
        if round_trips {
            println!("{name}: {round_tripped} CPU chunk(s) back from the device row for row");
            if round_tripped == 0 {
                problems.push(format!("{name}: no CPU chunk went through the round trip"));
            }
        }
    }

    for (reader, seen) in READERS.iter().zip(&seen) {
        let chip = reader.chip;
        println!(
            "{chip}: {} CPU chunk(s) equal from the history, {} real row(s), {} derived ADD \
             row(s), {} commit(s)",
            seen.chunks, seen.real, seen.derived_add_rows, seen.commits
        );
        if seen.chunks == 0 {
            problems.push(format!("{chip}: no CPU chunk was checked"));
        }
        if seen.real == 0 {
            problems.push(format!(
                "{chip}: no checked chunk held a real row, so the history entry proved nothing"
            ));
        }
        match reader.also {
            Some(Also::DerivedAddRows) if seen.derived_add_rows == 0 => problems.push(format!(
                "{chip}: no checked chunk derived an ADD row from a division, so the append \
                 proved nothing"
            )),
            Some(Also::Commits) if seen.commits == 0 => problems.push(format!(
                "{chip}: no chunk tallied a commit, so the running sums on padding rows proved \
                 nothing"
            )),
            _ => {}
        }
    }
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// fib's first chunk: the one CPU chunk of its first run.
fn fib_first_chunk() -> EmulationRecord {
    let fib = guest("fib");
    let mut first = None;
    history_records(fib.elf, &fib.runs()[0], |record| {
        if record.is_cpu_chunk && first.is_none() {
            first = Some(record);
        }
    });
    first.expect("fib ran no CPU chunk")
}

/// The first chunk of `fib` with each table given one row less than it holds: that table alone
/// spills, and the fill uploads row for row from its pageable copy.
#[test]
fn each_spilled_table_uploads_row_for_row() {
    let _turn = card();
    let record = fib_first_chunk();
    let history = history(&record);
    let counts = DerivedRows::of(history, &record.program);
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
        let differ = round_trip(MLE_GPU_DEVICE, &filled, counts, &record.program, 64)
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
    let record = fib_first_chunk();
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
