//! The byte chip's trace, built by writing each lookup into its row, against the trace the
//! per-row scan of every lookup builds: over every record of the record-parity guests, and over
//! a hand-built lookup set that reaches every opcode, every `BitRange` width and the edges of the
//! table.

use std::{
    borrow::{Borrow, BorrowMut},
    sync::Arc,
};

use hashbrown::HashMap;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use pico_vm::{
    chips::chips::byte::{
        columns::{
            ByteMultCols, BytePreprocessedCols, NUM_BYTE_MULT_COLS, NUM_BYTE_PREPROCESSED_COLS,
        },
        event::ByteLookupEvent,
        traces::{byte_lookup_row, NUM_ROWS},
        ByteChip,
    },
    compiler::riscv::opcode::ByteOpcode,
    emulator::riscv::{
        emulator::RiscvEmulator, public_values::RecordFinalPvsState, record::EmulationRecord,
        record_slots::hold_records_unbounded,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::ChipBehavior,
    mle::machine::riscv::{augmented_record, Kb},
};

// Only the guests and their runs: the comparison in there is between two emulation arms.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
use record_parity::{opts, program, selected_guests, stdin};

type Lookups = HashMap<ByteLookupEvent, usize>;

/// The rule the scan tested every row against, kept as it was written.
fn scan_row(lookup: &ByteLookupEvent) -> usize {
    if lookup.opcode == ByteOpcode::BitRange && lookup.a2 == 16 {
        ((lookup.b as usize) << 8) + lookup.c as usize
    } else if lookup.opcode == ByteOpcode::BitRange && lookup.a2 < 16 {
        let base = 1usize << 16;
        base + ((lookup.b as usize) << 8) + lookup.c as usize + (1usize << lookup.a2 as usize)
    } else {
        ((lookup.b as usize) << 8) + lookup.c as usize
    }
}

/// Every row tests every lookup.
fn scanned_trace(lookups: &Lookups) -> RowMajorMatrix<Kb> {
    let mut values = vec![Kb::ZERO; NUM_BYTE_MULT_COLS * NUM_ROWS];
    let lookups: Vec<_> = lookups.iter().collect();
    values
        .par_chunks_mut(NUM_BYTE_MULT_COLS)
        .enumerate()
        .for_each(|(row_idx, row)| {
            for (lookup, mult) in lookups.iter() {
                if row_idx == scan_row(lookup) {
                    let cols: &mut ByteMultCols<Kb> = row.borrow_mut();
                    cols.multiplicities[lookup.opcode as usize] += Kb::from_usize(**mult);
                }
            }
        });
    RowMajorMatrix::new(values, NUM_BYTE_MULT_COLS)
}

fn scattered_trace(record: &EmulationRecord) -> RowMajorMatrix<Kb> {
    ByteChip::<Kb>::default().generate_main(record, &mut EmulationRecord::default())
}

/// A record holding only `lookups`.
fn record_with_lookups(lookups: Lookups) -> EmulationRecord {
    EmulationRecord {
        byte_lookups: lookups,
        ..Default::default()
    }
}

/// A failure names the first differing cell rather than printing 1.4 million field elements.
fn assert_same_trace(what: &str, scattered: &RowMajorMatrix<Kb>, scanned: &RowMajorMatrix<Kb>) {
    assert_eq!(scattered.width, scanned.width, "{what}: width");
    assert_eq!(
        scattered.values.len(),
        scanned.values.len(),
        "{what}: height"
    );
    if let Some(at) = scattered
        .values
        .iter()
        .zip(&scanned.values)
        .position(|(got, want)| got != want)
    {
        panic!(
            "{what}: row {} column {}: scattered {}, scanned {}",
            at / NUM_BYTE_MULT_COLS,
            at % NUM_BYTE_MULT_COLS,
            scattered.values[at],
            scanned.values[at]
        );
    }
}

fn cell_sum(trace: &RowMajorMatrix<Kb>) -> u64 {
    trace
        .values
        .iter()
        .map(|cell| cell.as_canonical_u32() as u64)
        .sum()
}

/// Every record of every run of every guest `selected_guests` picks, the way the prover reads
/// it: after the chips' `extra_record` pass has raised the byte lookups. Each record is dropped
/// before the next is emulated: a large guest's whole run does not fit in memory beside a second
/// copy of itself.
#[test]
fn scatter_matches_scan_on_every_parity_guest_record() {
    hold_records_unbounded();
    let chips = RiscvChipType::<Kb>::all_chips();
    for guest in selected_guests() {
        for (run_index, run) in guest.runs().into_iter().enumerate() {
            let what = format!("{} run {run_index}", guest.name);
            let mut emulator = RiscvEmulator::new_single::<Kb>(
                program(guest.elf),
                Arc::new(RecordFinalPvsState::default()),
                opts(run.chunk_size),
            );
            emulator.write_stdin(&stdin(&run.stdin));

            let (mut records, mut with_lookups, mut lookups_seen) = (0usize, 0usize, 0usize);
            loop {
                let report = emulator
                    .emulate_batch(&mut |raw| {
                        // Only the lookups are compared, so the augmented record and the raw one
                        // are both dropped before the 2^17-row traces are built.
                        let byte_lookups =
                            std::mem::take(&mut augmented_record(&chips, &raw).byte_lookups);
                        drop(raw);
                        let at = format!("{what} record {records}");
                        let record = record_with_lookups(byte_lookups);
                        let scattered = scattered_trace(&record);
                        assert_same_trace(&at, &scattered, &scanned_trace(&record.byte_lookups));

                        // Independent of the scan: no lookup falls off the table, so the trace
                        // holds every multiplicity once.
                        let total: usize = record.byte_lookups.values().sum();
                        assert_eq!(cell_sum(&scattered), total as u64, "{at}: multiplicities");

                        records += 1;
                        with_lookups += usize::from(!record.byte_lookups.is_empty());
                        lookups_seen += record.byte_lookups.len();
                    })
                    .expect("the guest emulates");
                if report.done {
                    break;
                }
            }
            assert!(records > 0, "{what}: no record compared");
            assert!(
                with_lookups > 0,
                "{what}: no record carried a byte lookup, so every trace compared was empty"
            );
            eprintln!("{what}: {records} records, {lookups_seen} lookups");
        }
    }
}

fn bit_range(a2: u8, value: u16) -> ByteLookupEvent {
    ByteLookupEvent::new(ByteOpcode::BitRange, 0, a2, (value >> 8) as u8, value as u8)
}

/// Lookups that share a table cell, sit on its corners and its seams, or fall past its end.
fn hand_built_lookups() -> (Lookups, Vec<ByteLookupEvent>) {
    let mut lookups = Lookups::new();
    let mut dropped = Vec::new();
    let corners = [(0u8, 0u8), (0, 255), (255, 0), (255, 255), (1, 1), (7, 200)];

    for opcode in ByteOpcode::all() {
        if opcode == ByteOpcode::BitRange {
            continue;
        }
        for (b, c) in corners {
            // Distinct keys on one cell: the multiplicities must add.
            for (a1, mult) in [(0u16, 3usize), (1, 5), (2, 7)] {
                lookups.insert(ByteLookupEvent::new(opcode, a1, 0, b, c), mult);
            }
        }
    }

    // `a2` is the width: 16 reads the full table, 0..16 the rows after it, and anything wider is
    // read as a plain byte pair.
    for a2 in (0u8..=16).chain([17, 200]) {
        let widest = if a2 >= 16 { u16::MAX } else { (1u16 << a2) - 1 };
        for value in [0, widest] {
            lookups.insert(bit_range(a2, value), a2 as usize + 1);
        }
    }

    // The value is wider than its width says: row 65536 + 65535 + 2^15 is past the table.
    for (a2, value) in [(15u8, u16::MAX), (15, 1 << 15), (14, u16::MAX)] {
        let lookup = bit_range(a2, value);
        assert!(
            scan_row(&lookup) >= NUM_ROWS,
            "{lookup:?} should be past the table"
        );
        lookups.insert(lookup, 11);
        dropped.push(lookup);
    }

    // The value is wider than its width but the row exists: it lands on another width's row,
    // which is the same cell in both traces.
    lookups.insert(bit_range(3, 9), 13);

    (lookups, dropped)
}

#[test]
fn scatter_matches_scan_on_hand_built_lookups() {
    let (lookups, dropped) = hand_built_lookups();
    let record = record_with_lookups(lookups.clone());
    let scattered = scattered_trace(&record);
    assert_same_trace("hand-built", &scattered, &scanned_trace(&lookups));

    let kept: usize = lookups
        .iter()
        .filter(|(lookup, _)| !dropped.contains(lookup))
        .map(|(_, mult)| mult)
        .sum();
    assert_eq!(
        cell_sum(&scattered),
        kept as u64,
        "a lookup past the table is dropped and every other one is counted once"
    );

    // The last table row is the widest 15-bit value: a row the scan and the scatter both reach.
    let last = bit_range(15, 0x7fff);
    assert_eq!(scan_row(&last), NUM_ROWS - 1);
    let cols: &ByteMultCols<Kb> = scattered.values
        [(NUM_ROWS - 1) * NUM_BYTE_MULT_COLS..NUM_ROWS * NUM_BYTE_MULT_COLS]
        .borrow();
    assert_eq!(
        cols.multiplicities[ByteOpcode::BitRange as usize],
        Kb::from_usize(16)
    );
}

/// The scattered row is the scan's row for every operand pair, at the widths that change the rule.
#[test]
fn the_row_rule_is_the_scans() {
    for opcode in ByteOpcode::all() {
        for a2 in [0u8, 1, 7, 8, 15, 16, 17, 255] {
            for b in 0..=u8::MAX {
                for c in 0..=u8::MAX {
                    let lookup = ByteLookupEvent::new(opcode, 0, a2, b, c);
                    assert_eq!(byte_lookup_row(&lookup), scan_row(&lookup), "{lookup:?}");
                }
            }
        }
    }
}

/// A lookup's row is the row of the preprocessed table that holds its operands, so the trace and
/// the table the byte bus is balanced against cannot drift apart.
#[test]
fn a_lookups_row_holds_its_operands_in_the_preprocessed_table() {
    let table = ByteChip::<Kb>::preprocess();
    let (lookups, dropped) = hand_built_lookups();
    let mut checked = 0;
    for lookup in lookups.keys().filter(|lookup| !dropped.contains(lookup)) {
        let value = ((lookup.b as u32) << 8) + lookup.c as u32;
        if lookup.opcode == ByteOpcode::BitRange && lookup.a2 < 16 && value >= 1 << lookup.a2 {
            continue;
        }
        let row = byte_lookup_row(lookup);
        let cols: &BytePreprocessedCols<Kb> = table.values
            [row * NUM_BYTE_PREPROCESSED_COLS..(row + 1) * NUM_BYTE_PREPROCESSED_COLS]
            .borrow();
        match lookup.opcode {
            ByteOpcode::BitRange if lookup.a2 <= 16 => {
                assert_eq!(cols.value_u16, Kb::from_u32(value), "{lookup:?}");
                assert_eq!(cols.bits, Kb::from_u8(lookup.a2), "{lookup:?}");
            }
            _ => {
                assert_eq!(cols.b, Kb::from_u8(lookup.b), "{lookup:?}");
                assert_eq!(cols.c, Kb::from_u8(lookup.c), "{lookup:?}");
            }
        }
        checked += 1;
    }
    assert!(checked > 0, "no lookup was checked against the table");
}
