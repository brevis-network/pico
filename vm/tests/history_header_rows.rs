//! The rows a fill's header derives from a CPU chunk's history, against the rows of the event
//! streams the host's accessors rebuild from the same history.
//!
//! The header is counted from the history's lists and each division's operands
//! (`DerivedRows::of`), the streams by opcode and by each division event (`stream_derived_rows`),
//! and the device sizes the add chips' rows, div/rem's derived ADD rows among them, by the header.
//! Run on fib and on the chip-coverage guest, whose divisions derive ADD rows.

use pico_vm::emulator::riscv::{
    history_dump::{stream_derived_rows, HostStreams},
    history_fill::DerivedRows,
    record::EmulationRecord,
};

#[path = "common/chip_coverage.rs"]
mod chip_coverage;
// Only the guests and their runs.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
#[path = "common/trace_source.rs"]
mod trace_source;
use record_parity::{GUESTS, WHOLE};
use trace_source::{history_records, history_run};

/// The ADD rows `record`'s divisions derive, once the header and the streams agree on every row
/// count, or `None` for a record that is no CPU chunk.
fn header_rows_match_streams(record: &EmulationRecord) -> Option<u32> {
    if !record.is_cpu_chunk {
        return None;
    }
    let history = record
        .history
        .as_ref()
        .expect("a CPU chunk emulated through the history sink carries its history");
    let derived = DerivedRows::of(history, &record.program);
    let streams = HostStreams::of(record);
    assert_eq!(
        derived,
        stream_derived_rows(&streams.events()),
        "chunk {}: the header and the event streams count different rows",
        history.chunk
    );
    Some(derived.divrem_add)
}

#[test]
fn the_chip_coverage_header_rows_match_the_event_streams() {
    let (mut checked, mut divrem_add) = (0, 0);
    history_run(chip_coverage::elf(), &[], WHOLE, |record| {
        if let Some(rows) = header_rows_match_streams(&record) {
            checked += 1;
            divrem_add += rows;
        }
    });
    assert!(checked > 0, "no CPU chunk was checked");
    assert!(
        divrem_add > 0,
        "no division derived an ADD row, so the count was held to nothing"
    );
}

#[test]
fn the_fib_header_rows_match_the_event_streams() {
    let fib = GUESTS
        .iter()
        .find(|guest| guest.name == "fib")
        .expect("no guest fib");
    let mut checked = 0;
    for run in fib.runs() {
        history_records(fib.elf, &run, |record| {
            checked += usize::from(header_rows_match_streams(&record).is_some());
        });
    }
    assert!(checked > 0, "no CPU chunk was checked");
}
