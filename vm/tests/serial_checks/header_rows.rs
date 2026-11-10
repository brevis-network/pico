//! The rows a fill's header derives from a CPU chunk's history (`DerivedRows::of`), against the
//! same rows counted by the host off the same history: through its accessors
//! (`EmulationRecord::alu_ops`) on every guest, and from the event streams it rebuilds
//! (`stream_derived_rows`) on fib. The device sizes the add chips' rows by the header, div/rem's
//! derived ADD rows among them.
//!
//! No record-parity guest divides, so two tests of their own hold the derived ADD rows where some
//! are: the chip-coverage guest, whose signed divisions on negative operands derive them, whole and
//! cut fine; and a reth block at a production chunk size, up to its first chunk with div/rem rows.

use std::sync::Arc;

use pico_vm::{
    chips::chips::alu::divrem::utils::derived_add_rows,
    compiler::riscv::opcode::Opcode,
    emulator::riscv::{
        history_dump::{stream_derived_rows, HostStreams},
        history_fill::DerivedRows,
        public_values::RecordFinalPvsState,
        record::{AluStream, EmulationRecord},
        record_slots::hold_records_unbounded,
        riscv_emulator::RiscvEmulator,
        sink::{HistorySink, Sink},
    },
    mle::machine::riscv::Kb,
};

use crate::{
    chip_coverage,
    record_parity::{opts, program, stdin, WHOLE},
    trace_source::history_run,
};

/// The header's rows as the host's accessors count them off the record's history.
fn accessor_rows(record: &EmulationRecord) -> DerivedRows {
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

/// The header's rows of `record`, or `None` for a record that is no CPU chunk. Each count the
/// host's accessors, and with `streams` its event streams, disagree on is a problem under `label`.
fn header_rows(
    label: &str,
    record: &EmulationRecord,
    streams: bool,
    problems: &mut Vec<String>,
) -> Option<DerivedRows> {
    if !record.is_cpu_chunk {
        return None;
    }
    let Some(view) = record.history_view() else {
        problems.push(format!("{label}: a CPU chunk has no history"));
        return None;
    };
    let header = DerivedRows::of(view.history, view.program);
    let at = format!("{label} chunk {}", view.history.chunk);
    let accessors = accessor_rows(record);
    if header != accessors {
        problems.push(format!(
            "{at}: the header counts {header:?}, the host's accessors {accessors:?}"
        ));
    }
    if streams {
        let streamed = stream_derived_rows(&HostStreams::of(record).events());
        if header != streamed {
            problems.push(format!(
                "{at}: the header counts {header:?}, the event streams {streamed:?}"
            ));
        }
    }
    Some(header)
}

/// One guest's CPU chunks; `streams` adds the event streams' count to the accessors'.
pub struct Check {
    streams: bool,
    problems: Vec<String>,
    checked: usize,
}

impl Check {
    pub fn new(streams: bool) -> Self {
        Self {
            streams,
            problems: Vec::new(),
            checked: 0,
        }
    }

    pub fn record(&mut self, label: &str, record: &EmulationRecord) {
        if header_rows(label, record, self.streams, &mut self.problems).is_some() {
            self.checked += 1;
        }
    }

    pub fn finish(mut self) -> Vec<String> {
        if self.checked == 0 {
            self.problems
                .push("no CPU chunk's header rows were checked".to_string());
        }
        self.problems
    }
}

#[test]
fn the_chip_coverage_header_rows_match_the_host() {
    crate::before_any_emulation();
    let mut problems = Vec::new();
    for chunk_size in [WHOLE, 1 << 10] {
        let label = format!("chip-coverage @ {chunk_size}");
        let (mut checked, mut divrem_add) = (0, 0);
        history_run(chip_coverage::elf(), &[], chunk_size, |record| {
            if let Some(rows) = header_rows(&label, &record, true, &mut problems) {
                checked += 1;
                divrem_add += rows.divrem_add;
            }
        });
        if checked == 0 {
            problems.push(format!("{label}: no CPU chunk was checked"));
        }
        if divrem_add == 0 {
            problems.push(format!(
                "{label}: no division derived an ADD row, so the count was held to nothing"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// reth-23993050 at a production chunk size, up to its first chunk with div/rem rows.
#[test]
fn the_header_rows_match_the_host_on_a_reth_chunk() {
    crate::before_any_emulation();
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/../perf/bench_data/rv64/");
    let read = |file: &str| {
        std::fs::read(format!("{data}{file}")).unwrap_or_else(|e| panic!("{data}{file}: {e}"))
    };
    let program = program(&read("reth-elf"));
    hold_records_unbounded();
    let mut emulator = RiscvEmulator::new_single::<Kb>(
        program.clone(),
        Arc::new(RecordFinalPvsState::default()),
        opts(1 << 22),
    )
    .with_sink(Sink::History(HistorySink::new(EmulationRecord::new(
        program,
    ))));
    emulator.write_stdin(&stdin(&[read("reth-23993050.bin")]));
    let mut problems = Vec::new();
    let (mut chunks, mut divrem_rows) = (0, 0);
    while divrem_rows == 0 {
        let report = emulator
            .emulate_batch(&mut |record: EmulationRecord| {
                if divrem_rows == 0
                    && header_rows("reth-23993050", &record, false, &mut problems).is_some()
                {
                    chunks += 1;
                    divrem_rows = record
                        .history_view()
                        .map_or(0, |view| view.history.chip_steps.divrem.len());
                }
            })
            .expect("emulate_batch");
        if report.done {
            break;
        }
    }
    if divrem_rows == 0 {
        problems.push(format!(
            "reth-23993050 ran {chunks} chunk(s) and none held a div/rem row"
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
