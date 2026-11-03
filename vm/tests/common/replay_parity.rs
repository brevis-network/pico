//! The pipeline's replay workers against the serial interpreter, record by record, including
//! each CPU chunk's execution history. The comparison spans recovery, deferred records and
//! postprocessing.

use std::sync::{Arc, Mutex, PoisonError};

use pico_vm::{
    emulator::riscv::{
        public_values::RecordFinalPvsState,
        record::EmulationRecord,
        record_digest::{field_digests, is_compared, FieldDigest},
        record_slots::hold_records_unbounded,
        riscv_emulator::RiscvEmulator,
    },
    mle::machine::riscv::{emulate_with_pipeline_streaming, Kb},
};

use crate::record_parity::{opts, program, stdin, workers, GUESTS};

/// The pipeline takes its snapshot memory from one process-wide pool, so runs go one at a time.
static PIPELINE: Mutex<()> = Mutex::new(());

/// What a record is compared by, and what it holds beside that.
struct Reduced {
    cpu: bool,
    fields: Vec<FieldDigest>,
    history: Option<u64>,
    steps: usize,
    additions: usize,
}

fn reduce(record: &EmulationRecord) -> Reduced {
    Reduced {
        cpu: record.is_cpu_chunk,
        fields: field_digests(record)
            .into_iter()
            .filter(|(field, _, _)| is_compared(field))
            .collect(),
        history: record.history.as_ref().map(|history| history.digest()),
        steps: record
            .history
            .as_ref()
            .map_or(0, |history| history.steps.len()),
        additions: record.add_events.len(),
    }
}

/// The problems of one record of each path.
fn compare(serial: &Reduced, pipelined: &Reduced, found: &mut Vec<String>) {
    if let Some(((field, _, at_serial), (_, _, at_pipeline))) = serial
        .fields
        .iter()
        .zip(&pipelined.fields)
        .find(|(left, right)| left != right)
    {
        found.push(format!(
            "{field}: {at_serial:016x} by the interpreter, {at_pipeline:016x} by the pipeline"
        ));
    }
    if serial.fields.len() != pipelined.fields.len() {
        found.push(format!(
            "{} compared field(s) by the interpreter, {} by the pipeline",
            serial.fields.len(),
            pipelined.fields.len()
        ));
    }
    for (path, record) in [("interpreter", serial), ("pipeline", pipelined)] {
        let carries = record.cpu;
        if record.history.is_some() != carries {
            found.push(format!(
                "the {path}'s {} record {} a history",
                if record.cpu { "chunk" } else { "deferred" },
                if carries { "lacks" } else { "carries" }
            ));
        }
        if record.additions > 0 {
            found.push(format!(
                "the {path}'s record holds {} augmentation row(s) before augmentation",
                record.additions
            ));
        }
    }
    if serial.history != pipelined.history {
        found.push(format!(
            "history digest {:016x?} by the interpreter, {:016x?} by the pipeline",
            serial.history, pipelined.history
        ));
    }
}

/// Every run of the guest called `name` in [`GUESTS`], down both paths.
pub fn check(name: &str) {
    let guest = GUESTS
        .iter()
        .find(|guest| guest.name == name)
        .unwrap_or_else(|| panic!("no guest {name}"));
    let _one_at_a_time = PIPELINE.lock().unwrap_or_else(PoisonError::into_inner);
    hold_records_unbounded();
    let mut problems = Vec::new();
    let (mut steps, mut multi_chunk_runs) = (0, 0);
    for run in guest.runs() {
        let label = format!("{name} @ {}", run.chunk_size);
        let program = program(guest.elf);
        let stdin = stdin(&run.stdin);
        let opts = opts(run.chunk_size);

        let mut serial = Vec::new();
        let mut emulator = RiscvEmulator::new_single::<Kb>(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
            opts,
        );
        emulator.write_stdin(&stdin);
        loop {
            let report = emulator
                .emulate_batch(&mut |record: EmulationRecord| serial.push(reduce(&record)))
                .unwrap_or_else(|err| panic!("[{label}] the interpreter: {err}"));
            if report.done {
                break;
            }
        }

        let mut pipelined = Vec::new();
        emulate_with_pipeline_streaming(program, &stdin, opts, workers(), |record| {
            pipelined.push(reduce(&record));
        })
        .unwrap_or_else(|err| panic!("[{label}] the pipeline: {err:?}"));

        if serial.len() != pipelined.len() {
            problems.push(format!(
                "[{label}] {} record(s) by the interpreter, {} by the pipeline",
                serial.len(),
                pipelined.len()
            ));
        }
        for (index, (serial, pipelined)) in serial.iter().zip(&pipelined).enumerate() {
            let mut found = Vec::new();
            compare(serial, pipelined, &mut found);
            problems.extend(
                found
                    .into_iter()
                    .map(|problem| format!("[{label} record {index}] {problem}")),
            );
        }
        let chunks = pipelined.iter().filter(|record| record.cpu).count();
        steps += pipelined.iter().map(|record| record.steps).sum::<usize>();
        multi_chunk_runs += usize::from(chunks > 1);
        println!(
            "{label}: {} record(s), {chunks} chunk(s), history",
            pipelined.len()
        );
    }
    // The comparison says nothing without steps, and nothing about recovery without a worker
    // replaying more than one chunk.
    if steps == 0 {
        problems.push("no step written in any chunk".to_string());
    }
    if multi_chunk_runs == 0 {
        problems.push("no run cut more than one chunk".to_string());
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
