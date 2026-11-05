//! History readers agree with generated less-than rows, the commit tally and batched emulation.

use std::{borrow::BorrowMut, collections::BTreeMap, sync::Arc};

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_vm::{
    chips::chips::riscv_ecall::traces::commit_tally,
    compiler::word::Word,
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            public_values::{PublicValues, RecordFinalPvsState},
            record::EmulationRecord,
            record_slots::hold_records_unbounded,
            riscv_emulator::RiscvEmulator,
        },
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{chip::ChipBehavior, estimator::EventSizeCapture},
    mle::machine::{
        riscv::{augmented_record, Kb},
        shape::mle_natural_heights,
    },
    primitives::consts::{DIGEST_SIZE, LT_DATAPAR},
};

#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
use record_parity::{opts, program, stdin, Guest, Run, GUESTS};

#[derive(Debug, PartialEq)]
struct Reading {
    public_values: Vec<u32>,
    /// How many COMMIT and COMMIT_DEFERRED_PROOFS ecalls ran, and their mask (`commit_tally`).
    tally: (u32, u32),
    natural: BTreeMap<String, usize>,
    heights: Vec<(String, usize)>,
    /// The less-than trace's value slots that are not padding: one per operation it proves.
    less_than_ops: usize,
    estimate: String,
    branches: usize,
    stats: BTreeMap<String, usize>,
}

fn public_values_without_chunk_counters(record: &EmulationRecord) -> Vec<u32> {
    let mut values = record.public_values::<Kb>();
    let public_values: &mut PublicValues<Word<Kb>, Kb> = values.as_mut_slice().borrow_mut();
    // Deferred records inserted at batch boundaries change these counters.
    public_values.chunk = Kb::ZERO;
    public_values.execution_chunk = Kb::ZERO;
    values.iter().map(PrimeField32::as_canonical_u32).collect()
}

fn read(record: &EmulationRecord) -> Reading {
    let chips = RiscvChipType::<Kb>::all_chips();
    let augmented = augmented_record(&chips, record);
    let less_than = chips
        .iter()
        .find(|chip| chip.name() == "LessThan")
        .expect("the less-than chip");
    let trace = less_than.generate_main(&augmented, &mut EmulationRecord::default());
    let less_than_ops = trace
        .values
        .chunks(trace.width / LT_DATAPAR)
        .filter(|slot| slot.iter().any(|cell| *cell != Kb::ZERO))
        .count();
    Reading {
        public_values: public_values_without_chunk_counters(&augmented),
        tally: commit_tally(&augmented),
        natural: mle_natural_heights(&augmented),
        heights: RiscvChipType::<Kb>::riscv_heights(&augmented),
        less_than_ops,
        estimate: format!("{:?}", EventSizeCapture::snapshot(record, "kb").estimate()),
        stats: record.stats().into_iter().collect(),
        branches: record
            .history
            .as_ref()
            .expect("a CPU history")
            .chip_steps
            .branch
            .len(),
    }
}

/// The problems of one reading on its own: a less-than height that is not its trace's.
fn check_reading(arm: &str, reading: &Reading, found: &mut Vec<String>) {
    let rows = reading.less_than_ops.div_ceil(LT_DATAPAR);
    for (reader, height) in [
        (
            "mle_natural_heights",
            reading.natural.get("LessThan").copied(),
        ),
        (
            "riscv_heights",
            reading
                .heights
                .iter()
                .find(|(chip, _)| chip == "LessThan")
                .map(|&(_, height)| height),
        ),
    ] {
        if height != Some(rows) {
            found.push(format!(
                "{arm}: {reader} gives LessThan {height:?} rows, its trace holds {rows}"
            ));
        }
    }
}

#[derive(Debug, PartialEq)]
struct RunReading {
    records: Vec<(bool, Vec<u32>, usize)>,
    readings: Vec<Reading>,
    final_cycle: u64,
}

fn batches(guest: &Guest, run: &Run, batch_size: u32) -> RunReading {
    let program = program(guest.elf);
    let opts = EmulatorOpts {
        cost_estimator: true,
        chunk_batch_size: batch_size,
        ..opts(run.chunk_size)
    };
    hold_records_unbounded();
    let mut emulator =
        RiscvEmulator::new_single::<Kb>(program, Arc::new(RecordFinalPvsState::default()), opts);
    emulator.write_stdin(&stdin(&run.stdin));
    let mut out = RunReading {
        records: Vec::new(),
        readings: Vec::new(),
        final_cycle: 0,
    };
    loop {
        let mut expected_estimates = Vec::new();
        let mut chunks = 0;
        let report = emulator
            .emulate_batch(&mut |record: EmulationRecord| {
                expected_estimates.push(EventSizeCapture::snapshot(&record, "kb").estimate());
                if record.is_cpu_chunk {
                    out.records.push((
                        record.is_cpu_chunk,
                        public_values_without_chunk_counters(&record),
                        record.cpu_steps().len(),
                    ));
                    assert!(
                        !record.cpu_steps().is_empty(),
                        "an emitted CPU chunk holds steps"
                    );
                    out.readings.push(read(&record));
                    chunks += 1;
                } else {
                    assert!(record.history.is_none());
                    assert!(record.cpu_steps().is_empty());
                }
            })
            .expect("emulate_batch");
        assert_eq!(
            report.host_cycle_estimator.as_ref(),
            Some(&expected_estimates)
        );
        assert!(
            report.current_cycle > out.final_cycle,
            "a batch advances the clock"
        );
        out.final_cycle = report.current_cycle;
        if report.done {
            return out;
        }
        assert_eq!(
            emulator.state.current_chunk - report.start_chunk,
            batch_size,
            "a nonfinal batch crosses its chunk quota"
        );
        assert_eq!(chunks, batch_size, "a nonfinal batch cuts after its quota");
    }
}

fn check(name: &str) {
    let guest = GUESTS
        .iter()
        .find(|guest| guest.name == name)
        .unwrap_or_else(|| panic!("no guest {name}"));
    let mut branches = 0;
    for run in guest.runs() {
        let one = batches(guest, &run, 1);
        let two = batches(guest, &run, 2);
        assert_eq!(one, two, "{name} @ {}: changing batch size", run.chunk_size);
        assert!(!one.readings.is_empty(), "at least one CPU chunk");
        let mut found = Vec::new();
        let mut tally = (0, 0);
        for reading in &one.readings {
            check_reading("history", reading, &mut found);
            tally.0 += reading.tally.0;
            tally.1 += reading.tally.1;
            branches += reading.branches;
        }
        let words = DIGEST_SIZE as u32;
        assert_eq!(
            tally,
            (2 * words, (1 << (2 * words)) - 1),
            "the commits a guest makes before it halts"
        );
        assert!(found.is_empty(), "{}", found.join("\n"));
        println!(
            "{name} @ {}: {} CPU chunks, {} records, cycle {}",
            run.chunk_size,
            one.readings.len(),
            one.records.len(),
            one.final_cycle
        );
    }
    assert!(branches > 0, "branch comparisons are exercised");
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
fn poseidon2() {
    check("poseidon2");
}

#[test]
fn aggregator() {
    check("aggregator");
}

#[test]
fn bls12381_fp() {
    check("bls12381-fp");
}

#[test]
fn sha2() {
    check("sha2");
}

#[test]
fn sha3() {
    check("sha3");
}

#[test]
fn tiny_keccak() {
    check("tiny-keccak");
}

#[test]
fn k256() {
    check("k256");
}

#[test]
fn bn254_fp() {
    check("bn254-fp");
}

#[test]
fn bls12381_ws() {
    check("bls12381-ws");
}

#[test]
fn bn254_ws() {
    check("bn254-ws");
}
