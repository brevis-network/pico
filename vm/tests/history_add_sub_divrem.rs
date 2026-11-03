//! The add, addw, sub, subw and div/rem chips' device traces built from the execution history,
//! against the host's built from the same history, under the fixed trace oracle's per-air rules:
//! each of the five is a multiset of rows with its opcode flags' sum (div/rem: `is_real`) telling
//! real rows from padding, so the order the device splits the add and sub lists in, and appends
//! div/rem's derived ADD rows in, proves the same trace. Needs a card.
//!
//! One test per chip: it emulates fib, and the chip-coverage guest, whose divisions derive ADD
//! rows, and holds every CPU chunk's device context to the host's, every chip that read the history
//! with a real row having launched its history kernel (`trace_oracle::generate_and_check`). Every
//! history fill's device region is poisoned before its copies, so a kernel reading a byte no copy
//! wrote reads poison; the chip must have compared real rows somewhere in the run, the add chip
//! derived ones among them.

#![cfg(feature = "cuda")]

use std::sync::{Mutex, Once, PoisonError};

use pico_vm::{
    emulator::{
        record::RecordBehavior,
        riscv::{history_fill::DerivedRows, record::EmulationRecord},
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::MetaChip,
    mle::machine::{
        riscv::{air_id, init_mle_gpu_pool, prepare_chunk_shaped, Kb, MLE_GPU_DEVICE},
        trace_oracle::{self, poison, HostSide},
    },
};

// Only the guests and their runs.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
#[path = "common/trace_source.rs"]
mod trace_source;
use record_parity::{GUESTS, WHOLE};
use trace_source::{history_records, history_run};

/// Every RISC-V chip family, div/rem with derived ADD rows among them, in one chunk of [`WHOLE`].
const CHIP_COVERAGE_ELF: &[u8] = include_bytes!("../../perf/bench_data/rv64/chip-coverage-elf");

static POISON_HISTORY: Once = Once::new();

/// The card is one card: the tests take turns.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Every record of the runs the family is held to: fib's, at every chunk size its runs take, and
/// the chip-coverage guest's.
fn each_record(mut on_record: impl FnMut(&str, EmulationRecord)) {
    let fib = GUESTS
        .iter()
        .find(|guest| guest.name == "fib")
        .expect("no guest fib");
    for run in fib.runs() {
        history_records(fib.elf, &run, |record| on_record("fib", record));
    }
    history_run(CHIP_COVERAGE_ELF, &[], WHOLE, |record| {
        on_record("chip-coverage", record)
    });
}

/// The chip named `chip` (air `air`) from the history, against the host on every CPU chunk of
/// [`each_record`]. Returns the derived ADD rows the checked chunks' histories hold.
fn check_chip(chip: &str, air: usize) -> usize {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    POISON_HISTORY.call_once(poison::arm);
    init_mle_gpu_pool(MLE_GPU_DEVICE);
    let chips: Vec<MetaChip<Kb, RiscvChipType<Kb>>> = RiscvChipType::<Kb>::all_chips();
    let orchestrator = RiscvChipType::<Kb>::gpu_generate_extra_record_and_main_chips();

    let mut checked = 0usize;
    let mut real = 0usize;
    let mut derived = 0usize;
    each_record(|guest, record| {
        if !record.is_cpu_chunk {
            return;
        }
        let chunk_index = record.chunk_index();
        derived += record.history.as_ref().map_or(0, |history| {
            DerivedRows::of(history, &record.program).divrem_add as usize
        });
        let host = HostSide::build(&chips, &record);
        let chunk = prepare_chunk_shaped(&chips, record, false);
        let (verdict, _) = trace_oracle::generate_and_check(&host, &orchestrator, &chunk, &[])
            .unwrap_or_else(|failures| {
                panic!(
                    "{guest} chunk {chunk_index}: {chip} from the history:\n{}",
                    trace_oracle::describe(&failures)
                )
            });
        checked += 1;
        real += verdict.compared.get(&air).map_or(0, |report| report.real);
    });
    assert!(checked > 0, "{chip}: no CPU chunk was checked");
    assert!(
        real > 0,
        "{chip}: no checked chunk held a real row, so the history entry proved nothing"
    );
    println!(
        "{chip}: {checked} CPU chunk(s) equal from the history, {real} real row(s), {derived} \
         derived ADD row(s) in their histories"
    );
    derived
}

#[test]
fn add_from_the_history() {
    assert!(
        check_chip("Add", air_id::ADD) > 0,
        "no checked chunk derived an ADD row from a division, so the append proved nothing"
    );
}

#[test]
fn addw_from_the_history() {
    check_chip("Addw", air_id::ADDW);
}

#[test]
fn sub_from_the_history() {
    check_chip("Sub", air_id::SUB);
}

#[test]
fn subw_from_the_history() {
    check_chip("Subw", air_id::SUBW);
}

#[test]
fn divrem_from_the_history() {
    check_chip("DivRem", air_id::DIVREM);
}
