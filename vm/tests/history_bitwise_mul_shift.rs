//! The mul, bitwise, shift-left and shift-right chips' device traces built from the execution
//! history, against the host's built from the same history, under the fixed trace oracle's per-air
//! rules: each of the four is a multiset of rows with its opcode flags' sum telling real rows from
//! padding, so the history's list order proves the same trace. Needs a card.
//!
//! One test per chip: it emulates the chip-coverage guest, which runs every opcode of the four, and
//! fib, and holds every CPU chunk's device context to the host's, every chip that read the history
//! with a real row having launched its history kernel (`trace_oracle::generate_and_check`). Every
//! history fill's device region is poisoned before its copies, so a kernel reading a byte no copy
//! wrote reads poison; the chip must have compared real rows somewhere in the run.

#![cfg(feature = "cuda")]

use std::sync::{Mutex, Once, PoisonError};

use pico_vm::{
    emulator::{record::RecordBehavior, riscv::record::EmulationRecord},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::MetaChip,
    mle::machine::{
        riscv::{air_id, init_mle_gpu_pool, prepare_chunk_shaped, Kb, MLE_GPU_DEVICE},
        trace_oracle::{self, poison, HostSide},
    },
};

// Only the guests, their runs and the program, stdin and options builders.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
use record_parity::{FIB_ELF, GUESTS, WHOLE};
#[path = "common/chip_coverage.rs"]
mod chip_coverage;
#[path = "common/trace_source.rs"]
mod trace_source;
use trace_source::{history_records, history_run};

static POISON_HISTORY: Once = Once::new();

/// The card is one card: the tests take turns.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// The chip named `chip` (air `air`) from the history, against the host on every CPU chunk of the
/// chip-coverage guest and of fib's runs.
fn check_chip(chip: &str, air: usize) {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    POISON_HISTORY.call_once(poison::arm);
    init_mle_gpu_pool(MLE_GPU_DEVICE);
    let chips: Vec<MetaChip<Kb, RiscvChipType<Kb>>> = RiscvChipType::<Kb>::all_chips();
    let orchestrator = RiscvChipType::<Kb>::gpu_generate_extra_record_and_main_chips();

    let mut checked = 0usize;
    let mut real = 0usize;
    let mut check = |name: &str, record: EmulationRecord| {
        if !record.is_cpu_chunk {
            return;
        }
        let chunk_index = record.chunk_index();
        let host = HostSide::build(&chips, &record);
        let chunk = prepare_chunk_shaped(&chips, record, false);
        let (verdict, _) = trace_oracle::generate_and_check(&host, &orchestrator, &chunk, &[])
            .unwrap_or_else(|failures| {
                panic!(
                    "{name} chunk {chunk_index}: {chip} from the history:\n{}",
                    trace_oracle::describe(&failures)
                )
            });
        checked += 1;
        real += verdict.compared.get(&air).map_or(0, |report| report.real);
    };
    history_run(chip_coverage::elf(), &[], WHOLE, |record| {
        check("chip-coverage", record)
    });
    let fib = GUESTS
        .iter()
        .find(|guest| guest.name == "fib")
        .expect("the fib guest");
    for run in fib.runs() {
        history_records(FIB_ELF, &run, |record| check("fib", record));
    }
    assert!(checked > 0, "{chip}: no CPU chunk was checked");
    assert!(
        real > 0,
        "{chip}: no checked chunk held a real row, so the history entry proved nothing"
    );
    println!("{chip}: {checked} CPU chunk(s) equal from the history, {real} real row(s)");
}

#[test]
fn mul_from_the_history() {
    check_chip("Mul", air_id::MUL);
}

#[test]
fn bitwise_from_the_history() {
    check_chip("Bitwise", air_id::BITWISE);
}

#[test]
fn shift_left_from_the_history() {
    check_chip("ShiftLeft", air_id::SLL);
}

#[test]
fn shift_right_from_the_history() {
    check_chip("ShiftRight", air_id::SR);
}
