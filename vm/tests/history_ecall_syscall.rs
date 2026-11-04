//! The ecall and RISC-V syscall chips' device traces built from the execution history, against the
//! host's built from the same history, under the fixed trace oracle's per-air rules: the ecall
//! trace in order, its tally columns compared on padding rows too, and the syscall trace a multiset
//! of rows, with the global trace its rows feed in order. Needs a card.
//!
//! One test per chip: it emulates record-parity guests and holds every CPU chunk's device context
//! to the host's, every chip that read the history with a real row having launched its history
//! kernel (`trace_oracle::generate_and_check`). Every history fill's device region is poisoned
//! before its copies, so a kernel reading a byte no copy wrote reads poison; the chip must have
//! compared real rows somewhere in the run.

#![cfg(feature = "cuda")]

use std::sync::{Mutex, Once, PoisonError};

use pico_vm::{
    chips::chips::riscv_ecall::traces::deferred_commit_tally,
    emulator::record::RecordBehavior,
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
use record_parity::GUESTS;
use trace_source::history_records;

static POISON_HISTORY: Once = Once::new();

/// The card is one card: the tests take turns.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// The chip named `chip` (air `air`) from the history, against the host on every CPU chunk of
/// `guests`. Returns the deferred commits the run's chunks tallied.
fn check_chip(chip: &str, air: usize, guests: &[&str]) -> u32 {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    POISON_HISTORY.call_once(poison::arm);
    init_mle_gpu_pool(MLE_GPU_DEVICE);
    let chips: Vec<MetaChip<Kb, RiscvChipType<Kb>>> = RiscvChipType::<Kb>::all_chips();
    let orchestrator = RiscvChipType::<Kb>::gpu_generate_extra_record_and_main_chips();

    let mut checked = 0usize;
    let mut real = 0usize;
    let mut history_reads = 0usize;
    let mut deferred_commits = 0u32;
    for guest_name in guests {
        let guest = GUESTS
            .iter()
            .find(|guest| guest.name == *guest_name)
            .unwrap_or_else(|| panic!("no guest {guest_name}"));
        for run in guest.runs() {
            history_records(guest.elf, &run, |record| {
                if !record.is_cpu_chunk {
                    return;
                }
                let chunk_index = record.chunk_index();
                deferred_commits += deferred_commit_tally(&record).0;
                let host = HostSide::build(&chips, &record);
                let chunk = prepare_chunk_shaped(&chips, record, false);
                let (verdict, _) =
                    trace_oracle::generate_and_check(&host, &orchestrator, &chunk, &[])
                        .unwrap_or_else(|failures| {
                            panic!(
                                "{guest_name} chunk {chunk_index}: {chip} from the history:\n{}",
                                trace_oracle::describe(&failures)
                            )
                        });
                let chunk_real = verdict.compared.get(&air).map_or(0, |report| report.real);
                // A reader with real rows and no history launch fails the check above, so the chip
                // read its real rows from the history wherever it is a reader that has some.
                if chunk_real > 0 && trace_oracle::HISTORY_READERS.contains(&chip) {
                    history_reads += 1;
                }
                checked += 1;
                real += chunk_real;
            });
        }
    }
    assert!(checked > 0, "{chip}: no CPU chunk was checked");
    assert!(
        real > 0,
        "{chip}: no checked chunk held a real row, so the history entry proved nothing"
    );
    assert!(
        history_reads > 0,
        "{chip}: no checked chunk read its real rows from the history"
    );
    println!(
        "{chip}: {checked} CPU chunk(s) equal from the history, {real} real row(s), \
         {deferred_commits} deferred commit(s)"
    );
    deferred_commits
}

/// Every guest's halt commits its deferred-proofs digest word by word, so the run's last chunks
/// carry a nonzero tally down their padding rows.
#[test]
fn ecall_from_the_history() {
    let deferred_commits = check_chip("Ecall", air_id::ECALL, &["fib", "aggregator"]);
    assert!(
        deferred_commits > 0,
        "no chunk tallied a deferred commit, so the running sums on padding rows proved nothing"
    );
}

/// fib sends no syscall to a precompile table; these two send many.
#[test]
fn syscall_riscv_from_the_history() {
    check_chip(
        "SyscallRiscv",
        air_id::SYSCALL_RISCV,
        &["ed25519", "poseidon2"],
    );
}
