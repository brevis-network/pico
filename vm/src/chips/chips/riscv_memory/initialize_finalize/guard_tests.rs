//! The bounds a Finalize row puts on its address. Every dword an access touches ends its
//! chain in one Finalize row, so these bound every access: a row in the stack guard, or past
//! `2^32`, fails the AIR. Each row comes out of the chip's own `generate_main`, the second of two
//! events so that it is compared with a predecessor, and is evaluated on its own, with the
//! first-row, last-row and transition constraints off. The folder ignores lookups, so the bound
//! below `0x7800_0000`, a range check, is the end-to-end proof's to show.

use super::{MemoryChipType, MemoryInitializeFinalizeChip};
use crate::{
    chips::chips::riscv_memory::event::MemoryInitializeFinalizeEvent,
    emulator::riscv::record::EmulationRecord,
    machine::{chip::ChipBehavior, debug_folder::DebugConstraintFolder, septic::SepticDigest},
    primitives::{
        consts::MAX_NUM_PVS,
        layout::{HEAP_END, MEMORY_SIZE, STACK_BOTTOM},
    },
};
use p3_air::{Air, RowWindow};
use p3_field::{extension::QuinticTrinomialExtensionField, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;
type EF = QuinticTrinomialExtensionField<KoalaBear>;

/// The constraints a Finalize row for `addr`, after one for `0x1_0000`, violates.
fn failures(addr: u64) -> Vec<String> {
    let event = |addr| MemoryInitializeFinalizeEvent {
        addr,
        value: 0x1234,
        chunk: 1,
        timestamp: 8,
        used: 1,
    };
    let record = EmulationRecord {
        memory_finalize_events: vec![event(0x1_0000), event(addr)],
        ..Default::default()
    };
    let chip = MemoryInitializeFinalizeChip::<F>::new(MemoryChipType::Finalize);
    let trace = chip.generate_main(&record, &mut EmulationRecord::default());
    let row = trace.row_slice(1).expect("the second row").to_vec();
    let public_values = vec![F::ZERO; MAX_NUM_PVS];
    let dummy = [F::ZERO];
    let mut folder = DebugConstraintFolder::<F, EF> {
        preprocessed: RowWindow::from_two_rows(&dummy, &dummy),
        main: RowWindow::from_two_rows(&row, &row),
        global_cumulative_sum: SepticDigest::<F>::zero(),
        is_first_row: F::ZERO,
        is_last_row: F::ZERO,
        is_transition: F::ZERO,
        public_values: &public_values,
        failures: Vec::new(),
        scopes: Vec::new(),
        constraint_count: 0,
    };
    chip.eval(&mut folder);
    folder
        .failures
        .iter()
        .map(|(scopes, failure)| format!("{scopes:?} {failure:?}"))
        .collect()
}

/// The guard's edges, the stack and the top dword of memory are fine.
#[test]
fn a_finalize_row_outside_the_guard_satisfies_the_air() {
    for addr in [HEAP_END - 8, STACK_BOTTOM, MEMORY_SIZE - 8] {
        let failures = failures(addr);
        assert!(failures.is_empty(), "0x{addr:x}: {failures:?}");
    }
}

/// A dword in the stack guard, or past `2^32`, has no row.
#[test]
fn a_finalize_row_in_the_guard_or_past_2_32_fails_the_air() {
    for addr in [HEAP_END, STACK_BOTTOM - 8, 1 << 32, (1 << 32) + 0x1_0000] {
        assert!(!failures(addr).is_empty(), "0x{addr:x} satisfies the AIR");
    }
}
