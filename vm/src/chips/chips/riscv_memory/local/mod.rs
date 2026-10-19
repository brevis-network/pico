use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

#[derive(Default)]
pub struct MemoryLocalChip<F>(PhantomData<F>);

/// Tests for the three constraints a forged `MemoryLocal` entry would have to satisfy.
///
/// The chip labels the state a chunk inherits with a `clk` sentinel, and carries the real
/// `initial_clk` on every other interval. Those two shapes plus `initial_clk < final_clk` are
/// what a forged entry would have to satisfy — so each of them is
/// checked here against a tampered row.
///
/// `DebugConstraintFolder` is an `EmptyLookupBuilder`, so a failure reported here comes from the
/// algebraic constraints alone, never from a lookup that would have caught the tamper instead.
#[cfg(test)]
mod normalization_tests {
    use super::{
        columns::{MemoryLocalCols, NUM_MEMORY_LOCAL_INIT_COLS},
        MemoryLocalChip,
    };
    use crate::{
        chips::chips::events::{MemoryLocalEvent, MemoryRecord},
        emulator::riscv::record::EmulationRecord,
        machine::{chip::ChipBehavior, debug_folder::DebugConstraintFolder, septic::SepticDigest},
        primitives::consts::CHUNK_CLK_START,
    };
    use p3_air::{Air, RowWindow};
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing, PrimeField32};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use std::borrow::{Borrow, BorrowMut};

    type F = KoalaBear;
    type EF = BinomialExtensionField<KoalaBear, 4>;
    type Folder<'a> = DebugConstraintFolder<'a, F, EF>;

    /// One entry that starts in an earlier chunk (the sentinel shape) and one that starts in this
    /// chunk (the real-clk shape) — the two cases every constraint below has to separate.
    fn two_shape_trace() -> RowMajorMatrix<F> {
        let entry = |ic, iclk, fc, fclk| MemoryLocalEvent {
            addr: 0x2_0000,
            initial_mem_access: MemoryRecord {
                chunk: ic,
                timestamp: iclk,
                value: 0x1111_2222_3333_4444,
            },
            final_mem_access: MemoryRecord {
                chunk: fc,
                timestamp: fclk,
                value: 0x5555_6666_7777_8888,
            },
        };
        let record = EmulationRecord {
            cpu_local_memory_access: vec![
                entry(1, 9, 3, 40),               // starts earlier  -> sentinel
                entry(3, CHUNK_CLK_START, 3, 40), // starts here     -> real clk
            ],
            ..Default::default()
        };
        MemoryLocalChip::<F>::default().generate_main(&record, &mut EmulationRecord::default())
    }

    fn failures(row: &[F]) -> usize {
        let chip = MemoryLocalChip::<F>::default();
        let dummy_f = [F::ZERO];
        let mut folder = Folder {
            preprocessed: RowWindow::from_two_rows(&dummy_f, &dummy_f),
            main: RowWindow::from_two_rows(row, row),
            global_cumulative_sum: SepticDigest::<F>::zero(),
            is_first_row: F::ZERO,
            is_last_row: F::ZERO,
            is_transition: F::ONE,
            public_values: &[],
            failures: vec![],
            scopes: vec![],
            constraint_count: 0,
        };
        chip.eval(&mut folder);
        folder.failures.len()
    }

    fn honest_row() -> Vec<F> {
        let trace = two_shape_trace();
        assert_eq!(trace.width(), NUM_MEMORY_LOCAL_INIT_COLS);
        trace.values[..NUM_MEMORY_LOCAL_INIT_COLS].to_vec()
    }

    /// Both shapes coexist on an honest row, and the trace generator really does produce them:
    /// entry 0 gets the sentinel, entry 1 the real clk. Without this the tampers below could all
    /// be passing vacuously.
    #[test]
    fn both_shapes_hold_on_an_honest_row() {
        let row = honest_row();
        assert_eq!(failures(&row), 0, "honest row violates a constraint");

        let cols: &MemoryLocalCols<F> = row.as_slice().borrow();
        let earlier = &cols.memory_local_entries[0];
        let here = &cols.memory_local_entries[1];
        assert_eq!(earlier.initial_in_chunk, F::ZERO);
        assert_eq!(earlier.initial_clk_regional, F::ZERO, "sentinel expected");
        assert_eq!(here.initial_in_chunk, F::ONE);
        assert_eq!(
            here.initial_clk_regional,
            F::from_u32(CHUNK_CLK_START),
            "real initial_clk expected"
        );
    }

    /// Claiming the in-chunk shape for an interval that started earlier. This is the tamper that
    /// would let a forged entry carry a real clk while pointing its Global receive at another
    /// chunk — the combination that would let an entry claim an unearned start.
    #[test]
    fn mislabelling_an_earlier_start_as_in_chunk_is_rejected() {
        let mut row = honest_row();
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[0].initial_in_chunk = F::ONE;
        assert!(failures(&row) > 0);
    }

    /// An entry that starts in this chunk has to put its real `initial_clk` on the bus, not the
    /// sentinel: sharing the sentinel is what would make two intervals on one address
    /// indistinguishable there.
    #[test]
    fn in_chunk_entry_may_not_use_the_sentinel() {
        let mut row = honest_row();
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[1].initial_clk_regional = F::ZERO;
        assert!(failures(&row) > 0);
    }

    /// ...and conversely an entry that starts earlier may not put a real clk there.
    #[test]
    fn earlier_start_may_not_use_a_real_clk() {
        let mut row = honest_row();
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[0].initial_clk_regional = F::from_u32(9);
        assert!(failures(&row) > 0);
    }

    /// `initial_clk < final_clk` on the in-chunk shape, in both directions: equal timestamps
    /// (the entry whose two Global messages coincide) and a reversed interval.
    #[test]
    fn non_increasing_clk_on_an_in_chunk_entry_is_rejected() {
        for tamper in [F::from_u32(40), F::from_u32(41)] {
            let mut row = honest_row();
            let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
            cols.memory_local_entries[1].initial_clk = tamper;
            cols.memory_local_entries[1].initial_clk_regional = tamper;
            assert!(
                failures(&row) > 0,
                "accepted initial_clk={tamper:?} against final_clk=40"
            );
        }
    }

    /// The chunk must strictly advance on the sentinel shape, as an integer.
    ///
    /// This one rides on a byte-table lookup, not on an algebraic constraint, so the folder used
    /// above is structurally blind to it (`EmptyLookupBuilder` makes every lookup a no-op). What
    /// is checked here instead is the value that lookup would carry: a chunk that fails to
    /// advance underflows in the field and lands far outside a 16-bit table, so the byte-table
    /// multiset cannot balance.
    ///
    /// The same blindness applies to the range half of `initial_clk < final_clk`. The test above
    /// catches a tampered `initial_clk` through the decomposition equality
    /// (`diff == limb16 + hi9 * 2^16`), which *is* algebraic; a prover that also rewrites the
    /// limbs to match an underflowed diff is caught by their range checks, on the same argument
    /// as here.
    #[test]
    fn non_advancing_chunk_on_a_sentinel_entry_underflows_its_range_check() {
        let row = honest_row();
        let cols: &MemoryLocalCols<F> = row.as_slice().borrow();
        let entry = &cols.memory_local_entries[0];
        assert_eq!(
            entry.initial_in_chunk,
            F::ZERO,
            "entry 0 must be the sentinel shape for this test to mean anything"
        );

        // Honest: chunk 1 -> 3, so the lookup carries 1 and the table has it.
        let honest = entry.final_chunk - entry.initial_chunk - F::ONE;
        assert!(honest.as_canonical_u32() < (1 << 16));

        // Equal chunks: the lookup would carry -1, i.e. p-1.
        let stalled = entry.initial_chunk - entry.initial_chunk - F::ONE;
        assert!(stalled.as_canonical_u32() >= (1 << 16));

        // Going backwards is worse still, and lands outside for the same reason.
        let backwards = entry.initial_chunk - entry.final_chunk - F::ONE;
        assert!(backwards.as_canonical_u32() >= (1 << 16));
    }

    /// One fresh entry (zero initial state, outside the default record's empty image) next to
    /// an inherited one: the trace generator clears `has_initial` on the first only, and the
    /// row satisfies every constraint including G4.
    fn fresh_and_inherited_row() -> Vec<F> {
        let entry = |ic, iclk, iv| MemoryLocalEvent {
            addr: 0x2_0000,
            initial_mem_access: MemoryRecord {
                chunk: ic,
                timestamp: iclk,
                value: iv,
            },
            final_mem_access: MemoryRecord {
                chunk: 3,
                timestamp: 40,
                value: 0x5555_6666_7777_8888,
            },
        };
        let record = EmulationRecord {
            cpu_local_memory_access: vec![
                entry(0, 0, 0),                     // fresh: first touch, starts at zero
                entry(1, 9, 0x1111_2222_3333_4444), // inherited from chunk 1
            ],
            ..Default::default()
        };
        let trace =
            MemoryLocalChip::<F>::default().generate_main(&record, &mut EmulationRecord::default());
        trace.values[..NUM_MEMORY_LOCAL_INIT_COLS].to_vec()
    }

    #[test]
    fn fresh_entry_declares_and_inherited_entry_receives() {
        let row = fresh_and_inherited_row();
        assert_eq!(failures(&row), 0, "honest row violates a constraint");
        let cols: &MemoryLocalCols<F> = row.as_slice().borrow();
        assert_eq!(cols.memory_local_entries[0].has_initial, F::ZERO);
        assert_eq!(cols.memory_local_entries[1].has_initial, F::ONE);
    }

    /// G4: an entry that does not receive its initial state may only declare zero, limb by
    /// limb. Claiming an inherited (nonzero) initial value while declaring is what would let a
    /// prover invent a predecessor state.
    #[test]
    fn declaring_entry_may_not_carry_a_nonzero_initial_value() {
        for limb in 0..4 {
            let mut row = fresh_and_inherited_row();
            let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
            cols.memory_local_entries[0].initial_value.0[limb] = F::ONE;
            assert!(failures(&row) > 0, "limb {limb}");
        }
        // The same entry with `has_initial = 1` is free to carry it (the Global receive binds
        // it then), so the tamper above is caught by G4 and not by something else.
        let mut row = fresh_and_inherited_row();
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[0].has_initial = F::ONE;
        cols.memory_local_entries[0].initial_value.0[0] = F::ONE;
        assert_eq!(failures(&row), 0);
    }

    /// G1: the receive multiplicity is boolean.
    #[test]
    fn has_initial_must_be_boolean() {
        let mut row = fresh_and_inherited_row();
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[1].has_initial = F::from_u32(2);
        assert!(failures(&row) > 0);
    }

    /// G2: a padding entry may not receive. Only `has_initial` is set, so the G4 gate
    /// (`is_real - has_initial = -1`) is nonzero on an all-zero initial value and would not
    /// fire by itself; the failure has to come from G2.
    #[test]
    fn padding_may_not_receive_an_initial_state() {
        let mut row = vec![F::ZERO; NUM_MEMORY_LOCAL_INIT_COLS];
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[2].has_initial = F::ONE;
        assert!(failures(&row) > 0);
    }

    /// A padding entry may not claim the in-chunk shape: `initial_in_chunk` doubles as a
    /// degree-1 lookup multiplicity, so it has to be zero wherever `is_real` is.
    ///
    /// The clk columns are set so the gap decomposition it un-gates is *satisfied*
    /// (`final_clk - initial_clk - 1 == 0` with zero limbs). Without that the tamper also breaks
    /// the range check, and this test would keep passing with its own target constraint deleted
    /// -- which is what it did before, and what `failures()` returning a bare count cannot show.
    #[test]
    fn padding_may_not_claim_the_in_chunk_shape() {
        let mut row = vec![F::ZERO; NUM_MEMORY_LOCAL_INIT_COLS];
        assert_eq!(failures(&row), 0, "an all-zero padding row must be valid");
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        let slot = &mut cols.memory_local_entries[0];
        slot.initial_in_chunk = F::ONE;
        slot.final_clk = F::ONE;
        assert!(failures(&row) > 0);
    }
}
