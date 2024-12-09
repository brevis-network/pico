use super::{columns::MemoryInitCols, MemoryGlobalChip};
use crate::{
    compiler::recursion::program::RecursionProgram,
    machine::{
        builder::{ChipBuilder, RecursionMemoryBuilder},
        chip::ChipBehavior,
        lookup::{LookupType, SymbolicLookup},
    },
    recursion::{
        air::Block,
        runtime::RecursionRecord,
        stark::utils::{next_power_of_two, par_for_each_row},
    },
};
use core::mem::size_of;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use std::borrow::{Borrow, BorrowMut};

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();

impl<F: PrimeField32> ChipBehavior<F> for MemoryGlobalChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "MemoryGlobalChip".to_string()
    }

    fn generate_main(
        &self,
        input: &RecursionRecord<F>,
        _: &mut RecursionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let nb_events = input.first_memory_record.len() + input.last_memory_record.len();
        let nb_rows = next_power_of_two(nb_events, self.fixed_log2_rows);
        let mut values = vec![F::ZERO; nb_rows * NUM_MEMORY_INIT_COLS];

        par_for_each_row(&mut values, NUM_MEMORY_INIT_COLS, |i, row| {
            if i >= nb_events {
                return;
            }
            let cols: &mut MemoryInitCols<F> = row.borrow_mut();

            if i < input.first_memory_record.len() {
                let (addr, value) = &input.first_memory_record[i];
                cols.addr = *addr;
                cols.timestamp = F::ZERO;
                cols.value = *value;
                cols.is_initialize = F::ONE;

                cols.is_real = F::ONE;
            } else {
                let (addr, timestamp, value) =
                    &input.last_memory_record[i - input.first_memory_record.len()];
                let last = i == nb_events - 1;
                let (next_addr, _, _) = if last {
                    &(F::ZERO, F::ZERO, Block::from(F::ZERO))
                } else {
                    &input.last_memory_record[i - input.first_memory_record.len() + 1]
                };
                cols.addr = *addr;
                cols.timestamp = *timestamp;
                cols.value = *value;
                cols.is_finalize = F::ONE;
                (cols.diff_16bit_limb, cols.diff_12bit_limb) = if !last {
                    compute_addr_diff(*next_addr, *addr, true)
                } else {
                    (F::ZERO, F::ZERO)
                };
                (cols.addr_16bit_limb, cols.addr_12bit_limb) =
                    compute_addr_diff(*addr, F::ZERO, false);

                cols.is_real = F::ONE;
                cols.is_range_check = F::from_bool(!last);
            }
        });

        RowMajorMatrix::new(values, NUM_MEMORY_INIT_COLS)
    }

    fn is_active(&self, chunk: &Self::Record) -> bool {
        !chunk.first_memory_record.is_empty() || !chunk.last_memory_record.is_empty()
    }
}

impl<F: Field> BaseAir<F> for MemoryGlobalChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

/// Computes the difference between the `addr` and `prev_addr` and returns the 16-bit limb and
/// 12-bit limbs of the difference.
///
/// The parameter `subtract_one` is expected to be `true` when `addr` and `prev_addr` are
/// consecutive addresses in the global memory table (we don't allow repeated addresses), and
/// `false` when this function is used to perform the 28-bit range check on the `addr` field.
pub fn compute_addr_diff<F: PrimeField32>(addr: F, prev_addr: F, subtract_one: bool) -> (F, F) {
    let diff = addr.as_canonical_u32() - prev_addr.as_canonical_u32() - subtract_one as u32;
    let diff_16bit_limb = diff & 0xffff;
    let diff_12bit_limb = (diff >> 16) & 0xfff;
    (
        F::from_canonical_u32(diff_16bit_limb),
        F::from_canonical_u32(diff_12bit_limb),
    )
}

impl<F: Field, AB> Air<AB> for MemoryGlobalChip<F>
where
    AB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();
        let next: &MemoryInitCols<AB::Var> = (*next).borrow();

        // Verify that is_initialize and is_finalize and 1-is_real are bool and that at most one
        // is true.
        builder.assert_bool(local.is_initialize);
        builder.assert_bool(local.is_finalize);
        builder.assert_bool(local.is_real);
        builder
            .assert_bool(local.is_initialize + local.is_finalize + (AB::Expr::ONE - local.is_real));
        builder.assert_bool(local.is_range_check);

        // Assert the is_initialize rows come before the is_finalize rows, and those come before the
        // padding rows.
        // The first row should be an initialize row.
        builder.when_first_row().assert_one(local.is_initialize);

        // After an initialize row, we should either have a finalize row, or another initialize row.
        builder
            .when_transition()
            .when(local.is_initialize)
            .assert_one(next.is_initialize + next.is_finalize);

        // After a finalize row, we should either have a finalize row, or a padding row.
        builder
            .when_transition()
            .when(local.is_finalize)
            .assert_one(next.is_finalize + (AB::Expr::ONE - next.is_real));

        // After a padding row, we should only have another padding row.
        builder
            .when_transition()
            .when(AB::Expr::ONE - local.is_real)
            .assert_zero(next.is_real);

        // The last row should be a padding row or a finalize row.
        builder
            .when_last_row()
            .assert_one(local.is_finalize + AB::Expr::ONE - local.is_real);

        // Ensure that the is_range_check column is properly computed.
        // The flag column `is_range_check` is set iff is_finalize is set AND next.is_finalize is
        // set.
        builder
            .when(local.is_range_check)
            .assert_one(local.is_finalize * next.is_finalize);
        builder
            .when_not(local.is_range_check)
            .assert_zero(local.is_finalize * next.is_finalize);

        // Send requests for the 28-bit range checks and ensure that the limbs are correctly
        // computed.
        builder.recursion_eval_range_check_28bits(
            next.addr - local.addr - AB::Expr::ONE,
            local.diff_16bit_limb,
            local.diff_12bit_limb,
            local.is_range_check,
        );

        builder.recursion_eval_range_check_28bits(
            local.addr,
            local.addr_16bit_limb,
            local.addr_12bit_limb,
            local.is_finalize,
        );

        builder.looking(SymbolicLookup::new(
            vec![
                local.timestamp.into(),
                local.addr.into(),
                local.value[0].into(),
                local.value[1].into(),
                local.value[2].into(),
                local.value[3].into(),
            ],
            local.is_initialize.into(),
            LookupType::Memory,
        ));
        builder.looked(SymbolicLookup::new(
            vec![
                local.timestamp.into(),
                local.addr.into(),
                local.value[0].into(),
                local.value[1].into(),
                local.value[2].into(),
                local.value[3].into(),
            ],
            local.is_finalize.into(),
            LookupType::Memory,
        ));
    }
}
