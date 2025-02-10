use super::{
    columns::{MemoryInitializeFinalizeCols, NUM_MEMORY_INITIALIZE_FINALIZE_COLS},
    MemoryChipType, MemoryInitializeFinalizeChip,
};
use crate::{
    chips::gadgets::{
        field_range_check::bit_decomposition::FieldBitDecomposition, is_zero::IsZeroGadget,
    },
    compiler::word::Word,
    emulator::riscv::public_values::PublicValues,
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
    primitives::consts::MAX_NUM_PVS,
};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::array;

impl<F: Field> BaseAir<F> for MemoryInitializeFinalizeChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_INITIALIZE_FINALIZE_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for MemoryInitializeFinalizeChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryInitializeFinalizeCols<CB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &MemoryInitializeFinalizeCols<CB::Var> = (*next).borrow();

        builder.assert_bool(local.is_real);
        for i in 0..32 {
            builder.assert_bool(local.value[i]);
        }

        let mut byte1 = CB::Expr::ZERO;
        let mut byte2 = CB::Expr::ZERO;
        let mut byte3 = CB::Expr::ZERO;
        let mut byte4 = CB::Expr::ZERO;
        for i in 0..8 {
            byte1 += local.value[i].into() * CB::F::from_canonical_u8(1 << i);
            byte2 += local.value[i + 8].into() * CB::F::from_canonical_u8(1 << i);
            byte3 += local.value[i + 16].into() * CB::F::from_canonical_u8(1 << i);
            byte4 += local.value[i + 24].into() * CB::F::from_canonical_u8(1 << i);
        }
        let value = [byte1, byte2, byte3, byte4];

        if self.kind == MemoryChipType::Initialize {
            let mut values = vec![CB::Expr::ZERO, CB::Expr::ZERO, local.addr.into()];
            values.extend(value.clone().map(Into::into));

            // Send the "send interaction" to the global table.
            builder.looking(SymbolicLookup::new(
                vec![
                    CB::Expr::ZERO,
                    CB::Expr::ZERO,
                    local.addr.into(),
                    value[0].clone(),
                    value[1].clone(),
                    value[2].clone(),
                    value[3].clone(),
                    CB::Expr::ONE,
                    CB::Expr::ZERO,
                    CB::Expr::from_canonical_u8(LookupType::Memory as u8),
                ],
                local.is_real.into(),
                LookupType::Global,
                LookupScope::Regional,
            ));
        } else {
            let mut values = vec![
                local.chunk.into(),
                local.timestamp.into(),
                local.addr.into(),
            ];
            values.extend(value.clone());

            // Send the "receive interaction" to the global table.
            builder.looking(SymbolicLookup::new(
                vec![
                    local.chunk.into(),
                    local.timestamp.into(),
                    local.addr.into(),
                    value[0].clone(),
                    value[1].clone(),
                    value[2].clone(),
                    value[3].clone(),
                    CB::Expr::ZERO,
                    CB::Expr::ONE,
                    CB::Expr::from_canonical_u8(LookupType::Memory as u8),
                ],
                local.is_real.into(),
                LookupType::Global,
                LookupScope::Regional,
            ));
        }

        // Canonically decompose the address into bits so we can do comparisons.
        FieldBitDecomposition::<CB::F>::range_check(
            builder,
            local.addr,
            local.addr_bits,
            local.is_real.into(),
        );

        // Assertion for increasing address. We need to make two types of less-than assertions,
        // first we ned to assert that the addr < addr' when the next row is real. Then we need to
        // make assertions with regards to public values.
        //
        // If the chip is a `MemoryInitialize`:
        // - In the first row, we need to assert that previous_initialize_addr < addr.
        // - In the last real row, we need to assert that addr = last_initialize_addr.
        //
        // If the chip is a `MemoryFinalize`:
        // - In the first row, we need to assert that previous_finalize_addr < addr.
        // - In the last real row, we need to assert that addr = last_finalize_addr.

        // Assert that addr < addr' when the next row is real.
        builder
            .when_transition()
            .assert_eq(next.is_next_comp, next.is_real);
        next.lt_cols.eval(
            builder,
            &local.addr_bits.bits,
            &next.addr_bits.bits,
            next.is_next_comp,
        );

        // Assert that the real rows are all padded to the top.
        builder
            .when_transition()
            .when_not(local.is_real)
            .assert_zero(next.is_real);

        // Make assertions for the initial comparison.

        // We want to constrain that the `adrr` in the first row is larger than the previous
        // initialized/finalized address, unless the previous address is zero. Since the previous
        // address is either zero or constrained by a different chunk, we know it's an element of
        // the field, so we can get an element from the bit decomposition with no concern for
        // overflow.

        let local_addr_bits = local.addr_bits.bits;

        let public_values_array: [CB::Expr; MAX_NUM_PVS] =
            array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<CB::Expr>, CB::Expr> =
            public_values_array.as_slice().borrow();

        let prev_addr_bits = match self.kind {
            MemoryChipType::Initialize => &public_values.previous_initialize_addr_bits,
            MemoryChipType::Finalize => &public_values.previous_finalize_addr_bits,
        };

        // Since the previous address is either zero or constrained by a different chunk, we know
        // it's an element of the field, so we can get an element from the bit decomposition with
        // no concern for overflow.
        let prev_addr = prev_addr_bits
            .iter()
            .enumerate()
            .map(|(i, bit)| bit.clone() * CB::F::from_wrapped_u32(1 << i))
            .sum::<CB::Expr>();

        // Constrain the is_prev_addr_zero only in the first row.
        let is_first_row = builder.is_first_row();
        IsZeroGadget::<CB::F>::eval(builder, prev_addr, local.is_prev_addr_zero, is_first_row);

        // Constrain the inequality assertion in the first row.
        local.lt_cols.eval(
            builder,
            prev_addr_bits,
            &local_addr_bits,
            local.is_first_comp,
        );

        // Constrain the is_first_comp column.
        builder.assert_bool(local.is_first_comp);
        builder.when_first_row().assert_eq(
            local.is_first_comp,
            CB::Expr::ONE - local.is_prev_addr_zero.result,
        );

        // Ensure at least one real row.
        builder.when_first_row().assert_one(local.is_real);

        // Insure that there are no duplicate initializations by assuring there is exactly one
        // initialization event of the zero address. This is done by assuring that when the previous
        // address is zero, then the first row address is also zero, and that the second row is also
        // real, and the less than comparison is being made.
        builder
            .when_first_row()
            .when(local.is_prev_addr_zero.result)
            .assert_zero(local.addr);
        builder
            .when_first_row()
            .when(local.is_prev_addr_zero.result)
            .assert_one(next.is_real);
        // Ensure that in the address zero case the comparison is being made so that there is an
        // address bigger than zero being committed to.
        builder
            .when_first_row()
            .when(local.is_prev_addr_zero.result)
            .assert_one(next.is_next_comp);

        // Make assertions for specific types of memory chips.

        if self.kind == MemoryChipType::Initialize {
            builder
                .when(local.is_real)
                .assert_eq(local.timestamp, CB::F::ONE);
        }

        // Constraints related to register %x0.

        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the RISC-V spec.  To ensure that, we will constrain that the value is zero
        // whenever the `is_first_comp` flag is set to zero as well. This guarantees that the
        // presence of this flag asserts the initialization/finalization of %x0 to zero.
        //
        // **Remark**: it is up to the verifier to ensure that this flag is set to zero exactly
        // once, this can be constrained by the public values setting `previous_initialize_addr_bits` or
        // `previous_finalize_addr_bits` to zero.
        for i in 0..32 {
            builder
                .when_first_row()
                .when_not(local.is_first_comp)
                .assert_zero(local.value[i]);
        }

        // The last address is either:
        // - It's the last row and `is_real` is set to one.
        // - The flag `is_real` is set to one and the next `is_real` is set to zero.

        // Constrain the `is_last_addr` flag.
        builder.when_transition().assert_eq(
            local.is_last_addr,
            local.is_real * (CB::Expr::ONE - next.is_real),
        );

        // Make assertions for the final value. We need to connect the final valid address to the
        // corresponding `last_addr` value.
        let last_addr_bits = match self.kind {
            MemoryChipType::Initialize => &public_values.last_initialize_addr_bits,
            MemoryChipType::Finalize => &public_values.last_finalize_addr_bits,
        };

        // Constrain the last address bits to be equal to the corresponding `last_addr_bits` value.
        for (local_bit, pub_bit) in local.addr_bits.bits.iter().zip(last_addr_bits.iter()) {
            builder
                .when_last_row()
                .when(local.is_real)
                .assert_eq(*local_bit, pub_bit.clone());
            builder
                .when_transition()
                .when(local.is_last_addr)
                .assert_eq(*local_bit, pub_bit.clone());
        }
    }
}
