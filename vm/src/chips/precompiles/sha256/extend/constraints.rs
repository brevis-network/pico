use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::MemoryCols,
        gadgets::{
            addr_add::AddrAddGadget,
            u32::{
                add4_u32::Add4U32Gadget, rotate_right_u32::FixedRotateRightU32Gadget,
                shift_right_u32::FixedShiftRightU32Gadget, xor_u32::XorU32Gadget,
            },
        },
        precompiles::sha256::extend::{columns::ShaExtendCols, ShaExtendChip},
    },
    compiler::{riscv::opcode::ByteOpcode, word::Word},
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use core::borrow::Borrow;
use p3_air::Air;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::Matrix;
use std::iter::once;

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for ShaExtendChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        // Initialize columns.
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShaExtendCols<CB::Var> = (*local).borrow();

        // Assert that `is_real` is a bool.
        builder.assert_bool(local.is_real);

        // Receive the state.
        let receive_values = once(local.clk.into())
            .chain(local.w_ptr.map(Into::into))
            .chain(once(local.i.into()))
            .collect::<Vec<_>>();
        builder.looked(SymbolicLookup::new(
            receive_values,
            local.is_real.into(),
            LookupType::ShaExtend,
            LookupScope::Regional,
        ));

        // Send the next state, with incremented `local.i`.
        let send_values = once(local.clk.into() + CB::Expr::ONE)
            .chain(local.w_ptr.map(Into::into))
            .chain(once(local.i + CB::Expr::ONE))
            .collect::<Vec<_>>();
        builder.looking(SymbolicLookup::new(
            send_values,
            local.is_real.into(),
            LookupType::ShaExtend,
            LookupScope::Regional,
        ));

        // Check that `16 <= local.i < 64` holds.
        // This makes all the `AddrAddOperation`s below safe, as the increments will be bounded.
        builder.looking_byte(
            CB::Expr::from_canonical_u32(ByteOpcode::LTU as u32),
            CB::Expr::ONE,
            local.i - CB::Expr::from_canonical_u32(16),
            CB::Expr::from_canonical_u32(48),
            local.is_real,
        );

        let ptr = Word([
            local.w_ptr[0].into(),
            local.w_ptr[1].into(),
            local.w_ptr[2].into(),
            CB::Expr::ZERO,
        ]);

        // Evaluate the pointer `ptr + (i - 15) * 8`.
        AddrAddGadget::<CB::F>::eval(
            builder,
            ptr.clone(),
            Word::extend_expr::<CB>(
                (local.i - CB::F::from_canonical_u32(15)) * CB::F::from_canonical_u32(8),
            ),
            local.w_i_minus_15_ptr,
            local.is_real.into(),
        );

        // Read `w[i - 15]`.
        builder.eval_memory_access(
            local.chunk,
            local.clk,
            local.w_i_minus_15_ptr.value.map(Into::into),
            &local.w_i_minus_15,
            local.is_real,
        );

        // Check that `w[i - 15]` is an u32 value.
        let prev_value = local.w_i_minus_15.prev_value();
        let w_i_minus_15_prev_value_half_word = [prev_value[0], prev_value[1]];
        builder.assert_zero(prev_value[2]);
        builder.assert_zero(prev_value[3]);

        // Evaluate the pointer `ptr + (i - 2) * 8`.
        AddrAddGadget::<CB::F>::eval(
            builder,
            ptr.clone(),
            Word::extend_expr::<CB>(
                (local.i - CB::F::from_canonical_u32(2)) * CB::F::from_canonical_u32(8),
            ),
            local.w_i_minus_2_ptr,
            local.is_real.into(),
        );

        // Read `w[i - 2]`.
        builder.eval_memory_access(
            local.chunk,
            local.clk,
            local.w_i_minus_2_ptr.value.map(Into::into),
            &local.w_i_minus_2,
            local.is_real,
        );

        // Check that `w[i - 2]` is an u32 value.
        let prev_value = local.w_i_minus_2.prev_value();
        let w_i_minus_2_prev_value_half_word = [prev_value[0], prev_value[1]];
        builder.assert_zero(prev_value[2]);
        builder.assert_zero(prev_value[3]);

        // Evaluate the pointer `ptr + (i - 16) * 8`.
        AddrAddGadget::<CB::F>::eval(
            builder,
            ptr.clone(),
            Word::extend_expr::<CB>(
                (local.i - CB::F::from_canonical_u32(16)) * CB::F::from_canonical_u32(8),
            ),
            local.w_i_minus_16_ptr,
            local.is_real.into(),
        );

        // Read `w[i - 16]`.
        builder.eval_memory_access(
            local.chunk,
            local.clk,
            local.w_i_minus_16_ptr.value.map(Into::into),
            &local.w_i_minus_16,
            local.is_real,
        );

        // Check that `w[i - 16]` is an u32 value.
        let prev_value = local.w_i_minus_16.prev_value();
        let w_i_minus_16_prev_value_half_word = [prev_value[0], prev_value[1]];
        builder.assert_zero(prev_value[2]);
        builder.assert_zero(prev_value[3]);

        // Evaluate the pointer `ptr + (i - 7) * 8`.
        AddrAddGadget::<CB::F>::eval(
            builder,
            ptr.clone(),
            Word::extend_expr::<CB>(
                (local.i - CB::F::from_canonical_u32(7)) * CB::F::from_canonical_u32(8),
            ),
            local.w_i_minus_7_ptr,
            local.is_real.into(),
        );

        // Read `w[i - 7]`.
        builder.eval_memory_access(
            local.chunk,
            local.clk,
            local.w_i_minus_7_ptr.value.map(Into::into),
            &local.w_i_minus_7,
            local.is_real,
        );

        // Check that `w[i - 7]` is an u32 value.
        let prev_value = local.w_i_minus_7.prev_value();
        let w_i_minus_7_prev_value_half_word = [prev_value[0], prev_value[1]];
        builder.assert_zero(prev_value[2]);
        builder.assert_zero(prev_value[3]);

        // Compute `s0`.
        // w[i-15] rightrotate 7.
        FixedRotateRightU32Gadget::<CB::F>::eval(
            builder,
            w_i_minus_15_prev_value_half_word,
            7,
            local.w_i_minus_15_rr_7,
            local.is_real,
        );
        // w[i-15] rightrotate 18.
        FixedRotateRightU32Gadget::<CB::F>::eval(
            builder,
            w_i_minus_15_prev_value_half_word,
            18,
            local.w_i_minus_15_rr_18,
            local.is_real,
        );
        // w[i-15] rightshift 3.
        FixedShiftRightU32Gadget::<CB::F>::eval(
            builder,
            w_i_minus_15_prev_value_half_word,
            3,
            local.w_i_minus_15_rs_3,
            local.is_real,
        );
        // (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18)
        let s0_intermediate_result = XorU32Gadget::<CB::F>::eval(
            builder,
            local.w_i_minus_15_rr_7.value.map(Into::into),
            local.w_i_minus_15_rr_18.value.map(Into::into),
            local.s0_intermediate,
            local.is_real,
        );
        // s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
        let s0_result = XorU32Gadget::<CB::F>::eval(
            builder,
            s0_intermediate_result,
            local.w_i_minus_15_rs_3.value.map(Into::into),
            local.s0,
            local.is_real,
        );

        // Compute `s1`.
        // w[i-2] rightrotate 17.
        FixedRotateRightU32Gadget::<CB::F>::eval(
            builder,
            w_i_minus_2_prev_value_half_word,
            17,
            local.w_i_minus_2_rr_17,
            local.is_real,
        );
        // w[i-2] rightrotate 19.
        FixedRotateRightU32Gadget::<CB::F>::eval(
            builder,
            w_i_minus_2_prev_value_half_word,
            19,
            local.w_i_minus_2_rr_19,
            local.is_real,
        );
        // w[i-2] rightshift 10.
        FixedShiftRightU32Gadget::<CB::F>::eval(
            builder,
            w_i_minus_2_prev_value_half_word,
            10,
            local.w_i_minus_2_rs_10,
            local.is_real,
        );
        // (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19)
        let s1_intermediate_result = XorU32Gadget::<CB::F>::eval(
            builder,
            local.w_i_minus_2_rr_17.value.map(Into::into),
            local.w_i_minus_2_rr_19.value.map(Into::into),
            local.s1_intermediate,
            local.is_real,
        );
        // s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
        let s1_result = XorU32Gadget::<CB::F>::eval(
            builder,
            s1_intermediate_result,
            local.w_i_minus_2_rs_10.value.map(Into::into),
            local.s1,
            local.is_real,
        );

        // s2 := w[i-16] + s0 + w[i-7] + s1.
        Add4U32Gadget::<CB::F>::eval(
            builder,
            w_i_minus_16_prev_value_half_word.map(Into::into),
            s0_result,
            w_i_minus_7_prev_value_half_word.map(Into::into),
            s1_result,
            local.is_real,
            local.s2,
        );

        // The `s2_value_word` is the value to be written.
        let _s2_value_word = Word([
            local.s2.value[0].into(),
            local.s2.value[1].into(),
            CB::Expr::ZERO,
            CB::Expr::ZERO,
        ]);

        // Evaluate the pointer `ptr + i * 8`.
        AddrAddGadget::<CB::F>::eval(
            builder,
            ptr.clone(),
            Word::extend_expr::<CB>(local.i * CB::F::from_canonical_u32(8)),
            local.w_i_ptr,
            local.is_real.into(),
        );

        // Write `s2_value_word` into `w[i]`.
        builder.eval_memory_access(
            local.chunk,
            local.clk,
            local.w_i_ptr.value.map(Into::into),
            &local.w_i,
            local.is_real,
        );
    }
}
