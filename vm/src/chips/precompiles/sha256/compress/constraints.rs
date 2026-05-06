use super::{columns::ShaCompressCols, ShaCompressChip, SHA_COMPRESS_K};
use crate::{
    chips::gadgets::{
        addr_add::AddrAddGadget,
        u32::{
            add5_u32::Add5U32Gadget, add_u32::AddU32Gadget, and_u32::AndU32Gadget,
            not_u32::NotU32Gadget, rotate_right_u32::FixedRotateRightU32Gadget,
            xor_u32::XorU32Gadget,
        },
    },
    compiler::word::Word,
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, ChipWordBuilder, RiscVMemoryBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
    primitives::consts::u32_to_half_word,
};
use core::borrow::Borrow;
use p3_air::Air;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::Matrix;
use std::iter::once;

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for ShaCompressChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShaCompressCols<CB::Var> = (*local).borrow();

        self.eval_control_flow_flags(builder, local);
        self.eval_memory(builder, local);
        self.eval_compression_ops(builder, local);
        self.eval_finalize_ops(builder, local);
    }
}

impl<F: PrimeField32> ShaCompressChip<F> {
    fn eval_control_flow_flags<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &ShaCompressCols<CB::Var>,
    ) {
        // Assert that is_real is a bool.
        builder.assert_bool(local.is_real);

        let mut computed_index = CB::Expr::ZERO;

        // Verify that all of the octet columns are bool, and exactly one is true.
        let mut octet_sum = CB::Expr::ZERO;
        for i in 0..8 {
            builder.assert_bool(local.octet[i]);
            octet_sum = octet_sum.clone() + local.octet[i].into();
            computed_index = computed_index.clone()
                + local.octet[i].into() * CB::Expr::from_canonical_u32(i as u32);
        }
        builder.assert_one(octet_sum);

        // Verify that all of the octet_num columns are bool, and exactly one is true.
        let mut octet_num_sum = CB::Expr::ZERO;
        for i in 0..10 {
            builder.assert_bool(local.octet_num[i]);
            octet_num_sum = octet_num_sum.clone() + local.octet_num[i].into();
            computed_index = computed_index.clone()
                + local.octet_num[i].into() * CB::Expr::from_canonical_u32(8 * i as u32);
        }
        builder.assert_one(octet_num_sum);

        // Check that the `local.index` matches the `octet`, `octet_num` flags.
        builder.assert_eq(local.index, computed_index.clone());

        // Assert that the is_initialize flag is correct.
        builder.assert_eq(local.is_initialize, local.octet_num[0] * local.is_real);

        // Assert that the is_compression flag is correct.
        builder.assert_eq(
            local.is_compression,
            (local.octet_num[1]
                + local.octet_num[2]
                + local.octet_num[3]
                + local.octet_num[4]
                + local.octet_num[5]
                + local.octet_num[6]
                + local.octet_num[7]
                + local.octet_num[8])
                * local.is_real,
        );

        // Assert that the is_finalize flag is correct.
        builder.assert_eq(local.is_finalize, local.octet_num[9] * local.is_real);

        // Receive state.
        let receive_values = once(local.clk.into())
            .chain(local.w_ptr.map(Into::into))
            .chain(local.h_ptr.map(Into::into))
            .chain(once(local.index.into()))
            .chain(
                [
                    local.a, local.b, local.c, local.d, local.e, local.f, local.g, local.h,
                ]
                .into_iter()
                .flat_map(|word| word.into_iter())
                .map(Into::into),
            )
            .collect::<Vec<_>>();
        builder.looked(SymbolicLookup::new(
            receive_values,
            local.is_real.into(),
            LookupType::ShaCompress,
            LookupScope::Regional,
        ));

        // Send state, for initialize and finalize.
        let send_values = once(local.clk.into())
            .chain(local.w_ptr.map(Into::into))
            .chain(local.h_ptr.map(Into::into))
            .chain(once(local.index.into() + CB::Expr::ONE))
            .chain(
                [
                    local.a, local.b, local.c, local.d, local.e, local.f, local.g, local.h,
                ]
                .into_iter()
                .flat_map(|word| word.into_iter())
                .map(Into::into),
            )
            .collect::<Vec<_>>();
        builder.looking(SymbolicLookup::new(
            send_values,
            local.is_initialize + local.is_finalize,
            LookupType::ShaCompress,
            LookupScope::Regional,
        ));

        // Send state, for compression.
        // h := g
        // g := f
        // f := e
        // e := d + temp1
        // d := c
        // c := b
        // b := a
        // a := temp1 + temp2
        let compression_send_values = once(local.clk.into())
            .chain(local.w_ptr.map(Into::into))
            .chain(local.h_ptr.map(Into::into))
            .chain(once(local.index.into() + CB::Expr::ONE))
            .chain(
                [
                    local.temp1_add_temp2.value,
                    local.a,
                    local.b,
                    local.c,
                    local.d_add_temp1.value,
                    local.e,
                    local.f,
                    local.g,
                ]
                .into_iter()
                .flat_map(|word| word.into_iter())
                .map(Into::into),
            )
            .collect::<Vec<_>>();

        builder.looking(SymbolicLookup::new(
            compression_send_values,
            local.is_compression.into(),
            LookupType::ShaCompress,
            LookupScope::Regional,
        ));
    }

    /// Constrains that memory address is correct and that memory is correctly written/read.
    fn eval_memory<CB: ChipBuilder<F>>(&self, builder: &mut CB, local: &ShaCompressCols<CB::Var>) {
        // Extend the `mem_value` to a `Word` by appending zeroes before writing to memory.
        let mem_value_word = Word::extend_half::<CB>(&local.mem_value);

        // The `clk` only increments at finalize.
        builder.eval_memory_access(
            local.chunk,
            local.clk + local.is_finalize,
            local.mem_addr.map(Into::into),
            &local.mem,
            local.is_initialize + local.is_compression + local.is_finalize,
        );

        // During initialize and compression, verify that memory is read only and does not change.
        builder
            .when(local.is_initialize + local.is_compression)
            .assert_word_eq(local.mem.prev_value, mem_value_word.clone());
        // Check that the upper two limbs of the read memory is zero.
        builder.assert_zero(local.mem.prev_value[2]);
        builder.assert_zero(local.mem.prev_value[3]);

        // Verify correct mem address.
        builder
            .when(local.is_initialize)
            .assert_all_eq(local.mem_addr, local.mem_addr_init.value);
        builder
            .when(local.is_compression)
            .assert_all_eq(local.mem_addr, local.mem_addr_compress.value);
        builder
            .when(local.is_finalize)
            .assert_all_eq(local.mem_addr, local.mem_addr_finalize.value);

        // On initialize, `ptr = h_ptr + index * 8`.
        AddrAddGadget::<CB::F>::eval(
            builder,
            Word([
                local.h_ptr[0].into(),
                local.h_ptr[1].into(),
                local.h_ptr[2].into(),
                CB::Expr::ZERO,
            ]),
            Word::extend_expr::<CB>(local.index * CB::Expr::from_canonical_u32(8)),
            local.mem_addr_init,
            local.is_initialize.into(),
        );

        // On compress, `ptr = w_ptr + (index - 8) * 8`.
        AddrAddGadget::<CB::F>::eval(
            builder,
            Word([
                local.w_ptr[0].into(),
                local.w_ptr[1].into(),
                local.w_ptr[2].into(),
                CB::Expr::ZERO,
            ]),
            Word::extend_expr::<CB>(
                (local.index - CB::Expr::from_canonical_u32(8)) * CB::Expr::from_canonical_u32(8),
            ),
            local.mem_addr_compress,
            local.is_compression.into(),
        );

        // On finalize, `ptr = h_ptr + (index - 72) * 8`.
        AddrAddGadget::<CB::F>::eval(
            builder,
            Word([
                local.h_ptr[0].into(),
                local.h_ptr[1].into(),
                local.h_ptr[2].into(),
                CB::Expr::ZERO,
            ]),
            Word::extend_expr::<CB>(
                (local.index - CB::Expr::from_canonical_u32(72)) * CB::Expr::from_canonical_u32(8),
            ),
            local.mem_addr_finalize,
            local.is_finalize.into(),
        );

        // In the initialize phase, verify that local.a, local.b, ... are correctly read from
        // memory and does not change.
        let a_word = Word::extend_half::<CB>(&local.a);
        let b_word = Word::extend_half::<CB>(&local.b);
        let c_word = Word::extend_half::<CB>(&local.c);
        let d_word = Word::extend_half::<CB>(&local.d);
        let e_word = Word::extend_half::<CB>(&local.e);
        let f_word = Word::extend_half::<CB>(&local.f);
        let g_word = Word::extend_half::<CB>(&local.g);
        let h_word = Word::extend_half::<CB>(&local.h);
        let vars = [
            a_word, b_word, c_word, d_word, e_word, f_word, g_word, h_word,
        ];
        for (i, var) in vars.iter().enumerate() {
            builder
                .when(local.is_initialize * local.octet[i])
                .assert_word_eq(var.clone(), local.mem.prev_value);
            builder
                .when(local.is_initialize * local.octet[i])
                .assert_word_eq(var.clone(), mem_value_word.clone());
        }

        // In the finalize phase, verify that the correct value is written to memory.
        builder
            .when(local.is_finalize)
            .assert_all_eq(local.mem_value, local.finalize_add.value);
    }

    fn eval_compression_ops<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &ShaCompressCols<CB::Var>,
    ) {
        // Constrain k column which loops over 64 constant values.
        for i in 0..64 {
            let octet_num = i / 8;
            let inner_index = i % 8;
            let k: [CB::F; 2] = u32_to_half_word(SHA_COMPRESS_K[i]);
            builder
                .when(local.octet_num[octet_num + 1] * local.octet[inner_index])
                .assert_all_eq(local.k, k);
        }

        // S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25).
        // Calculate e rightrotate 6.
        FixedRotateRightU32Gadget::<CB::F>::eval(
            builder,
            local.e,
            6,
            local.e_rr_6,
            local.is_compression,
        );
        // Calculate e rightrotate 11.
        FixedRotateRightU32Gadget::<CB::F>::eval(
            builder,
            local.e,
            11,
            local.e_rr_11,
            local.is_compression,
        );
        // Calculate e rightrotate 25.
        FixedRotateRightU32Gadget::<CB::F>::eval(
            builder,
            local.e,
            25,
            local.e_rr_25,
            local.is_compression,
        );
        // Calculate (e rightrotate 6) xor (e rightrotate 11).
        let s1_intermediate = XorU32Gadget::<CB::F>::eval(
            builder,
            local.e_rr_6.value.map(Into::into),
            local.e_rr_11.value.map(Into::into),
            local.s1_intermediate,
            local.is_compression,
        );
        // Calculate S1 := ((e rightrotate 6) xor (e rightrotate 11)) xor (e rightrotate 25).
        let s1 = XorU32Gadget::<CB::F>::eval(
            builder,
            s1_intermediate,
            local.e_rr_25.value.map(Into::into),
            local.s1,
            local.is_compression,
        );

        // Calculate ch := (e and f) xor ((not e) and g).
        // Calculate e and f.
        let e_and_f = AndU32Gadget::<CB::F>::eval(
            builder,
            local.e.map(Into::into),
            local.f.map(Into::into),
            local.e_and_f,
            local.is_compression,
        );
        // Calculate not e.
        NotU32Gadget::<CB::F>::eval(builder, local.e, local.e_not, local.is_compression);
        // Calculate (not e) and g.
        let e_not_and_g = AndU32Gadget::<CB::F>::eval(
            builder,
            local.e_not.value.map(Into::into),
            local.g.map(Into::into),
            local.e_not_and_g,
            local.is_compression,
        );
        // Calculate ch := (e and f) xor ((not e) and g).
        let ch = XorU32Gadget::<CB::F>::eval(
            builder,
            e_and_f,
            e_not_and_g,
            local.ch,
            local.is_compression,
        );

        // Calculate temp1 := h + S1 + ch + k[i] + w[i].
        Add5U32Gadget::<CB::F>::eval(
            builder,
            &[
                local.h.map(Into::into),
                s1.map(Into::into),
                ch,
                local.k.map(Into::into),
                local.mem_value.map(Into::into),
            ],
            local.is_compression,
            local.temp1,
        );

        // Calculate S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22).
        // Calculate a rightrotate 2.
        FixedRotateRightU32Gadget::<CB::F>::eval(
            builder,
            local.a,
            2,
            local.a_rr_2,
            local.is_compression,
        );
        // Calculate a rightrotate 13.
        FixedRotateRightU32Gadget::<CB::F>::eval(
            builder,
            local.a,
            13,
            local.a_rr_13,
            local.is_compression,
        );
        // Calculate a rightrotate 22.
        FixedRotateRightU32Gadget::<CB::F>::eval(
            builder,
            local.a,
            22,
            local.a_rr_22,
            local.is_compression,
        );
        // Calculate (a rightrotate 2) xor (a rightrotate 13).
        let s0_intermediate = XorU32Gadget::<CB::F>::eval(
            builder,
            local.a_rr_2.value.map(Into::into),
            local.a_rr_13.value.map(Into::into),
            local.s0_intermediate,
            local.is_compression,
        );
        // Calculate S0 := ((a rightrotate 2) xor (a rightrotate 13)) xor (a rightrotate 22).
        let s0 = XorU32Gadget::<CB::F>::eval(
            builder,
            s0_intermediate,
            local.a_rr_22.value.map(Into::into),
            local.s0,
            local.is_compression,
        );

        // Calculate maj := (a and b) xor (a and c) xor (b and c).
        // Calculate a and b.
        let a_and_b = AndU32Gadget::<CB::F>::eval(
            builder,
            local.a.map(Into::into),
            local.b.map(Into::into),
            local.a_and_b,
            local.is_compression,
        );
        // Calculate a and c.
        let a_and_c = AndU32Gadget::<CB::F>::eval(
            builder,
            local.a.map(Into::into),
            local.c.map(Into::into),
            local.a_and_c,
            local.is_compression,
        );
        // Calculate b and c.
        let b_and_c = AndU32Gadget::<CB::F>::eval(
            builder,
            local.b.map(Into::into),
            local.c.map(Into::into),
            local.b_and_c,
            local.is_compression,
        );
        // Calculate (a and b) xor (a and c).
        let maj_intermediate = XorU32Gadget::<CB::F>::eval(
            builder,
            a_and_b,
            a_and_c,
            local.maj_intermediate,
            local.is_compression,
        );
        // Calculate maj := ((a and b) xor (a and c)) xor (b and c).
        let maj = XorU32Gadget::<CB::F>::eval(
            builder,
            maj_intermediate,
            b_and_c,
            local.maj,
            local.is_compression,
        );

        // Calculate temp2 := s0 + maj.
        AddU32Gadget::<CB::F>::eval(
            builder,
            s0.map(Into::into),
            maj.map(Into::into),
            local.temp2,
            local.is_compression,
        );

        // Calculate d + temp1 for the new value of e.
        AddU32Gadget::<CB::F>::eval(
            builder,
            local.d.map(Into::into),
            local.temp1.value.map(Into::into),
            local.d_add_temp1,
            local.is_compression,
        );

        // Calculate temp1 + temp2 for the new value of a.
        AddU32Gadget::<CB::F>::eval(
            builder,
            local.temp1.value.map(Into::into),
            local.temp2.value.map(Into::into),
            local.temp1_add_temp2,
            local.is_compression,
        );
    }

    fn eval_finalize_ops<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &ShaCompressCols<CB::Var>,
    ) {
        // In the finalize phase, execute h[0] + a, h[1] + b, ..., h[7] + h, one per row.
        // The operand can be fetched by an inner product of the `octet` flags and the operands.
        let add_operands = [
            local.a, local.b, local.c, local.d, local.e, local.f, local.g, local.h,
        ];
        let mut filtered_operand = [CB::Expr::ZERO, CB::Expr::ZERO];
        for (flag, operand) in local.octet.into_iter().zip(add_operands.iter()) {
            filtered_operand[0] = filtered_operand[0].clone() + flag * operand[0];
            filtered_operand[1] = filtered_operand[1].clone() + flag * operand[1];
        }

        // In the finalize phase, constrain that the `filtered_operand` is the operand for the row.
        builder
            .when(local.is_finalize)
            .assert_all_eq(filtered_operand.clone(), local.finalized_operand);

        // Constrain the addition of the operand with the previous memory value.
        // The memory write is constrained in the `eval_memory` function.
        AddU32Gadget::<CB::F>::eval(
            builder,
            [local.mem.prev_value.0[0], local.mem.prev_value.0[1]].map(Into::into),
            local.finalized_operand.map(Into::into),
            local.finalize_add,
            local.is_finalize,
        );
    }
}
