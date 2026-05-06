use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::MemoryCols,
        gadgets::{
            addr_add::AddrAddGadget,
            field::field_op::FieldOperation,
            is_zero::IsZeroGadget,
            syscall_addr::SyscallAddrGadget,
            uint256::U256Field,
            utils::{
                conversions::{
                    generate_limbs_from_read_cols_u8, generate_limbs_from_write_cols_u8,
                    limbs_to_words,
                },
                field_params::NumLimbs,
                limbs::Limbs,
                polynomial::Polynomial,
            },
        },
        precompiles::uint256::{
            columns::{Uint256MulCols, NUM_UINT256_MUL_COLS},
            Uint256MulChip,
        },
    },
    compiler::word::Word,
    emulator::riscv::syscalls::SyscallCode,
    machine::builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
};
use hybrid_array::Array;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field> BaseAir<F> for Uint256MulChip<F> {
    fn width(&self) -> usize {
        NUM_UINT256_MUL_COLS
    }
}

impl<F: Field, CB> Air<CB> for Uint256MulChip<F>
where
    CB: ChipBuilder<F>,
    Limbs<CB::Var, <U256Field as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Uint256MulCols<CB::Var> = (*local).borrow();

        // We are computing (x * y) % modulus. The value of x is stored in the "prev_value" of
        // the x_memory, since we write to it later.
        // Extract byte limbs from u16 word limbs via U16→U8 conversion.
        let x_limbs_vec =
            generate_limbs_from_write_cols_u8(builder, &local.x_memory[..], local.is_real.into());
        let x_limbs: Limbs<CB::Expr, <U256Field as NumLimbs>::Limbs> =
            Limbs(Array::try_from_iter(x_limbs_vec).expect("failed to convert x limbs"));

        let y_limbs_vec =
            generate_limbs_from_read_cols_u8(builder, &local.y_memory[..], local.is_real.into());
        let y_limbs: Limbs<CB::Expr, <U256Field as NumLimbs>::Limbs> =
            Limbs(Array::try_from_iter(y_limbs_vec).expect("failed to convert y limbs"));

        let modulus_limbs_vec = generate_limbs_from_read_cols_u8(
            builder,
            &local.modulus_memory[..],
            local.is_real.into(),
        );
        let modulus_limbs: Limbs<CB::Expr, <U256Field as NumLimbs>::Limbs> = Limbs(
            Array::try_from_iter(modulus_limbs_vec).expect("failed to convert modulus limbs"),
        );

        // If the modulus is zero, then we don't perform the modulus operation.
        // Evaluate the modulus_is_zero operation by summing each byte of the modulus. The sum will
        // not overflow because we are summing 32 bytes.
        let modulus_byte_sum = modulus_limbs
            .0
            .iter()
            .fold(CB::Expr::ZERO, |acc, limb| acc + limb.clone());
        IsZeroGadget::<CB::F>::eval(
            builder,
            modulus_byte_sum,
            local.modulus_is_zero,
            local.is_real.into(),
        );

        // If the modulus is zero, we'll actually use 2^256 as the modulus, so nothing happens.
        // Otherwise, we use the modulus passed in.
        let modulus_is_zero = local.modulus_is_zero.result;
        let mut coeff_2_256 = Vec::new();
        coeff_2_256.resize(32, CB::Expr::ZERO);
        coeff_2_256.push(CB::Expr::ONE);
        let modulus_polynomial: Polynomial<CB::Expr> = modulus_limbs.clone().into();
        let p_modulus: Polynomial<CB::Expr> = modulus_polynomial
            * (CB::Expr::ONE - modulus_is_zero.into())
            + Polynomial::from_coefficients(&coeff_2_256) * modulus_is_zero.into();

        // Evaluate the uint256 multiplication
        local.output.eval_with_modulus(
            builder,
            &x_limbs,
            &y_limbs,
            &p_modulus,
            FieldOperation::Mul,
            local.is_real,
        );

        // Verify the range of the output if the modulus is not zero. Also, check the value of
        // modulus_is_not_zero.
        local.output_range_check.eval(
            builder,
            &local.output.result,
            &modulus_limbs,
            local.modulus_is_not_zero,
        );
        builder.assert_eq(
            local.modulus_is_not_zero,
            local.is_real * (CB::Expr::ONE - modulus_is_zero.into()),
        );

        // Assert that the correct result is being written to x_memory.
        // Reconstruct byte-level results into Words for memory write constraints.
        let result_words = limbs_to_words(
            &local
                .output
                .result
                .0
                .iter()
                .map(|v| (*v).into())
                .collect::<Vec<CB::Expr>>(),
            CB::F::from_canonical_u32(256).into(),
        );
        let do_check: CB::Expr = local.is_real.into();
        for (i, word) in result_words.iter().enumerate() {
            for (v, w) in local.x_memory[i].inner.value().0.iter().zip(word.0.iter()) {
                builder
                    .when(do_check.clone())
                    .assert_eq((*v).into(), w.clone());
            }
        }

        // Address alignment constraints.
        let x_ptr =
            SyscallAddrGadget::<CB::F>::eval(builder, 32, local.x_ptr, local.is_real.into());
        let y_ptr =
            SyscallAddrGadget::<CB::F>::eval(builder, 64, local.y_ptr, local.is_real.into());

        for i in 0..local.x_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    x_ptr[0].into(),
                    x_ptr[1].into(),
                    x_ptr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                local.x_addrs[i],
                local.is_real.into(),
            );
        }
        for i in 0..local.y_and_modulus_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    y_ptr[0].into(),
                    y_ptr[1].into(),
                    y_ptr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                local.y_and_modulus_addrs[i],
                local.is_real.into(),
            );
        }

        // Memory access constraints.
        // Read and write x using constrained addresses.
        for (i, access) in local.x_memory.iter().enumerate() {
            builder.eval_memory_access(
                local.chunk.into(),
                local.clk.into() + CB::Expr::ONE,
                local.x_addrs[i].value.map(Into::into),
                &access.inner,
                local.is_real,
            )
        }

        // Evaluate the y_ptr memory access. We concatenate y and modulus into a single array since
        // we read it contiguously from the y_ptr memory location.
        for (i, access) in local
            .y_memory
            .iter()
            .chain(local.modulus_memory.iter())
            .enumerate()
        {
            builder.eval_memory_access(
                local.chunk.into(),
                local.clk.into(),
                local.y_and_modulus_addrs[i].value.map(Into::into),
                &access.inner,
                local.is_real,
            )
        }

        // Receive the arguments.
        builder.looked_syscall(
            local.clk,
            CB::F::from_canonical_u32(SyscallCode::UINT256_MUL.syscall_id()),
            x_ptr.map(Into::into),
            y_ptr.map(Into::into),
            local.is_real,
        );

        // Assert that is_real is a boolean.
        builder.assert_bool(local.is_real);
    }
}
