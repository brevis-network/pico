use core::{
    borrow::{Borrow, BorrowMut},
    fmt::Debug,
    marker::PhantomData,
    mem::size_of,
};

use crate::{
    chips::{
        chips::byte::event::ByteRecordBehavior,
        gadgets::{
            field::field_op::FieldOperation,
            utils::{
                field_params::{FieldType, FpOpField, NumLimbs},
                limbs::Limbs,
                polynomial::Polynomial,
            },
        },
        precompiles::checked_u64_to_u32,
    },
    compiler::riscv::program::Program,
    emulator::riscv::{record::EmulationRecord, syscalls::SyscallCode},
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
    },
};
use hybrid_array::{typenum::Unsigned, Array};
use itertools::Itertools;
use num::{BigUint, Zero};
use p3_air::{Air, BaseAir};
use p3_field::{Field, FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use pico_derive::AlignedBorrow;

use super::words_to_bytes_le_slice;
use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::{
            MemoryCols, MemoryReadColsU8, MemoryWriteColsU8,
        },
        gadgets::{
            addr_add::AddrAddGadget,
            field::{field_lt::FieldLtCols, field_op::FieldOpCols},
            syscall_addr::SyscallAddrGadget,
            utils::conversions::{
                generate_limbs_from_read_cols_u8, generate_limbs_from_write_cols_u8, limbs_to_words,
            },
        },
        utils::pad_rows_fixed,
    },
    compiler::word::Word,
    emulator::riscv::syscalls::precompiles::PrecompileEvent,
};

pub const fn num_fp2_mul_cols<P>() -> usize
where
    P: FpOpField,
{
    size_of::<Fp2MulCols<u8, P>>()
}

#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct Fp2MulChip<F, P> {
    _marker: PhantomData<fn(F, P) -> (F, P)>,
}

/// A set of columns for the FpAdd operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp2MulCols<F, P>
where
    P: FpOpField,
{
    pub is_real: F,
    pub chunk: F,
    pub clk: F,
    pub x_ptr: SyscallAddrGadget<F>,
    pub y_ptr: SyscallAddrGadget<F>,
    pub x_addrs: Array<AddrAddGadget<F>, P::WordsCurvePoint>,
    pub y_addrs: Array<AddrAddGadget<F>, P::WordsCurvePoint>,
    pub x_access: Array<MemoryWriteColsU8<F>, P::WordsCurvePoint>,
    pub y_access: Array<MemoryReadColsU8<F>, P::WordsCurvePoint>,
    pub(crate) a0_mul_b0: FieldOpCols<F, P>,
    pub(crate) a1_mul_b1: FieldOpCols<F, P>,
    pub(crate) a0_mul_b1: FieldOpCols<F, P>,
    pub(crate) a1_mul_b0: FieldOpCols<F, P>,
    pub(crate) c0: FieldOpCols<F, P>,
    pub(crate) c1: FieldOpCols<F, P>,
    pub(crate) c0_range: FieldLtCols<F, P>,
    pub(crate) c1_range: FieldLtCols<F, P>,
}

impl<F, P> Fp2MulChip<F, P>
where
    F: PrimeField32,
    P: FpOpField,
{
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    fn populate_field_ops(
        blu_events: &mut impl ByteRecordBehavior,
        cols: &mut Fp2MulCols<F, P>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        let modulus_bytes = P::MODULUS;
        let modulus = BigUint::from_bytes_le(modulus_bytes);

        // Reject an operand at or above the modulus here, before any field op runs -- this is a
        // *domain* error and the message should say so. Without it the same input trips
        // `populate_carry_and_witness`' internal `debug_assert!(&carry < modulus)` several layers
        // down, which reports a symptom rather than the cause.
        //
        // Trace-side only, deliberately: the AIR does not constrain the operands and does not need
        // to. Each field op asserts `a op b == result + carry * modulus`, which holds mod p for any
        // representative, and the result is pinned twice -- to the memory bus, and below the modulus
        // by the existing exit range check -- so the value written back is unique whatever
        // representative the operands use.
        for (name, v) in [("p.x", &p_x), ("p.y", &p_y), ("q.x", &q_x), ("q.y", &q_y)] {
            assert!(*v < modulus, "fp2 coordinate {name} must be < modulus");
        }

        let a0_mul_b0 = cols.a0_mul_b0.populate_with_modulus(
            blu_events,
            &p_x,
            &q_x,
            &modulus,
            FieldOperation::Mul,
        );
        let a1_mul_b1 = cols.a1_mul_b1.populate_with_modulus(
            blu_events,
            &p_y,
            &q_y,
            &modulus,
            FieldOperation::Mul,
        );
        let a0_mul_b1 = cols.a0_mul_b1.populate_with_modulus(
            blu_events,
            &p_x,
            &q_y,
            &modulus,
            FieldOperation::Mul,
        );
        let a1_mul_b0 = cols.a1_mul_b0.populate_with_modulus(
            blu_events,
            &p_y,
            &q_x,
            &modulus,
            FieldOperation::Mul,
        );
        let c0 = cols.c0.populate_with_modulus(
            blu_events,
            &a0_mul_b0,
            &a1_mul_b1,
            &modulus,
            FieldOperation::Sub,
        );
        let c1 = cols.c1.populate_with_modulus(
            blu_events,
            &a0_mul_b1,
            &a1_mul_b0,
            &modulus,
            FieldOperation::Add,
        );
        cols.c0_range.populate(blu_events, &c0, &modulus);
        cols.c1_range.populate(blu_events, &c1, &modulus);
    }
}

impl<F, P> ChipBehavior<F> for Fp2MulChip<F, P>
where
    F: PrimeField32,
    P: FpOpField,
{
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        match P::FIELD_TYPE {
            FieldType::Bn254 => "Bn254Fp2Mul".to_string(),
            FieldType::Bls381 => "Bls381Fp2Mul".to_string(),
            _ => unimplemented!("fp2 available only for Bn254 and Bls12381"),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = match P::FIELD_TYPE {
            FieldType::Bn254 => input.get_precompile_events(SyscallCode::BN254_FP2_MUL),
            FieldType::Bls381 => input.get_precompile_events(SyscallCode::BLS12381_FP2_MUL),
            _ => unimplemented!("fp2 available only for Bn254 and Bls12381"),
        };

        let mut rows = Vec::new();
        let mut new_byte_lookup_events = Vec::new();

        for (_, event) in events {
            let event = match (P::FIELD_TYPE, event) {
                (FieldType::Bn254, PrecompileEvent::Bn254Fp2Mul(event)) => event,
                (FieldType::Bls381, PrecompileEvent::Bls12381Fp2Mul(event)) => event,
                _ => unreachable!(),
            };

            let mut row = vec![F::ZERO; num_fp2_mul_cols::<P>()];
            let cols: &mut Fp2MulCols<F, P> = row.as_mut_slice().borrow_mut();

            let p = &event.x;
            let q = &event.y;
            let p_x = BigUint::from_bytes_le(&words_to_bytes_le_slice(&p[..p.len() / 2]));
            let p_y = BigUint::from_bytes_le(&words_to_bytes_le_slice(&p[p.len() / 2..]));
            let q_x = BigUint::from_bytes_le(&words_to_bytes_le_slice(&q[..q.len() / 2]));
            let q_y = BigUint::from_bytes_le(&words_to_bytes_le_slice(&q[q.len() / 2..]));

            cols.is_real = F::ONE;
            cols.chunk = F::from_canonical_u32(event.chunk);
            cols.clk = F::from_canonical_u32(checked_u64_to_u32(event.clk, "fptower fp2 mul clk"));
            cols.x_ptr.populate(
                &mut new_byte_lookup_events,
                event.x_ptr,
                P::NUM_LIMBS as u64 * 2,
            );
            cols.y_ptr.populate(
                &mut new_byte_lookup_events,
                event.y_ptr,
                P::NUM_LIMBS as u64 * 2,
            );

            Self::populate_field_ops(&mut new_byte_lookup_events, cols, p_x, p_y, q_x, q_y);

            for i in 0..cols.y_access.len() {
                cols.y_access[i]
                    .inner
                    .populate(event.y_memory_records[i], &mut new_byte_lookup_events);
                cols.y_access[i].prev_value_u8.populate_u16_to_u8_safe(
                    &mut new_byte_lookup_events,
                    event.y_memory_records[i].value,
                );
                cols.y_addrs[i].populate(&mut new_byte_lookup_events, event.y_ptr, i as u64 * 8);
            }
            for i in 0..cols.x_access.len() {
                cols.x_access[i]
                    .inner
                    .populate(event.x_memory_records[i], &mut new_byte_lookup_events);
                cols.x_access[i].prev_value_u8.populate_u16_to_u8_safe(
                    &mut new_byte_lookup_events,
                    event.x_memory_records[i].prev_value,
                );
                cols.x_addrs[i].populate(&mut new_byte_lookup_events, event.x_ptr, i as u64 * 8);
            }
            rows.push(row)
        }

        new_byte_lookup_events
            .iter()
            .for_each(|x| output.add_byte_lookup_event(*x));

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = vec![F::ZERO; num_fp2_mul_cols::<P>()];
                let cols: &mut Fp2MulCols<F, P> = row.as_mut_slice().borrow_mut();
                let zero = BigUint::zero();
                Self::populate_field_ops(
                    &mut vec![],
                    cols,
                    zero.clone(),
                    zero.clone(),
                    zero.clone(),
                    zero,
                );
                row
            },
            log_rows,
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_fp2_mul_cols::<P>(),
        )
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, input: &Self::Record) -> bool {
        if let Some(shape) = input.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match P::FIELD_TYPE {
                FieldType::Bn254 => !input
                    .get_precompile_events(SyscallCode::BN254_FP2_MUL)
                    .is_empty(),
                FieldType::Bls381 => !input
                    .get_precompile_events(SyscallCode::BLS12381_FP2_MUL)
                    .is_empty(),
                _ => unimplemented!("fp2 available only for Bn254 and Bls12381"),
            }
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F, P> BaseAir<F> for Fp2MulChip<F, P>
where
    P: FpOpField,
{
    fn width(&self) -> usize {
        num_fp2_mul_cols::<P>()
    }
}

impl<F, P, CB> Air<CB> for Fp2MulChip<F, P>
where
    F: Field,
    CB: ChipBuilder<F>,
    P: FpOpField,
    Limbs<CB::Var, <P as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Fp2MulCols<CB::Var, P> = (*local).borrow();

        builder.assert_bool(local.is_real);

        let num_words_field_element = <P as NumLimbs>::Limbs::USIZE / 8;

        let p_x_limbs = generate_limbs_from_write_cols_u8(
            builder,
            &local.x_access[0..num_words_field_element],
            local.is_real.into(),
        );
        let p_x: Limbs<CB::Expr, <P as NumLimbs>::Limbs> =
            Limbs((&*p_x_limbs).try_into().expect("failed to convert limbs"));
        let q_x_limbs = generate_limbs_from_read_cols_u8(
            builder,
            &local.y_access[0..num_words_field_element],
            local.is_real.into(),
        );
        let q_x: Limbs<CB::Expr, <P as NumLimbs>::Limbs> =
            Limbs((&*q_x_limbs).try_into().expect("failed to convert limbs"));
        let p_y_limbs = generate_limbs_from_write_cols_u8(
            builder,
            &local.x_access[num_words_field_element..],
            local.is_real.into(),
        );
        let p_y: Limbs<CB::Expr, <P as NumLimbs>::Limbs> =
            Limbs((&*p_y_limbs).try_into().expect("failed to convert limbs"));
        let q_y_limbs = generate_limbs_from_read_cols_u8(
            builder,
            &local.y_access[num_words_field_element..],
            local.is_real.into(),
        );
        let q_y: Limbs<CB::Expr, <P as NumLimbs>::Limbs> =
            Limbs((&*q_y_limbs).try_into().expect("failed to convert limbs"));

        let modulus_coeffs = P::MODULUS
            .iter()
            .map(|&limbs| CB::Expr::from_canonical_u8(limbs))
            .collect_vec();
        let p_modulus = Polynomial::from_coefficients(&modulus_coeffs);

        {
            local.a0_mul_b0.eval_with_modulus(
                builder,
                &p_x,
                &q_x,
                &p_modulus,
                FieldOperation::Mul,
                local.is_real,
            );

            local.a1_mul_b1.eval_with_modulus(
                builder,
                &p_y,
                &q_y,
                &p_modulus,
                FieldOperation::Mul,
                local.is_real,
            );

            local.c0.eval_with_modulus(
                builder,
                &local.a0_mul_b0.result,
                &local.a1_mul_b1.result,
                &p_modulus,
                FieldOperation::Sub,
                local.is_real,
            );
        }

        {
            local.a0_mul_b1.eval_with_modulus(
                builder,
                &p_x,
                &q_y,
                &p_modulus,
                FieldOperation::Mul,
                local.is_real,
            );

            local.a1_mul_b0.eval_with_modulus(
                builder,
                &p_y,
                &q_x,
                &p_modulus,
                FieldOperation::Mul,
                local.is_real,
            );

            local.c1.eval_with_modulus(
                builder,
                &local.a0_mul_b1.result,
                &local.a1_mul_b0.result,
                &p_modulus,
                FieldOperation::Add,
                local.is_real,
            );
        }

        let c0_result_limbs: Vec<CB::Expr> = local
            .c0
            .result
            .0
            .iter()
            .copied()
            .map(|x| x.into())
            .collect();
        let c0_result_words =
            limbs_to_words::<CB::Expr>(&c0_result_limbs, CB::F::from_canonical_u32(256).into());

        let c1_result_limbs: Vec<CB::Expr> = local
            .c1
            .result
            .0
            .iter()
            .copied()
            .map(|x| x.into())
            .collect();
        let c1_result_words =
            limbs_to_words::<CB::Expr>(&c1_result_limbs, CB::F::from_canonical_u32(256).into());

        let result_words = c0_result_words
            .into_iter()
            .chain(c1_result_words)
            .collect_vec();

        local
            .c0_range
            .eval(builder, &local.c0.result, &p_modulus, local.is_real);
        local
            .c1_range
            .eval(builder, &local.c1.result, &p_modulus, local.is_real);

        let x_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            P::NUM_LIMBS as u32 * 2,
            local.x_ptr,
            local.is_real.into(),
        );
        let y_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            P::NUM_LIMBS as u32 * 2,
            local.y_ptr,
            local.is_real.into(),
        );

        // x_addrs[i] = x_ptr + 8 * i
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

        // y_addrs[i] = y_ptr + 8 * i
        for i in 0..local.y_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    y_ptr[0].into(),
                    y_ptr[1].into(),
                    y_ptr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                local.y_addrs[i],
                local.is_real.into(),
            );
        }

        for (access, addr) in local.y_access.iter().zip(local.y_addrs.iter()) {
            builder.eval_memory_access(
                local.chunk,
                local.clk,
                addr.value.map(Into::into),
                &access.inner,
                local.is_real,
            );
        }

        // We write x at clk+1 since x, y could be the same.
        for (i, (access, addr)) in local.x_access.iter().zip(local.x_addrs.iter()).enumerate() {
            builder.eval_memory_access(
                local.chunk,
                local.clk + CB::F::ONE,
                addr.value.map(Into::into),
                &access.inner,
                local.is_real,
            );
            // NOTE: `.inner` is `FilteredAirBuilder::inner`, the *unfiltered* builder, so the
            // `when` below is discarded and this equality also applies to padding rows. Left as-is
            // deliberately -- an ungated constraint is soundness-stronger, so adding the gate would
            // weaken the constraint set.
            let do_check: CB::Expr = local.is_real.into();
            for (v, w) in access.inner.value().0.iter().zip(result_words[i].0.iter()) {
                builder
                    .when(do_check.clone())
                    .inner
                    .assert_eq((*v).into(), w.clone());
            }
        }

        let syscall_id_felt = match P::FIELD_TYPE {
            FieldType::Bn254 => CB::F::from_canonical_u32(SyscallCode::BN254_FP2_MUL.syscall_id()),
            FieldType::Bls381 => {
                CB::F::from_canonical_u32(SyscallCode::BLS12381_FP2_MUL.syscall_id())
            }
            _ => unimplemented!("fp2 available only for Bn254 and Bls12381"),
        };

        builder.looked_syscall(
            local.chunk,
            local.clk,
            syscall_id_felt,
            x_ptr.map(Into::into),
            y_ptr.map(Into::into),
            local.is_real,
        );
    }
}
