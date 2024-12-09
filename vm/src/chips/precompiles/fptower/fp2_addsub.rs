use core::{
    borrow::{Borrow, BorrowMut},
    fmt::Debug,
    marker::PhantomData,
    mem::size_of,
};

use crate::{
    chips::{
        chips::rangecheck::event::RangeRecordBehavior,
        gadgets::{
            field::field_op::FieldOperation,
            utils::{
                field_params::{FieldType, FpOpField, NumLimbs},
                limbs::Limbs,
                polynomial::Polynomial,
            },
        },
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
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use pico_derive::AlignedBorrow;

use crate::chips::{
    chips::riscv_memory::read_write::columns::{value_as_limbs, MemoryReadCols, MemoryWriteCols},
    gadgets::field::field_op::FieldOpCols,
};

use super::{limbs_from_prev_access, words_to_bytes_le_slice};
use crate::recursion::stark::utils::pad_rows;

pub const fn num_fp2_addsub_cols<P>() -> usize
where
    P: FpOpField,
    <P as NumLimbs>::Limbs: Debug,
    <P as NumLimbs>::Witness: Debug,
{
    size_of::<Fp2AddSubCols<u8, P>>()
}

#[derive(Default)]
pub struct Fp2AddSubChip<F, P> {
    _marker: PhantomData<(F, P)>,
}

/// A set of columns for the FpAdd operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp2AddSubCols<F, P>
where
    P: FpOpField,
    <P as NumLimbs>::Limbs: Debug,
    <P as NumLimbs>::Witness: Debug,
{
    pub is_real: F,
    pub chunk: F,
    pub nonce: F,
    pub clk: F,
    pub is_add: F,
    pub x_ptr: F,
    pub y_ptr: F,
    pub x_access: Array<MemoryWriteCols<F>, P::WordsCurvePoint>,
    pub y_access: Array<MemoryReadCols<F>, P::WordsCurvePoint>,
    pub(crate) c0: FieldOpCols<F, P>,
    pub(crate) c1: FieldOpCols<F, P>,
}

impl<F, P> Fp2AddSubChip<F, P>
where
    F: PrimeField32,
    P: FpOpField,
    <P as NumLimbs>::Limbs: Debug,
    <P as NumLimbs>::Witness: Debug,
{
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    fn populate_field_ops(
        blu_events: &mut impl RangeRecordBehavior,
        chunk: u32,
        cols: &mut Fp2AddSubCols<F, P>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
        op: FieldOperation,
    ) {
        let modulus_bytes = P::MODULUS;
        let modulus = BigUint::from_bytes_le(modulus_bytes);
        cols.c0
            .populate_with_modulus(blu_events, chunk, &p_x, &q_x, &modulus, op);
        cols.c1
            .populate_with_modulus(blu_events, chunk, &p_y, &q_y, &modulus, op);
    }
}

impl<F, P> ChipBehavior<F> for Fp2AddSubChip<F, P>
where
    F: PrimeField32,
    P: FpOpField,
    <P as NumLimbs>::Limbs: Debug,
    <P as NumLimbs>::Witness: Debug,
{
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        match P::FIELD_TYPE {
            FieldType::Bn254 => "Bn254Fp2AddSub".to_string(),
            FieldType::Bls381 => "Bls381Fp2AddSub".to_string(),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = match P::FIELD_TYPE {
            FieldType::Bn254 => input.fp2_bn254_addsub_events.iter(),
            FieldType::Bls381 => input.fp2_bls381_addsub_events.iter(),
        };

        let mut rows = Vec::new();
        let mut new_byte_lookup_events = Vec::new();

        for event in events {
            let mut row = vec![F::ZERO; num_fp2_addsub_cols::<P>()];
            let cols: &mut Fp2AddSubCols<F, P> = row.as_mut_slice().borrow_mut();

            let p = &event.x;
            let q = &event.y;
            let p_x = BigUint::from_bytes_le(&words_to_bytes_le_slice(&p[..p.len() / 2]));
            let p_y = BigUint::from_bytes_le(&words_to_bytes_le_slice(&p[p.len() / 2..]));
            let q_x = BigUint::from_bytes_le(&words_to_bytes_le_slice(&q[..q.len() / 2]));
            let q_y = BigUint::from_bytes_le(&words_to_bytes_le_slice(&q[q.len() / 2..]));

            cols.is_real = F::ONE;
            cols.is_add = F::from_bool(event.op == FieldOperation::Add);
            cols.chunk = F::from_canonical_u32(event.chunk);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.x_ptr = F::from_canonical_u32(event.x_ptr);
            cols.y_ptr = F::from_canonical_u32(event.y_ptr);

            Self::populate_field_ops(
                &mut new_byte_lookup_events,
                event.chunk,
                cols,
                p_x,
                p_y,
                q_x,
                q_y,
                event.op,
            );

            // Populate the memory access columns.
            for i in 0..cols.y_access.len() {
                cols.y_access[i].populate(event.y_memory_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..cols.x_access.len() {
                cols.x_access[i].populate(event.x_memory_records[i], &mut new_byte_lookup_events);
            }
            rows.push(row)
        }

        new_byte_lookup_events
            .iter()
            .for_each(|x| output.add_range_lookup_event(*x));

        pad_rows(&mut rows, || {
            let mut row = vec![F::ZERO; num_fp2_addsub_cols::<P>()];
            let cols: &mut Fp2AddSubCols<F, P> = row.as_mut_slice().borrow_mut();
            cols.is_add = F::ONE;
            let zero = BigUint::zero();
            Self::populate_field_ops(
                &mut vec![],
                0,
                cols,
                zero.clone(),
                zero.clone(),
                zero.clone(),
                zero,
                FieldOperation::Add,
            );
            row
        });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_fp2_addsub_cols::<P>(),
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut Fp2AddSubCols<F, P> = trace.values
                [i * num_fp2_addsub_cols::<P>()..(i + 1) * num_fp2_addsub_cols::<P>()]
                .borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, input: &Self::Record) -> bool {
        let events = match P::FIELD_TYPE {
            FieldType::Bn254 => &input.fp2_bn254_addsub_events,
            FieldType::Bls381 => &input.fp2_bls381_addsub_events,
        };
        !events.is_empty()
    }
}

impl<F, P> BaseAir<F> for Fp2AddSubChip<F, P>
where
    F: Sync,
    P: FpOpField,
    <P as NumLimbs>::Limbs: Debug,
    <P as NumLimbs>::Witness: Debug,
{
    fn width(&self) -> usize {
        num_fp2_addsub_cols::<P>()
    }
}

impl<F, P, CB> Air<CB> for Fp2AddSubChip<F, P>
where
    F: Field,
    CB: ChipBuilder<F>,
    P: FpOpField,
    <P as NumLimbs>::Limbs: Debug,
    <P as NumLimbs>::Witness: Debug,
    Limbs<CB::Var, <P as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Fp2AddSubCols<CB::Var, P> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &Fp2AddSubCols<CB::Var, P> = (*next).borrow();

        // Constrain the `is_add` flag to be boolean.
        builder.assert_bool(local.is_add);

        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + CB::Expr::ONE, next.nonce);
        let num_words_field_element = <P as NumLimbs>::Limbs::USIZE / 4;

        let p_x = limbs_from_prev_access(&local.x_access[0..num_words_field_element]);
        let p_y = limbs_from_prev_access(&local.x_access[num_words_field_element..]);

        let q_x = limbs_from_prev_access(&local.y_access[0..num_words_field_element]);
        let q_y = limbs_from_prev_access(&local.y_access[num_words_field_element..]);

        let modulus_coeffs = P::MODULUS
            .iter()
            .map(|&limbs| CB::Expr::from_canonical_u8(limbs))
            .collect_vec();
        let p_modulus = Polynomial::from_coefficients(&modulus_coeffs);

        {
            local.c0.eval_variable(
                builder,
                &p_x,
                &q_x,
                &p_modulus,
                local.is_add,
                CB::Expr::ONE - local.is_add,
                CB::F::ZERO,
                CB::F::ZERO,
                local.chunk,
                local.is_real,
            );

            local.c1.eval_variable(
                builder,
                &p_y,
                &q_y,
                &p_modulus,
                local.is_add,
                CB::Expr::ONE - local.is_add,
                CB::F::ZERO,
                CB::F::ZERO,
                local.chunk,
                local.is_real,
            );
        }

        builder.when(local.is_real).inner.assert_all_eq(
            local.c0.result,
            value_as_limbs(&local.x_access[0..num_words_field_element]),
        );
        builder.when(local.is_real).inner.assert_all_eq(
            local.c1.result,
            value_as_limbs(&local.x_access[num_words_field_element..]),
        );
        builder.eval_memory_access_slice(
            local.chunk,
            local.clk.into(),
            local.y_ptr,
            &local.y_access,
            local.is_real,
        );
        builder.eval_memory_access_slice(
            local.chunk,
            local.clk + CB::F::from_canonical_u32(1), /* We read p at +1 since p, q could be the
                                                       * same. */
            local.x_ptr,
            &local.x_access,
            local.is_real,
        );

        let (add_syscall_id, sub_syscall_id) = match P::FIELD_TYPE {
            FieldType::Bn254 => (
                CB::F::from_canonical_u32(SyscallCode::BN254_FP2_ADD.syscall_id()),
                CB::F::from_canonical_u32(SyscallCode::BN254_FP2_SUB.syscall_id()),
            ),
            FieldType::Bls381 => (
                CB::F::from_canonical_u32(SyscallCode::BLS12381_FP2_ADD.syscall_id()),
                CB::F::from_canonical_u32(SyscallCode::BLS12381_FP2_SUB.syscall_id()),
            ),
        };

        let syscall_id_felt =
            local.is_add * add_syscall_id + (CB::Expr::ONE - local.is_add) * sub_syscall_id;

        builder.looked_syscall(
            local.chunk,
            local.clk,
            local.nonce,
            syscall_id_felt,
            local.x_ptr,
            local.y_ptr,
            local.is_real,
        );
    }
}
