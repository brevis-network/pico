use super::{limbs_from_prev_access, words_to_bytes_le_slice};
use crate::{
    chips::{
        chips::{
            rangecheck::event::RangeRecordBehavior,
            riscv_memory::read_write::columns::{value_as_limbs, MemoryReadCols, MemoryWriteCols},
        },
        gadgets::{
            field::field_op::{FieldOpCols, FieldOperation},
            utils::{
                field_params::{FieldType, FpOpField, NumLimbs},
                limbs::Limbs,
                polynomial::Polynomial,
            },
        },
    },
    compiler::riscv::program::Program,
    emulator::{
        record::RecordBehavior,
        riscv::{
            record::EmulationRecord,
            syscalls::{precompiles::PrecompileEvent, SyscallCode},
        },
    },
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
        lookup::LookupScope,
    },
    recursion_v2::stark::utils::pad_rows_fixed,
};
use core::{
    borrow::{Borrow, BorrowMut},
    fmt::Debug,
    marker::PhantomData,
    mem::size_of,
};
use hybrid_array::Array;
use itertools::Itertools;
use num::{BigUint, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use pico_derive::AlignedBorrow;
use tracing::debug;

pub const fn num_fp_cols<P>() -> usize
where
    P: FpOpField,
{
    size_of::<FpOpCols<u8, P>>()
}

#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct FpOpChip<F, P> {
    _marker: PhantomData<fn(F, P) -> (F, P)>,
}

/// A set of columns for the FpAdd operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FpOpCols<F, P>
where
    P: FpOpField,
{
    pub is_real: F,
    pub chunk: F,
    pub nonce: F,
    pub clk: F,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub x_ptr: F,
    pub y_ptr: F,
    pub x_access: Array<MemoryWriteCols<F>, P::WordsFieldElement>,
    pub y_access: Array<MemoryReadCols<F>, P::WordsFieldElement>,
    pub(crate) output: FieldOpCols<F, P>,
}

impl<F, P> FpOpChip<F, P>
where
    F: PrimeField32,
    P: FpOpField,
{
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops(
        blu_events: &mut impl RangeRecordBehavior,
        chunk: u32,
        cols: &mut FpOpCols<F, P>,
        p: BigUint,
        q: BigUint,
        op: FieldOperation,
    ) {
        let modulus_bytes = P::MODULUS;
        let modulus = BigUint::from_bytes_le(modulus_bytes);
        cols.output
            .populate_with_modulus(blu_events, chunk, &p, &q, &modulus, op);
    }
}

impl<F, P> ChipBehavior<F> for FpOpChip<F, P>
where
    F: PrimeField32,
    P: FpOpField,
{
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        match P::FIELD_TYPE {
            FieldType::Bn254 => "Bn254FpOp".to_string(),
            FieldType::Bls381 => "Bls381FpOp".to_string(),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        // All the fp events for a given curve are coalesce to the curve's Add operation.  Only retrieve
        // precompile events for that operation.
        // TODO:  Fix this.

        let events = match P::FIELD_TYPE {
            FieldType::Bn254 => input
                .get_precompile_events(SyscallCode::BN254_FP_ADD)
                .iter(),
            FieldType::Bls381 => input
                .get_precompile_events(SyscallCode::BLS12381_FP_ADD)
                .iter(),
        };

        debug!(
            "record {} fp precompile events {:?}",
            input.chunk_index(),
            events.len()
        );

        let mut rows = Vec::new();
        let mut new_byte_lookup_events = Vec::new();

        for (_, event) in events {
            let event = match (P::FIELD_TYPE, event) {
                (FieldType::Bn254, PrecompileEvent::Bn254Fp(event)) => event,
                (FieldType::Bls381, PrecompileEvent::Bls12381Fp(event)) => event,
                _ => unreachable!(),
            };

            let mut row = vec![F::ZERO; num_fp_cols::<P>()];
            let cols: &mut FpOpCols<F, P> = row.as_mut_slice().borrow_mut();

            let modulus = &BigUint::from_bytes_le(P::MODULUS);
            let p = BigUint::from_bytes_le(&words_to_bytes_le_slice(&event.x)) % modulus;
            let q = BigUint::from_bytes_le(&words_to_bytes_le_slice(&event.y)) % modulus;

            cols.is_add = F::from_canonical_u8((event.op == FieldOperation::Add) as u8);
            cols.is_sub = F::from_canonical_u8((event.op == FieldOperation::Sub) as u8);
            cols.is_mul = F::from_canonical_u8((event.op == FieldOperation::Mul) as u8);
            cols.is_real = F::ONE;
            cols.chunk = F::from_canonical_u32(event.chunk);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.x_ptr = F::from_canonical_u32(event.x_ptr);
            cols.y_ptr = F::from_canonical_u32(event.y_ptr);

            Self::populate_field_ops(
                &mut new_byte_lookup_events,
                event.chunk,
                cols,
                p,
                q,
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

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = vec![F::ZERO; num_fp_cols::<P>()];
                let cols: &mut FpOpCols<F, P> = row.as_mut_slice().borrow_mut();
                let zero = BigUint::zero();
                cols.is_add = F::from_canonical_u8(1);
                Self::populate_field_ops(
                    &mut vec![],
                    0,
                    cols,
                    zero.clone(),
                    zero,
                    FieldOperation::Add,
                );
                row
            },
            log_rows,
        );

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_fp_cols::<P>(),
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut FpOpCols<F, P> =
                trace.values[i * num_fp_cols::<P>()..(i + 1) * num_fp_cols::<P>()].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, input: &Self::Record) -> bool {
        // All the fp events for a given curve are coalesce to the curve's Add operation. Only
        // check for that operation.

        assert!(
            input
                .get_precompile_events(SyscallCode::BN254_FP_SUB)
                .is_empty()
                && input
                    .get_precompile_events(SyscallCode::BN254_FP_MUL)
                    .is_empty()
                && input
                    .get_precompile_events(SyscallCode::BLS12381_FP_SUB)
                    .is_empty()
                && input
                    .get_precompile_events(SyscallCode::BLS12381_FP_MUL)
                    .is_empty()
        );

        if let Some(shape) = input.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match P::FIELD_TYPE {
                FieldType::Bn254 => !input
                    .get_precompile_events(SyscallCode::BN254_FP_ADD)
                    .is_empty(),
                FieldType::Bls381 => !input
                    .get_precompile_events(SyscallCode::BLS12381_FP_ADD)
                    .is_empty(),
            }
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F, P> BaseAir<F> for FpOpChip<F, P>
where
    P: FpOpField,
{
    fn width(&self) -> usize {
        num_fp_cols::<P>()
    }
}

impl<F, P, CB> Air<CB> for FpOpChip<F, P>
where
    F: Field,
    CB: ChipBuilder<F>,
    P: FpOpField,
    Limbs<CB::Var, <P as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &FpOpCols<CB::Var, P> = (*local).borrow();

        // Check that nonce is incremented.
        builder.when_first_row().assert_zero(local.nonce);

        // Check that operations flags are boolean.
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_sub);
        builder.assert_bool(local.is_mul);

        // Check that only one of them is set.
        builder.assert_eq(local.is_add + local.is_sub + local.is_mul, CB::Expr::ONE);

        let p = limbs_from_prev_access(&local.x_access);
        let q = limbs_from_prev_access(&local.y_access);

        let modulus_coeffs = P::MODULUS
            .iter()
            .map(|&limbs| CB::Expr::from_canonical_u8(limbs))
            .collect_vec();
        let p_modulus = Polynomial::from_coefficients(&modulus_coeffs);

        local.output.eval_variable(
            builder,
            &p,
            &q,
            &p_modulus,
            local.is_add,
            local.is_sub,
            local.is_mul,
            CB::F::ZERO,
            local.chunk,
            local.is_real,
        );

        builder
            .when(local.is_real)
            .inner
            .assert_all_eq(local.output.result, value_as_limbs(&local.x_access));

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

        // Select the correct syscall id based on the operation flags.
        //
        // *Remark*: If support for division is added, we will need to add the division syscall id.
        let (add_syscall_id, sub_syscall_id, mul_syscall_id) = match P::FIELD_TYPE {
            FieldType::Bn254 => (
                CB::F::from_canonical_u32(SyscallCode::BN254_FP_ADD.syscall_id()),
                CB::F::from_canonical_u32(SyscallCode::BN254_FP_SUB.syscall_id()),
                CB::F::from_canonical_u32(SyscallCode::BN254_FP_MUL.syscall_id()),
            ),
            FieldType::Bls381 => (
                CB::F::from_canonical_u32(SyscallCode::BLS12381_FP_ADD.syscall_id()),
                CB::F::from_canonical_u32(SyscallCode::BLS12381_FP_SUB.syscall_id()),
                CB::F::from_canonical_u32(SyscallCode::BLS12381_FP_MUL.syscall_id()),
            ),
        };
        let syscall_id_felt = local.is_add * add_syscall_id
            + local.is_sub * sub_syscall_id
            + local.is_mul * mul_syscall_id;

        builder.looked_syscall(
            local.chunk,
            local.clk,
            local.nonce,
            syscall_id_felt,
            local.x_ptr,
            local.y_ptr,
            local.is_real,
            LookupScope::Regional,
        );
    }
}
