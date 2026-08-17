use super::words_to_bytes_le_slice;
use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryCols, MemoryReadColsU8, MemoryWriteColsU8},
        },
        gadgets::{
            addr_add::AddrAddGadget,
            field::{
                field_lt::FieldLtCols,
                field_op::{FieldOpCols, FieldOperation},
            },
            syscall_addr::SyscallAddrGadget,
            utils::{
                conversions::{
                    generate_limbs_from_read_cols_u8, generate_limbs_from_write_cols_u8,
                    limbs_to_words,
                },
                field_params::{FieldType, FpOpField, NumLimbs},
                limbs::Limbs,
                polynomial::Polynomial,
            },
        },
        precompiles::checked_u64_to_u32,
        utils::pad_rows_fixed,
    },
    compiler::{riscv::program::Program, word::Word},
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
    },
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
use p3_air::{Air, BaseAir};
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
    pub clk: F,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,

    pub x_ptr: SyscallAddrGadget<F>,
    pub y_ptr: SyscallAddrGadget<F>,
    pub x_addrs: Array<AddrAddGadget<F>, P::WordsFieldElement>,
    pub y_addrs: Array<AddrAddGadget<F>, P::WordsFieldElement>,
    pub x_access: Array<MemoryWriteColsU8<F>, P::WordsFieldElement>,
    pub y_access: Array<MemoryReadColsU8<F>, P::WordsFieldElement>,

    pub(crate) output: FieldOpCols<F, P>,
    pub(crate) output_range: FieldLtCols<F, P>,
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
        blu_events: &mut impl ByteRecordBehavior,
        cols: &mut FpOpCols<F, P>,
        p: BigUint,
        q: BigUint,
        op: FieldOperation,
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
        assert!(p < modulus, "fp operand x must be < modulus");
        assert!(q < modulus, "fp operand y must be < modulus");

        let output = cols
            .output
            .populate_with_modulus(blu_events, &p, &q, &modulus, op);
        cols.output_range.populate(blu_events, &output, &modulus);
    }
}

impl<F: PrimeField32, P: FpOpField> ChipBehavior<F> for FpOpChip<F, P> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        match P::FIELD_TYPE {
            FieldType::Bn254 => "Bn254FpOp".to_string(),
            FieldType::Bls381 => "Bls381FpOp".to_string(),
            FieldType::Secp256k1 => "Secp256k1FpOp".to_string(),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        // All the fp events for a given curve are coalesce to the curve's Add operation. Only retrieve
        // precompile events for that operation.
        let events = match P::FIELD_TYPE {
            FieldType::Bn254 => input
                .get_precompile_events(SyscallCode::BN254_FP_ADD)
                .iter(),
            FieldType::Bls381 => input
                .get_precompile_events(SyscallCode::BLS12381_FP_ADD)
                .iter(),
            FieldType::Secp256k1 => input
                .get_precompile_events(SyscallCode::SECP256K1_FP_ADD)
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
                (FieldType::Secp256k1, PrecompileEvent::Secp256k1Fp(event)) => event,
                _ => unreachable!(),
            };

            let mut row = vec![F::ZERO; num_fp_cols::<P>()];
            let cols: &mut FpOpCols<F, P> = row.as_mut_slice().borrow_mut();

            // Read exactly what the AIR reads: the raw memory limbs.
            //
            // These used to be reduced (`% modulus`) here, which the AIR never mirrors — it feeds
            // `x_access`/`y_access` straight into `FieldOpCols` (see `eval` below). For an operand
            // at or above the modulus the two therefore disagreed about `carry`, and the row could
            // not be proved even though the emulator had accepted the syscall. The reduction also
            // hid the missing entrance check, since `populate` never saw an out-of-range operand.
            let p = BigUint::from_bytes_le(&words_to_bytes_le_slice(&event.x));
            let q = BigUint::from_bytes_le(&words_to_bytes_le_slice(&event.y));

            cols.is_add = F::from_canonical_u8((event.op == FieldOperation::Add) as u8);
            cols.is_sub = F::from_canonical_u8((event.op == FieldOperation::Sub) as u8);
            cols.is_mul = F::from_canonical_u8((event.op == FieldOperation::Mul) as u8);
            cols.is_real = F::ONE;
            cols.chunk = F::from_canonical_u32(event.chunk);
            cols.clk = F::from_canonical_u32(checked_u64_to_u32(event.clk, "fptower fp clk"));

            cols.x_ptr.populate(
                &mut new_byte_lookup_events,
                event.x_ptr,
                P::NUM_LIMBS as u64,
            );
            cols.y_ptr.populate(
                &mut new_byte_lookup_events,
                event.y_ptr,
                P::NUM_LIMBS as u64,
            );

            Self::populate_field_ops(&mut new_byte_lookup_events, cols, p, q, event.op);

            // Populate the memory access columns.
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
            rows.push(row);
        }

        new_byte_lookup_events
            .iter()
            .for_each(|x| output.add_byte_lookup_event(*x));

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
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_fp_cols::<P>(),
        )
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
                FieldType::Secp256k1 => !input
                    .get_precompile_events(SyscallCode::SECP256K1_FP_ADD)
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

        // Check that operations flags are boolean.
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_sub);
        builder.assert_bool(local.is_mul);
        builder.assert_bool(local.is_real);

        // Check that only one of them is set.
        builder.assert_eq(local.is_add + local.is_sub + local.is_mul, CB::Expr::ONE);

        let p_limbs: Vec<CB::Expr> =
            generate_limbs_from_write_cols_u8(builder, &local.x_access, local.is_real.into());
        let p: Limbs<CB::Expr, <P as NumLimbs>::Limbs> =
            Limbs((&*p_limbs).try_into().expect("failed to convert limbs"));
        let q_limbs: Vec<CB::Expr> =
            generate_limbs_from_read_cols_u8(builder, &local.y_access, local.is_real.into());
        let q: Limbs<CB::Expr, <P as NumLimbs>::Limbs> =
            Limbs((&*q_limbs).try_into().expect("failed to convert limbs"));

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
            CB::Expr::ZERO,
            local.is_real,
        );
        local
            .output_range
            .eval(builder, &local.output.result, &p_modulus, local.is_real);

        let result_limbs: Vec<CB::Expr> = local
            .output
            .result
            .0
            .iter()
            .copied()
            .map(|x| x.into())
            .collect();
        let result_words =
            limbs_to_words::<CB::Expr>(&result_limbs, CB::F::from_canonical_u32(256).into());

        let x_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            P::NUM_LIMBS as u32,
            local.x_ptr,
            local.is_real.into(),
        );
        let y_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            P::NUM_LIMBS as u32,
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
            FieldType::Secp256k1 => (
                CB::F::from_canonical_u32(SyscallCode::SECP256K1_FP_ADD.syscall_id()),
                CB::F::from_canonical_u32(SyscallCode::SECP256K1_FP_SUB.syscall_id()),
                CB::F::from_canonical_u32(SyscallCode::SECP256K1_FP_MUL.syscall_id()),
            ),
        };
        let syscall_id_felt = local.is_add * add_syscall_id
            + local.is_sub * sub_syscall_id
            + local.is_mul * mul_syscall_id;

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
