use crate::{
    chips::{
        chips::{
            rangecheck::event::{RangeLookupEvent, RangeRecordBehavior},
            riscv_memory::read_write::columns::{value_as_limbs, MemoryReadCols, MemoryWriteCols},
        },
        gadgets::{
            curves::{
                edwards::{
                    ed25519::Ed25519BaseField, EdwardsParameters, NUM_LIMBS, WORDS_CURVE_POINT,
                },
                AffinePoint, EllipticCurve,
            },
            field::{
                field_den::FieldDenCols,
                field_inner_product::FieldInnerProductCols,
                field_op::{FieldOpCols, FieldOperation},
            },
            utils::{
                field_params::{FieldParameters, NumLimbs},
                limbs::Limbs,
            },
        },
    },
    compiler::riscv::program::Program,
    emulator::{
        record::RecordBehavior,
        riscv::{
            record::EmulationRecord,
            syscalls::{
                precompiles::{edwards::event::EllipticCurveAddEvent, PrecompileEvent},
                SyscallCode,
            },
        },
    },
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
        lookup::LookupScope,
        utils::limbs_from_prev_access,
    },
    recursion_v2::stark::utils::pad_rows_fixed,
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use hashbrown::HashMap;
use num::{BigUint, Zero};
use p3_air::{Air, BaseAir};
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator, ParallelSlice};
use pico_derive::AlignedBorrow;
use std::{fmt::Debug, marker::PhantomData};
use tracing::debug;

pub const NUM_ED_ADD_COLS: usize = size_of::<EdAddAssignCols<u8>>();

/// A set of columns to compute `EdAdd` where a, b are field elements.
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed
/// or made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdAddAssignCols<T> {
    pub is_real: T,
    pub chunk: T,
    pub clk: T,
    pub nonce: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: [MemoryWriteCols<T>; WORDS_CURVE_POINT],
    pub q_access: [MemoryReadCols<T>; WORDS_CURVE_POINT],
    pub(crate) x3_numerator: FieldInnerProductCols<T, Ed25519BaseField>,
    pub(crate) y3_numerator: FieldInnerProductCols<T, Ed25519BaseField>,
    pub(crate) x1_mul_y1: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x2_mul_y2: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) f: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) d_mul_f: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x3_ins: FieldDenCols<T, Ed25519BaseField>,
    pub(crate) y3_ins: FieldDenCols<T, Ed25519BaseField>,
}

#[derive(Default)]
pub struct EdAddAssignChip<F, E> {
    _marker: PhantomData<(F, E)>,
}

impl<F: PrimeField32, E: EllipticCurve + EdwardsParameters> EdAddAssignChip<F, E> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops(
        record: &mut impl RangeRecordBehavior,
        chunk: u32,
        cols: &mut EdAddAssignCols<F>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        let x3_numerator = cols.x3_numerator.populate(
            record,
            chunk,
            &[p_x.clone(), q_x.clone()],
            &[q_y.clone(), p_y.clone()],
        );
        let y3_numerator = cols.y3_numerator.populate(
            record,
            chunk,
            &[p_y.clone(), p_x.clone()],
            &[q_y.clone(), q_x.clone()],
        );
        let x1_mul_y1 = cols
            .x1_mul_y1
            .populate(record, chunk, &p_x, &p_y, FieldOperation::Mul);
        let x2_mul_y2 = cols
            .x2_mul_y2
            .populate(record, chunk, &q_x, &q_y, FieldOperation::Mul);
        let f = cols
            .f
            .populate(record, chunk, &x1_mul_y1, &x2_mul_y2, FieldOperation::Mul);

        let d = E::d_biguint();
        let d_mul_f = cols
            .d_mul_f
            .populate(record, chunk, &f, &d, FieldOperation::Mul);

        cols.x3_ins
            .populate(record, chunk, &x3_numerator, &d_mul_f, true);
        cols.y3_ins
            .populate(record, chunk, &y3_numerator, &d_mul_f, false);
    }
}

impl<F: PrimeField32, E: EllipticCurve + EdwardsParameters> ChipBehavior<F>
    for EdAddAssignChip<F, E>
{
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "EdAddAssign".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let events: Vec<_> = input
            .get_precompile_events(SyscallCode::ED_ADD)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::EdAdd(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();
        debug!(
            "record {} ed add precompile events {:?}",
            input.chunk_index(),
            events.len()
        );
        let (_rows, nonces): (Vec<[F; NUM_ED_ADD_COLS]>, Vec<_>) = events
            .par_iter()
            .map(|event| {
                let mut row = [F::ZERO; NUM_ED_ADD_COLS];
                let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
                let mut rlu = Vec::new();
                Self::event_to_row(event, cols, &mut rlu);
                let nonce = *input.nonce_lookup.get(&event.lookup_id).unwrap();
                (row, nonce)
            })
            .unzip();

        let mut rows = _rows.clone();

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = [F::ZERO; NUM_ED_ADD_COLS];
                let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
                let zero = BigUint::zero();
                Self::populate_field_ops(
                    &mut vec![],
                    0,
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
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ED_ADD_COLS,
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut EdAddAssignCols<F> =
                trace.values[i * NUM_ED_ADD_COLS..(i + 1) * NUM_ED_ADD_COLS].borrow_mut();
            let nonce = nonces.get(i).unwrap_or(&0);
            cols.nonce = F::from_canonical_u32(*nonce);
        }

        trace
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let events: Vec<_> = input
            .get_precompile_events(SyscallCode::ED_ADD)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::EdAdd(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let rlu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut range: HashMap<RangeLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::ZERO; NUM_ED_ADD_COLS];
                    let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
                    Self::event_to_row(event, cols, &mut range);
                });
                range
            })
            .collect::<Vec<_>>();

        output.add_rangecheck_lookup_events(rlu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record.get_precompile_events(SyscallCode::ED_ADD).is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F: PrimeField32, E: EllipticCurve + EdwardsParameters> EdAddAssignChip<F, E> {
    /// Create a row from an event.
    fn event_to_row(
        event: &EllipticCurveAddEvent,
        cols: &mut EdAddAssignCols<F>,
        rlu: &mut impl RangeRecordBehavior,
    ) {
        // Decode affine points.
        let p = &event.p;
        let q = &event.q;
        let p = AffinePoint::<E>::from_words_le(p);
        let (p_x, p_y) = (p.x, p.y);
        let q = AffinePoint::<E>::from_words_le(q);
        let (q_x, q_y) = (q.x, q.y);

        // Populate basic columns.
        cols.is_real = F::ONE;
        cols.chunk = F::from_canonical_u32(event.chunk);
        cols.clk = F::from_canonical_u32(event.clk);
        cols.p_ptr = F::from_canonical_u32(event.p_ptr);
        cols.q_ptr = F::from_canonical_u32(event.q_ptr);

        Self::populate_field_ops(rlu, event.chunk, cols, p_x, p_y, q_x, q_y);

        // Populate the memory access columns.
        for i in 0..WORDS_CURVE_POINT {
            cols.q_access[i].populate(event.q_memory_records[i], rlu);
        }
        for i in 0..WORDS_CURVE_POINT {
            cols.p_access[i].populate(event.p_memory_records[i], rlu);
        }
    }
}

impl<F: Sync, E: EllipticCurve + EdwardsParameters> BaseAir<F> for EdAddAssignChip<F, E> {
    fn width(&self) -> usize {
        NUM_ED_ADD_COLS
    }
}

impl<F, CB, E> Air<CB> for EdAddAssignChip<F, E>
where
    F: Field,
    CB: ChipBuilder<F>,
    E: EllipticCurve + EdwardsParameters,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &EdAddAssignCols<CB::Var> = (*local).borrow();

        let x1: Limbs<CB::Var, <Ed25519BaseField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.p_access[0..8]);
        let x2: Limbs<CB::Var, <Ed25519BaseField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.q_access[0..8]);
        let y1: Limbs<CB::Var, <Ed25519BaseField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.p_access[8..16]);
        let y2: Limbs<CB::Var, <Ed25519BaseField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.q_access[8..16]);

        // x3_numerator = x1 * y2 + x2 * y1.
        local
            .x3_numerator
            .eval(builder, &[x1, x2], &[y2, y1], local.chunk, local.is_real);

        // y3_numerator = y1 * y2 + x1 * x2.
        local
            .y3_numerator
            .eval(builder, &[y1, x1], &[y2, x2], local.chunk, local.is_real);

        // f = x1 * x2 * y1 * y2.
        local.x1_mul_y1.eval(
            builder,
            &x1,
            &y1,
            FieldOperation::Mul,
            local.chunk,
            local.is_real,
        );
        local.x2_mul_y2.eval(
            builder,
            &x2,
            &y2,
            FieldOperation::Mul,
            local.chunk,
            local.is_real,
        );

        let x1_mul_y1 = local.x1_mul_y1.result;
        let x2_mul_y2 = local.x2_mul_y2.result;
        local.f.eval(
            builder,
            &x1_mul_y1,
            &x2_mul_y2,
            FieldOperation::Mul,
            local.chunk,
            local.is_real,
        );

        // d * f.
        let f = local.f.result;
        let d_biguint = E::d_biguint();
        let d_const = E::BaseField::to_limbs_field::<CB::Expr, _>(&d_biguint);
        local.d_mul_f.eval(
            builder,
            &f,
            &d_const,
            FieldOperation::Mul,
            local.chunk,
            local.is_real,
        );

        let d_mul_f = local.d_mul_f.result;

        // x3 = x3_numerator / (1 + d * f).
        local.x3_ins.eval(
            builder,
            &local.x3_numerator.result,
            &d_mul_f,
            true,
            local.chunk,
            local.is_real,
        );

        // y3 = y3_numerator / (1 - d * f).
        local.y3_ins.eval(
            builder,
            &local.y3_numerator.result,
            &d_mul_f,
            false,
            local.chunk,
            local.is_real,
        );

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]
        // This is to ensure that p_access is updated with the new value.
        let p_access_vec = value_as_limbs(&local.p_access);
        builder
            .when(local.is_real)
            .assert_all_eq(local.x3_ins.result, p_access_vec[0..NUM_LIMBS].to_vec());
        builder.when(local.is_real).assert_all_eq(
            local.y3_ins.result,
            p_access_vec[NUM_LIMBS..NUM_LIMBS * 2].to_vec(),
        );

        builder.eval_memory_access_slice(
            local.chunk,
            local.clk.into(),
            local.q_ptr,
            &local.q_access,
            local.is_real,
        );

        builder.eval_memory_access_slice(
            local.chunk,
            local.clk + CB::F::from_canonical_u32(1),
            local.p_ptr,
            &local.p_access,
            local.is_real,
        );

        builder.looked_syscall(
            local.chunk,
            local.clk,
            local.nonce,
            CB::F::from_canonical_u32(SyscallCode::ED_ADD.syscall_id()),
            local.p_ptr,
            local.q_ptr,
            local.is_real,
            LookupScope::Regional,
        );
    }
}
