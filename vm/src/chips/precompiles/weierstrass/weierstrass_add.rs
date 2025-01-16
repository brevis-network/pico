use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryCols, MemoryReadCols, MemoryWriteCols},
        },
        gadgets::{
            curves::{AffinePoint, CurveType, EllipticCurve},
            field::field_op::{FieldOpCols, FieldOperation},
            utils::{
                field_params::{FieldParameters, NumLimbs, NumWords},
                limbs::Limbs,
            },
        },
    },
    compiler::riscv::program::Program,
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{precompiles::PrecompileEvent, SyscallCode},
    },
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
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
use hybrid_array::Array;
use num::{BigUint, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use pico_derive::AlignedBorrow;
use std::{fmt::Debug, marker::PhantomData};
use tracing::info;
use typenum::Unsigned;

pub const fn num_weierstrass_add_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassAddAssignCols<u8, P>>()
}

/// A set of columns to compute `WeierstrassAdd` that add two points on a Weierstrass curve.
///
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed or
/// made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassAddAssignCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub chunk: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: Array<MemoryWriteCols<T>, P::WordsCurvePoint>,
    pub q_access: Array<MemoryReadCols<T>, P::WordsCurvePoint>,
    pub(crate) slope_denominator: FieldOpCols<T, P>,
    pub(crate) slope_numerator: FieldOpCols<T, P>,
    pub(crate) slope: FieldOpCols<T, P>,
    pub(crate) slope_squared: FieldOpCols<T, P>,
    pub(crate) p_x_plus_q_x: FieldOpCols<T, P>,
    pub(crate) x3_ins: FieldOpCols<T, P>,
    pub(crate) p_x_minus_x: FieldOpCols<T, P>,
    pub(crate) y3_ins: FieldOpCols<T, P>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<T, P>,
}

#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct WeierstrassAddAssignChip<F, E> {
    _marker: PhantomData<fn(F, E) -> (F, E)>,
}

impl<F: PrimeField32, E: EllipticCurve> WeierstrassAddAssignChip<F, E> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops(
        blu_events: &mut impl ByteRecordBehavior,
        chunk: u32,
        cols: &mut WeierstrassAddAssignCols<F, E::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        // This populates necessary field operations to calculate the addition of two points on a
        // Weierstrass curve.

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            let slope_numerator =
                cols.slope_numerator
                    .populate(blu_events, chunk, &q_y, &p_y, FieldOperation::Sub);

            let slope_denominator =
                cols.slope_denominator
                    .populate(blu_events, chunk, &q_x, &p_x, FieldOperation::Sub);

            cols.slope.populate(
                blu_events,
                chunk,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + q.x).
        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate(blu_events, chunk, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_q_x =
                cols.p_x_plus_q_x
                    .populate(blu_events, chunk, &p_x, &q_x, FieldOperation::Add);
            cols.x3_ins.populate(
                blu_events,
                chunk,
                &slope_squared,
                &p_x_plus_q_x,
                FieldOperation::Sub,
            )
        };

        // y = slope * (p.x - x_3n) - p.y.
        {
            let p_x_minus_x =
                cols.p_x_minus_x
                    .populate(blu_events, chunk, &p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                blu_events,
                chunk,
                &slope,
                &p_x_minus_x,
                FieldOperation::Mul,
            );
            cols.y3_ins.populate(
                blu_events,
                chunk,
                &slope_times_p_x_minus_x,
                &p_y,
                FieldOperation::Sub,
            );
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve> ChipBehavior<F> for WeierstrassAddAssignChip<F, E> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1AddAssign".to_string(),
            CurveType::Bn254 => "Bn254AddAssign".to_string(),
            CurveType::Bls12381 => "Bls12381AddAssign".to_string(),
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        }
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => &input.get_precompile_events(SyscallCode::SECP256K1_ADD),
            CurveType::Bn254 => &input.get_precompile_events(SyscallCode::BN254_ADD),
            CurveType::Bls12381 => &input.get_precompile_events(SyscallCode::BLS12381_ADD),
            _ => panic!("Unsupported curve"),
        };

        info!("weierstrass add precompile events: {:?}", events.len());

        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();

        for i in 0..events.len() {
            let (_syscall_event, precompile_event) = &events[i];

            let event = match precompile_event {
                PrecompileEvent::Secp256k1Add(event)
                | PrecompileEvent::Bn254Add(event)
                | PrecompileEvent::Bls12381Add(event) => event,
                _ => unreachable!(),
            };
            let mut row = vec![F::ZERO; num_weierstrass_add_cols::<E::BaseField>()];
            let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> =
                row.as_mut_slice().borrow_mut();

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

            Self::populate_field_ops(
                &mut new_byte_lookup_events,
                event.chunk,
                cols,
                p_x,
                p_y,
                q_x,
                q_y,
            );

            // Populate the memory access columns.
            for i in 0..cols.q_access.len() {
                cols.q_access[i].populate(event.q_memory_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..cols.p_access.len() {
                cols.p_access[i].populate(event.p_memory_records[i], &mut new_byte_lookup_events);
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
                let mut row = vec![F::ZERO; num_weierstrass_add_cols::<E::BaseField>()];
                let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> =
                    row.as_mut_slice().borrow_mut();
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
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_weierstrass_add_cols::<E::BaseField>(),
        )
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, chunk: &Self::Record) -> bool {
        if let Some(shape) = chunk.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => !chunk
                    .get_precompile_events(SyscallCode::SECP256K1_ADD)
                    .is_empty(),
                CurveType::Bn254 => !chunk
                    .get_precompile_events(SyscallCode::BN254_ADD)
                    .is_empty(),
                CurveType::Bls12381 => !chunk
                    .get_precompile_events(SyscallCode::BLS12381_ADD)
                    .is_empty(),
                _ => panic!("Unsupported curve"),
            }
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F, E: EllipticCurve> BaseAir<F> for WeierstrassAddAssignChip<F, E> {
    fn width(&self) -> usize {
        num_weierstrass_add_cols::<E::BaseField>()
    }
}

impl<F, CB, E: EllipticCurve> Air<CB> for WeierstrassAddAssignChip<F, E>
where
    F: Field,
    CB: ChipBuilder<F>,
    Limbs<CB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WeierstrassAddAssignCols<CB::Var, E::BaseField> = (*local).borrow();

        let num_words_field_element = <E::BaseField as NumLimbs>::Limbs::USIZE / 4;

        let p_x = limbs_from_prev_access(&local.p_access[0..num_words_field_element]);
        let p_y = limbs_from_prev_access(&local.p_access[num_words_field_element..]);

        let q_x = limbs_from_prev_access(&local.q_access[0..num_words_field_element]);
        let q_y = limbs_from_prev_access(&local.q_access[num_words_field_element..]);

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            local
                .slope_numerator
                .eval(builder, &q_y, &p_y, FieldOperation::Sub, local.is_real);

            local
                .slope_denominator
                .eval(builder, &q_x, &p_x, FieldOperation::Sub, local.is_real);

            local.slope.eval(
                builder,
                &local.slope_numerator.result,
                &local.slope_denominator.result,
                FieldOperation::Div,
                local.is_real,
            );

            &local.slope.result
        };

        // x = slope * slope - self.x - other.x.
        let x = {
            local
                .slope_squared
                .eval(builder, slope, slope, FieldOperation::Mul, local.is_real);

            local
                .p_x_plus_q_x
                .eval(builder, &p_x, &q_x, FieldOperation::Add, local.is_real);

            local.x3_ins.eval(
                builder,
                &local.slope_squared.result,
                &local.p_x_plus_q_x.result,
                FieldOperation::Sub,
                local.is_real,
            );

            &local.x3_ins.result
        };

        // y = slope * (p.x - x_3n) - q.y.
        {
            local
                .p_x_minus_x
                .eval(builder, &p_x, x, FieldOperation::Sub, local.is_real);

            local.slope_times_p_x_minus_x.eval(
                builder,
                slope,
                &local.p_x_minus_x.result,
                FieldOperation::Mul,
                local.is_real,
            );

            local.y3_ins.eval(
                builder,
                &local.slope_times_p_x_minus_x.result,
                &p_y,
                FieldOperation::Sub,
                local.is_real,
            );
        }

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]. This is to
        // ensure that p_access is updated with the new value.
        for i in 0..E::BaseField::NUM_LIMBS {
            builder
                .when(local.is_real)
                .assert_eq(local.x3_ins.result[i], local.p_access[i / 4].value()[i % 4]);
            builder.when(local.is_real).assert_eq(
                local.y3_ins.result[i],
                local.p_access[num_words_field_element + i / 4].value()[i % 4],
            );
        }

        builder.eval_memory_access_slice(
            local.chunk,
            local.clk.into(),
            local.q_ptr,
            &local.q_access,
            local.is_real,
        );
        builder.eval_memory_access_slice(
            local.chunk,
            local.clk + CB::F::from_canonical_u32(1), /* We read p at +1 since p, q could be the
                                                       * same. */
            local.p_ptr,
            &local.p_access,
            local.is_real,
        );

        // Fetch the syscall id for the curve type.
        let syscall_id_felt = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                CB::F::from_canonical_u32(SyscallCode::SECP256K1_ADD.syscall_id())
            }
            CurveType::Bn254 => CB::F::from_canonical_u32(SyscallCode::BN254_ADD.syscall_id()),
            CurveType::Bls12381 => {
                CB::F::from_canonical_u32(SyscallCode::BLS12381_ADD.syscall_id())
            }
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        };

        builder.looked_syscall(
            local.chunk,
            local.clk,
            syscall_id_felt,
            local.p_ptr,
            local.q_ptr,
            local.is_real,
            LookupScope::Regional,
        );
    }
}
