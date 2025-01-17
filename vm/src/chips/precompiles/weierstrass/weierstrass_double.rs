use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryCols, MemoryWriteCols},
        },
        gadgets::{
            curves::{weierstrass::WeierstrassParameters, AffinePoint, CurveType, EllipticCurve},
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
use p3_field::{Field, FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use pico_derive::AlignedBorrow;
use std::{fmt::Debug, marker::PhantomData};

pub const fn num_weierstrass_double_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassDoubleAssignCols<u8, P>>()
}

/// A set of columns to double a point on a Weierstrass curve.
///
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed or
/// made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassDoubleAssignCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub chunk: T,
    pub clk: T,
    pub p_ptr: T,
    pub p_access: Array<MemoryWriteCols<T>, P::WordsCurvePoint>,
    pub(crate) slope_denominator: FieldOpCols<T, P>,
    pub(crate) slope_numerator: FieldOpCols<T, P>,
    pub(crate) slope: FieldOpCols<T, P>,
    pub(crate) p_x_squared: FieldOpCols<T, P>,
    pub(crate) p_x_squared_times_3: FieldOpCols<T, P>,
    pub(crate) slope_squared: FieldOpCols<T, P>,
    pub(crate) p_x_plus_p_x: FieldOpCols<T, P>,
    pub(crate) x3_ins: FieldOpCols<T, P>,
    pub(crate) p_x_minus_x: FieldOpCols<T, P>,
    pub(crate) y3_ins: FieldOpCols<T, P>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<T, P>,
}

#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct WeierstrassDoubleAssignChip<F, E> {
    _marker: PhantomData<fn(F, E) -> (F, E)>,
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> WeierstrassDoubleAssignChip<F, E> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    fn populate_field_ops(
        blu_events: &mut impl ByteRecordBehavior,
        cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
    ) {
        // This populates necessary field operations to double a point on a Weierstrass curve.

        let a = E::a_int();

        // slope = slope_numerator / slope_denominator.
        let slope = {
            // slope_numerator = a + (p.x * p.x) * 3.
            let slope_numerator = {
                let p_x_squared =
                    cols.p_x_squared
                        .populate(blu_events, &p_x, &p_x, FieldOperation::Mul);
                let p_x_squared_times_3 = cols.p_x_squared_times_3.populate(
                    blu_events,
                    &p_x_squared,
                    &BigUint::from(3u32),
                    FieldOperation::Mul,
                );
                cols.slope_numerator.populate(
                    blu_events,
                    &a,
                    &p_x_squared_times_3,
                    FieldOperation::Add,
                )
            };

            // slope_denominator = 2 * y.
            let slope_denominator = cols.slope_denominator.populate(
                blu_events,
                &BigUint::from(2u32),
                &p_y,
                FieldOperation::Mul,
            );

            cols.slope.populate(
                blu_events,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + p.x).
        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate(blu_events, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_p_x =
                cols.p_x_plus_p_x
                    .populate(blu_events, &p_x, &p_x, FieldOperation::Add);
            cols.x3_ins.populate(
                blu_events,
                &slope_squared,
                &p_x_plus_p_x,
                FieldOperation::Sub,
            )
        };

        // y = slope * (p.x - x) - p.y.
        {
            let p_x_minus_x = cols
                .p_x_minus_x
                .populate(blu_events, &p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                blu_events,
                &slope,
                &p_x_minus_x,
                FieldOperation::Mul,
            );
            cols.y3_ins.populate(
                blu_events,
                &slope_times_p_x_minus_x,
                &p_y,
                FieldOperation::Sub,
            );
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> ChipBehavior<F>
    for WeierstrassDoubleAssignChip<F, E>
{
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1DoubleAssign".to_string(),
            CurveType::Bn254 => "Bn254DoubleAssign".to_string(),
            CurveType::Bls12381 => "Bls12381DoubleAssign".to_string(),
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        }
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        // collects the events based on the curve type.

        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_DOUBLE),
            CurveType::Bn254 => input.get_precompile_events(SyscallCode::BN254_DOUBLE),
            CurveType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_DOUBLE),
            _ => panic!("Unsupported curve"),
        };

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows_only = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|event_pair| {
                        let (_syscall_event, precompile_event) = event_pair;
                        let event = match precompile_event {
                            PrecompileEvent::Secp256k1Double(event)
                            | PrecompileEvent::Bn254Double(event)
                            | PrecompileEvent::Bls12381Double(event) => event,
                            _ => unreachable!(),
                        };

                        let mut row = vec![F::ZERO; num_weierstrass_double_cols::<E::BaseField>()];
                        let cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField> =
                            row.as_mut_slice().borrow_mut();

                        // Decode affine points.
                        let p = &event.p;
                        let p = AffinePoint::<E>::from_words_le(p);
                        let (p_x, p_y) = (p.x, p.y);

                        // Populate basic columns.
                        cols.is_real = F::ONE;
                        cols.chunk = F::from_canonical_u32(event.chunk);
                        cols.clk = F::from_canonical_u32(event.clk);
                        cols.p_ptr = F::from_canonical_u32(event.p_ptr);

                        Self::populate_field_ops(&mut new_byte_lookup_events, cols, p_x, p_y);

                        // Populate the memory access columns.
                        for i in 0..cols.p_access.len() {
                            cols.p_access[i]
                                .populate(event.p_memory_records[i], &mut new_byte_lookup_events);
                        }
                        row
                    })
                    .collect::<Vec<_>>();
                //record.add_rangecheck_lookup_events(new_byte_lookup_events);
                //output.add_rangecheck_lookup_events(new_byte_lookup_events)
                // TODO can only get from out side
                //output.add_range_lookup_events(new_byte_lookup_events);
                (rows, new_byte_lookup_events)
            })
            .collect::<Vec<_>>();

        // Generate the trace rows for each event.
        let mut rows = Vec::new();
        for row in rows_only {
            rows.extend(row.0);
            output.add_byte_lookup_events(row.1);
        }

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = vec![F::ZERO; num_weierstrass_double_cols::<E::BaseField>()];
                let cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField> =
                    row.as_mut_slice().borrow_mut();
                let zero = BigUint::zero();
                Self::populate_field_ops(&mut vec![], cols, zero.clone(), zero.clone());
                row
            },
            log_rows,
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_weierstrass_double_cols::<E::BaseField>(),
        )
    }

    fn is_active(&self, chunk: &Self::Record) -> bool {
        if let Some(shape) = chunk.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => !chunk
                    .get_precompile_events(SyscallCode::SECP256K1_DOUBLE)
                    .is_empty(),
                CurveType::Bn254 => !chunk
                    .get_precompile_events(SyscallCode::BN254_DOUBLE)
                    .is_empty(),
                CurveType::Bls12381 => !chunk
                    .get_precompile_events(SyscallCode::BLS12381_DOUBLE)
                    .is_empty(),
                _ => panic!("Unsupported curve"),
            }
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F, E: EllipticCurve + WeierstrassParameters> BaseAir<F> for WeierstrassDoubleAssignChip<F, E> {
    fn width(&self) -> usize {
        num_weierstrass_double_cols::<E::BaseField>()
    }
}

impl<F: PrimeField32, CB, E: EllipticCurve + WeierstrassParameters> Air<CB>
    for WeierstrassDoubleAssignChip<F, E>
where
    F: Field,
    CB: ChipBuilder<F>,
    Limbs<CB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WeierstrassDoubleAssignCols<CB::Var, E::BaseField> = (*local).borrow();

        let num_words_field_element = E::BaseField::NUM_LIMBS / 4;
        let p_x = limbs_from_prev_access(&local.p_access[0..num_words_field_element]);
        let p_y = limbs_from_prev_access(&local.p_access[num_words_field_element..]);

        // `a` in the Weierstrass form: y^2 = x^3 + a * x + b.
        let a = E::BaseField::to_limbs_field::<CB::Expr, _>(&E::a_int());

        // slope = slope_numerator / slope_denominator.
        let slope = {
            // slope_numerator = a + (p.x * p.x) * 3.
            {
                local
                    .p_x_squared
                    .eval(builder, &p_x, &p_x, FieldOperation::Mul, local.is_real);

                local.p_x_squared_times_3.eval(
                    builder,
                    &local.p_x_squared.result,
                    &E::BaseField::to_limbs_field::<CB::Expr, _>(&BigUint::from(3u32)),
                    FieldOperation::Mul,
                    local.is_real,
                );

                local.slope_numerator.eval(
                    builder,
                    &a,
                    &local.p_x_squared_times_3.result,
                    FieldOperation::Add,
                    local.is_real,
                );
            };

            // slope_denominator = 2 * y.
            local.slope_denominator.eval(
                builder,
                &E::BaseField::to_limbs_field::<CB::Expr, _>(&BigUint::from(2u32)),
                &p_y,
                FieldOperation::Mul,
                local.is_real,
            );

            local.slope.eval(
                builder,
                &local.slope_numerator.result,
                &local.slope_denominator.result,
                FieldOperation::Div,
                local.is_real,
            );

            &local.slope.result
        };

        // x = slope * slope - (p.x + p.x).
        let x = {
            local
                .slope_squared
                .eval(builder, slope, slope, FieldOperation::Mul, local.is_real);
            local
                .p_x_plus_p_x
                .eval(builder, &p_x, &p_x, FieldOperation::Add, local.is_real);
            local.x3_ins.eval(
                builder,
                &local.slope_squared.result,
                &local.p_x_plus_p_x.result,
                FieldOperation::Sub,
                local.is_real,
            );
            &local.x3_ins.result
        };

        // y = slope * (p.x - x) - p.y.
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
            local.p_ptr,
            &local.p_access,
            local.is_real,
        );

        // Fetch the syscall id for the curve type.
        let syscall_id_felt = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                CB::F::from_canonical_u32(SyscallCode::SECP256K1_DOUBLE.syscall_id())
            }
            CurveType::Bn254 => CB::F::from_canonical_u32(SyscallCode::BN254_DOUBLE.syscall_id()),
            CurveType::Bls12381 => {
                CB::F::from_canonical_u32(SyscallCode::BLS12381_DOUBLE.syscall_id())
            }
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        };

        builder.looked_syscall(
            local.clk,
            syscall_id_felt,
            local.p_ptr,
            CB::Expr::ZERO,
            local.is_real,
        );
    }
}
