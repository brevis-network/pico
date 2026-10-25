use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryCols, MemoryReadColsU8, MemoryWriteColsU8},
        },
        gadgets::{
            addr_add::AddrAddGadget,
            curves::{
                weierstrass::secp256r1::Secp256r1BaseField, AffinePoint, CurveType, EllipticCurve,
                EllipticCurveParameters,
            },
            field::{
                bls381::Bls381BaseField,
                bn254::Bn254BaseField,
                field_lt::FieldLtCols,
                field_op::{FieldOpCols, FieldOperation},
                secp256k1::Secp256k1BaseField,
            },
            syscall_addr::SyscallAddrGadget,
            utils::{
                conversions::{
                    generate_limbs_from_read_cols_u8, generate_limbs_from_write_cols_u8,
                    limbs_to_words,
                },
                field_params::{FieldParameters, NumLimbs, NumWords},
                limbs::Limbs,
                polynomial::Polynomial,
            },
        },
        precompiles::checked_u64_to_u32,
        trace::TraceData,
        utils::{next_power_of_two, pad_rows_fixed},
    },
    compiler::{riscv::program::Program, word::Word},
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{
        ffi::FFIEmulationRecord,
        record::EmulationRecord,
        syscalls::{
            precompiles::{edwards::event::EllipticCurveAddEventFFI, PrecompileEvent},
            SyscallCode,
        },
    },
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
    },
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind};
use hybrid_array::Array;
use num::{BigUint, One, Zero};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use pico_derive::AlignedBorrow;
use pico_gpu_api::{
    cuda_weierstrass_add_bls12381_generate_extra_record_and_main,
    cuda_weierstrass_add_bn254_generate_extra_record_and_main,
    cuda_weierstrass_add_secp256k1_generate_extra_record_and_main,
    cuda_weierstrass_add_secp256r1_generate_extra_record_and_main,
};
use std::{fmt::Debug, marker::PhantomData, mem::transmute};
use tracing::{debug, info};
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
    pub p_ptr: SyscallAddrGadget<T>,
    pub q_ptr: SyscallAddrGadget<T>,
    pub p_addrs: Array<AddrAddGadget<T>, P::WordsCurvePoint>,
    pub q_addrs: Array<AddrAddGadget<T>, P::WordsCurvePoint>,
    pub p_access: Array<MemoryWriteColsU8<T>, P::WordsCurvePoint>,
    pub q_access: Array<MemoryReadColsU8<T>, P::WordsCurvePoint>,
    pub(crate) slope_denominator: FieldOpCols<T, P>,
    pub(crate) inverse_check: FieldOpCols<T, P>,
    pub(crate) slope_numerator: FieldOpCols<T, P>,
    pub(crate) slope: FieldOpCols<T, P>,
    pub(crate) slope_squared: FieldOpCols<T, P>,
    pub(crate) p_x_plus_q_x: FieldOpCols<T, P>,
    pub(crate) x3_ins: FieldOpCols<T, P>,
    pub(crate) p_x_minus_x: FieldOpCols<T, P>,
    pub(crate) y3_ins: FieldOpCols<T, P>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<T, P>,
    pub x3_range: FieldLtCols<T, P>,
    pub y3_range: FieldLtCols<T, P>,
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
        cols: &mut WeierstrassAddAssignCols<F, E::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        // Reject a coordinate at or above the modulus before any field op runs, as the
        // sibling `weierstrass_double.rs` does. Trace-side only: the outputs are already
        // pinned to the memory bus and below the modulus by `x3_range`/`y3_range`.
        let modulus = E::BaseField::modulus();
        assert!(p_x < modulus, "curve coordinate p.x must be < modulus");
        assert!(p_y < modulus, "curve coordinate p.y must be < modulus");
        assert!(q_x < modulus, "curve coordinate q.x must be < modulus");
        assert!(q_y < modulus, "curve coordinate q.y must be < modulus");

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            let slope_numerator =
                cols.slope_numerator
                    .populate(blu_events, &q_y, &p_y, FieldOperation::Sub);

            let slope_denominator =
                cols.slope_denominator
                    .populate(blu_events, &q_x, &p_x, FieldOperation::Sub);

            // inverse_check: verify denominator is non-zero by computing 1 / denom.
            // For padding rows (all zeros), denominator is 0 — use 0/0=0 (allowed by field_op).
            let inverse_numerator = if slope_denominator == BigUint::zero() {
                BigUint::zero()
            } else {
                BigUint::one()
            };
            cols.inverse_check.populate(
                blu_events,
                &inverse_numerator,
                &slope_denominator,
                FieldOperation::Div,
            );

            cols.slope.populate(
                blu_events,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + q.x).
        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate(blu_events, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_q_x =
                cols.p_x_plus_q_x
                    .populate(blu_events, &p_x, &q_x, FieldOperation::Add);
            let x3 = cols.x3_ins.populate(
                blu_events,
                &slope_squared,
                &p_x_plus_q_x,
                FieldOperation::Sub,
            );
            cols.x3_range
                .populate(blu_events, &x3, &E::BaseField::modulus());
            x3
        };

        // y = slope * (p.x - x_3n) - p.y.
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
            let y3 = cols.y3_ins.populate(
                blu_events,
                &slope_times_p_x_minus_x,
                &p_y,
                FieldOperation::Sub,
            );
            cols.y3_range
                .populate(blu_events, &y3, &E::BaseField::modulus());
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve> ChipBehavior<F> for WeierstrassAddAssignChip<F, E> {
    type Record = EmulationRecord;
    type GpuRecord = FFIEmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1AddAssign".to_string(),
            CurveType::Secp256r1 => "Secp256r1AddAssign".to_string(),
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
            CurveType::Secp256r1 => &input.get_precompile_events(SyscallCode::SECP256R1_ADD),
            CurveType::Bn254 => &input.get_precompile_events(SyscallCode::BN254_ADD),
            CurveType::Bls12381 => &input.get_precompile_events(SyscallCode::BLS12381_ADD),
            _ => panic!("Unsupported curve"),
        };

        debug!("weierstrass add precompile events: {:?}", events.len());

        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();

        for i in 0..events.len() {
            let (_syscall_event, precompile_event) = &events[i];

            let event = match precompile_event {
                PrecompileEvent::Secp256k1Add(event)
                | PrecompileEvent::Secp256r1Add(event)
                | PrecompileEvent::Bn254Add(event)
                | PrecompileEvent::Bls12381Add(event) => event,
                _ => unreachable!(),
            };
            let mut row = vec![F::ZERO; num_weierstrass_add_cols::<E::BaseField>()];
            let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> =
                row.as_mut_slice().borrow_mut();

            // Decode affine points directly from u64 words.
            let p = AffinePoint::<E>::from_dwords_le(&event.p);
            let (p_x, p_y) = (p.x, p.y);
            let q = AffinePoint::<E>::from_dwords_le(&event.q);
            let (q_x, q_y) = (q.x, q.y);

            // Populate basic columns.
            cols.is_real = F::ONE;
            cols.chunk = F::from_u32(event.chunk);
            cols.clk = F::from_u32(checked_u64_to_u32(event.clk, "weierstrass add clk"));
            let len = <E::BaseField as NumLimbs>::Limbs::USIZE as u64 * 2;
            cols.p_ptr
                .populate(&mut new_byte_lookup_events, event.p_ptr, len);
            cols.q_ptr
                .populate(&mut new_byte_lookup_events, event.q_ptr, len);

            Self::populate_field_ops(&mut new_byte_lookup_events, cols, p_x, p_y, q_x, q_y);

            // Populate the memory access columns.
            for i in 0..cols.q_access.len() {
                cols.q_access[i]
                    .inner
                    .populate(event.q_memory_records[i], &mut new_byte_lookup_events);
                cols.q_access[i].prev_value_u8.populate_u16_to_u8_safe(
                    &mut new_byte_lookup_events,
                    event.q_memory_records[i].value,
                );
                cols.q_addrs[i].populate(&mut new_byte_lookup_events, event.q_ptr, 8 * i as u64);
            }
            for i in 0..cols.p_access.len() {
                cols.p_access[i]
                    .inner
                    .populate(event.p_memory_records[i], &mut new_byte_lookup_events);
                cols.p_access[i].prev_value_u8.populate_u16_to_u8_safe(
                    &mut new_byte_lookup_events,
                    event.p_memory_records[i].prev_value,
                );
                cols.p_addrs[i].populate(&mut new_byte_lookup_events, event.p_ptr, 8 * i as u64);
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
                let one = BigUint::one();

                // Set q_access memory values to match field_ops inputs (q_x=1, q_y=1).
                // The eval reads point coords from memory columns via
                // generate_limbs_from_read_cols_u8, so the memory values MUST
                // match what populate_field_ops receives, otherwise the
                // polynomial constraint (which is NOT gated by is_real) fails.
                let num_words_field_element = <E::BaseField as NumLimbs>::Limbs::USIZE / 8;
                // q_x first word = 1
                cols.q_access[0].inner.access.value.0[0] = F::ONE;
                cols.q_access[0].prev_value_u8.low_bytes[0] = F::ONE;
                // q_y first word = 1
                cols.q_access[num_words_field_element].inner.access.value.0[0] = F::ONE;
                cols.q_access[num_words_field_element]
                    .prev_value_u8
                    .low_bytes[0] = F::ONE;

                Self::populate_field_ops(&mut vec![], cols, zero.clone(), zero, one.clone(), one);
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
                CurveType::Secp256r1 => !chunk
                    .get_precompile_events(SyscallCode::SECP256R1_ADD)
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

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        // 1. Get events
        let events: &[EllipticCurveAddEventFFI<E::BaseField>] = match E::CURVE_TYPE {
            CurveType::Bn254 => {
                let events = prepared_gpu_events.bn254_weierstrass_add_events.as_slice();
                unsafe {
                    transmute::<
                        &[EllipticCurveAddEventFFI<Bn254BaseField>],
                        &[EllipticCurveAddEventFFI<E::BaseField>],
                    >(events)
                }
            }
            CurveType::Bls12381 => {
                let events = prepared_gpu_events
                    .bls12381_weierstrass_add_events
                    .as_slice();
                unsafe {
                    transmute::<
                        &[EllipticCurveAddEventFFI<Bls381BaseField>],
                        &[EllipticCurveAddEventFFI<E::BaseField>],
                    >(events)
                }
            }
            CurveType::Secp256k1 => {
                let events = prepared_gpu_events
                    .secp256k1_weierstrass_add_events
                    .as_slice();
                unsafe {
                    transmute::<
                        &[EllipticCurveAddEventFFI<Secp256k1BaseField>],
                        &[EllipticCurveAddEventFFI<E::BaseField>],
                    >(events)
                }
            }
            CurveType::Secp256r1 => {
                let events = prepared_gpu_events
                    .secp256r1_weierstrass_add_events
                    .as_slice();
                unsafe {
                    transmute::<
                        &[EllipticCurveAddEventFFI<Secp256r1BaseField>],
                        &[EllipticCurveAddEventFFI<E::BaseField>],
                    >(events)
                }
            }
            _ => panic!("Unsupported curve"),
        };

        // 2. Calculate padding rows
        let nrows = events.len();
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = next_power_of_two(nrows, log2_nrows);

        // 3. Create CUDA stream and memory pool
        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING)
            .expect("Failed to create CUDA stream");

        // 4. Copy events to the gpu
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let event_size = events.len();
        let mut d_events =
            DevicePoolAllocation::<EllipticCurveAddEventFFI<E::BaseField>>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .expect("GPU event memory allocation failed");

        unsafe {
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                events.as_c_void_ptr(),
                std::mem::size_of_val(events),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        // 5. Allocate and generate trace
        let num_cols = num_weierstrass_add_cols::<<E as EllipticCurveParameters>::BaseField>();
        let trace_size = padded_nrows * num_cols;

        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .expect("GPU trace memory allocation failed");

        // Generate trace
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        unsafe {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => {
                    cuda_weierstrass_add_secp256k1_generate_extra_record_and_main(
                        num_cols,
                        event_size,
                        trace_size,
                        d_events.as_ptr() as *const _,
                        d_trace.as_mut_ptr() as *mut _,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }
                CurveType::Secp256r1 => {
                    cuda_weierstrass_add_secp256r1_generate_extra_record_and_main(
                        num_cols,
                        event_size,
                        trace_size,
                        d_events.as_ptr() as *const _,
                        d_trace.as_mut_ptr() as *mut _,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }
                CurveType::Bn254 => {
                    cuda_weierstrass_add_bn254_generate_extra_record_and_main(
                        num_cols,
                        event_size,
                        trace_size,
                        d_events.as_ptr() as *const _,
                        d_trace.as_mut_ptr() as *mut _,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }
                CurveType::Bls12381 => {
                    cuda_weierstrass_add_bls12381_generate_extra_record_and_main(
                        num_cols,
                        event_size,
                        trace_size,
                        d_events.as_ptr() as *const _,
                        d_trace.as_mut_ptr() as *mut _,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }
                _ => panic!("Unsupported curve"),
            }
        }

        // 6. Switch to main stream and return result
        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!(
            "[weierstrass-add-assign-chip] generate_main on GPU, curve={:?}",
            E::CURVE_TYPE
        );

        TraceData::Gpu(num_cols, d_trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => !record.secp256k1_weierstrass_add_events.is_empty(),
                CurveType::Secp256r1 => !record.secp256r1_weierstrass_add_events.is_empty(),
                CurveType::Bn254 => !record.bn254_weierstrass_add_events.is_empty(),
                CurveType::Bls12381 => !record.bls12381_weierstrass_add_events.is_empty(),
                _ => panic!("Unsupported curve"),
            }
        }
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
        let local = main.current_slice();
        let local: &WeierstrassAddAssignCols<CB::Var, E::BaseField> = (*local).borrow();

        let num_words_field_element = <E::BaseField as NumLimbs>::Limbs::USIZE / 8;

        // Extract byte limbs from u16 word limbs via U16→U8 conversion.
        let p_x_limbs = generate_limbs_from_write_cols_u8(
            builder,
            &local.p_access[0..num_words_field_element],
            local.is_real.into(),
        );
        let p_x: Limbs<CB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(Array::try_from_iter(p_x_limbs).expect("failed to convert p_x limbs"));
        let p_y_limbs = generate_limbs_from_write_cols_u8(
            builder,
            &local.p_access[num_words_field_element..],
            local.is_real.into(),
        );
        let p_y: Limbs<CB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(Array::try_from_iter(p_y_limbs).expect("failed to convert p_y limbs"));
        let q_x_limbs = generate_limbs_from_read_cols_u8(
            builder,
            &local.q_access[0..num_words_field_element],
            local.is_real.into(),
        );
        let q_x: Limbs<CB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(Array::try_from_iter(q_x_limbs).expect("failed to convert q_x limbs"));
        let q_y_limbs = generate_limbs_from_read_cols_u8(
            builder,
            &local.q_access[num_words_field_element..],
            local.is_real.into(),
        );
        let q_y: Limbs<CB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(Array::try_from_iter(q_y_limbs).expect("failed to convert q_y limbs"));

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            local
                .slope_numerator
                .eval(builder, &q_y, &p_y, FieldOperation::Sub, local.is_real);

            local
                .slope_denominator
                .eval(builder, &q_x, &p_x, FieldOperation::Sub, local.is_real);

            // Check (q.x - p.x) is non-zero by computing 1 / (q.x - p.x).
            let mut coeff_1 = vec![CB::Expr::ZERO; <E::BaseField as NumLimbs>::Limbs::USIZE];
            coeff_1[0] = CB::Expr::ONE;
            let one_polynomial = Polynomial::from_coefficients(&coeff_1);

            local.inverse_check.eval(
                builder,
                &one_polynomial,
                &local.slope_denominator.result,
                FieldOperation::Div,
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

        // Range check x3 and y3 against the field modulus.
        let modulus = E::BaseField::to_limbs_field::<CB::Expr, CB::F>(&E::BaseField::modulus());
        local
            .x3_range
            .eval(builder, &local.x3_ins.result, &modulus, local.is_real);
        local
            .y3_range
            .eval(builder, &local.y3_ins.result, &modulus, local.is_real);

        // Reconstruct byte-level results into Words for memory write constraints.
        let x3_result_words = limbs_to_words(
            &local
                .x3_ins
                .result
                .0
                .iter()
                .map(|v| (*v).into())
                .collect::<Vec<CB::Expr>>(),
            CB::F::from_u32(256).into(),
        );
        let y3_result_words = limbs_to_words(
            &local
                .y3_ins
                .result
                .0
                .iter()
                .map(|v| (*v).into())
                .collect::<Vec<CB::Expr>>(),
            CB::F::from_u32(256).into(),
        );
        let result_words: Vec<_> = x3_result_words.into_iter().chain(y3_result_words).collect();

        // Address alignment constraints.
        let p_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            <E::BaseField as NumLimbs>::Limbs::USIZE as u32 * 2,
            local.p_ptr,
            local.is_real.into(),
        );
        let q_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            <E::BaseField as NumLimbs>::Limbs::USIZE as u32 * 2,
            local.q_ptr,
            local.is_real.into(),
        );

        for i in 0..local.p_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    p_ptr[0].into(),
                    p_ptr[1].into(),
                    p_ptr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                local.p_addrs[i],
                local.is_real.into(),
            );
        }
        for i in 0..local.q_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    q_ptr[0].into(),
                    q_ptr[1].into(),
                    q_ptr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                local.q_addrs[i],
                local.is_real.into(),
            );
        }

        // Memory access constraints.
        // Read q — iterate and call eval_memory_access individually.
        for (i, q_col) in local.q_access.iter().enumerate() {
            builder.eval_memory_access(
                local.chunk,
                local.clk.into(),
                local.q_addrs[i].value.map(Into::into),
                &q_col.inner,
                local.is_real,
            );
        }

        // Write p — iterate with value constraints.
        for (i, (p_col, write_value)) in local.p_access.iter().zip(result_words.iter()).enumerate()
        {
            builder.eval_memory_access(
                local.chunk,
                local.clk + CB::F::from_u32(1), /* p at +1 since p, q could be same */
                local.p_addrs[i].value.map(Into::into),
                &p_col.inner,
                local.is_real,
            );
            // Constrain that the current value matches the computed write value.
            let do_check: CB::Expr = local.is_real.into();
            for (v, w) in p_col.inner.value().0.iter().zip(write_value.0.iter()) {
                builder
                    .when(do_check.clone())
                    .assert_eq((*v).into(), w.clone());
            }
        }

        // Fetch the syscall id for the curve type.
        let syscall_id_felt = match E::CURVE_TYPE {
            CurveType::Secp256k1 => CB::F::from_u32(SyscallCode::SECP256K1_ADD.syscall_id()),
            CurveType::Secp256r1 => CB::F::from_u32(SyscallCode::SECP256R1_ADD.syscall_id()),
            CurveType::Bn254 => CB::F::from_u32(SyscallCode::BN254_ADD.syscall_id()),
            CurveType::Bls12381 => CB::F::from_u32(SyscallCode::BLS12381_ADD.syscall_id()),
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        };

        builder.looked_syscall(
            local.chunk,
            local.clk,
            syscall_id_felt,
            p_ptr.map(Into::into),
            q_ptr.map(Into::into),
            local.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use crate::chips::gadgets::utils::RandBigUint;
    use itertools::Itertools;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{rng, rngs::ThreadRng, RngExt};

    use crate::{
        chips::{
            chips::{
                byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
                events::{MemoryReadRecord, MemoryWriteRecord},
            },
            gadgets::curves::{
                weierstrass::{
                    bls381::Bls12381Parameters, bn254::Bn254Parameters,
                    secp256k1::Secp256k1Parameters, secp256r1::Secp256r1Parameters, SwCurve,
                },
                CurveType, EllipticCurve,
            },
            precompiles::weierstrass::weierstrass_add::WeierstrassAddAssignChip,
            tests::init_test_stream,
            trace::TraceData,
        },
        emulator::riscv::{
            record::EmulationRecord,
            syscalls::{
                precompiles::{EllipticCurveAddEvent, PrecompileEvent, PrecompileEvents},
                SyscallCode, SyscallEvent,
            },
        },
        instances::{
            compiler::shapes::riscv_shape::RiscvPadShape,
            preparer::{
                gpu_allocate_byte_trace, gpu_finalize_byte_trace, precompute_event_size,
                PreallocatedGpuMemory, PreparedGpuEvents,
            },
        },
        machine::chip::ChipBehavior,
    };

    type F = KoalaBear;

    /// Lazily initialized record for use across multiple tests.
    static SECP256K1_SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| {
        generate_record::<SwCurve<Secp256k1Parameters>, 16>(1 << 4, CurveType::Secp256k1)
    });

    static SECP256R1_SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| {
        generate_record::<SwCurve<Secp256r1Parameters>, 16>(1 << 4, CurveType::Secp256r1)
    });

    static BN254_SHARD: LazyLock<EmulationRecord> =
        LazyLock::new(|| generate_record::<SwCurve<Bn254Parameters>, 16>(1 << 4, CurveType::Bn254));

    static BLS12381_SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| {
        generate_record::<SwCurve<Bls12381Parameters>, 24>(1 << 4, CurveType::Bls12381)
    });

    fn cpu_generate_main<E: EllipticCurve>(
        chip: &WeierstrassAddAssignChip<F, E>,
        input: &EmulationRecord,
    ) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    fn generate_record<E: EllipticCurve, const WORDS_CURVE_POINT: usize>(
        size: usize,
        curve_type: CurveType,
    ) -> EmulationRecord {
        let mut rng = rng();
        let size = size as u32;
        let p_q_pairs = (0..4)
            .map(|_| {
                let p = random_point::<E>(&mut rng);
                let mut q = random_point::<E>(&mut rng);
                while p == q {
                    q = random_point::<E>(&mut rng);
                }
                (p, q)
            })
            .collect_vec();
        let events = (0..size)
            .map(|i| {
                let chunk = 0u32;
                let clk = i as u64;
                let p_ptr = (rng.random_range(0..size) * 4) as u64;
                let q_ptr = (rng.random_range(0..size) * 4) as u64;
                let (p, q) = p_q_pairs[(i as usize) % p_q_pairs.len()].clone();
                let p_memory_records = (0..WORDS_CURVE_POINT as u32)
                    .map(|_| MemoryWriteRecord {
                        prev_timestamp: i,
                        timestamp: i + 1,
                        ..Default::default()
                    })
                    .collect();
                let q_memory_records = (0..WORDS_CURVE_POINT as u32)
                    .map(|_| MemoryReadRecord {
                        prev_timestamp: i,
                        timestamp: i + 1,
                        ..Default::default()
                    })
                    .collect();
                let event = EllipticCurveAddEvent {
                    chunk,
                    clk,
                    p_ptr,
                    p,
                    q_ptr,
                    q,
                    p_memory_records,
                    q_memory_records,
                    local_mem_access: vec![],
                };
                match curve_type {
                    CurveType::Secp256k1 => (
                        SyscallEvent {
                            syscall_id: SyscallCode::SECP256K1_ADD.syscall_id(),
                            ..Default::default()
                        },
                        PrecompileEvent::Secp256k1Add(event),
                    ),
                    CurveType::Secp256r1 => (
                        SyscallEvent {
                            syscall_id: SyscallCode::SECP256R1_ADD.syscall_id(),
                            ..Default::default()
                        },
                        PrecompileEvent::Secp256r1Add(event),
                    ),
                    CurveType::Bn254 => (
                        SyscallEvent {
                            syscall_id: SyscallCode::BN254_ADD.syscall_id(),
                            ..Default::default()
                        },
                        PrecompileEvent::Bn254Add(event),
                    ),
                    CurveType::Bls12381 => (
                        SyscallEvent {
                            syscall_id: SyscallCode::BLS12381_ADD.syscall_id(),
                            ..Default::default()
                        },
                        PrecompileEvent::Bls12381Add(event),
                    ),
                    _ => panic!("Unsupported curve: {}", curve_type),
                }
            })
            .collect_vec();

        let syscode = match curve_type {
            CurveType::Secp256k1 => SyscallCode::SECP256K1_ADD,
            CurveType::Secp256r1 => SyscallCode::SECP256R1_ADD,
            CurveType::Bn254 => SyscallCode::BN254_ADD,
            CurveType::Bls12381 => SyscallCode::BLS12381_ADD,
            _ => panic!("Unsupported curve: {}", curve_type),
        };
        let mut precompile_events = PrecompileEvents::default();
        precompile_events.insert(syscode, events);

        let mut record = EmulationRecord::default();
        record.precompile_events = precompile_events.clone();

        record
    }

    fn random_point<E: EllipticCurve>(rng: &mut ThreadRng) -> Vec<u64> {
        let base = E::ec_generator();
        let point = rng.random_biguint(E::nb_scalar_bits() as u64);
        let point = base * point;
        // Convert u32 words to u64 dwords
        let words = point.to_words_le();
        words
            .chunks(2)
            .map(|chunk| {
                let lo = chunk[0] as u64;
                let hi = if chunk.len() > 1 { chunk[1] as u64 } else { 0 };
                lo | (hi << 32)
            })
            .collect()
    }

    fn gpu_generate_extra_record_and_main<E: EllipticCurve>(
        chip: &WeierstrassAddAssignChip<F, E>,
        input: &EmulationRecord,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> RowMajorMatrix<F> {
        let stream = init_test_stream();
        let trace = chip.gpu_generate_extra_record_and_main(
            0,
            input,
            prepared_gpu_events,
            preallocated_gpu_memory,
        );
        trace.to_host(stream)
    }

    #[test]
    fn test_secp256k1_addassign_generate_extra_record_and_main() {
        let original_record = LazyLock::force(&SECP256K1_SHARD);

        type E = SwCurve<Secp256k1Parameters>;
        let chip = WeierstrassAddAssignChip::<F, E>::default();

        // Complete the record for CPU computation.
        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);
        // Precompute event sizes for GPU computation.
        let mut counted_record = original_record.clone();
        let mut event_counter = precompute_event_size::<F>(&mut counted_record);
        // ignore events
        event_counter.num_poseidon2_events = 0;
        event_counter.num_global_lookup_events = 0;
        event_counter.num_syscall_events = 0;
        event_counter.num_precompile_syscall_events = 0;
        // Assert that the event counts are the same.
        event_counter.assert_event_counts_match(&complete_record);

        // Shape padding for CPU and GPU computation.
        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 4);
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 4);

        // Generate CPU trace.
        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        // Generate GPU trace.
        let stream = init_test_stream();
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);
        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
            ..Default::default()
        };
        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );
        // Assert trace consistency.
        assert_eq!(cpu_trace, gpu_trace);

        // Finalize the byte trace. And assert that the byte trace is consistent.
        gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();

        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(&stream);
        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }

    #[test]
    fn test_secp256r1_addassign_generate_extra_record_and_main() {
        let original_record = LazyLock::force(&SECP256R1_SHARD);

        type E = SwCurve<Secp256r1Parameters>;
        let chip = WeierstrassAddAssignChip::<F, E>::default();

        // Complete the record for CPU computation.
        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);
        // Precompute event sizes for GPU computation.
        let mut counted_record = original_record.clone();
        let mut event_counter = precompute_event_size::<F>(&mut counted_record);
        // ignore events
        event_counter.num_poseidon2_events = 0;
        event_counter.num_global_lookup_events = 0;
        event_counter.num_syscall_events = 0;
        event_counter.num_precompile_syscall_events = 0;
        // Assert that the event counts are the same.
        event_counter.assert_event_counts_match(&complete_record);

        // Shape padding for CPU and GPU computation.
        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 4);
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 4);

        // Generate CPU trace.
        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        // Generate GPU trace.
        let stream = init_test_stream();
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);
        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
            ..Default::default()
        };
        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );
        // Assert trace consistency.
        assert_eq!(cpu_trace, gpu_trace);

        // Finalize the byte trace. And assert that the byte trace is consistent.
        gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();

        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(&stream);
        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }

    #[test]
    fn test_bn254_addassign_generate_extra_record_and_main() {
        let original_record = LazyLock::force(&BN254_SHARD);

        type E = SwCurve<Bn254Parameters>;
        let chip = WeierstrassAddAssignChip::<F, E>::default();

        // Complete the record for CPU computation.
        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);
        // Precompute event sizes for GPU computation.
        let mut counted_record = original_record.clone();
        let mut event_counter = precompute_event_size::<F>(&mut counted_record);
        // ignore events
        event_counter.num_poseidon2_events = 0;
        event_counter.num_global_lookup_events = 0;
        event_counter.num_syscall_events = 0;
        event_counter.num_precompile_syscall_events = 0;
        // Assert that the event counts are the same.
        event_counter.assert_event_counts_match(&complete_record);

        // Shape padding for CPU and GPU computation.
        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 4);
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 4);

        // Generate CPU trace.
        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        // Generate GPU trace.
        let stream = init_test_stream();
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);
        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
            ..Default::default()
        };
        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );
        // Assert trace consistency.
        assert_eq!(cpu_trace, gpu_trace);

        // Finalize the byte trace. And assert that the byte trace is consistent.
        gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();

        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(&stream);
        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }

    #[test]
    fn test_bls12381_addassign_generate_extra_record_and_main() {
        let original_record = LazyLock::force(&BLS12381_SHARD);

        type E = SwCurve<Bls12381Parameters>;
        let chip = WeierstrassAddAssignChip::<F, E>::default();

        // Complete the record for CPU computation.
        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);
        // Precompute event sizes for GPU computation.
        let mut counted_record = original_record.clone();
        let mut event_counter = precompute_event_size::<F>(&mut counted_record);
        // ignore events
        event_counter.num_poseidon2_events = 0;
        event_counter.num_global_lookup_events = 0;
        event_counter.num_syscall_events = 0;
        event_counter.num_precompile_syscall_events = 0;
        // Assert that the event counts are the same.
        event_counter.assert_event_counts_match(&complete_record);

        // Shape padding for CPU and GPU computation.
        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 4);
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 4);

        // Generate CPU trace.
        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        // Generate GPU trace.
        let stream = init_test_stream();
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);
        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
            ..Default::default()
        };
        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );

        // Assert trace consistency.
        assert_eq!(cpu_trace, gpu_trace);

        // Finalize the byte trace. And assert that the byte trace is consistent.
        gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();

        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(&stream);
        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }

    #[test]
    fn bench_weierstrass_add_cpu_vs_gpu() {
        use std::time::Instant;

        fn bench_curve<E: EllipticCurve, const WORDS_CURVE_POINT: usize>(curve_type: CurveType) {
            let chip = WeierstrassAddAssignChip::<F, E>::new();
            let warmup_sizes: Vec<usize> = vec![1 << 10];
            let bench_sizes: Vec<usize> = vec![1 << 10, 1 << 14, 1 << 16];

            println!("\n  [{curve_type}]");
            println!("  {:-<58}", "");
            println!(
                "  {:<12} {:>12} {:>12} {:>12}",
                "events", "cpu (ms)", "gpu (ms)", "speedup"
            );
            println!("  {:-<58}", "");

            for (is_warmup, &num_events) in warmup_sizes
                .iter()
                .map(|n| (true, n))
                .chain(bench_sizes.iter().map(|n| (false, n)))
            {
                let original_record =
                    generate_record::<E, WORDS_CURVE_POINT>(num_events, curve_type);

                let mut complete_record = original_record.clone();
                let mut counted_record = original_record.clone();

                let log_rows = (num_events as f64).log2().ceil() as usize + 1;
                complete_record.shape = Some(RiscvPadShape::default());
                complete_record
                    .shape
                    .as_mut()
                    .unwrap()
                    .inner
                    .insert(chip.name(), log_rows);
                counted_record.shape = Some(RiscvPadShape::default());
                counted_record
                    .shape
                    .as_mut()
                    .unwrap()
                    .inner
                    .insert(chip.name(), log_rows);

                // CPU
                let cpu_start = Instant::now();
                chip.extra_record(&original_record, &mut complete_record);
                let cpu_trace = cpu_generate_main(&chip, &complete_record);
                let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

                // GPU
                let stream = init_test_stream();
                let prepared_gpu_events = PreparedGpuEvents::new(
                    &counted_record,
                    precompute_event_size::<F>(&mut counted_record.clone()),
                );
                let mut preallocated_gpu_memory = PreallocatedGpuMemory {
                    d_byte_trace: gpu_allocate_byte_trace(stream, 0).unwrap(),
                    ..Default::default()
                };

                stream.synchronize().unwrap();

                let gpu_start = Instant::now();
                let gpu_trace = gpu_generate_extra_record_and_main(
                    &chip,
                    &counted_record,
                    &prepared_gpu_events,
                    &mut preallocated_gpu_memory,
                );
                stream.synchronize().unwrap();
                let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

                if is_warmup {
                    println!(
                        "  {:<12} {:>12} {:>12} {:>12}",
                        num_events, "warmup", "warmup", "—"
                    );
                    continue;
                }

                assert_eq!(
                    cpu_trace, gpu_trace,
                    "Main trace mismatch at bench size {}",
                    num_events
                );

                let speedup = cpu_ms / gpu_ms;
                println!(
                    "  {:<12} {:>12.2} {:>12.2} {:>11.1}x  ✓",
                    num_events, cpu_ms, gpu_ms, speedup
                );
            }
            println!("  {:-<58}", "");
        }

        println!("\n{:=<60}", "");
        println!("  WeierstrassAddAssign CPU vs GPU Benchmark");
        println!("{:=<60}", "");

        bench_curve::<SwCurve<Secp256k1Parameters>, 16>(CurveType::Secp256k1);
        bench_curve::<SwCurve<Secp256r1Parameters>, 16>(CurveType::Secp256r1);
        bench_curve::<SwCurve<Bn254Parameters>, 16>(CurveType::Bn254);
        bench_curve::<SwCurve<Bls12381Parameters>, 24>(CurveType::Bls12381);
    }
}
