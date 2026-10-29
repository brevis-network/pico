use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryCols, MemoryWriteColsU8},
        },
        gadgets::{
            addr_add::AddrAddGadget,
            curves::{weierstrass::WeierstrassParameters, AffinePoint, CurveType, EllipticCurve},
            field::{
                field_lt::FieldLtCols,
                field_op::{FieldOpCols, FieldOperation},
            },
            syscall_addr::SyscallAddrGadget,
            utils::{
                conversions::{generate_limbs_from_write_cols_u8, limbs_to_words},
                field_params::{FieldParameters, NumLimbs, NumWords},
                limbs::Limbs,
                polynomial::Polynomial,
            },
        },
        precompiles::checked_u64_to_u32,
        utils::pad_rows_fixed,
    },
    compiler::{riscv::program::Program, word::Word},
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{precompiles::PrecompileEvent, SyscallCode},
    },
    iter::{PicoIterator, PicoSlice},
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
    },
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{
        gadgets::{
            curves::{weierstrass::secp256r1::Secp256r1BaseField, EllipticCurveParameters},
            field::{
                bls381::Bls381BaseField, bn254::Bn254BaseField, secp256k1::Secp256k1BaseField,
            },
        },
        trace::TraceData,
        utils::next_power_of_two,
    },
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::syscalls::precompiles::ec::event::EllipticCurveDoubleFfiEvent,
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind};
use hybrid_array::Array;
#[cfg(feature = "cuda")]
use log::info;
use num::{BigUint, One, Zero};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_derive::AlignedBorrow;
#[cfg(feature = "cuda")]
use pico_gpu_api::{
    cuda_weierstrass_double_bls12381_generate_extra_record_and_main,
    cuda_weierstrass_double_bn254_generate_extra_record_and_main,
    cuda_weierstrass_double_secp256k1_generate_extra_record_and_main,
    cuda_weierstrass_double_secp256r1_generate_extra_record_and_main,
};
#[cfg(feature = "cuda")]
use std::mem::transmute;
use std::{fmt::Debug, marker::PhantomData};
use typenum::Unsigned;

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
    pub p_ptr: SyscallAddrGadget<T>,
    pub p_addrs: Array<AddrAddGadget<T>, P::WordsCurvePoint>,
    pub p_access: Array<MemoryWriteColsU8<T>, P::WordsCurvePoint>,
    pub(crate) slope_denominator: FieldOpCols<T, P>,
    pub(crate) inverse_check: FieldOpCols<T, P>,
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
    pub x3_range: FieldLtCols<T, P>,
    pub y3_range: FieldLtCols<T, P>,
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

        // Reject a coordinate at or above the modulus here, before any field op runs.
        //
        // This is a *domain* error and the message should say so. Without this check the same
        // input trips `populate_carry_and_witness`' internal `debug_assert!(&carry < modulus)`
        // several layers down inside `p_x_squared`, which reports a symptom rather than the cause.
        //
        // Trace-side only, deliberately: the AIR does not constrain the operands and does not need
        // to. Each field op asserts `a op b == result + carry * modulus`, which holds mod p for any
        // representative, and both outputs are pinned -- to the memory bus and, by
        // `x3_range`/`y3_range`, below the modulus -- so the value written back is unique whatever
        // representative the operands use. The only non-arithmetic predicate here, `inverse_check`,
        // asks a field question (is the denominator invertible), so it too is insensitive to the
        // representative.
        let modulus = E::BaseField::modulus();
        assert!(p_x < modulus, "curve coordinate p.x must be < modulus");
        assert!(p_y < modulus, "curve coordinate p.y must be < modulus");

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

        // x = slope * slope - (p.x + p.x).
        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate(blu_events, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_p_x =
                cols.p_x_plus_p_x
                    .populate(blu_events, &p_x, &p_x, FieldOperation::Add);
            let x3 = cols.x3_ins.populate(
                blu_events,
                &slope_squared,
                &p_x_plus_p_x,
                FieldOperation::Sub,
            );
            cols.x3_range
                .populate(blu_events, &x3, &E::BaseField::modulus());
            x3
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

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> ChipBehavior<F>
    for WeierstrassDoubleAssignChip<F, E>
{
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1DoubleAssign".to_string(),
            CurveType::Secp256r1 => "Secp256r1DoubleAssign".to_string(),
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
            CurveType::Secp256r1 => input.get_precompile_events(SyscallCode::SECP256R1_DOUBLE),
            CurveType::Bn254 => input.get_precompile_events(SyscallCode::BN254_DOUBLE),
            CurveType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_DOUBLE),
            _ => panic!("Unsupported curve"),
        };

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows_only = events
            .pico_chunks(chunk_size)
            .map(|events| {
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|event_pair| {
                        let (_syscall_event, precompile_event) = event_pair;
                        let event = match precompile_event {
                            PrecompileEvent::Secp256k1Double(event)
                            | PrecompileEvent::Secp256r1Double(event)
                            | PrecompileEvent::Bn254Double(event)
                            | PrecompileEvent::Bls12381Double(event) => event,
                            _ => unreachable!(),
                        };

                        let mut row = vec![F::ZERO; num_weierstrass_double_cols::<E::BaseField>()];
                        let cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField> =
                            row.as_mut_slice().borrow_mut();

                        // Decode affine points directly from u64 words.
                        let p = AffinePoint::<E>::from_dwords_le(&event.p);
                        let (p_x, p_y) = (p.x, p.y);

                        // Populate basic columns.
                        cols.is_real = F::ONE;
                        cols.chunk = F::from_u32(event.chunk);
                        cols.clk =
                            F::from_u32(checked_u64_to_u32(event.clk, "weierstrass double clk"));
                        let len = <E::BaseField as NumLimbs>::Limbs::USIZE as u64 * 2;
                        cols.p_ptr
                            .populate(&mut new_byte_lookup_events, event.p_ptr, len);

                        Self::populate_field_ops(&mut new_byte_lookup_events, cols, p_x, p_y);

                        // Populate the memory access columns.
                        for i in 0..cols.p_access.len() {
                            cols.p_access[i]
                                .inner
                                .populate(event.p_memory_records[i], &mut new_byte_lookup_events);
                            cols.p_access[i].prev_value_u8.populate_u16_to_u8_safe(
                                &mut new_byte_lookup_events,
                                event.p_memory_records[i].prev_value,
                            );
                            cols.p_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.p_ptr,
                                8 * i as u64,
                            );
                        }
                        row
                    })
                    .collect::<Vec<_>>();
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
                // Use (x = 0, y = 1) as the dummy point so that
                // slope_denominator = 2*y = 2 is non-zero, avoiding the
                // `division by zero` assertion in FieldOpCols::populate for
                // curves with a != 0 (e.g. secp256r1 where a = -3).
                //
                // The eval reads point coords from `p_access` via
                // `generate_limbs_from_write_cols_u8`, which uses
                // `inner.prev_value` and `prev_value_u8.low_bytes`. Those
                // constraints are NOT gated by is_real, so the memory
                // values must match the field-op inputs (p_y = 1).
                let num_words_field_element = <E::BaseField as NumLimbs>::Limbs::USIZE / 8;
                cols.p_access[num_words_field_element].inner.prev_value.0[0] = F::ONE;
                cols.p_access[num_words_field_element]
                    .prev_value_u8
                    .low_bytes[0] = F::ONE;

                let zero = BigUint::zero();
                let one = BigUint::one();
                Self::populate_field_ops(&mut vec![], cols, zero, one);
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
                CurveType::Secp256r1 => !chunk
                    .get_precompile_events(SyscallCode::SECP256R1_DOUBLE)
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

#[cfg(feature = "cuda")]
impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> GpuChipBehavior<F>
    for WeierstrassDoubleAssignChip<F, E>
{
    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        use p3_koala_bear::KoalaBear;

        // 1. Get events
        let events: &[EllipticCurveDoubleFfiEvent<E::BaseField>] = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                let events = prepared_gpu_events
                    .secp256k1_weierstrass_double_events
                    .as_slice();
                unsafe {
                    transmute::<
                        &[EllipticCurveDoubleFfiEvent<Secp256k1BaseField>],
                        &[EllipticCurveDoubleFfiEvent<E::BaseField>],
                    >(events)
                }
            }
            CurveType::Secp256r1 => {
                let events = prepared_gpu_events
                    .secp256r1_weierstrass_double_events
                    .as_slice();
                unsafe {
                    transmute::<
                        &[EllipticCurveDoubleFfiEvent<Secp256r1BaseField>],
                        &[EllipticCurveDoubleFfiEvent<E::BaseField>],
                    >(events)
                }
            }
            CurveType::Bn254 => {
                let events = prepared_gpu_events
                    .bn254_weierstrass_double_events
                    .as_slice();
                unsafe {
                    transmute::<
                        &[EllipticCurveDoubleFfiEvent<Bn254BaseField>],
                        &[EllipticCurveDoubleFfiEvent<E::BaseField>],
                    >(events)
                }
            }
            CurveType::Bls12381 => {
                let events = prepared_gpu_events
                    .bls12381_weierstrass_double_events
                    .as_slice();
                unsafe {
                    transmute::<
                        &[EllipticCurveDoubleFfiEvent<Bls381BaseField>],
                        &[EllipticCurveDoubleFfiEvent<E::BaseField>],
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
            DevicePoolAllocation::<EllipticCurveDoubleFfiEvent<E::BaseField>>::alloc_from_pool_async(
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
        let num_cols = num_weierstrass_double_cols::<<E as EllipticCurveParameters>::BaseField>();
        let trace_size = padded_nrows * num_cols;
        println!(
            "[weierstrass-double-assign-chip] num_events: {}",
            events.len()
        );
        println!("[weierstrass-double-assign-chip] num_cols: {}", num_cols);

        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .expect("GPU trace memory allocation failed");

        // Generate trace
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        unsafe {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => {
                    cuda_weierstrass_double_secp256k1_generate_extra_record_and_main(
                        d_events.as_ptr() as *const _,
                        events.len(),
                        d_trace.as_mut_ptr() as *mut _,
                        padded_nrows,
                        num_cols,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }
                CurveType::Secp256r1 => {
                    cuda_weierstrass_double_secp256r1_generate_extra_record_and_main(
                        d_events.as_ptr() as *const _,
                        events.len(),
                        d_trace.as_mut_ptr() as *mut _,
                        padded_nrows,
                        num_cols,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }
                CurveType::Bn254 => {
                    cuda_weierstrass_double_bn254_generate_extra_record_and_main(
                        d_events.as_ptr() as *const _,
                        events.len(),
                        d_trace.as_mut_ptr() as *mut _,
                        padded_nrows,
                        num_cols,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }
                CurveType::Bls12381 => {
                    cuda_weierstrass_double_bls12381_generate_extra_record_and_main(
                        d_events.as_ptr() as *const _,
                        events.len(),
                        d_trace.as_mut_ptr() as *mut _,
                        padded_nrows,
                        num_cols,
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

        info!("[weierstrass-double-assign-chip] generate_main on GPU");

        TraceData::Gpu(num_cols, d_trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => !record.secp256k1_weierstrass_double_events.is_empty(),
                CurveType::Secp256r1 => !record.secp256r1_weierstrass_double_events.is_empty(),
                CurveType::Bn254 => !record.bn254_weierstrass_double_events.is_empty(),
                CurveType::Bls12381 => !record.bls12381_weierstrass_double_events.is_empty(),
                _ => panic!("Unsupported curve"),
            }
        }
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
        let local = main.current_slice();
        let local: &WeierstrassDoubleAssignCols<CB::Var, E::BaseField> = (*local).borrow();

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

        // Bound the input coordinates before any field op consumes them.
        //
        // `generate_limbs_from_write_cols_u8` only pins each limb to a byte, i.e. the point to
        // `[0, 2^{8 * NUM_LIMBS})²` — the range `FieldOpCols`' safety comment assumes, which is
        // weaker than what its carry budget needs. `p_x_squared`'s carry has to represent
        // `floor(p.x² / modulus)`, and for `p.x` near `2^{8 * NUM_LIMBS}` that exceeds
        // `NUM_LIMBS` bytes.
        let modulus_limbs =
            E::BaseField::to_limbs_field::<CB::Expr, CB::F>(&E::BaseField::modulus());

        // `a` in the Weierstrass form: y^2 = x^3 + a * x + b.
        let a = E::BaseField::to_limbs_field::<CB::Expr, CB::F>(&E::a_int());

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
                    &E::BaseField::to_limbs_field::<CB::Expr, CB::F>(&BigUint::from(3u32)),
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
                &E::BaseField::to_limbs_field::<CB::Expr, CB::F>(&BigUint::from(2u32)),
                &p_y,
                FieldOperation::Mul,
                local.is_real,
            );

            // Check `2 * y` is non-zero by computing 1 / (2 * y).
            //
            // Without this the `Div` below is `slope * (2 * y) == 3 * x^2 + a`, which pins
            // `slope` only while the denominator is non-zero: at `2 * y == 0` and
            // `3 * x^2 + a == 0` it degenerates to `slope * 0 == 0` and every `slope`
            // satisfies it, making the doubled point prover-chosen. Nothing here checks the
            // input point is on the curve, so such a point is reachable from guest memory.
            //
            // `Div` is constrained as `result * b == a`, so with `a = 1` this is unsatisfiable
            // exactly when `b == 0`. Same guard as `weierstrass_add`. Completeness is not at
            // risk: a point with `y = 0` has order 2, and all four curves here have odd group
            // order, so no legitimate curve point has `y = 0` — and the padding row uses
            // `(x = 0, y = 1)` deliberately, keeping `2 * y = 2`.
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

        // Range check x3 and y3 against the field modulus.
        local
            .x3_range
            .eval(builder, &local.x3_ins.result, &modulus_limbs, local.is_real);
        local
            .y3_range
            .eval(builder, &local.y3_ins.result, &modulus_limbs, local.is_real);

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

        // Memory access constraints.
        // Write p — iterate with value constraints.
        for (i, (p_col, write_value)) in local.p_access.iter().zip(result_words.iter()).enumerate()
        {
            builder.eval_memory_access(
                local.chunk,
                local.clk.into(),
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
            CurveType::Secp256k1 => CB::F::from_u32(SyscallCode::SECP256K1_DOUBLE.syscall_id()),
            CurveType::Secp256r1 => CB::F::from_u32(SyscallCode::SECP256R1_DOUBLE.syscall_id()),
            CurveType::Bn254 => CB::F::from_u32(SyscallCode::BN254_DOUBLE.syscall_id()),
            CurveType::Bls12381 => CB::F::from_u32(SyscallCode::BLS12381_DOUBLE.syscall_id()),
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        };

        builder.looked_syscall(
            local.chunk,
            local.clk,
            syscall_id_felt,
            p_ptr.map(Into::into),
            [CB::F::ZERO, CB::F::ZERO, CB::F::ZERO],
            local.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "cuda")]
    use std::sync::LazyLock;

    #[cfg(feature = "cuda")]
    use crate::chips::gadgets::utils::RandBigUint;
    #[cfg(feature = "cuda")]
    use itertools::Itertools;
    #[cfg(feature = "cuda")]
    use p3_koala_bear::KoalaBear;
    #[cfg(feature = "cuda")]
    use p3_matrix::dense::RowMajorMatrix;
    #[cfg(feature = "cuda")]
    use rand::{rng, rngs::ThreadRng, RngExt};

    #[cfg(feature = "cuda")]
    use crate::{
        chips::{
            chips::{
                byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
                events::MemoryWriteRecord,
            },
            gadgets::curves::{
                weierstrass::{
                    bls381::Bls12381Parameters, bn254::Bn254Parameters,
                    secp256k1::Secp256k1Parameters, secp256r1::Secp256r1Parameters, SwCurve,
                    WeierstrassParameters,
                },
                CurveType, EllipticCurve, EllipticCurveParameters,
            },
            precompiles::weierstrass::weierstrass_double::WeierstrassDoubleAssignChip,
            tests::init_test_stream,
            trace::TraceData,
        },
        emulator::riscv::{
            record::EmulationRecord,
            syscalls::{
                precompiles::{
                    ec::event::EllipticCurveDoubleEvent, PrecompileEvent, PrecompileEvents,
                },
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
        machine::chip::{ChipBehavior, GpuChipBehavior},
    };

    #[cfg(feature = "cuda")]
    type F = KoalaBear;

    #[cfg(feature = "cuda")]
    static SECP256K1_SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| {
        generate_record::<SwCurve<Secp256k1Parameters>, 16>(1 << 16, CurveType::Secp256k1)
    });

    #[cfg(feature = "cuda")]
    static SECP256R1_SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| {
        generate_record::<SwCurve<Secp256r1Parameters>, 16>(1 << 16, CurveType::Secp256r1)
    });

    #[cfg(feature = "cuda")]
    static BN254_SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| {
        generate_record::<SwCurve<Bn254Parameters>, 16>(1 << 16, CurveType::Bn254)
    });

    #[cfg(feature = "cuda")]
    static BLS12381_SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| {
        generate_record::<SwCurve<Bls12381Parameters>, 24>(1 << 16, CurveType::Bls12381)
    });

    #[cfg(feature = "cuda")]
    fn cpu_generate_main<E: EllipticCurve + WeierstrassParameters>(
        chip: &WeierstrassDoubleAssignChip<F, E>,
        input: &EmulationRecord,
    ) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    #[cfg(feature = "cuda")]
    fn generate_record<E: EllipticCurve, const WORDS_CURVE_POINT: usize>(
        size: usize,
        curve_type: CurveType,
    ) -> EmulationRecord {
        let mut rng = rng();
        let size = size as u32;
        let points = (0..4).map(|_| random_point::<E>(&mut rng)).collect_vec();
        let events = (0..size)
            .map(|i| {
                let chunk = 0u32;
                let clk = i as u64;
                let p_ptr = (rng.random_range(0..size) * 4) as u64;
                let p = points[(i as usize) % points.len()].clone();
                let p_memory_records = (0..WORDS_CURVE_POINT as u32)
                    .map(|_| MemoryWriteRecord {
                        prev_timestamp: i,
                        timestamp: i + 1,
                        ..Default::default()
                    })
                    .collect();
                let event = EllipticCurveDoubleEvent {
                    chunk,
                    clk,
                    p_ptr,
                    p,
                    p_memory_records,
                    local_mem_access: vec![],
                };
                match curve_type {
                    CurveType::Secp256k1 => (
                        SyscallEvent {
                            syscall_id: SyscallCode::SECP256K1_DOUBLE.syscall_id(),
                            ..Default::default()
                        },
                        PrecompileEvent::Secp256k1Double(event),
                    ),
                    CurveType::Secp256r1 => (
                        SyscallEvent {
                            syscall_id: SyscallCode::SECP256R1_DOUBLE.syscall_id(),
                            ..Default::default()
                        },
                        PrecompileEvent::Secp256r1Double(event),
                    ),
                    CurveType::Bn254 => (
                        SyscallEvent {
                            syscall_id: SyscallCode::BN254_DOUBLE.syscall_id(),
                            ..Default::default()
                        },
                        PrecompileEvent::Bn254Double(event),
                    ),
                    CurveType::Bls12381 => (
                        SyscallEvent {
                            syscall_id: SyscallCode::BLS12381_DOUBLE.syscall_id(),
                            ..Default::default()
                        },
                        PrecompileEvent::Bls12381Double(event),
                    ),
                    _ => panic!("Unsupported curve: {}", curve_type),
                }
            })
            .collect_vec();

        let syscode = match curve_type {
            CurveType::Secp256k1 => SyscallCode::SECP256K1_DOUBLE,
            CurveType::Secp256r1 => SyscallCode::SECP256R1_DOUBLE,
            CurveType::Bn254 => SyscallCode::BN254_DOUBLE,
            CurveType::Bls12381 => SyscallCode::BLS12381_DOUBLE,
            _ => panic!("Unsupported curve: {}", curve_type),
        };
        let mut precompile_events = PrecompileEvents::default();
        precompile_events.insert(syscode, events);

        let mut record = EmulationRecord::default();
        record.precompile_events = precompile_events.clone();

        record
    }

    #[cfg(feature = "cuda")]
    fn random_point<E: EllipticCurve>(rng: &mut ThreadRng) -> Vec<u64> {
        let base = E::ec_generator();
        loop {
            let scalar = rng.random_biguint(E::nb_scalar_bits() as u64);
            if scalar == num_bigint::BigUint::from(0u32) {
                continue;
            }
            let point = &base * &scalar;
            // Ensure y != 0 (point not at infinity or half-order point)
            let words = point.to_words_le();
            let num_words_field = words.len() / 2;
            let y_zero = words[num_words_field..].iter().all(|w| *w == 0);
            if y_zero {
                continue;
            }
            return words
                .chunks(2)
                .map(|chunk| {
                    let lo = chunk[0] as u64;
                    let hi = if chunk.len() > 1 { chunk[1] as u64 } else { 0 };
                    lo | (hi << 32)
                })
                .collect();
        }
    }

    #[cfg(feature = "cuda")]
    fn gpu_generate_extra_record_and_main<E: EllipticCurve + WeierstrassParameters>(
        chip: &WeierstrassDoubleAssignChip<F, E>,
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

    #[cfg(feature = "cuda")]
    fn test_doubleassign<E: EllipticCurve + WeierstrassParameters>(
        original_record: &EmulationRecord,
    ) {
        let chip = WeierstrassDoubleAssignChip::<F, E>::new();

        let mut complete_record = original_record.clone();
        let mut counted_record = original_record.clone();

        let log_rows = 17;
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
        chip.extra_record(original_record, &mut complete_record);
        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        // GPU
        let stream = init_test_stream();
        let event_counter = precompute_event_size::<F>(&mut counted_record);
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);
        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_byte_trace: gpu_allocate_byte_trace(stream, 0).unwrap(),
            ..Default::default()
        };
        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );
        assert_eq!(cpu_trace, gpu_trace);

        gpu_finalize_byte_trace(stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();

        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(stream);
        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn test_secp256k1_doubleassign_generate_extra_record_and_main() {
        test_doubleassign::<SwCurve<Secp256k1Parameters>>(&SECP256K1_SHARD);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn test_secp256r1_doubleassign_generate_extra_record_and_main() {
        test_doubleassign::<SwCurve<Secp256r1Parameters>>(&SECP256R1_SHARD);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn test_bn254_doubleassign_generate_extra_record_and_main() {
        test_doubleassign::<SwCurve<Bn254Parameters>>(&BN254_SHARD);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn test_bls12381_doubleassign_generate_extra_record_and_main() {
        test_doubleassign::<SwCurve<Bls12381Parameters>>(&BLS12381_SHARD);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn bench_weierstrass_double_cpu_vs_gpu() {
        use std::{
            mem::{size_of, transmute},
            time::Instant,
        };

        use cudart::{
            memory_pools::DevicePoolAllocation,
            slice::{CudaSlice, CudaSliceMut},
            stream::{CudaStream, CudaStreamCreateFlags},
        };
        use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind};
        use pico_gpu_api::{
            cuda_weierstrass_double_bls12381_generate_extra_record_and_main,
            cuda_weierstrass_double_bn254_generate_extra_record_and_main,
            cuda_weierstrass_double_secp256k1_generate_extra_record_and_main,
            cuda_weierstrass_double_secp256r1_generate_extra_record_and_main,
        };

        use crate::{
            cuda_adaptor::resource_pool::{
                mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
            },
            emulator::riscv::syscalls::precompiles::ec::event::EllipticCurveDoubleFfiEvent,
        };

        fn bench_curve<E: EllipticCurve + WeierstrassParameters, const WORDS_CURVE_POINT: usize>(
            curve_type: CurveType,
        ) {
            let chip = WeierstrassDoubleAssignChip::<F, E>::new();
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

                // === CPU ===
                let cpu_start = Instant::now();
                chip.extra_record(&original_record, &mut complete_record);
                let cpu_trace = cpu_generate_main(&chip, &complete_record);
                let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

                // === GPU (inline to separate H2D / kernel / D2H) ===
                let prepared_gpu_events = PreparedGpuEvents::new(
                    &counted_record,
                    precompute_event_size::<F>(&mut counted_record.clone()),
                );

                // Get events slice
                let events: &[EllipticCurveDoubleFfiEvent<E::BaseField>] = match E::CURVE_TYPE {
                    CurveType::Secp256k1 => unsafe {
                        transmute(
                            prepared_gpu_events
                                .secp256k1_weierstrass_double_events
                                .as_slice(),
                        )
                    },
                    CurveType::Secp256r1 => unsafe {
                        transmute(
                            prepared_gpu_events
                                .secp256r1_weierstrass_double_events
                                .as_slice(),
                        )
                    },
                    CurveType::Bn254 => unsafe {
                        transmute(
                            prepared_gpu_events
                                .bn254_weierstrass_double_events
                                .as_slice(),
                        )
                    },
                    CurveType::Bls12381 => unsafe {
                        transmute(
                            prepared_gpu_events
                                .bls12381_weierstrass_double_events
                                .as_slice(),
                        )
                    },
                    _ => panic!("Unsupported curve"),
                };

                let padded_nrows = 1usize << log_rows;
                let num_cols = super::num_weierstrass_double_cols::<
                    <E as EllipticCurveParameters>::BaseField,
                >();
                let trace_size = padded_nrows * num_cols;

                let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING)
                    .expect("Failed to create CUDA stream");
                let sync_mem_pool = get_global_mem_pool(0);
                let mem_pool = &sync_mem_pool.0;

                // H2D: copy events to GPU (outside timer)
                let mut d_events =
                    DevicePoolAllocation::<EllipticCurveDoubleFfiEvent<E::BaseField>>::alloc_from_pool_async(
                        events.len(), mem_pool, stream,
                    ).expect("GPU event alloc failed");
                unsafe {
                    let _ = cudaMemcpyAsync(
                        d_events.as_mut_c_void_ptr(),
                        events.as_c_void_ptr(),
                        events.len() * size_of::<EllipticCurveDoubleFfiEvent<E::BaseField>>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );
                }

                // Allocate trace + byte trace on GPU (outside timer)
                let mut d_trace =
                    DevicePoolAllocation::<p3_koala_bear::KoalaBear>::alloc_from_pool_async(
                        trace_size, mem_pool, stream,
                    )
                    .expect("GPU trace alloc failed");
                let mut d_byte_trace = gpu_allocate_byte_trace(stream, 0).unwrap().unwrap();

                // Sync to ensure H2D and allocations are done
                stream.synchronize().unwrap();

                // === TIMED: kernel only ===
                let gpu_start = Instant::now();
                unsafe {
                    match E::CURVE_TYPE {
                        CurveType::Secp256k1 => {
                            cuda_weierstrass_double_secp256k1_generate_extra_record_and_main(
                                d_events.as_ptr() as *const _,
                                events.len(),
                                d_trace.as_mut_ptr() as *mut _,
                                padded_nrows,
                                num_cols,
                                d_byte_trace.as_mut_ptr() as *mut _,
                                stream.into(),
                            );
                        }
                        CurveType::Secp256r1 => {
                            cuda_weierstrass_double_secp256r1_generate_extra_record_and_main(
                                d_events.as_ptr() as *const _,
                                events.len(),
                                d_trace.as_mut_ptr() as *mut _,
                                padded_nrows,
                                num_cols,
                                d_byte_trace.as_mut_ptr() as *mut _,
                                stream.into(),
                            );
                        }
                        CurveType::Bn254 => {
                            cuda_weierstrass_double_bn254_generate_extra_record_and_main(
                                d_events.as_ptr() as *const _,
                                events.len(),
                                d_trace.as_mut_ptr() as *mut _,
                                padded_nrows,
                                num_cols,
                                d_byte_trace.as_mut_ptr() as *mut _,
                                stream.into(),
                            );
                        }
                        CurveType::Bls12381 => {
                            cuda_weierstrass_double_bls12381_generate_extra_record_and_main(
                                d_events.as_ptr() as *const _,
                                events.len(),
                                d_trace.as_mut_ptr() as *mut _,
                                padded_nrows,
                                num_cols,
                                d_byte_trace.as_mut_ptr() as *mut _,
                                stream.into(),
                            );
                        }
                        _ => panic!("Unsupported curve"),
                    }
                }
                stream.synchronize().unwrap();
                let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

                // D2H: copy trace back for verification (outside timer)
                let sync_stream = get_global_stream_pool(0);
                let main_stream = &sync_stream.0;
                let d_trace = d_trace.swap_stream(main_stream);
                main_stream.synchronize().unwrap();
                let gpu_trace = TraceData::<F>::Gpu(num_cols, d_trace).to_host(main_stream);

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

        // Initialize CUDA context and global memory pool
        init_test_stream();

        println!("\n{:=<60}", "");
        println!("  WeierstrassDoubleAssign CPU vs GPU Benchmark (kernel only)");
        println!("{:=<60}", "");

        bench_curve::<SwCurve<Secp256k1Parameters>, 16>(CurveType::Secp256k1);
        bench_curve::<SwCurve<Secp256r1Parameters>, 16>(CurveType::Secp256r1);
        bench_curve::<SwCurve<Bn254Parameters>, 16>(CurveType::Bn254);
        bench_curve::<SwCurve<Bls12381Parameters>, 24>(CurveType::Bls12381);
    }
}
