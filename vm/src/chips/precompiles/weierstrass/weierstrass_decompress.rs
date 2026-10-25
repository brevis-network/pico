use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryReadColsU8, MemoryWriteColsU8},
        },
        gadgets::{
            addr_add::AddrAddGadget,
            curves::{
                weierstrass::{
                    bls381::{bls12381_sqrt, Bls12381},
                    secp256k1::{secp256k1_sqrt, Secp256k1},
                    secp256r1::{secp256r1_sqrt, Secp256r1},
                    WeierstrassParameters,
                },
                CurveType, EllipticCurve,
            },
            field::{
                field_inner_product::FieldInnerProductCols,
                field_lt::FieldLtCols,
                field_op::{FieldOpCols, FieldOperation},
                field_sqrt::FieldSqrtCols,
            },
            syscall_addr::SyscallAddrGadget,
            utils::{
                conversions::{
                    generate_limbs_from_read_cols_u8, generate_limbs_from_write_cols_u8,
                    limbs_to_words,
                },
                field_params::{limbs_from_slice, FieldParameters, NumLimbs, NumWords},
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
            precompiles::{ec::event::EllipticCurveDecompressEventFFI, PrecompileEvent},
            SyscallCode,
        },
    },
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
    },
    primitives::consts::u64_to_u16_limbs,
};
use core::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
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
use p3_matrix::dense::RowMajorMatrix;
use pico_derive::AlignedBorrow;
use pico_gpu_api::{
    cuda_weierstrass_decompress_bls12381_generate_extra_record_and_main,
    cuda_weierstrass_decompress_secp256k1_generate_extra_record_and_main,
    cuda_weierstrass_decompress_secp256r1_generate_extra_record_and_main,
};
use std::fmt::Debug;
use tracing::{debug, info};
use typenum::Unsigned;

pub const fn num_weierstrass_decompress_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassDecompressCols<u8, P>>()
}

/// A set of columns to compute `WeierstrassDecompress` that decompresses a point on a Weierstrass
/// curve.
#[derive(Debug, Clone, AlignedBorrow, Eq, PartialEq)]
#[repr(C)]
pub struct WeierstrassDecompressCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub chunk: T,
    pub clk: T,
    pub ptr: SyscallAddrGadget<T>,
    pub x_addrs: Array<AddrAddGadget<T>, P::WordsFieldElement>,
    pub y_addrs: Array<AddrAddGadget<T>, P::WordsFieldElement>,
    pub sign_bit: T,
    pub x_access: Array<MemoryReadColsU8<T>, P::WordsFieldElement>,
    pub y_access: Array<MemoryWriteColsU8<T>, P::WordsFieldElement>,
    pub(crate) range_x: FieldLtCols<T, P>,
    pub(crate) x_2: FieldOpCols<T, P>,
    pub(crate) x_3: FieldOpCols<T, P>,
    pub(crate) ax_plus_b: FieldInnerProductCols<T, P>,
    pub(crate) x_3_plus_b_plus_ax: FieldOpCols<T, P>,
    pub(crate) y: FieldSqrtCols<T, P>,
    pub(crate) neg_y: FieldOpCols<T, P>,
    pub(crate) neg_y_range_check: FieldLtCols<T, P>,
}

/// A set of columns to compute `WeierstrassDecompress` that decompresses a point on a Weierstrass
/// curve.
#[derive(Debug, Clone, AlignedBorrow, Eq, PartialEq)]
#[repr(C)]
pub struct LexicographicChoiceCols<T, P: FieldParameters + NumWords> {
    pub comparison_lt_cols: FieldLtCols<T, P>,
    pub is_y_eq_sqrt_y_result: T,
    pub when_sqrt_y_res_is_lt: T,
    pub when_neg_y_res_is_lt: T,
}

/// The convention for choosing the decompressed `y` value given a sign bit.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SignChoiceRule {
    /// Lease significant bit convention.
    ///
    /// In this convention, the `sign_bit` matches the pairty of the `y` value. This is the
    /// convention used in the ECDSA signature scheme, for example, in the secp256k1 curve.
    LeastSignificantBit,
    /// Lexicographic convention.
    ///
    /// In this convention, the `sign_bit` corresponds to whether the `y` value is larger than its
    /// negative counterpart with respect to the embedding of ptime field elements as integers.
    /// This onvention used in the BLS signature scheme, for example, in the BLS12-381 curve.
    Lexicographic,
}

#[allow(clippy::type_complexity)]
pub struct WeierstrassDecompressChip<F, E> {
    sign_rule: SignChoiceRule,
    _marker: PhantomData<fn(F, E) -> (F, E)>,
}

impl<F> Default for WeierstrassDecompressChip<F, Bls12381> {
    fn default() -> Self {
        Self::with_lexicographic_rule()
    }
}

impl<F> Default for WeierstrassDecompressChip<F, Secp256k1> {
    fn default() -> Self {
        Self::with_lsb_rule()
    }
}

impl<F> Default for WeierstrassDecompressChip<F, Secp256r1> {
    fn default() -> Self {
        Self::with_lsb_rule()
    }
}

impl<F, E> WeierstrassDecompressChip<F, E> {
    pub const fn new(sign_rule: SignChoiceRule) -> Self {
        Self {
            sign_rule,
            _marker: PhantomData,
        }
    }

    pub const fn with_lsb_rule() -> Self {
        Self {
            sign_rule: SignChoiceRule::LeastSignificantBit,
            _marker: PhantomData,
        }
    }

    pub const fn with_lexicographic_rule() -> Self {
        Self {
            sign_rule: SignChoiceRule::Lexicographic,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> WeierstrassDecompressChip<F, E> {
    fn populate_field_ops(
        blu_events: &mut impl ByteRecordBehavior,
        cols: &mut WeierstrassDecompressCols<F, E::BaseField>,
        x: BigUint,
    ) {
        // Y = sqrt(x^3 + ax + b)
        cols.range_x
            .populate(blu_events, &x, &E::BaseField::modulus());
        let x_2 = cols
            .x_2
            .populate(blu_events, &x.clone(), &x.clone(), FieldOperation::Mul);
        let x_3 = cols.x_3.populate(blu_events, &x_2, &x, FieldOperation::Mul);
        let b = E::b_int();
        let a = E::a_int();
        let ax_plus_b = cols
            .ax_plus_b
            .populate(blu_events, &[a, b], &[x, BigUint::one()]);
        let x_3_plus_b_plus_ax =
            cols.x_3_plus_b_plus_ax
                .populate(blu_events, &x_3, &ax_plus_b, FieldOperation::Add);

        let sqrt_fn = match E::CURVE_TYPE {
            CurveType::Bls12381 => bls12381_sqrt,
            CurveType::Secp256k1 => secp256k1_sqrt,
            CurveType::Secp256r1 => secp256r1_sqrt,
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        };
        let y = cols.y.populate(blu_events, &x_3_plus_b_plus_ax, sqrt_fn);

        let zero = BigUint::zero();
        let neg_y = cols
            .neg_y
            .populate(blu_events, &zero, &y, FieldOperation::Sub);
        cols.neg_y_range_check
            .populate(blu_events, &neg_y, &E::BaseField::modulus());
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> ChipBehavior<F>
    for WeierstrassDecompressChip<F, E>
{
    type Record = EmulationRecord;
    type GpuRecord = FFIEmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1Decompress".to_string(),
            CurveType::Secp256r1 => "Secp256r1Decompress".to_string(),
            CurveType::Bls12381 => "Bls12381Decompress".to_string(),
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
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_DECOMPRESS),
            CurveType::Secp256r1 => input.get_precompile_events(SyscallCode::SECP256R1_DECOMPRESS),
            CurveType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_DECOMPRESS),
            _ => panic!("Unsupported curve"),
        };

        let mut rows = Vec::new();
        let weierstrass_width = num_weierstrass_decompress_cols::<E::BaseField>();
        let width = BaseAir::<F>::width(self);

        let mut new_byte_lookup_events = Vec::new();

        let modulus = E::BaseField::modulus();

        for i in 0..events.len() {
            let (_syscall_event, precompile_event) = &events[i];

            let event = match precompile_event {
                PrecompileEvent::Secp256k1Decompress(event)
                | PrecompileEvent::Secp256r1Decompress(event)
                | PrecompileEvent::Bls12381Decompress(event) => event,
                _ => unreachable!(),
            };

            let mut row = vec![F::ZERO; width];
            let cols: &mut WeierstrassDecompressCols<F, E::BaseField> =
                row[0..weierstrass_width].borrow_mut();

            cols.is_real = F::from_bool(true);
            cols.chunk = F::from_u32(event.chunk);
            cols.clk = F::from_u32(checked_u64_to_u32(event.clk, "weierstrass decompress clk"));
            let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;
            let len = num_limbs as u64 * 2;
            cols.ptr
                .populate(&mut new_byte_lookup_events, event.ptr, len);
            cols.sign_bit = F::from_bool(event.sign_bit);

            let x = BigUint::from_bytes_le(
                &event
                    .x_words
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<u8>>(),
            );
            Self::populate_field_ops(&mut new_byte_lookup_events, cols, x);

            for i in 0..cols.x_access.len() {
                cols.x_access[i]
                    .inner
                    .populate(event.x_memory_records[i], &mut new_byte_lookup_events);
                cols.x_access[i].prev_value_u8.populate_u16_to_u8_safe(
                    &mut new_byte_lookup_events,
                    event.x_memory_records[i].value,
                );
                cols.x_addrs[i].populate(
                    &mut new_byte_lookup_events,
                    event.ptr + num_limbs as u64,
                    8 * i as u64,
                );
            }
            for i in 0..cols.y_access.len() {
                cols.y_access[i]
                    .inner
                    .populate(event.y_memory_records[i], &mut new_byte_lookup_events);
                cols.y_access[i].prev_value_u8.populate_u16_to_u8_safe(
                    &mut new_byte_lookup_events,
                    event.y_memory_records[i].prev_value,
                );
                cols.y_addrs[i].populate(&mut new_byte_lookup_events, event.ptr, 8 * i as u64);
            }

            if matches!(self.sign_rule, SignChoiceRule::Lexicographic) {
                let lsb = cols.y.lsb;
                let choice_cols: &mut LexicographicChoiceCols<F, E::BaseField> =
                    row[weierstrass_width..width].borrow_mut();

                let decompressed_y = BigUint::from_bytes_le(
                    &event
                        .decompressed_y_words
                        .iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );
                let neg_y = &modulus - &decompressed_y;

                let is_y_eq_sqrt_y_result =
                    F::from_u8((event.decompressed_y_words[0] & 1) as u8) == lsb;
                choice_cols.is_y_eq_sqrt_y_result = F::from_bool(is_y_eq_sqrt_y_result);

                if event.sign_bit {
                    assert!(neg_y < decompressed_y);
                    choice_cols.when_sqrt_y_res_is_lt = F::from_bool(!is_y_eq_sqrt_y_result);
                    choice_cols.when_neg_y_res_is_lt = F::from_bool(is_y_eq_sqrt_y_result);
                    choice_cols.comparison_lt_cols.populate(
                        &mut new_byte_lookup_events,
                        &neg_y,
                        &decompressed_y,
                    );
                } else {
                    assert!(neg_y > decompressed_y);
                    choice_cols.when_sqrt_y_res_is_lt = F::from_bool(is_y_eq_sqrt_y_result);
                    choice_cols.when_neg_y_res_is_lt = F::from_bool(!is_y_eq_sqrt_y_result);
                    choice_cols.comparison_lt_cols.populate(
                        &mut new_byte_lookup_events,
                        &decompressed_y,
                        &neg_y,
                    );
                }
            }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = vec![F::ZERO; width];
                let cols: &mut WeierstrassDecompressCols<F, E::BaseField> =
                    row.as_mut_slice()[0..weierstrass_width].borrow_mut();

                // take X of the generator as a dummy value to make sure Y^2 = X^3 + aX + b holds
                let dummy_value = E::generator().0;
                let dummy_bytes = dummy_value.to_bytes_le();
                // Convert bytes to u64 words for the dummy x_access values
                let u64_words: Vec<u64> = dummy_bytes
                    .chunks(8)
                    .map(|chunk| {
                        let mut arr = [0u8; 8];
                        arr[..chunk.len()].copy_from_slice(chunk);
                        u64::from_le_bytes(arr)
                    })
                    .collect();
                for i in 0..cols.x_access.len() {
                    let limbs = u64_to_u16_limbs(u64_words[i]);
                    cols.x_access[i].inner.access.value = crate::compiler::word::Word([
                        F::from_u16(limbs[0]),
                        F::from_u16(limbs[1]),
                        F::from_u16(limbs[2]),
                        F::from_u16(limbs[3]),
                    ]);
                    // Must also set prev_value_u8.low_bytes so that the U16→U8
                    // decomposition in eval (generate_limbs_from_read_cols_u8)
                    // produces correct byte limbs.  Without this, padding rows
                    // have low_bytes=0 while value≠0, causing the polynomial
                    // constraint (which is NOT gated by is_real) to fail.
                    for j in 0..4 {
                        cols.x_access[i].prev_value_u8.low_bytes[j] =
                            F::from_u8((limbs[j] & 0xFF) as u8);
                    }
                }

                Self::populate_field_ops(&mut vec![], cols, dummy_value);
                row
            },
            log_rows,
        );

        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), width)
    }

    fn is_active(&self, chunk: &Self::Record) -> bool {
        if let Some(shape) = chunk.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => !chunk
                    .get_precompile_events(SyscallCode::SECP256K1_DECOMPRESS)
                    .is_empty(),
                CurveType::Secp256r1 => !chunk
                    .get_precompile_events(SyscallCode::SECP256R1_DECOMPRESS)
                    .is_empty(),
                CurveType::Bls12381 => !chunk
                    .get_precompile_events(SyscallCode::BLS12381_DECOMPRESS)
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
        use p3_koala_bear::KoalaBear;

        // 1. Get events
        // coerce to c_void here to avoid type confusion since this is multi typed event
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => prepared_gpu_events
                .secp256k1_weierstrass_decompress_events
                .as_c_void_ptr(),
            CurveType::Secp256r1 => prepared_gpu_events
                .secp256r1_weierstrass_decompress_events
                .as_c_void_ptr(),
            CurveType::Bls12381 => prepared_gpu_events
                .bls12381_weierstrass_decompress_events
                .as_c_void_ptr(),
            _ => panic!("Unsupported curve"),
        };
        let num_events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => prepared_gpu_events
                .secp256k1_weierstrass_decompress_events
                .len(),
            CurveType::Secp256r1 => prepared_gpu_events
                .secp256r1_weierstrass_decompress_events
                .len(),
            CurveType::Bls12381 => prepared_gpu_events
                .bls12381_weierstrass_decompress_events
                .len(),
            _ => panic!("Unsupported curve"),
        };

        // 2. Calculate padding rows
        let nrows = num_events;
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = next_power_of_two(nrows, log2_nrows);

        // 3. Create CUDA stream and memory pool
        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING)
            .expect("Failed to create CUDA stream");

        // 4. Copy events to the gpu
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let event_size = num_events;
        let mut d_events = DevicePoolAllocation::<EllipticCurveDecompressEventFFI<E::BaseField>>::alloc_from_pool_async(
            event_size, mem_pool, stream,
        )
        .expect("GPU event memory allocation failed");

        unsafe {
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                events,
                event_size * size_of::<EllipticCurveDecompressEventFFI<E::BaseField>>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        // 5. Allocate and generate trace
        let total_cols = BaseAir::<F>::width(self);
        let num_cols = num_weierstrass_decompress_cols::<E::BaseField>();
        let num_lexi_cols = total_cols - num_cols;
        let trace_size = padded_nrows * total_cols;
        debug!("[weierstrass-decompress-chip] num_events: {num_events}");
        debug!("[weierstrass-decompress-chip] num_cols: {total_cols}");

        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .expect("GPU trace memory allocation failed");

        // Generate trace
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        unsafe {
            match E::CURVE_TYPE {
                CurveType::Bls12381 => {
                    cuda_weierstrass_decompress_bls12381_generate_extra_record_and_main(
                        d_events.as_ptr() as *const _,
                        num_events,
                        d_trace.as_mut_ptr() as *mut _,
                        padded_nrows,
                        num_cols,
                        num_lexi_cols,
                        self.sign_rule == SignChoiceRule::Lexicographic,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    )
                }
                CurveType::Secp256k1 => {
                    cuda_weierstrass_decompress_secp256k1_generate_extra_record_and_main(
                        d_events.as_ptr() as *const _,
                        num_events,
                        d_trace.as_mut_ptr() as *mut _,
                        padded_nrows,
                        num_cols,
                        num_lexi_cols,
                        self.sign_rule == SignChoiceRule::Lexicographic,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    )
                }
                CurveType::Secp256r1 => {
                    cuda_weierstrass_decompress_secp256r1_generate_extra_record_and_main(
                        d_events.as_ptr() as *const _,
                        num_events,
                        d_trace.as_mut_ptr() as *mut _,
                        padded_nrows,
                        num_cols,
                        num_lexi_cols,
                        self.sign_rule == SignChoiceRule::Lexicographic,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    )
                }
                _ => panic!("Unsupported curve"),
            };
        }

        // 6. Switch to main stream and return result
        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[weierstrass-decompress-chip] generate_main on GPU");

        TraceData::Gpu(total_cols, d_trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => !record.secp256k1_weierstrass_decompress_events.is_empty(),
                CurveType::Secp256r1 => !record.secp256r1_weierstrass_decompress_events.is_empty(),
                CurveType::Bls12381 => !record.bls12381_weierstrass_decompress_events.is_empty(),
                _ => panic!("Unsupported curve"),
            }
        }
    }
}

impl<F, E: EllipticCurve> BaseAir<F> for WeierstrassDecompressChip<F, E> {
    fn width(&self) -> usize {
        num_weierstrass_decompress_cols::<E::BaseField>()
            + match self.sign_rule {
                SignChoiceRule::LeastSignificantBit => 0,
                SignChoiceRule::Lexicographic => {
                    size_of::<LexicographicChoiceCols<u8, E::BaseField>>()
                }
            }
    }
}

impl<F: PrimeField32, CB, E: EllipticCurve + WeierstrassParameters> Air<CB>
    for WeierstrassDecompressChip<F, E>
where
    F: Field,
    CB: ChipBuilder<F>,
    Limbs<CB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();

        let weierstrass_cols = num_weierstrass_decompress_cols::<E::BaseField>();
        let local_slice = main.current_slice();
        let local: &WeierstrassDecompressCols<CB::Var, E::BaseField> =
            (*local_slice)[0..weierstrass_cols].borrow();

        let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;

        builder.assert_bool(local.sign_bit);

        // Extract byte limbs from u16 word limbs via U16→U8 conversion.
        let x_limbs =
            generate_limbs_from_read_cols_u8(builder, &local.x_access[..], local.is_real.into());

        // `y_access.prev_value_u8` is populated by the trace, which emits u8 range checks;
        // they need a matching evaluation here or the byte table is over-received. The
        // returned limbs are unused — `y_access`'s value is constrained below against
        // `sqrt_y`/`neg_y` — so this call exists to balance those lookups and to pin the
        // byte decomposition. It is a write access, hence the `write` helper, which reads
        // `inner.prev_value` just as the trace did.
        let _ =
            generate_limbs_from_write_cols_u8(builder, &local.y_access[..], local.is_real.into());
        let x: Limbs<CB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(Array::try_from_iter(x_limbs).expect("failed to convert x limbs"));
        let max_num_limbs = E::BaseField::to_limbs_field_slice(&E::BaseField::modulus());
        local.range_x.eval(
            builder,
            &x,
            &limbs_from_slice::<CB::Expr, <E::BaseField as NumLimbs>::Limbs, CB::F>(max_num_limbs),
            local.is_real,
        );
        local
            .x_2
            .eval(builder, &x, &x, FieldOperation::Mul, local.is_real);
        local.x_3.eval(
            builder,
            &local.x_2.result,
            &x,
            FieldOperation::Mul,
            local.is_real,
        );
        let b_const = E::BaseField::to_limbs_field::<CB::F, _>(&E::b_int());
        let a_const = E::BaseField::to_limbs_field::<CB::F, _>(&E::a_int());
        let params = [a_const, b_const];
        let p_x: Polynomial<CB::Expr> = x.into();
        let p_one: Polynomial<CB::Expr> =
            E::BaseField::to_limbs_field::<CB::F, _>(&BigUint::one()).into();
        local
            .ax_plus_b
            .eval(builder, &params, &[p_x, p_one], local.is_real);
        local.x_3_plus_b_plus_ax.eval(
            builder,
            &local.x_3.result,
            &local.ax_plus_b.result,
            FieldOperation::Add,
            local.is_real,
        );

        local.neg_y.eval(
            builder,
            &[CB::Expr::ZERO].iter(),
            &local.y.multiplication.result,
            FieldOperation::Sub,
            local.is_real,
        );

        // Range check neg_y against the field modulus.
        let modulus = E::BaseField::to_limbs_field::<CB::Expr, CB::F>(&E::BaseField::modulus());
        local
            .neg_y_range_check
            .eval(builder, &local.neg_y.result, &modulus, local.is_real);

        local.y.eval(
            builder,
            &local.x_3_plus_b_plus_ax.result,
            local.y.lsb,
            local.is_real,
        );

        // Convert computed sqrt(y) and neg_y results from u8 limbs to u16 Words for value constraints.
        let sqrt_y_words = limbs_to_words(
            &local
                .y
                .multiplication
                .result
                .0
                .iter()
                .map(|v| (*v).into())
                .collect::<Vec<CB::Expr>>(),
            CB::F::from_u32(256).into(),
        );
        let neg_y_words = limbs_to_words(
            &local
                .neg_y
                .result
                .0
                .iter()
                .map(|v| (*v).into())
                .collect::<Vec<CB::Expr>>(),
            CB::F::from_u32(256).into(),
        );

        // Constrain the y value according the sign rule convention.
        match self.sign_rule {
            SignChoiceRule::LeastSignificantBit => {
                // When the sign rule is LeastSignificantBit, the sign_bit should match the parity
                // of the result. The parity of the square root result is given by the local.y.lsb
                // value. Thus, if the sign_bit matches the local.y.lsb value, then the result
                // should be the square root of the y value. Otherwise, the result should be the
                // negative square root of the y value.
                // The actual y write value constraint is applied in the memory write loop below.
            }
            SignChoiceRule::Lexicographic => {
                // When the sign rule is Lexicographic, the sign_bit corresponds to whether
                // the result is greater than or less its negative with respect to the lexicographic
                // ordering, embedding prime field values as integers.
                //
                // In order to endorce these constraints, we will use the auxillary choice columns.

                // Get the choice columns from the row slice
                let choice_cols: &LexicographicChoiceCols<CB::Var, E::BaseField> = (*local_slice)
                    [weierstrass_cols
                        ..weierstrass_cols
                            + size_of::<LexicographicChoiceCols<u8, E::BaseField>>()]
                    .borrow();

                // Assert that the flags are booleans.
                builder.assert_bool(choice_cols.is_y_eq_sqrt_y_result);
                builder.assert_bool(choice_cols.when_sqrt_y_res_is_lt);
                builder.assert_bool(choice_cols.when_neg_y_res_is_lt);

                // Assert that the `when` flags are disjoint:
                builder.when(local.is_real).assert_one(
                    choice_cols.when_sqrt_y_res_is_lt + choice_cols.when_neg_y_res_is_lt,
                );

                // NOTE: The actual y write value constraint is applied in the memory write loop below
                // using sqrt_y_words / neg_y_words, conditioned on is_y_eq_sqrt_y_result.

                // Assert that the comparison only turns on when `is_real` is true.
                builder
                    .when_not(local.is_real)
                    .assert_zero(choice_cols.when_sqrt_y_res_is_lt);
                builder
                    .when_not(local.is_real)
                    .assert_zero(choice_cols.when_neg_y_res_is_lt);

                // Assert that the flags are set correctly. When the sign_bit is true, we want that
                // `neg_y < y`, and vice versa when the sign_bit is false. Hence, when should have:
                // - When `sign_bit` is true , then when_sqrt_y_res_is_lt = (y != sqrt(y)).
                // - When `sign_bit` is false, then when_neg_y_res_is_lt = (y == sqrt(y)).
                // - When `sign_bit` is true , then when_sqrt_y_res_is_lt = (y != sqrt(y)).
                // - When `sign_bit` is false, then when_neg_y_res_is_lt = (y == sqrt(y)).
                //
                // Since the when less-than flags are disjoint, we can assert that:
                // - When `sign_bit` is true , then is_y_eq_sqrt_y_result == when_neg_y_res_is_lt.
                // - When `sign_bit` is false, then is_y_eq_sqrt_y_result == when_sqrt_y_res_is_lt.
                builder.when(local.is_real).when(local.sign_bit).assert_eq(
                    choice_cols.is_y_eq_sqrt_y_result,
                    choice_cols.when_neg_y_res_is_lt,
                );
                builder
                    .when(local.is_real)
                    .when_not(local.sign_bit)
                    .assert_eq(
                        choice_cols.is_y_eq_sqrt_y_result,
                        choice_cols.when_sqrt_y_res_is_lt,
                    );

                // Assert the less-than comparisons according to the flags.

                choice_cols.comparison_lt_cols.eval(
                    builder,
                    &local.y.multiplication.result,
                    &local.neg_y.result,
                    choice_cols.when_sqrt_y_res_is_lt,
                );

                choice_cols.comparison_lt_cols.eval(
                    builder,
                    &local.neg_y.result,
                    &local.y.multiplication.result,
                    choice_cols.when_neg_y_res_is_lt,
                );
            }
        }

        // Address alignment constraints.
        let ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            <E::BaseField as NumLimbs>::Limbs::USIZE as u32 * 2,
            local.ptr,
            local.is_real.into(),
        );

        // x_addrs[i] = ptr + num_limbs + 8*i
        for i in 0..local.x_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), CB::Expr::ZERO]),
                Word::from(num_limbs as u64 + 8 * i as u64),
                local.x_addrs[i],
                local.is_real.into(),
            );
        }

        // y_addrs[i] = ptr + 8*i
        for i in 0..local.y_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), CB::Expr::ZERO]),
                Word::from(8 * i as u64),
                local.y_addrs[i],
                local.is_real.into(),
            );
        }

        // Memory access constraints.
        // Read x — x is at offset num_limbs from ptr.
        for (i, x_col) in local.x_access.iter().enumerate() {
            builder.eval_memory_access(
                local.chunk,
                local.clk.into(),
                local.x_addrs[i].value.map(Into::into),
                &x_col.inner,
                local.is_real,
            );
        }
        // Write y — y is at offset 0 from ptr, with value constraints.
        // We constrain y_access.value == sqrt_y_words or neg_y_words conditionally.

        for (i, y_col) in local.y_access.iter().enumerate() {
            builder.eval_memory_access(
                local.chunk,
                local.clk.into(),
                local.y_addrs[i].value.map(Into::into),
                &y_col.inner,
                local.is_real,
            );

            // Constrain the write value to the correct computed y result.
            let do_check: CB::Expr = local.is_real.into();
            match self.sign_rule {
                SignChoiceRule::LeastSignificantBit => {
                    // When lsb != 1 - sign_bit (i.e., lsb == sign_bit),
                    // write value = sqrt(y).
                    for (v, w) in y_col
                        .inner
                        .access
                        .value
                        .0
                        .iter()
                        .zip(sqrt_y_words[i].0.iter())
                    {
                        builder
                            .when(do_check.clone())
                            .when_ne(local.y.lsb, CB::Expr::ONE - local.sign_bit)
                            .assert_eq((*v).into(), w.clone());
                    }
                    // When lsb != sign_bit (i.e., lsb == 1 - sign_bit),
                    // write value = neg_y.
                    for (v, w) in y_col
                        .inner
                        .access
                        .value
                        .0
                        .iter()
                        .zip(neg_y_words[i].0.iter())
                    {
                        builder
                            .when(do_check.clone())
                            .when_ne(local.y.lsb, local.sign_bit)
                            .assert_eq((*v).into(), w.clone());
                    }
                }
                SignChoiceRule::Lexicographic => {
                    let choice_cols: &LexicographicChoiceCols<CB::Var, E::BaseField> =
                        (*local_slice)[weierstrass_cols
                            ..weierstrass_cols
                                + size_of::<LexicographicChoiceCols<u8, E::BaseField>>()]
                            .borrow();
                    // When is_y_eq_sqrt_y_result, write value = sqrt(y).
                    for (v, w) in y_col
                        .inner
                        .access
                        .value
                        .0
                        .iter()
                        .zip(sqrt_y_words[i].0.iter())
                    {
                        builder
                            .when(do_check.clone())
                            .when(choice_cols.is_y_eq_sqrt_y_result)
                            .assert_eq((*v).into(), w.clone());
                    }
                    // When not is_y_eq_sqrt_y_result, write value = neg_y.
                    for (v, w) in y_col
                        .inner
                        .access
                        .value
                        .0
                        .iter()
                        .zip(neg_y_words[i].0.iter())
                    {
                        builder
                            .when(do_check.clone())
                            .when_not(choice_cols.is_y_eq_sqrt_y_result)
                            .assert_eq((*v).into(), w.clone());
                    }
                }
            }
        }

        let syscall_id = match E::CURVE_TYPE {
            CurveType::Bls12381 => CB::F::from_u32(SyscallCode::BLS12381_DECOMPRESS.syscall_id()),
            CurveType::Secp256k1 => CB::F::from_u32(SyscallCode::SECP256K1_DECOMPRESS.syscall_id()),
            CurveType::Secp256r1 => CB::F::from_u32(SyscallCode::SECP256R1_DECOMPRESS.syscall_id()),
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        };

        let sign_bit_expr: CB::Expr = local.sign_bit.into();
        builder.looked_syscall(
            local.chunk,
            local.clk,
            syscall_id,
            ptr.map(Into::into),
            [sign_bit_expr, CB::Expr::ZERO, CB::Expr::ZERO],
            local.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        chips::{
            chips::{
                byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
                events::{MemoryReadRecord, MemoryWriteRecord},
            },
            gadgets::curves::{
                weierstrass::{bls381::Bls12381, secp256k1::Secp256k1, WeierstrassParameters},
                CurveType, EllipticCurve, EllipticCurveParameters,
            },
            tests::init_test_stream,
            trace::TraceData,
        },
        emulator::riscv::{
            record::EmulationRecord,
            syscalls::{
                precompiles::{ec::event::EllipticCurveDecompressEvent, PrecompileEvent},
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
    use alloy_primitives::hex;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::RngExt;

    type Chip<F, P> = super::WeierstrassDecompressChip<F, P>;
    type F = KoalaBear;

    fn cpu_generate_main<P: EllipticCurve + WeierstrassParameters>(
        chip: &Chip<F, P>,
        input: &EmulationRecord,
    ) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    fn gpu_generate_extra_record_and_main<E: EllipticCurve + WeierstrassParameters>(
        chip: &Chip<F, E>,
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

    // TODO: add test_secp256r1_decompress_generate_extra_record_and_main

    #[test]
    fn test_secp256k1_decompress_generate_extra_record_and_main() {
        use crate::{
            //chips::gadgets::field::bls381::Bls381BaseField,
            emulator::riscv::{
                record::EmulationRecord,
                syscalls::{
                    precompiles::{ec::event::EllipticCurveDecompressEvent, PrecompileEvent},
                    SyscallEvent,
                },
            },
        };
        use alloy_primitives::hex;
        use rand::RngExt;
        let mut chunk = EmulationRecord::default();

        let mut rng = rand::rng();
        let x_memory = MemoryReadRecord {
            value: 1010,
            chunk: 0,
            timestamp: 50,
            prev_chunk: 0,
            prev_timestamp: 20,
        };
        let y_memory = MemoryWriteRecord {
            value: 10101,
            chunk: 0,
            timestamp: 52,
            prev_value: 33,
            prev_chunk: 0,
            prev_timestamp: 22,
        };
        // Helper: convert hex bytes to Vec<u64> words (LE)
        fn bytes_to_u64_words(bytes: &[u8]) -> Vec<u64> {
            bytes
                .chunks(8)
                .map(|chunk| {
                    let mut arr = [0u8; 8];
                    arr[..chunk.len()].copy_from_slice(chunk);
                    u64::from_le_bytes(arr)
                })
                .collect()
        }
        let decompress_events = vec![
            EllipticCurveDecompressEvent {
                chunk: 0,
                clk: 100,
                ptr: 200,
                sign_bit: false,
                x_words: bytes_to_u64_words(&hex!(
                    "0400000000000000000000000000000000000000000000000000000000000000"
                )),
                decompressed_y_words: bytes_to_u64_words(&hex!(
                    "9310b168b56d03437b45d2832c3f2a8ff53c2474e1f5e20afe0f8e7253c48e59"
                )),
                x_memory_records: [x_memory; 4].to_vec(),
                y_memory_records: [y_memory; 4].to_vec(),
                local_mem_access: vec![],
            },
            EllipticCurveDecompressEvent {
                chunk: 0,
                clk: 101,
                ptr: 201,
                sign_bit: true,
                x_words: bytes_to_u64_words(&hex!(
                    "0400000000000000000000000000000000000000000000000000000000000000"
                )),
                decompressed_y_words: bytes_to_u64_words(&hex!(
                    "9ceb4e974992fcbc84ba2d7cd3c0d5700ac3db8b1e0a1df501f0718dac3b71a6"
                )),
                x_memory_records: [x_memory; 4].to_vec(),
                y_memory_records: [y_memory; 4].to_vec(),
                local_mem_access: vec![],
            },
            EllipticCurveDecompressEvent {
                chunk: 0,
                clk: 102,
                ptr: 202,
                sign_bit: false,
                x_words: bytes_to_u64_words(&hex!(
                    "feffffffffffffff000000000000000000000000000000000000000000000000"
                )),
                decompressed_y_words: bytes_to_u64_words(&hex!(
                    "96a09a39e2a23c89829e6faea0fa65bb6aae70eb0e3560994a40e93cf0d95f65"
                )),
                x_memory_records: [x_memory; 4].to_vec(),
                y_memory_records: [y_memory; 4].to_vec(),
                local_mem_access: vec![],
            },
            EllipticCurveDecompressEvent {
                chunk: 0,
                clk: 103,
                ptr: 203,
                sign_bit: true,
                x_words: bytes_to_u64_words(&hex!(
                    "feffffffffffffff000000000000000000000000000000000000000000000000"
                )),
                decompressed_y_words: bytes_to_u64_words(&hex!(
                    "995b65c61c5dc3767d6190515f059a4495518f14f1ca9f66b5bf16c30f26a09a"
                )),
                x_memory_records: [x_memory; 4].to_vec(),
                y_memory_records: [y_memory; 4].to_vec(),
                local_mem_access: vec![],
            },
        ];
        let rand_syscall = SyscallEvent {
            chunk: rng.random(),
            clk: rng.random(),
            syscall_id: rng.random(),
            arg1: rng.random(),
            arg2: rng.random(),
        };
        let decompress_events = decompress_events
            .into_iter()
            .map(|x| (rand_syscall, PrecompileEvent::Secp256k1Decompress(x)))
            .collect();
        chunk
            .precompile_events
            .insert(SyscallCode::SECP256K1_DECOMPRESS, decompress_events);
        let original_record = &chunk;

        type E = Secp256k1;
        let chip = Chip::<F, E>::default();

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
            .insert(chip.name(), 16);
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 16);

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
        for (i, (cpu_row, gpu_row)) in cpu_trace
            .row_slices()
            .zip(gpu_trace.row_slices())
            .enumerate()
        {
            assert_eq!(cpu_row, gpu_row, "Main trace mismatch at row {i}");
        }

        // Finalize the byte trace. And assert that the byte trace is consistent.
        gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();

        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(&stream);
        for (i, (cpu, gpu)) in cpu_byte_trace
            .row_slices()
            .zip(host_gpu_byte_trace.row_slices())
            .enumerate()
        {
            assert_eq!(cpu, gpu, "row {i}");
        }
        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }

    #[test]
    fn test_bls12381_decompress_generate_extra_record_and_main() {
        use crate::{
            //chips::gadgets::field::bls381::Bls381BaseField,
            emulator::riscv::{
                record::EmulationRecord,
                syscalls::{
                    precompiles::{ec::event::EllipticCurveDecompressEvent, PrecompileEvent},
                    SyscallEvent,
                },
            },
        };
        use alloy_primitives::hex;
        use rand::RngExt;
        let mut chunk = EmulationRecord::default();

        let mut rng = rand::rng();
        let x_memory = MemoryReadRecord {
            value: 1010,
            chunk: 0,
            timestamp: 50,
            prev_chunk: 0,
            prev_timestamp: 20,
        };
        let y_memory = MemoryWriteRecord {
            value: 10101,
            chunk: 0,
            timestamp: 52,
            prev_value: 33,
            prev_chunk: 0,
            prev_timestamp: 22,
        };
        // Helper: convert hex bytes to Vec<u64> words (LE)
        fn bytes_to_u64_words(bytes: &[u8]) -> Vec<u64> {
            bytes
                .chunks(8)
                .map(|chunk| {
                    let mut arr = [0u8; 8];
                    arr[..chunk.len()].copy_from_slice(chunk);
                    u64::from_le_bytes(arr)
                })
                .collect()
        }
        let decompress_events = vec![
            EllipticCurveDecompressEvent {
                chunk: 0,
                clk: 100,
                ptr: 200,
                sign_bit: false,
                x_words: bytes_to_u64_words(&hex!("040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                decompressed_y_words: bytes_to_u64_words(&hex!(
                    "6c70be4a353ea95e5ddee100edb84663448384925ed89dda266b92c988f960c79b3e76f3c3ff3cb312620dd4ad9b980a"
                )),
                x_memory_records: [x_memory; 6].to_vec(),
                y_memory_records: [y_memory; 6].to_vec(),
                local_mem_access: vec![],
            },
            EllipticCurveDecompressEvent {
                chunk: 0,
                clk: 101,
                ptr: 201,
                sign_bit: true,
                x_words: bytes_to_u64_words(&hex!("040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                decompressed_y_words: bytes_to_u64_words(&hex!(
                    "3f3a41b5cac1555ba22172b0114765bbdf722c6442fa928c98a7f229fc51169d3b6ed54ff2a7de97878472653c76680f"
                )),
                x_memory_records: [x_memory; 6].to_vec(),
                y_memory_records: [y_memory; 6].to_vec(),
                local_mem_access: vec![],
            },
            EllipticCurveDecompressEvent {
                chunk: 0,
                clk: 102,
                ptr: 202,
                sign_bit: false,
                x_words: bytes_to_u64_words(&hex!("ffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                decompressed_y_words: bytes_to_u64_words(&hex!(
                    "333297ee8b157d3791a8c1c439f20c4bd60df2f10ee7c6376fa1370b5f8d524481ba72fdb28c54d348380ccf545c4f01"
                )),
                x_memory_records: [x_memory; 6].to_vec(),
                y_memory_records: [y_memory; 6].to_vec(),
                local_mem_access: vec![],
            },
            EllipticCurveDecompressEvent {
                chunk: 0,
                clk: 103,
                ptr: 203,
                sign_bit: true,
                x_words: bytes_to_u64_words(&hex!("ffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                decompressed_y_words: bytes_to_u64_words(&hex!(
                    "7878681174ea81826e5792ecc40d9fd34de8be0492eb692f50714de825be242056f2d845031bc77751ae736a95b5b118"
                )),
                x_memory_records: [x_memory; 6].to_vec(),
                y_memory_records: [y_memory; 6].to_vec(),
                local_mem_access: vec![],
            },
        ];
        let rand_syscall = SyscallEvent {
            chunk: rng.random(),
            clk: rng.random(),
            syscall_id: rng.random(),
            arg1: rng.random(),
            arg2: rng.random(),
        };
        let decompress_events = decompress_events
            .into_iter()
            .map(|x| (rand_syscall, PrecompileEvent::Bls12381Decompress(x)))
            .collect();
        chunk
            .precompile_events
            .insert(SyscallCode::BLS12381_DECOMPRESS, decompress_events);
        let original_record = &chunk;

        type E = Bls12381;
        let chip = Chip::<F, E>::default();

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
            .insert(chip.name(), 16);
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 16);

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
        for (i, (cpu_row, gpu_row)) in cpu_trace
            .row_slices()
            .zip(gpu_trace.row_slices())
            .enumerate()
        {
            assert_eq!(cpu_row, gpu_row, "Main trace mismatch at row {i}");
        }

        // Finalize the byte trace. And assert that the byte trace is consistent.
        gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();

        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(&stream);
        for (i, (cpu, gpu)) in cpu_byte_trace
            .row_slices()
            .zip(host_gpu_byte_trace.row_slices())
            .enumerate()
        {
            assert_eq!(cpu, gpu, "row {i}");
        }
        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }

    #[test]
    fn bench_weierstrass_decompress_cpu_vs_gpu() {
        use std::{mem::size_of, time::Instant};

        use cudart::{
            memory_pools::DevicePoolAllocation,
            slice::{CudaSlice, CudaSliceMut},
            stream::{CudaStream, CudaStreamCreateFlags},
        };
        use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind};
        use p3_air::BaseAir;
        use pico_gpu_api::{
            cuda_weierstrass_decompress_bls12381_generate_extra_record_and_main,
            cuda_weierstrass_decompress_secp256k1_generate_extra_record_and_main,
        };

        use crate::{
            cuda_adaptor::resource_pool::{
                mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
            },
            emulator::riscv::syscalls::precompiles::ec::event::EllipticCurveDecompressEventFFI,
        };

        fn bytes_to_u64_words(bytes: &[u8]) -> Vec<u64> {
            bytes
                .chunks(8)
                .map(|chunk| {
                    let mut word = [0u8; 8];
                    word[..chunk.len()].copy_from_slice(chunk);
                    u64::from_le_bytes(word)
                })
                .collect()
        }

        fn generate_decompress_record<E: EllipticCurve + WeierstrassParameters>(
            num_events: usize,
            _curve_type: CurveType,
            syscall_code: SyscallCode,
            wrap_event: fn(EllipticCurveDecompressEvent) -> PrecompileEvent,
            x_bytes: &[u8],
            y_bytes: &[u8],
            num_dwords: usize,
        ) -> EmulationRecord {
            let mut rng = rand::rng();
            let x_memory = MemoryReadRecord {
                value: 10101,
                chunk: 1,
                timestamp: 2,
                prev_chunk: 0,
                prev_timestamp: 0,
            };
            let y_memory = MemoryWriteRecord {
                value: 10101,
                chunk: 1,
                timestamp: 2,
                prev_value: 33,
                prev_chunk: 0,
                prev_timestamp: 0,
            };
            let base_event = EllipticCurveDecompressEvent {
                chunk: 0,
                clk: 100,
                ptr: 200,
                sign_bit: false,
                x_words: bytes_to_u64_words(x_bytes),
                decompressed_y_words: bytes_to_u64_words(y_bytes),
                x_memory_records: vec![x_memory; num_dwords],
                y_memory_records: vec![y_memory; num_dwords],
                local_mem_access: vec![],
            };
            let rand_syscall = SyscallEvent {
                chunk: rng.random(),
                clk: rng.random(),
                syscall_id: rng.random(),
                arg1: rng.random(),
                arg2: rng.random(),
            };
            let events: Vec<_> = (0..num_events)
                .map(|i| {
                    let mut e = base_event.clone();
                    e.clk = 100 + i as u64;
                    e.ptr = 200 + (i as u64) * 32;
                    (rand_syscall, wrap_event(e))
                })
                .collect();
            let mut chunk = EmulationRecord::default();
            chunk.precompile_events.insert(syscall_code, events);
            chunk
        }

        fn bench_decompress<E: EllipticCurve + WeierstrassParameters>(
            curve_name: &str,
            syscall_code: SyscallCode,
            wrap_event: fn(EllipticCurveDecompressEvent) -> PrecompileEvent,
            x_bytes: &[u8],
            y_bytes: &[u8],
            num_dwords: usize,
            lexi: bool,
            cuda_fn: unsafe extern "C" fn(
                *const std::ffi::c_void,
                usize,
                *mut std::ffi::c_void,
                usize,
                usize,
                usize,
                bool,
                *mut std::ffi::c_void,
                cudart_sys::cudaStream_t,
            ) -> pico_gpu_api::Error,
        ) {
            let chip = super::WeierstrassDecompressChip::<F, E>::new(if lexi {
                super::SignChoiceRule::Lexicographic
            } else {
                super::SignChoiceRule::LeastSignificantBit
            });
            let warmup_sizes: Vec<usize> = vec![1 << 10];
            let bench_sizes: Vec<usize> = vec![1 << 10, 1 << 14, 1 << 16];

            println!("\n  [{curve_name}]");
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
                let original_record = generate_decompress_record::<E>(
                    num_events,
                    E::CURVE_TYPE,
                    syscall_code,
                    wrap_event,
                    x_bytes,
                    y_bytes,
                    num_dwords,
                );

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

                // === GPU ===
                let prepared_gpu_events = PreparedGpuEvents::new(
                    &counted_record,
                    precompute_event_size::<F>(&mut counted_record.clone()),
                );

                let events_ptr = match E::CURVE_TYPE {
                    CurveType::Secp256k1 => prepared_gpu_events
                        .secp256k1_weierstrass_decompress_events
                        .as_c_void_ptr(),
                    CurveType::Bls12381 => prepared_gpu_events
                        .bls12381_weierstrass_decompress_events
                        .as_c_void_ptr(),
                    _ => panic!("Unsupported curve"),
                };
                let events_len = match E::CURVE_TYPE {
                    CurveType::Secp256k1 => prepared_gpu_events
                        .secp256k1_weierstrass_decompress_events
                        .len(),
                    CurveType::Bls12381 => prepared_gpu_events
                        .bls12381_weierstrass_decompress_events
                        .len(),
                    _ => panic!("Unsupported curve"),
                };

                let padded_nrows = 1usize << log_rows;
                let total_cols = BaseAir::<F>::width(&chip);
                let num_cols = super::num_weierstrass_decompress_cols::<
                    <E as EllipticCurveParameters>::BaseField,
                >();
                let num_lexi_cols = total_cols - num_cols;
                let trace_size = padded_nrows * total_cols;

                let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING)
                    .expect("Failed to create CUDA stream");
                let sync_mem_pool = get_global_mem_pool(0);
                let mem_pool = &sync_mem_pool.0;

                // H2D
                let mut d_events = DevicePoolAllocation::<
                    EllipticCurveDecompressEventFFI<E::BaseField>,
                >::alloc_from_pool_async(
                    events_len, mem_pool, stream
                )
                .expect("GPU event alloc failed");
                unsafe {
                    let _ = cudaMemcpyAsync(
                        d_events.as_mut_c_void_ptr(),
                        events_ptr,
                        events_len * size_of::<EllipticCurveDecompressEventFFI<E::BaseField>>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );
                }

                let mut d_trace =
                    DevicePoolAllocation::<p3_koala_bear::KoalaBear>::alloc_from_pool_async(
                        trace_size, mem_pool, stream,
                    )
                    .expect("GPU trace alloc failed");
                let mut d_byte_trace = gpu_allocate_byte_trace(stream, 0).unwrap().unwrap();

                stream.synchronize().unwrap();

                // === TIMED: kernel only ===
                let gpu_start = Instant::now();
                unsafe {
                    cuda_fn(
                        d_events.as_ptr() as *const _,
                        events_len,
                        d_trace.as_mut_ptr() as *mut _,
                        padded_nrows,
                        num_cols,
                        num_lexi_cols,
                        lexi,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }
                stream.synchronize().unwrap();
                let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

                // D2H
                let sync_stream = get_global_stream_pool(0);
                let main_stream = &sync_stream.0;
                let d_trace = d_trace.swap_stream(main_stream);
                main_stream.synchronize().unwrap();
                let gpu_trace = TraceData::<F>::Gpu(total_cols, d_trace).to_host(main_stream);

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
        println!("  WeierstrassDecompress CPU vs GPU Benchmark (kernel only)");
        println!("{:=<60}", "");

        bench_decompress::<Secp256k1>(
            "secp256k1",
            SyscallCode::SECP256K1_DECOMPRESS,
            PrecompileEvent::Secp256k1Decompress,
            &hex!("0400000000000000000000000000000000000000000000000000000000000000"),
            &hex!("9310b168b56d03437b45d2832c3f2a8ff53c2474e1f5e20afe0f8e7253c48e59"),
            4,
            false,
            cuda_weierstrass_decompress_secp256k1_generate_extra_record_and_main,
        );

        bench_decompress::<Bls12381>(
            "bls12381",
            SyscallCode::BLS12381_DECOMPRESS,
            PrecompileEvent::Bls12381Decompress,
            &hex!("040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            &hex!("6c70be4a353ea95e5ddee100edb84663448384925ed89dda266b92c988f960c79b3e76f3c3ff3cb312620dd4ad9b980a"),
            6,
            true,
            cuda_weierstrass_decompress_bls12381_generate_extra_record_and_main,
        );
    }
}
