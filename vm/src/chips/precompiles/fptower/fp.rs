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
#[cfg(feature = "cuda")]
use crate::{
    chips::{
        gadgets::{
            field::{
                bls381::Bls381BaseField, bn254::Bn254BaseField, secp256k1::Secp256k1BaseField,
            },
            utils::field_params::NumWords,
        },
        precompiles::fptower::{
            dummy_row::{DUMMY_ROW_BLS381_KB, DUMMY_ROW_BN254_KB, DUMMY_ROW_SECP256K1_KB},
            ffi::FfiFpEvent,
        },
        trace::TraceData,
        utils::next_power_of_two,
    },
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
};
use core::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
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
use itertools::Itertools;
use num::{BigUint, Zero};
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use pico_derive::AlignedBorrow;
#[cfg(feature = "cuda")]
use pico_gpu_api::{
    cuda_precompile_fp_op_bls381_generate_extra_record_and_main,
    cuda_precompile_fp_op_bn254_generate_extra_record_and_main,
    cuda_precompile_fp_op_secp256k1_generate_extra_record_and_main,
};
#[cfg(feature = "cuda")]
use std::mem::transmute;
use tracing::debug;
#[cfg(feature = "cuda")]
use tracing::info;

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
    pub(crate) fn populate_field_ops(
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
            ExactSizeIterator::len(&events)
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

            cols.is_add = F::from_u8((event.op == FieldOperation::Add) as u8);
            cols.is_sub = F::from_u8((event.op == FieldOperation::Sub) as u8);
            cols.is_mul = F::from_u8((event.op == FieldOperation::Mul) as u8);
            cols.is_real = F::ONE;
            cols.chunk = F::from_u32(event.chunk);
            cols.clk = F::from_u32(checked_u64_to_u32(event.clk, "fptower fp clk"));

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
                cols.is_add = F::from_u8(1);
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

#[cfg(feature = "cuda")]
impl<F: PrimeField32, P: FpOpField> GpuChipBehavior<F> for FpOpChip<F, P> {
    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let events: &[FfiFpEvent<P::WordsFieldElement>] = match P::FIELD_TYPE {
            FieldType::Bn254 => {
                let events = prepared_gpu_events.bn254_fp_add_events.as_slice();
                unsafe {
                    transmute::<
                        &[FfiFpEvent<<Bn254BaseField as NumWords>::WordsFieldElement>],
                        &[FfiFpEvent<P::WordsFieldElement>],
                    >(events)
                }
            }
            FieldType::Bls381 => {
                let events = prepared_gpu_events.bls12381_fp_add_events.as_slice();
                unsafe {
                    transmute::<
                        &[FfiFpEvent<<Bls381BaseField as NumWords>::WordsFieldElement>],
                        &[FfiFpEvent<P::WordsFieldElement>],
                    >(events)
                }
            }
            FieldType::Secp256k1 => {
                let events = prepared_gpu_events.secp256k1_fp_add_events.as_slice();
                unsafe {
                    transmute::<
                        &[FfiFpEvent<<Secp256k1BaseField as NumWords>::WordsFieldElement>],
                        &[FfiFpEvent<P::WordsFieldElement>],
                    >(events)
                }
            }
        };

        let num_cols_per_row = num_fp_cols::<P>();
        let log_rows = input.shape_chip_size(&self.name());
        let num_total_rows = next_power_of_two(events.len(), log_rows);

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let event_size = events.len();
        let mut d_events =
            DevicePoolAllocation::<FfiFpEvent<P::WordsFieldElement>>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                events.as_c_void_ptr(),
                std::mem::size_of_val(events),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        let trace_size = num_total_rows * num_cols_per_row;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        let mut d_dummy_row = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
            num_cols_per_row,
            mem_pool,
            stream,
        )
        .unwrap();

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        match P::FIELD_TYPE {
            FieldType::Bls381 => {
                unsafe {
                    let _ = cudaMemcpyAsync(
                        d_dummy_row.as_mut_c_void_ptr(),
                        DUMMY_ROW_BLS381_KB.as_c_void_ptr(),
                        num_cols_per_row * size_of::<KoalaBear>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );
                    cuda_precompile_fp_op_bls381_generate_extra_record_and_main(
                        num_cols_per_row,
                        event_size,
                        trace_size,
                        d_events.as_ptr() as *const _,
                        d_trace.as_mut_ptr() as *mut _,
                        d_dummy_row.as_ptr() as *const _,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }

                info!("[precompile-fp-op-chip-bls381] generate_extra_record_and_main on GPU");
            }
            FieldType::Bn254 => {
                unsafe {
                    let _ = cudaMemcpyAsync(
                        d_dummy_row.as_mut_c_void_ptr(),
                        DUMMY_ROW_BN254_KB.as_c_void_ptr(),
                        num_cols_per_row * size_of::<KoalaBear>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );
                    cuda_precompile_fp_op_bn254_generate_extra_record_and_main(
                        num_cols_per_row,
                        event_size,
                        trace_size,
                        d_events.as_ptr() as *const _,
                        d_trace.as_mut_ptr() as *mut _,
                        d_dummy_row.as_ptr() as *const _,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }

                info!("[precompile-fp-op-chip-bn254] generate_extra_record_and_main on GPU")
            }
            FieldType::Secp256k1 => {
                unsafe {
                    let _ = cudaMemcpyAsync(
                        d_dummy_row.as_mut_c_void_ptr(),
                        DUMMY_ROW_SECP256K1_KB.as_c_void_ptr(),
                        num_cols_per_row * size_of::<KoalaBear>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );
                    cuda_precompile_fp_op_secp256k1_generate_extra_record_and_main(
                        num_cols_per_row,
                        event_size,
                        trace_size,
                        d_events.as_ptr() as *const _,
                        d_trace.as_mut_ptr() as *mut _,
                        d_dummy_row.as_ptr() as *const _,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }

                info!("[precompile-fp-op-chip-secp256k1] generate_extra_record_and_main on GPU")
            }
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        TraceData::Gpu(num_fp_cols::<P>(), d_trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        // All the fp events for a given curve are coalesce to the curve's Add operation. Only
        // check for that operation.
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match P::FIELD_TYPE {
                FieldType::Bls381 => !record.bls12381_fp_add_events.is_empty(),
                FieldType::Bn254 => !record.bn254_fp_add_events.is_empty(),
                FieldType::Secp256k1 => !record.secp256k1_fp_add_events.is_empty(),
            }
        }
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
        let local = main.current_slice();
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
            .map(|&limbs| CB::Expr::from_u8(limbs))
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
        let result_words = limbs_to_words::<CB::Expr>(&result_limbs, CB::F::from_u32(256).into());

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
                CB::F::from_u32(SyscallCode::BN254_FP_ADD.syscall_id()),
                CB::F::from_u32(SyscallCode::BN254_FP_SUB.syscall_id()),
                CB::F::from_u32(SyscallCode::BN254_FP_MUL.syscall_id()),
            ),
            FieldType::Bls381 => (
                CB::F::from_u32(SyscallCode::BLS12381_FP_ADD.syscall_id()),
                CB::F::from_u32(SyscallCode::BLS12381_FP_SUB.syscall_id()),
                CB::F::from_u32(SyscallCode::BLS12381_FP_MUL.syscall_id()),
            ),
            FieldType::Secp256k1 => (
                CB::F::from_u32(SyscallCode::SECP256K1_FP_ADD.syscall_id()),
                CB::F::from_u32(SyscallCode::SECP256K1_FP_SUB.syscall_id()),
                CB::F::from_u32(SyscallCode::SECP256K1_FP_MUL.syscall_id()),
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "cuda")]
    use std::sync::LazyLock;

    #[cfg(feature = "cuda")]
    use itertools::Itertools;
    #[cfg(feature = "cuda")]
    use num::BigUint;
    #[cfg(feature = "cuda")]
    use p3_field::PrimeField32;
    #[cfg(feature = "cuda")]
    use p3_koala_bear::KoalaBear;
    #[cfg(feature = "cuda")]
    use p3_matrix::dense::RowMajorMatrix;
    #[cfg(feature = "cuda")]
    use rand::{rng, RngExt};

    #[cfg(feature = "cuda")]
    use crate::{
        chips::{
            chips::{
                byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
                events::{MemoryReadRecord, MemoryWriteRecord},
            },
            gadgets::{
                field::{
                    bls381::Bls381BaseField, bn254::Bn254BaseField, field_op::FieldOperation,
                    secp256k1::Secp256k1BaseField,
                },
                utils::field_params::{FieldType, FpOpField, NumWords},
            },
            precompiles::fptower::fp::FpOpChip,
            tests::init_test_stream,
            trace::TraceData,
        },
        emulator::riscv::{
            record::EmulationRecord,
            syscalls::{
                precompiles::{FpEvent, PrecompileEvent},
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
    use typenum::Unsigned;

    #[cfg(feature = "cuda")]
    type F = KoalaBear;

    #[cfg(feature = "cuda")]
    const FIELD_OPERATIONS: [FieldOperation; 4] = [
        FieldOperation::Add,
        FieldOperation::Sub,
        FieldOperation::Mul,
        FieldOperation::Div,
    ];

    #[cfg(feature = "cuda")]
    static BLS381_SHARD: LazyLock<EmulationRecord> =
        LazyLock::new(|| make_shard::<Bls381BaseField>(5));
    #[cfg(feature = "cuda")]
    static BN254_SHARD: LazyLock<EmulationRecord> =
        LazyLock::new(|| make_shard::<Bn254BaseField>(5));
    #[cfg(feature = "cuda")]
    static SECP256K1_SHARD: LazyLock<EmulationRecord> =
        LazyLock::new(|| make_shard::<Secp256k1BaseField>(5));

    #[cfg(feature = "cuda")]
    fn cpu_generate_main<P: FpOpField>(
        chip: &FpOpChip<F, P>,
        input: &EmulationRecord,
    ) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    #[cfg(feature = "cuda")]
    fn random_base_field_element<P: FpOpField>() -> BigUint {
        let modulus_bytes = P::MODULUS;
        let modulus = BigUint::from_bytes_le(modulus_bytes);
        let mut rng = rand::rng();
        let mut bytes = vec![0u8; modulus.bits() as usize / 8 + 1];
        rng.fill(&mut bytes[..]);
        let candidate = BigUint::from_bytes_le(&bytes);
        candidate % modulus
    }

    #[cfg(feature = "cuda")]
    /// Convert u32 digits (LE) from BigUint to u64 dwords (LE).
    /// Pads to `num_dwords` entries.
    fn u32_digits_to_u64_dwords(digits: &[u32], num_dwords: usize) -> Vec<u64> {
        let mut result = Vec::with_capacity(num_dwords);
        for i in 0..num_dwords {
            let lo = if 2 * i < digits.len() {
                digits[2 * i] as u64
            } else {
                0u64
            };
            let hi = if 2 * i + 1 < digits.len() {
                (digits[2 * i + 1] as u64) << 32
            } else {
                0u64
            };
            result.push(lo | hi);
        }
        result
    }

    #[cfg(feature = "cuda")]
    pub(super) fn make_shard<P: FpOpField>(num_iters: usize) -> EmulationRecord {
        let mut rng = rng();
        let mut rec = EmulationRecord::default();

        let syscall_codes = match P::FIELD_TYPE {
            FieldType::Bls381 => [
                SyscallCode::BLS12381_FP_ADD,
                SyscallCode::BLS12381_FP_ADD,
                SyscallCode::BLS12381_FP_ADD,
                SyscallCode::BLS12381_FP_ADD,
            ],
            FieldType::Bn254 => [
                SyscallCode::BN254_FP_ADD,
                SyscallCode::BN254_FP_ADD,
                SyscallCode::BN254_FP_ADD,
                SyscallCode::BN254_FP_ADD,
            ],
            FieldType::Secp256k1 => [
                SyscallCode::SECP256K1_FP_ADD,
                SyscallCode::SECP256K1_FP_ADD,
                SyscallCode::SECP256K1_FP_ADD,
                SyscallCode::SECP256K1_FP_ADD,
            ],
        };

        let num_dwords = <P as NumWords>::WordsFieldElement::USIZE;

        for _ in 0..num_iters {
            let chunk = rng.random::<u32>() % (KoalaBear::ORDER_U32 - 1);
            let clk = (rng.random::<u32>() % (KoalaBear::ORDER_U32 - 1)) as u64;
            let arg1 = (rng.random::<u32>() % (KoalaBear::ORDER_U32 - 1)) as u64;
            let arg2 = (rng.random::<u32>() % (KoalaBear::ORDER_U32 - 1)) as u64;

            let fp_x = random_base_field_element::<P>();
            let fp_y = random_base_field_element::<P>();
            // Convert BigUint u32 digits to u64 dwords
            let x_dwords = u32_digits_to_u64_dwords(&fp_x.to_u32_digits(), num_dwords);
            let y_dwords = u32_digits_to_u64_dwords(&fp_y.to_u32_digits(), num_dwords);

            let timestamps = (0..=num_dwords)
                .map(|_| rng.random::<u32>() % (KoalaBear::ORDER_U32 - 1))
                .sorted()
                .collect::<Vec<_>>();
            let chunks = (0..=num_dwords)
                .map(|_| rng.random::<u32>() % (KoalaBear::ORDER_U32 - 1))
                .sorted()
                .collect::<Vec<_>>();
            let memory_write_records = (0..num_dwords)
                .map(|i| MemoryWriteRecord {
                    value: (rng.random::<u32>() % (KoalaBear::ORDER_U32 - 1)) as u64,
                    chunk: chunks[i + 1],
                    timestamp: timestamps[i + 1],
                    prev_value: (rng.random::<u32>() % (KoalaBear::ORDER_U32 - 1)) as u64,
                    prev_chunk: chunks[i],
                    prev_timestamp: timestamps[i],
                })
                .collect::<Vec<_>>();
            let memory_read_records = (0..num_dwords)
                .map(|i| MemoryReadRecord {
                    value: (rng.random::<u32>() % (KoalaBear::ORDER_U32 - 1)) as u64,
                    chunk: chunks[i + 1],
                    timestamp: timestamps[i + 1],
                    prev_chunk: chunks[i],
                    prev_timestamp: timestamps[i],
                })
                .collect::<Vec<_>>();

            for (&op, &syscall_code) in FIELD_OPERATIONS.iter().zip(syscall_codes.iter()) {
                let event = FpEvent {
                    chunk,
                    clk,
                    x_ptr: (rng.random::<u32>() % (KoalaBear::ORDER_U32 - 1)) as u64,
                    x: x_dwords.clone().into_boxed_slice(),
                    y_ptr: (rng.random::<u32>() % (KoalaBear::ORDER_U32 - 1)) as u64,
                    y: y_dwords.clone().into_boxed_slice(),
                    op,
                    x_memory_records: memory_write_records.clone().into_boxed_slice(),
                    y_memory_records: memory_read_records.clone().into_boxed_slice(),
                    local_mem_access: vec![],
                };

                let syscall_event = SyscallEvent {
                    chunk,
                    clk,
                    syscall_id: syscall_code as u32,
                    arg1,
                    arg2,
                };

                let event = match P::FIELD_TYPE {
                    FieldType::Bls381 => PrecompileEvent::Bls12381Fp(event),
                    FieldType::Bn254 => PrecompileEvent::Bn254Fp(event),
                    FieldType::Secp256k1 => PrecompileEvent::Secp256k1Fp(event),
                };

                rec.precompile_events
                    .add_event(syscall_code, syscall_event, event);
            }
        }

        rec
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn test_bn254_fp_generate_extra_record_and_main() {
        type P = Bn254BaseField;
        let chunk = LazyLock::force(&BN254_SHARD);
        test_precompile_fp_generate_extra_record_and_main_helper::<P>(chunk);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn test_bls381_fp_generate_extra_record_and_main() {
        type P = Bls381BaseField;
        let chunk = LazyLock::force(&BLS381_SHARD);
        test_precompile_fp_generate_extra_record_and_main_helper::<P>(chunk);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn test_secp256k1_fp_generate_extra_record_and_main() {
        type P = Secp256k1BaseField;
        let chunk = LazyLock::force(&SECP256K1_SHARD);
        test_precompile_fp_generate_extra_record_and_main_helper::<P>(chunk);
    }

    #[cfg(feature = "cuda")]
    fn test_precompile_fp_generate_extra_record_and_main_helper<P: FpOpField>(
        original_record: &EmulationRecord,
    ) {
        let chip = FpOpChip::<F, P>::new();

        // Complete the record for CPU computation.
        let mut complete_record = original_record.clone();
        chip.extra_record(original_record, &mut complete_record);
        // Precompute event sizes for GPU computation.
        let mut counted_record = original_record.clone();
        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 5);
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 5);

        let mut event_counter = precompute_event_size::<F>(&mut counted_record);
        // Ignore Poseidon2 event counting
        event_counter.num_poseidon2_events = complete_record.poseidon2_events.len();
        // Ignore Global lookup event counting
        event_counter.num_global_lookup_events = complete_record.global_lookup_events.len();
        // Assert that the event counts are the same.
        event_counter.assert_event_counts_match(&complete_record);

        // Generate CPU trace.
        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        // Generate GPU trace.
        let stream = init_test_stream();
        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_byte_trace: gpu_allocate_byte_trace(stream, 0).unwrap(),
            ..Default::default()
        };
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);
        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );
        // Assert trace consistency.
        assert_eq!(cpu_trace, gpu_trace);

        // Finalize the byte trace. And assert that the byte trace is consistent.
        gpu_finalize_byte_trace(stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();

        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(stream);

        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }

    #[cfg(feature = "cuda")]
    fn gpu_generate_extra_record_and_main<P: FpOpField>(
        chip: &FpOpChip<F, P>,
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
    #[test]
    fn bench_fp_op_cpu_vs_gpu() {
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
            cuda_precompile_fp_op_bls381_generate_extra_record_and_main,
            cuda_precompile_fp_op_bn254_generate_extra_record_and_main,
            cuda_precompile_fp_op_secp256k1_generate_extra_record_and_main,
        };

        use super::num_fp_cols;
        use crate::{
            chips::precompiles::fptower::{
                dummy_row::{DUMMY_ROW_BLS381_KB, DUMMY_ROW_BN254_KB, DUMMY_ROW_SECP256K1_KB},
                ffi::FfiFpEvent,
            },
            cuda_adaptor::resource_pool::{
                mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
            },
        };

        fn bench_field<P: FpOpField>(field_label: &str) {
            let chip = FpOpChip::<F, P>::new();
            let warmup_sizes: Vec<usize> = vec![1 << 10];
            let bench_sizes: Vec<usize> = vec![1 << 10, 1 << 14, 1 << 16, 1 << 18];

            println!("\n  [{field_label}]");
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
                // Each make_shard call produces 4 events per iteration (ADD, SUB, MUL, DIV)
                // so we divide by 4 to get num_iters
                let num_iters = num_events / 4;
                let original_record = make_shard::<P>(num_iters);

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
                    precompute_event_size::<F>(&counted_record.clone()),
                );

                // Get events slice
                let events: &[FfiFpEvent<P::WordsFieldElement>] = match P::FIELD_TYPE {
                    FieldType::Bn254 => unsafe {
                        transmute(prepared_gpu_events.bn254_fp_add_events.as_slice())
                    },
                    FieldType::Bls381 => unsafe {
                        transmute(prepared_gpu_events.bls12381_fp_add_events.as_slice())
                    },
                    FieldType::Secp256k1 => unsafe {
                        transmute(prepared_gpu_events.secp256k1_fp_add_events.as_slice())
                    },
                };

                let padded_nrows = 1usize << log_rows;
                let num_cols = num_fp_cols::<P>();
                let trace_size = padded_nrows * num_cols;

                let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING)
                    .expect("Failed to create CUDA stream");
                let sync_mem_pool = get_global_mem_pool(0);
                let mem_pool = &sync_mem_pool.0;

                // H2D: copy events to GPU (outside timer)
                let mut d_events =
                    DevicePoolAllocation::<FfiFpEvent<P::WordsFieldElement>>::alloc_from_pool_async(
                        events.len(),
                        mem_pool,
                        stream,
                    )
                    .expect("GPU event alloc failed");
                unsafe {
                    let _ = cudaMemcpyAsync(
                        d_events.as_mut_c_void_ptr(),
                        events.as_c_void_ptr(),
                        events.len() * size_of::<FfiFpEvent<P::WordsFieldElement>>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );
                }

                // Allocate trace + byte trace + dummy row on GPU (outside timer)
                let mut d_trace =
                    DevicePoolAllocation::<p3_koala_bear::KoalaBear>::alloc_from_pool_async(
                        trace_size, mem_pool, stream,
                    )
                    .expect("GPU trace alloc failed");
                let mut d_byte_trace = gpu_allocate_byte_trace(stream, 0).unwrap().unwrap();
                let mut d_dummy_row =
                    DevicePoolAllocation::<p3_koala_bear::KoalaBear>::alloc_from_pool_async(
                        num_cols, mem_pool, stream,
                    )
                    .expect("GPU dummy row alloc failed");

                // Copy dummy row to GPU
                let dummy_row: &[p3_koala_bear::KoalaBear] = match P::FIELD_TYPE {
                    FieldType::Bn254 => &DUMMY_ROW_BN254_KB,
                    FieldType::Bls381 => &DUMMY_ROW_BLS381_KB,
                    FieldType::Secp256k1 => &DUMMY_ROW_SECP256K1_KB,
                };
                unsafe {
                    let _ = cudaMemcpyAsync(
                        d_dummy_row.as_mut_c_void_ptr(),
                        dummy_row.as_c_void_ptr(),
                        num_cols * size_of::<p3_koala_bear::KoalaBear>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );
                }

                // Sync to ensure H2D and allocations are done
                stream.synchronize().unwrap();

                // === TIMED: kernel only ===
                let gpu_start = Instant::now();
                unsafe {
                    match P::FIELD_TYPE {
                        FieldType::Secp256k1 => {
                            cuda_precompile_fp_op_secp256k1_generate_extra_record_and_main(
                                num_cols,
                                events.len(),
                                trace_size,
                                d_events.as_ptr() as *const _,
                                d_trace.as_mut_ptr() as *mut _,
                                d_dummy_row.as_ptr() as *const _,
                                d_byte_trace.as_mut_ptr() as *mut _,
                                stream.into(),
                            );
                        }
                        FieldType::Bn254 => {
                            cuda_precompile_fp_op_bn254_generate_extra_record_and_main(
                                num_cols,
                                events.len(),
                                trace_size,
                                d_events.as_ptr() as *const _,
                                d_trace.as_mut_ptr() as *mut _,
                                d_dummy_row.as_ptr() as *const _,
                                d_byte_trace.as_mut_ptr() as *mut _,
                                stream.into(),
                            );
                        }
                        FieldType::Bls381 => {
                            cuda_precompile_fp_op_bls381_generate_extra_record_and_main(
                                num_cols,
                                events.len(),
                                trace_size,
                                d_events.as_ptr() as *const _,
                                d_trace.as_mut_ptr() as *mut _,
                                d_dummy_row.as_ptr() as *const _,
                                d_byte_trace.as_mut_ptr() as *mut _,
                                stream.into(),
                            );
                        }
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
        println!("  FpOp CPU vs GPU Benchmark (kernel only)");
        println!("{:=<60}", "");

        bench_field::<Secp256k1BaseField>("secp256k1");
        bench_field::<Bn254BaseField>("bn254");
        bench_field::<Bls381BaseField>("bls12381");
    }
}
