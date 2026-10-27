#[cfg(feature = "cuda")]
use super::ffi::FfiFp2AddSubEvent;
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
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{precompiles::PrecompileEvent, SyscallCode},
    },
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder, ScopedBuilder},
        chip::ChipBehavior,
    },
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{
        gadgets::{
            curves::weierstrass::{bls381::Bls381BaseField, bn254::Bn254BaseField},
            utils::field_params::NumWords,
        },
        trace::TraceData,
        utils::next_power_of_two,
    },
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
};
use core::{
    borrow::{Borrow, BorrowMut},
    fmt::Debug,
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
use hybrid_array::{typenum::Unsigned, Array};
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
    cuda_precompile_fp2_add_sub_bls12381_generate_extra_record_and_main,
    cuda_precompile_fp2_add_sub_bn254_generate_extra_record_and_main,
};
#[cfg(feature = "cuda")]
use std::mem::transmute;
#[cfg(feature = "cuda")]
use tracing::info;

pub const fn num_fp2_addsub_cols<P>() -> usize
where
    P: FpOpField,
{
    size_of::<Fp2AddSubCols<u8, P>>()
}

#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct Fp2AddSubChip<F, P> {
    _marker: PhantomData<fn(F, P) -> (F, P)>,
}

/// A set of columns for the FpAdd operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp2AddSubCols<F, P>
where
    P: FpOpField,
{
    pub is_real: F,
    pub chunk: F,
    pub clk: F,
    pub is_add: F,
    pub x_ptr: SyscallAddrGadget<F>,
    pub y_ptr: SyscallAddrGadget<F>,
    pub x_addrs: Array<AddrAddGadget<F>, P::WordsCurvePoint>,
    pub y_addrs: Array<AddrAddGadget<F>, P::WordsCurvePoint>,
    pub x_access: Array<MemoryWriteColsU8<F>, P::WordsCurvePoint>,
    pub y_access: Array<MemoryReadColsU8<F>, P::WordsCurvePoint>,
    pub(crate) c0: FieldOpCols<F, P>,
    pub(crate) c1: FieldOpCols<F, P>,
    pub(crate) c0_range: FieldLtCols<F, P>,
    pub(crate) c1_range: FieldLtCols<F, P>,
}

impl<F, P> Fp2AddSubChip<F, P>
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
        cols: &mut Fp2AddSubCols<F, P>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
        op: FieldOperation,
    ) {
        let modulus_bytes = P::MODULUS;
        let modulus = BigUint::from_bytes_le(modulus_bytes);

        // Reject non-reduced operands here, as `fp.rs` and `fp2_mul.rs` do. Otherwise the
        // limbs are silently truncated and SUB becomes unsatisfiable with no clue why.
        for (name, v) in [("p.x", &p_x), ("p.y", &p_y), ("q.x", &q_x), ("q.y", &q_y)] {
            assert!(*v < modulus, "fp2 coordinate {name} must be < modulus");
        }

        let c0 = cols
            .c0
            .populate_with_modulus(blu_events, &p_x, &q_x, &modulus, op);
        let c1 = cols
            .c1
            .populate_with_modulus(blu_events, &p_y, &q_y, &modulus, op);
        cols.c0_range.populate(blu_events, &c0, &modulus);
        cols.c1_range.populate(blu_events, &c1, &modulus);
    }
}

impl<F, P> ChipBehavior<F> for Fp2AddSubChip<F, P>
where
    F: PrimeField32,
    P: FpOpField,
{
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        match P::FIELD_TYPE {
            FieldType::Bn254 => "Bn254Fp2AddSub".to_string(),
            FieldType::Bls381 => "Bls381Fp2AddSub".to_string(),
            _ => unimplemented!("fp2 available only for Bn254 and Bls12381"),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        // All the fp2 sub and add events for a given curve are coalesce to the curve's Add operation. Only retrieve
        // precompile events for that operation.
        let events = match P::FIELD_TYPE {
            FieldType::Bn254 => input
                .get_precompile_events(SyscallCode::BN254_FP2_ADD)
                .iter(),
            FieldType::Bls381 => input
                .get_precompile_events(SyscallCode::BLS12381_FP2_ADD)
                .iter(),
            _ => unimplemented!("fp2 available only for Bn254 and Bls12381"),
        };

        let mut rows = Vec::new();
        let mut new_byte_lookup_events = Vec::new();

        for (_, event) in events {
            let event = match (P::FIELD_TYPE, event) {
                (FieldType::Bn254, PrecompileEvent::Bn254Fp2AddSub(event)) => event,
                (FieldType::Bls381, PrecompileEvent::Bls12381Fp2AddSub(event)) => event,
                _ => unreachable!(),
            };

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
            cols.chunk = F::from_u32(event.chunk);
            cols.clk = F::from_u32(checked_u64_to_u32(event.clk, "fptower fp2 addsub clk"));
            cols.x_ptr.populate(
                &mut new_byte_lookup_events,
                event.x_ptr,
                P::NUM_LIMBS as u64 * 2,
            );
            cols.y_ptr.populate(
                &mut new_byte_lookup_events,
                event.y_ptr,
                P::NUM_LIMBS as u64 * 2,
            );

            Self::populate_field_ops(
                &mut new_byte_lookup_events,
                cols,
                p_x,
                p_y,
                q_x,
                q_y,
                event.op,
            );

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
            rows.push(row)
        }

        new_byte_lookup_events
            .iter()
            .for_each(|x| output.add_byte_lookup_event(*x));

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = vec![F::ZERO; num_fp2_addsub_cols::<P>()];
                let cols: &mut Fp2AddSubCols<F, P> = row.as_mut_slice().borrow_mut();
                cols.is_add = F::ONE;
                let zero = BigUint::zero();
                Self::populate_field_ops(
                    &mut vec![],
                    cols,
                    zero.clone(),
                    zero.clone(),
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
            num_fp2_addsub_cols::<P>(),
        )
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, input: &Self::Record) -> bool {
        // All the fp2 sub and add events for a given curve are coalesce to the curve's Add operation. Only retrieve
        // precompile events for that operation.
        assert!(
            input
                .get_precompile_events(SyscallCode::BN254_FP2_SUB)
                .is_empty()
                && input
                    .get_precompile_events(SyscallCode::BLS12381_FP2_SUB)
                    .is_empty()
        );

        if let Some(shape) = input.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match P::FIELD_TYPE {
                FieldType::Bn254 => !input
                    .get_precompile_events(SyscallCode::BN254_FP2_ADD)
                    .is_empty(),
                FieldType::Bls381 => !input
                    .get_precompile_events(SyscallCode::BLS12381_FP2_ADD)
                    .is_empty(),
                _ => unimplemented!("fp2 available only for Bn254 and Bls12381"),
            }
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F, P> GpuChipBehavior<F> for Fp2AddSubChip<F, P>
where
    F: PrimeField32,
    P: FpOpField,
{
    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        // All the fp2 sub and add events for a given curve are coalesce to the curve's Add operation. Only retrieve
        // precompile events for that operation.
        let events: &[FfiFp2AddSubEvent<P::WordsCurvePoint>] = match P::FIELD_TYPE {
            FieldType::Bn254 => {
                let events = prepared_gpu_events.bn254_fp2_add_sub_events.as_slice();
                unsafe {
                    transmute::<
                        &[FfiFp2AddSubEvent<<Bn254BaseField as NumWords>::WordsCurvePoint>],
                        &[FfiFp2AddSubEvent<P::WordsCurvePoint>],
                    >(events)
                }
            }
            FieldType::Bls381 => {
                let events = prepared_gpu_events.bls12381_fp2_add_sub_events.as_slice();
                unsafe {
                    transmute::<
                        &[FfiFp2AddSubEvent<<Bls381BaseField as NumWords>::WordsCurvePoint>],
                        &[FfiFp2AddSubEvent<P::WordsCurvePoint>],
                    >(events)
                }
            }
            _ => unimplemented!("fp2 available only for Bn254 and Bls12381"),
        };

        let num_cols_per_row = num_fp2_addsub_cols::<P>();
        let log_rows = input.shape_chip_size(&self.name());
        let num_total_rows = next_power_of_two(events.len(), log_rows);

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let event_size = events.len();
        let mut d_events =
            DevicePoolAllocation::<FfiFp2AddSubEvent<P::WordsCurvePoint>>::alloc_from_pool_async(
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

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        match P::FIELD_TYPE {
            FieldType::Bls381 => {
                unsafe {
                    cuda_precompile_fp2_add_sub_bls12381_generate_extra_record_and_main(
                        num_cols_per_row,
                        event_size,
                        trace_size,
                        d_events.as_ptr() as *const _,
                        d_trace.as_mut_ptr() as *mut _,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }

                info!(
                    "[precompile-fp2-add-sub-chip-bls12-381] generate_extra_record_and_main on GPU"
                );
            }
            FieldType::Bn254 => {
                unsafe {
                    cuda_precompile_fp2_add_sub_bn254_generate_extra_record_and_main(
                        num_cols_per_row,
                        event_size,
                        trace_size,
                        d_events.as_ptr() as *const _,
                        d_trace.as_mut_ptr() as *mut _,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                    );
                }

                info!("[precompile-fp2-add-sub-chip-bn254] generate_extra_record_and_main on GPU")
            }
            _ => unreachable!(),
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        TraceData::Gpu(num_fp2_addsub_cols::<P>(), d_trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        // All the fp2 sub and add events for a given curve are coalesce to the curve's Add operation. Only retrieve
        // precompile events for that operation.
        // assert!(record.bn254_fp_add_events.is_empty() && record.bls12381_fp_add_events.is_empty());

        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match P::FIELD_TYPE {
                FieldType::Bn254 => !record.bn254_fp2_add_sub_events.is_empty(),
                FieldType::Bls381 => !record.bls12381_fp2_add_sub_events.is_empty(),
                _ => unimplemented!("fp2 available only for Bn254 and Bls12381"),
            }
        }
    }
}

impl<F, P> BaseAir<F> for Fp2AddSubChip<F, P>
where
    P: FpOpField,
{
    fn width(&self) -> usize {
        num_fp2_addsub_cols::<P>()
    }
}

impl<F, P, CB> Air<CB> for Fp2AddSubChip<F, P>
where
    F: Field,
    CB: ChipBuilder<F> + ScopedBuilder,
    P: FpOpField,
    Limbs<CB::Var, <P as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &Fp2AddSubCols<CB::Var, P> = (*local).borrow();

        // Constrain the `is_add` and `is_real` flags to be boolean.
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_real);

        let num_words_field_element = <P as NumLimbs>::Limbs::USIZE / 8;

        let p_x_limbs = generate_limbs_from_write_cols_u8(
            builder,
            &local.x_access[0..num_words_field_element],
            local.is_real.into(),
        );
        let p_x: Limbs<CB::Expr, <P as NumLimbs>::Limbs> =
            Limbs((&*p_x_limbs).try_into().expect("failed to convert limbs"));
        let q_x_limbs = generate_limbs_from_read_cols_u8(
            builder,
            &local.y_access[0..num_words_field_element],
            local.is_real.into(),
        );
        let q_x: Limbs<CB::Expr, <P as NumLimbs>::Limbs> =
            Limbs((&*q_x_limbs).try_into().expect("failed to convert limbs"));
        let p_y_limbs = generate_limbs_from_write_cols_u8(
            builder,
            &local.x_access[num_words_field_element..],
            local.is_real.into(),
        );
        let p_y: Limbs<CB::Expr, <P as NumLimbs>::Limbs> =
            Limbs((&*p_y_limbs).try_into().expect("failed to convert limbs"));
        let q_y_limbs = generate_limbs_from_read_cols_u8(
            builder,
            &local.y_access[num_words_field_element..],
            local.is_real.into(),
        );
        let q_y: Limbs<CB::Expr, <P as NumLimbs>::Limbs> =
            Limbs((&*q_y_limbs).try_into().expect("failed to convert limbs"));

        let modulus_coeffs = P::MODULUS
            .iter()
            .map(|&limbs| CB::Expr::from_u8(limbs))
            .collect_vec();
        let p_modulus = Polynomial::from_coefficients(&modulus_coeffs);

        {
            builder.with_scope("c0", |builder| {
                local.c0.eval_variable(
                    builder,
                    &p_x,
                    &q_x,
                    &p_modulus,
                    local.is_add,
                    CB::Expr::ONE - local.is_add,
                    CB::F::ZERO,
                    CB::F::ZERO,
                    local.is_real,
                )
            });

            builder.with_scope("c1", |builder| {
                local.c1.eval_variable(
                    builder,
                    &p_y,
                    &q_y,
                    &p_modulus,
                    local.is_add,
                    CB::Expr::ONE - local.is_add,
                    CB::F::ZERO,
                    CB::F::ZERO,
                    local.is_real,
                )
            });
        }

        let c0_result_limbs: Vec<CB::Expr> = local
            .c0
            .result
            .0
            .iter()
            .copied()
            .map(|x| x.into())
            .collect();
        let c0_result_words =
            limbs_to_words::<CB::Expr>(&c0_result_limbs, CB::F::from_u32(256).into());

        let c1_result_limbs: Vec<CB::Expr> = local
            .c1
            .result
            .0
            .iter()
            .copied()
            .map(|x| x.into())
            .collect();
        let c1_result_words =
            limbs_to_words::<CB::Expr>(&c1_result_limbs, CB::F::from_u32(256).into());

        let result_words = c0_result_words
            .into_iter()
            .chain(c1_result_words)
            .collect_vec();

        local
            .c0_range
            .eval(builder, &local.c0.result, &p_modulus, local.is_real);
        local
            .c1_range
            .eval(builder, &local.c1.result, &p_modulus, local.is_real);

        let x_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            P::NUM_LIMBS as u32 * 2,
            local.x_ptr,
            local.is_real.into(),
        );
        let y_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            P::NUM_LIMBS as u32 * 2,
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

        let (add_syscall_id, sub_syscall_id) = match P::FIELD_TYPE {
            FieldType::Bn254 => (
                CB::F::from_u32(SyscallCode::BN254_FP2_ADD.syscall_id()),
                CB::F::from_u32(SyscallCode::BN254_FP2_SUB.syscall_id()),
            ),
            FieldType::Bls381 => (
                CB::F::from_u32(SyscallCode::BLS12381_FP2_ADD.syscall_id()),
                CB::F::from_u32(SyscallCode::BLS12381_FP2_SUB.syscall_id()),
            ),
            _ => unimplemented!("fp2 available only for Bn254 and Bls12381"),
        };

        let syscall_id_felt =
            local.is_add * add_syscall_id + (CB::Expr::ONE - local.is_add) * sub_syscall_id;

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
    use std::sync::LazyLock;

    #[cfg(feature = "cuda")]
    use crate::{
        chips::{
            chips::{
                byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
                events::{MemoryReadRecord, MemoryWriteRecord},
            },
            gadgets::{
                curves::weierstrass::bls381::Bls381BaseField,
                field::{bn254::Bn254BaseField, field_op::FieldOperation},
                utils::field_params::{FieldType, FpOpField},
            },
            precompiles::fptower::fp2_addsub::Fp2AddSubChip,
            tests::init_test_stream,
            trace::TraceData,
        },
        emulator::riscv::{
            record::EmulationRecord,
            syscalls::{
                precompiles::{Fp2AddSubEvent, PrecompileEvent, PrecompileEvents},
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
    // Lazily initialized record for use across multiple tests (small size for debugging).
    static BN254_SHARD: LazyLock<EmulationRecord> =
        LazyLock::new(|| generate_record::<Bn254BaseField>(1 << 3));

    #[cfg(feature = "cuda")]
    static BLS12381_SHARD: LazyLock<EmulationRecord> =
        LazyLock::new(|| generate_record::<Bls381BaseField>(1 << 3));

    #[cfg(feature = "cuda")]
    fn cpu_generate_main<P: FpOpField>(
        chip: &Fp2AddSubChip<F, P>,
        input: &EmulationRecord,
    ) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    #[cfg(feature = "cuda")]
    pub(super) fn generate_record<P: FpOpField>(size: usize) -> EmulationRecord {
        use typenum::Unsigned;
        let mut rng = rng();
        let size = size as u32;
        let double_num_words = P::WordsCurvePoint::USIZE;
        let mut precompile_events = PrecompileEvents::default();
        let op = FieldOperation::Add;
        let syscall_id = match P::FIELD_TYPE {
            FieldType::Bn254 => SyscallCode::BN254_FP2_ADD,
            FieldType::Bls381 => SyscallCode::BLS12381_FP2_ADD,
            _ => unreachable!(),
        };
        let events = (0..size)
            .map(|i| {
                let chunk = 0u32;
                let clk = i as u64;
                let x_ptr = (rng.random_range(0..size) * 4) as u64;
                let y_ptr = (rng.random_range(0..size) * 4) as u64;
                let x = random_base_field_elements::<P>(&mut rng);
                let y = random_base_field_elements::<P>(&mut rng);
                let x_memory_records = (0..double_num_words as u32)
                    .map(|_| MemoryWriteRecord {
                        prev_timestamp: i,
                        timestamp: i + 1,
                        ..Default::default()
                    })
                    .collect();
                let y_memory_records = (0..double_num_words as u32)
                    .map(|_| MemoryReadRecord {
                        prev_timestamp: i,
                        timestamp: i + 1,
                        ..Default::default()
                    })
                    .collect();
                let event = Fp2AddSubEvent {
                    op,
                    chunk,
                    clk,
                    x_ptr,
                    x,
                    y_ptr,
                    y,
                    x_memory_records,
                    y_memory_records,
                    local_mem_access: vec![],
                };
                let precompile_event = match P::FIELD_TYPE {
                    FieldType::Bn254 => PrecompileEvent::Bn254Fp2AddSub(event),
                    FieldType::Bls381 => PrecompileEvent::Bls12381Fp2AddSub(event),
                    _ => unreachable!(),
                };
                let syscall_event = SyscallEvent {
                    syscall_id: syscall_id as u32,
                    ..Default::default()
                };
                (syscall_event, precompile_event)
            })
            .collect_vec();
        precompile_events.insert(syscall_id, events);

        let mut record = EmulationRecord::default();
        record.precompile_events = precompile_events.clone();

        record
    }

    #[cfg(feature = "cuda")]
    fn random_base_field_elements<P: FpOpField>(rng: &mut ThreadRng) -> Box<[u64]> {
        let x = rng.random_biguint(P::num_bits() as u64) % P::modulus();
        let y = rng.random_biguint(P::num_bits() as u64) % P::modulus();
        let x_digits = x.to_u64_digits();
        let y_digits = y.to_u64_digits();
        let num_dwords = P::NUM_LIMBS / 8;
        let mut result = vec![0u64; num_dwords * 2];
        for (i, &d) in x_digits.iter().enumerate() {
            if i < num_dwords {
                result[i] = d;
            }
        }
        for (i, &d) in y_digits.iter().enumerate() {
            if i < num_dwords {
                result[num_dwords + i] = d;
            }
        }
        result.into_boxed_slice()
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn test_bn254_fp2_add_sub_generate_extra_record_and_main() {
        type P = Bn254BaseField;
        let chunk = LazyLock::force(&BN254_SHARD);
        test_precompile_fp2_add_sub_generate_extra_record_and_main_helper::<P>(chunk);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn test_bls12381_fp2_add_sub_generate_extra_record_and_main() {
        type P = Bls381BaseField;
        let chunk = LazyLock::force(&BLS12381_SHARD);
        test_precompile_fp2_add_sub_generate_extra_record_and_main_helper::<P>(chunk);
    }

    #[cfg(feature = "cuda")]
    fn test_precompile_fp2_add_sub_generate_extra_record_and_main_helper<P: FpOpField>(
        original_record: &EmulationRecord,
    ) {
        let chip = Fp2AddSubChip::<F, P>::new();

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
            d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
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
        chip: &Fp2AddSubChip<F, P>,
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
    fn bench_fp2_add_sub_cpu_vs_gpu() {
        // Initialize CUDA context and global memory pool
        init_test_stream();

        println!("\n============================================================");
        println!("  Fp2AddSub CPU vs GPU Benchmark (kernel only)");
        println!("============================================================\n");

        bench_fp2_add_sub_for_field::<Bn254BaseField>("bn254");
        bench_fp2_add_sub_for_field::<Bls381BaseField>("bls12381");
    }

    #[cfg(feature = "cuda")]
    fn bench_fp2_add_sub_for_field<P: FpOpField>(label: &str) {
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
            cuda_precompile_fp2_add_sub_bls12381_generate_extra_record_and_main,
            cuda_precompile_fp2_add_sub_bn254_generate_extra_record_and_main,
        };

        use super::num_fp2_addsub_cols;
        use crate::{
            chips::precompiles::fptower::ffi::FfiFp2AddSubEvent,
            cuda_adaptor::resource_pool::{
                mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
            },
        };

        println!("  [{}]", label);
        println!("  ----------------------------------------------------------");
        println!(
            "  {:10}    {:>10}  {:>10}   {:>10}",
            "events", "cpu (ms)", "gpu (ms)", "speedup"
        );
        println!("  ----------------------------------------------------------");

        let warmup_sizes: Vec<usize> = vec![1 << 10];
        let bench_sizes: Vec<usize> = vec![1 << 10, 1 << 14, 1 << 16, 1 << 18];

        for (is_warmup, &num_events) in warmup_sizes
            .iter()
            .map(|n| (true, n))
            .chain(bench_sizes.iter().map(|n| (false, n)))
        {
            let record = generate_record::<P>(num_events);
            let chip = Fp2AddSubChip::<F, P>::new();

            let log_rows = (num_events as f64).log2().ceil() as usize + 1;

            // CPU — needs complete record (with extra_record applied)
            let mut complete_record = record.clone();
            complete_record.shape = Some(RiscvPadShape::default());
            complete_record
                .shape
                .as_mut()
                .unwrap()
                .inner
                .insert(chip.name(), log_rows);
            chip.extra_record(&record, &mut complete_record);
            let cpu_start = Instant::now();
            let cpu_trace = cpu_generate_main(&chip, &complete_record);
            let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

            // === GPU (inline to separate H2D / kernel / D2H) ===
            let mut counted_record = record.clone();
            counted_record.shape = Some(RiscvPadShape::default());
            counted_record
                .shape
                .as_mut()
                .unwrap()
                .inner
                .insert(chip.name(), log_rows);
            let mut event_counter = precompute_event_size::<F>(&mut counted_record);
            event_counter.num_poseidon2_events = record.poseidon2_events.len();
            event_counter.num_global_lookup_events = record.global_lookup_events.len();
            let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);

            // Get events slice
            let events: &[FfiFp2AddSubEvent<P::WordsCurvePoint>] = match P::FIELD_TYPE {
                FieldType::Bn254 => unsafe {
                    transmute(prepared_gpu_events.bn254_fp2_add_sub_events.as_slice())
                },
                FieldType::Bls381 => unsafe {
                    transmute(prepared_gpu_events.bls12381_fp2_add_sub_events.as_slice())
                },
                _ => unreachable!(),
            };

            let padded_nrows = 1usize << log_rows;
            let num_cols = num_fp2_addsub_cols::<P>();
            let trace_size = padded_nrows * num_cols;

            let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING)
                .expect("Failed to create CUDA stream");
            let sync_mem_pool = get_global_mem_pool(0);
            let mem_pool = &sync_mem_pool.0;

            // H2D: copy events to GPU (outside timer)
            let mut d_events =
                DevicePoolAllocation::<FfiFp2AddSubEvent<P::WordsCurvePoint>>::alloc_from_pool_async(
                    events.len(),
                    mem_pool,
                    stream,
                )
                .expect("GPU event alloc failed");
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    events.len() * size_of::<FfiFp2AddSubEvent<P::WordsCurvePoint>>(),
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
                match P::FIELD_TYPE {
                    FieldType::Bn254 => {
                        cuda_precompile_fp2_add_sub_bn254_generate_extra_record_and_main(
                            num_cols,
                            events.len(),
                            trace_size,
                            d_events.as_ptr() as *const _,
                            d_trace.as_mut_ptr() as *mut _,
                            d_byte_trace.as_mut_ptr() as *mut _,
                            stream.into(),
                        );
                    }
                    FieldType::Bls381 => {
                        cuda_precompile_fp2_add_sub_bls12381_generate_extra_record_and_main(
                            num_cols,
                            events.len(),
                            trace_size,
                            d_events.as_ptr() as *const _,
                            d_trace.as_mut_ptr() as *mut _,
                            d_byte_trace.as_mut_ptr() as *mut _,
                            stream.into(),
                        );
                    }
                    _ => unreachable!(),
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
                    "  {:10}    {:>10}  {:>10}   {:>10}",
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
                "  {:10}    {:10.2}  {:10.2}   {:7.1}x  ✓",
                num_events, cpu_ms, gpu_ms, speedup
            );
        }

        println!("  ----------------------------------------------------------\n");
    }
}
