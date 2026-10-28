use crate::{
    chips::chips::ext_dot_product::{
        columns::{
            ExtDotProductCols, ExtDotProductPreprocessedCols, NUM_EXT_DOT_PRODUCT_COLS,
            NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS,
        },
        ExtDotProductChip,
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{ExtDotProductEvent, ExtDotProductInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::{EXT_DOT_PRODUCT_DATAPAR, EXT_DOT_PRODUCT_GROUPS},
};
#[cfg(feature = "cuda")]
use crate::{
    chips::trace::TraceData,
    compiler::recursion::{mle_instruction_buckets::MleVariant, types::Address},
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    machine::chip::GpuChipBehavior,
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::*;
#[cfg(feature = "cuda")]
use log::info;
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::{
    cuda_ext_dot_product_generate_main, cuda_ext_dot_product_generate_preprocessed,
};
use std::borrow::BorrowMut;

#[cfg(feature = "cuda")]
/// H2D mirror of the CUDA `ExtDotProductPreprocMeta`: per-instruction bookkeeping for the two-buffer
/// device-side row expansion (the mu/val addresses live in separate flat buffers).
#[repr(C)]
#[derive(Clone, Copy)]
struct ExtDotProductPreprocMeta<F: Copy> {
    n_rows: u32,
    mu_offset: u32,
    val_offset: u32,
    row_offset: u32,
    acc_addr: Address<F>,
    mult: F,
}

impl<F> BaseAir<F> for ExtDotProductChip<F> {
    fn width(&self) -> usize {
        NUM_EXT_DOT_PRODUCT_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for ExtDotProductChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "ExtDotProduct".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().ext_dot_product,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::ExtDotProduct(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &ExtDotProductInstr<F>| {
                let n_groups = instr.val_addrs.len();
                debug_assert_eq!(
                    instr.mu_addrs.len(),
                    n_groups * (EXT_DOT_PRODUCT_DATAPAR / EXT_DOT_PRODUCT_GROUPS)
                );
                // The lowering pads the address vectors to a whole number of rows
                // with zero-address (zero-value) groups.
                debug_assert_eq!(n_groups % EXT_DOT_PRODUCT_GROUPS, 0);
                let n_rows = n_groups / EXT_DOT_PRODUCT_GROUPS;
                for i in 0..n_rows {
                    let mut row = [F::ZERO; NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS];
                    let cols: &mut ExtDotProductPreprocessedCols<F> =
                        row.as_mut_slice().borrow_mut();
                    cols.is_real = F::ONE;
                    cols.is_end = F::from_bool(i == n_rows - 1);
                    for j in 0..EXT_DOT_PRODUCT_DATAPAR {
                        cols.mu_addrs[j] = instr.mu_addrs[EXT_DOT_PRODUCT_DATAPAR * i + j];
                    }
                    for g in 0..EXT_DOT_PRODUCT_GROUPS {
                        cols.val_addrs[g] = instr.val_addrs[EXT_DOT_PRODUCT_GROUPS * i + g];
                    }
                    cols.acc_addr = instr.acc_addr;
                    cols.mult = if i == n_rows - 1 { instr.mult } else { F::ZERO };
                    rows.push(row);
                }
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .ext_dot_product_events
            .iter()
            .map(|event: &ExtDotProductEvent<F>| {
                let mut row = [F::ZERO; NUM_EXT_DOT_PRODUCT_COLS];
                let cols: &mut ExtDotProductCols<F> = row.as_mut_slice().borrow_mut();
                cols.mus = event.mus;
                cols.vals = event.vals;
                cols.acc = event.acc;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_EXT_DOT_PRODUCT_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_EXT_DOT_PRODUCT_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for ExtDotProductChip<F> {
    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        use p3_koala_bear::KoalaBear;

        // Two-buffer layout: each instruction's mu/val element addresses go into flat side buffers
        // and the kernel expands its n_groups/GROUPS rows on the device. The host only serializes the
        // `Vec<Address>` fields and computes integer offsets (row_offset = prefix sum of row counts).
        let width = NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS;
        let mut mu_flat: Vec<Address<F>> = Vec::new();
        let mut val_flat: Vec<Address<F>> = Vec::new();
        let mut metas: Vec<ExtDotProductPreprocMeta<F>> = Vec::new();
        let mut row_cursor: u32 = 0;
        program
            .mle_candidates(MleVariant::ExtDotProduct)
            .filter_map(|instruction| {
                if let Instruction::ExtDotProduct(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &ExtDotProductInstr<F>| {
                let n_groups = instr.val_addrs.len();
                let n_rows = (n_groups / EXT_DOT_PRODUCT_GROUPS) as u32;
                let mu_offset = mu_flat.len() as u32;
                let val_offset = val_flat.len() as u32;
                mu_flat.extend_from_slice(&instr.mu_addrs);
                val_flat.extend_from_slice(&instr.val_addrs);
                metas.push(ExtDotProductPreprocMeta {
                    n_rows,
                    mu_offset,
                    val_offset,
                    row_offset: row_cursor,
                    acc_addr: instr.acc_addr,
                    mult: instr.mult,
                });
                row_cursor += n_rows;
            });

        let num_rows = row_cursor as usize;

        let padded_nb_rows = program.padded_prep_rows(&self.name(), num_rows);

        let sync_stream = get_global_stream_pool(device_id);
        let stream = &sync_stream.0;
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * width;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut _,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream.into(),
            );
        }

        if num_rows > 0 {
            let num_instrs = metas.len();
            let mut d_metas =
                DevicePoolAllocation::<ExtDotProductPreprocMeta<F>>::alloc_from_pool_async(
                    num_instrs, mem_pool, stream,
                )
                .unwrap();
            let mut d_mu = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
                mu_flat.len(),
                mem_pool,
                stream,
            )
            .unwrap();
            let mut d_val = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
                val_flat.len(),
                mem_pool,
                stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_metas.as_mut_c_void_ptr(),
                    metas.as_c_void_ptr(),
                    num_instrs * size_of::<ExtDotProductPreprocMeta<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
                let _ = cudaMemcpyAsync(
                    d_mu.as_mut_c_void_ptr(),
                    mu_flat.as_c_void_ptr(),
                    mu_flat.len() * size_of::<Address<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
                let _ = cudaMemcpyAsync(
                    d_val.as_mut_c_void_ptr(),
                    val_flat.as_c_void_ptr(),
                    val_flat.len() * size_of::<Address<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_ext_dot_product_generate_preprocessed(
                    d_metas.as_ptr() as *const _,
                    num_instrs,
                    d_mu.as_ptr() as *const _,
                    d_val.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    width,
                    stream.into(),
                );
            }
        }

        info!("[ext-dot-product-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(width, d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
    ) -> TraceData<'_, F> {
        use p3_koala_bear::KoalaBear;

        // The event is fixed-size (#[repr(C)]) and maps 1:1 to a trace row; copy it straight to the
        // device and let the kernel scatter each event into its row.
        let events = &input.ext_dot_product_events;

        let nb_rows = events.len().max(16);
        let padded_nb_rows = match input.fixed_log2_rows(&self.name()) {
            Some(log_rows) => {
                let specified = 1 << log_rows;
                assert!(
                    specified >= nb_rows,
                    "fixed_log2_rows too small: 2^{log_rows}={specified} < {nb_rows} real rows"
                );
                specified
            }
            None => nb_rows.next_power_of_two(),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_EXT_DOT_PRODUCT_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut _,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream.into(),
            );
        }

        let event_size = events.len();
        if event_size > 0 {
            let mut d_events =
                DevicePoolAllocation::<ExtDotProductEvent<F>>::alloc_from_pool_async(
                    event_size, mem_pool, stream,
                )
                .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<ExtDotProductEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_ext_dot_product_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_EXT_DOT_PRODUCT_COLS,
                    stream.into(),
                );
            }
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[ext-dot-product-chip] generate_main on GPU");

        TraceData::Gpu(NUM_EXT_DOT_PRODUCT_COLS, d_trace)
    }
}
