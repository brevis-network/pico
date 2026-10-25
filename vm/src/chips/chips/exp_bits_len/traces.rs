use crate::{
    chips::{
        chips::{
            exp_bits_len::{
                assert_koalabear_field,
                columns::{
                    ExpBitsLenCols, ExpBitsLenPreprocessedCols, LOW_BITS_COUNT,
                    NUM_BITS_MAX_PLUS_ONE, NUM_EXP_BITS_LEN_COLS,
                    NUM_EXP_BITS_LEN_PREPROCESSED_COLS,
                },
                ExpBitsLenChip,
            },
            recursion_memory::MemoryAccessCols,
        },
        trace::TraceData,
        utils::{next_power_of_two, pad_rows_fixed},
    },
    compiler::recursion::{
        instruction::Instruction,
        mle_instruction_buckets::MleVariant,
        program::RecursionProgram,
        types::{Address, ExpBitsLenInstr},
    },
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::{ChipBehavior, PreprocessedRows},
};
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::*;
use log::info;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::{cuda_exp_bits_len_generate_main, cuda_exp_bits_len_generate_preprocessed};
use std::borrow::BorrowMut;

/// H2D mirror of the CUDA `ExpBitsLenFlatEvent`: `bit_src` is pre-reduced to its canonical u32 so
/// the kernel does its bit logic on a plain integer (base stays a field element for the ladder).
#[repr(C)]
#[derive(Clone, Copy)]
struct ExpBitsLenFlatEvent<F: Copy> {
    base: F,
    bit_src: u32,
    num_bits: u32,
}

/// H2D mirror of the CUDA `ExpBitsLenPreprocMeta`: per-instruction bookkeeping for the two-buffer
/// expansion (the per-row bit outputs live in a flat `MemoryAccessCols` side buffer).
#[repr(C)]
#[derive(Clone, Copy)]
struct ExpBitsLenPreprocMeta<F: Copy> {
    base: F,
    num_bits: u32,
    bit_src_in_addr: Address<F>,
    result_out_addr: Address<F>,
    result_mult: F,
    bit_outs_offset: u32,
    bit_outs_count: u32,
}

/// Builds the 32 witnessed rows for a single request over the KoalaBear field
/// (`LOW_BITS_COUNT = 24`).
fn build_block<F: PrimeField32>(
    base: F,
    decomp_src: u32,
    n: usize,
) -> [[F; NUM_EXP_BITS_LEN_COLS]; NUM_BITS_MAX_PLUS_ONE] {
    debug_assert!(n < NUM_BITS_MAX_PLUS_ONE);
    debug_assert!(decomp_src < (1u32 << (NUM_BITS_MAX_PLUS_ONE - 1)));

    // base^(2^step) for step = 0..32.
    let mut bases = [F::ZERO; NUM_BITS_MAX_PLUS_ONE];
    let mut cur = base;
    for slot in bases.iter_mut() {
        *slot = cur;
        cur = cur * cur;
    }

    // Reverse product: results[step] is the exponentiation restricted to set bits at positions
    // `>= step` (and `< n`). results[0] is the final `base^(decomp_src mod 2^n)`.
    let mut results = [F::ONE; NUM_BITS_MAX_PLUS_ONE];
    let mut acc = F::ONE;
    for step in (0..NUM_BITS_MAX_PLUS_ONE - 1).rev() {
        if step < n && ((decomp_src >> step) & 1) == 1 {
            acc *= bases[step];
        }
        results[step] = acc;
    }

    let mut block = [[F::ZERO; NUM_EXP_BITS_LEN_COLS]; NUM_BITS_MAX_PLUS_ONE];
    let mut low_bits_are_zero = true;
    let mut high_bits_all_one = false;
    for step in 0..NUM_BITS_MAX_PLUS_ONE {
        if step == LOW_BITS_COUNT {
            high_bits_all_one = true;
        }

        let shifted = decomp_src >> step;
        let num_bits = n.saturating_sub(step);
        let low_bits_left = LOW_BITS_COUNT.saturating_sub(step);

        let cols: &mut ExpBitsLenCols<F> = block[step].as_mut_slice().borrow_mut();
        cols.bit_idx = F::from_usize(step);
        cols.base = bases[step];
        cols.bit_src = F::from_u32(shifted);
        cols.num_bits = F::from_usize(num_bits);
        cols.apply_bit = F::from_bool(num_bits != 0);
        cols.low_bits_left = F::from_usize(low_bits_left);
        cols.in_low_region = F::from_bool(low_bits_left != 0);
        cols.result = results[step];
        cols.result_multiplier = if num_bits != 0 && (shifted & 1) == 1 {
            bases[step]
        } else {
            F::ONE
        };
        cols.bit_src_mod_2 = F::from_bool((shifted & 1) == 1);
        cols.low_bits_are_zero = F::from_bool(low_bits_are_zero);
        cols.high_bits_all_one = F::from_bool(high_bits_all_one);

        if step < LOW_BITS_COUNT {
            low_bits_are_zero &= (shifted & 1) == 0;
        } else if step + 1 < NUM_BITS_MAX_PLUS_ONE {
            high_bits_all_one &= (shifted & 1) == 1;
        }
    }
    block
}

/// A padding row satisfies the ungated `result_multiplier - 1 = apply_bit * bit * (base - 1)`
/// equation (`result_multiplier = 1`, everything else zero) and contributes no memory lookups.
fn padding_row<F: PrimeField32>() -> [F; NUM_EXP_BITS_LEN_COLS] {
    let mut row = [F::ZERO; NUM_EXP_BITS_LEN_COLS];
    let cols: &mut ExpBitsLenCols<F> = row.as_mut_slice().borrow_mut();
    cols.result = F::ONE;
    cols.result_multiplier = F::ONE;
    row
}

impl<F: PrimeField32> ChipBehavior<F> for ExpBitsLenChip<F> {
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "ExpBitsLen".to_string()
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().exp_bits_len,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_koalabear_field::<F>();
        let mut rows: Vec<[F; NUM_EXP_BITS_LEN_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::ExpBitsLen(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &ExpBitsLenInstr<F>| {
                let mut block =
                    vec![[F::ZERO; NUM_EXP_BITS_LEN_PREPROCESSED_COLS]; NUM_BITS_MAX_PLUS_ONE];
                block.iter_mut().enumerate().for_each(|(i, row)| {
                    let cols: &mut ExpBitsLenPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                    let is_first = i == 0;
                    let is_last = i == NUM_BITS_MAX_PLUS_ONE - 1;
                    cols.is_first = F::from_bool(is_first);
                    cols.is_last = F::from_bool(is_last);
                    cols.is_real = F::ONE;
                    // Read the input on the first row only (negative mult = read).
                    cols.bit_src_in = MemoryAccessCols {
                        addr: instr.bit_src_in_addr,
                        mult: -F::from_bool(is_first),
                    };
                    // Write the result on the first row only (positive mult = write; the count is
                    // backfilled from `read_counts` in convert.rs `finish()`).
                    cols.result_out = MemoryAccessCols {
                        addr: instr.result_out_addr,
                        mult: instr.result_mult * F::from_bool(is_first),
                    };
                    // Per-row bit output. Rows without a consumer (terminal row, or bits beyond the
                    // requested export width) carry the zero address with mult 0.
                    let (bit_addr, bit_mult) = if i < instr.bit_outs_addrs_mults.len() {
                        instr.bit_outs_addrs_mults[i]
                    } else {
                        (Address(F::ZERO), F::ZERO)
                    };
                    cols.bit_out = MemoryAccessCols {
                        addr: bit_addr,
                        mult: bit_mult,
                    };
                    // Per-request constants, injected on the first row (see the `is_first` anchors).
                    if is_first {
                        cols.base_const = instr.base;
                        cols.num_bits_const = F::from_u32(instr.num_bits);
                    }
                });
                rows.extend(block);
            });

        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_EXP_BITS_LEN_PREPROCESSED_COLS],
            program.fixed_log2_rows(&self.name()),
        );

        Some(RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_EXP_BITS_LEN_PREPROCESSED_COLS,
        ))
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        assert_koalabear_field::<F>();
        let mut rows: Vec<[F; NUM_EXP_BITS_LEN_COLS]> = Vec::new();

        for event in input.exp_bits_len_events.iter() {
            let block = build_block(
                event.base,
                event.bit_src.as_canonical_u32(),
                event.num_bits as usize,
            );
            rows.extend(block);
        }

        pad_rows_fixed(
            &mut rows,
            padding_row::<F>,
            input.fixed_log2_rows(&self.name()),
        );

        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_EXP_BITS_LEN_COLS)
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXP_BITS_LEN_PREPROCESSED_COLS
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        assert_koalabear_field::<F>();

        // Two-buffer layout: per-instruction metadata + a flat (addr, mult) buffer for the per-row
        // bit outputs. The kernel writes the 32-row block for each instruction on the device; the
        // host only serializes the variable-length `bit_outs_addrs_mults` and copies integer offsets.
        let width = NUM_EXP_BITS_LEN_PREPROCESSED_COLS;
        let mut metas: Vec<ExpBitsLenPreprocMeta<F>> = Vec::new();
        let mut bit_outs_flat: Vec<MemoryAccessCols<F>> = Vec::new();
        program
            .mle_candidates(MleVariant::ExpBitsLen)
            .filter_map(|instruction| {
                if let Instruction::ExpBitsLen(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &ExpBitsLenInstr<F>| {
                let bit_outs_offset = bit_outs_flat.len() as u32;
                let bit_outs_count = instr.bit_outs_addrs_mults.len() as u32;
                for &(addr, mult) in &instr.bit_outs_addrs_mults {
                    bit_outs_flat.push(MemoryAccessCols { addr, mult });
                }
                metas.push(ExpBitsLenPreprocMeta {
                    base: instr.base,
                    num_bits: instr.num_bits,
                    bit_src_in_addr: instr.bit_src_in_addr,
                    result_out_addr: instr.result_out_addr,
                    result_mult: instr.result_mult,
                    bit_outs_offset,
                    bit_outs_count,
                });
            });

        let num_instrs = metas.len();
        let real_rows = num_instrs * NUM_BITS_MAX_PLUS_ONE;
        let padded_nb_rows = program.padded_prep_rows(&self.name(), real_rows);

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

        if real_rows > 0 {
            let mut d_metas =
                DevicePoolAllocation::<ExpBitsLenPreprocMeta<F>>::alloc_from_pool_async(
                    num_instrs, mem_pool, stream,
                )
                .unwrap();
            let mut d_bit_outs =
                DevicePoolAllocation::<MemoryAccessCols<F>>::alloc_from_pool_async(
                    bit_outs_flat.len().max(1),
                    mem_pool,
                    stream,
                )
                .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_metas.as_mut_c_void_ptr(),
                    metas.as_c_void_ptr(),
                    num_instrs * size_of::<ExpBitsLenPreprocMeta<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
                if !bit_outs_flat.is_empty() {
                    let _ = cudaMemcpyAsync(
                        d_bit_outs.as_mut_c_void_ptr(),
                        bit_outs_flat.as_c_void_ptr(),
                        bit_outs_flat.len() * size_of::<MemoryAccessCols<F>>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );
                }

                cuda_exp_bits_len_generate_preprocessed(
                    d_metas.as_ptr() as *const _,
                    num_instrs,
                    d_bit_outs.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    width,
                    real_rows,
                    stream.into(),
                );
            }
        }

        info!("[exp-bits-len-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(width, d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
        _: Option<&Self::GpuRecord>,
    ) -> TraceData<'_, F> {
        assert_koalabear_field::<F>();

        // `bit_src` is pre-reduced to canonical u32 so the kernel's bit logic runs on a plain integer
        // (matching the CPU `event.bit_src.as_canonical_u32()`); base stays a field element.
        let events: Box<[ExpBitsLenFlatEvent<F>]> = input
            .exp_bits_len_events
            .iter()
            .map(|ev| ExpBitsLenFlatEvent {
                base: ev.base,
                bit_src: ev.bit_src.as_canonical_u32(),
                num_bits: ev.num_bits,
            })
            .collect();

        let num_events = events.len();
        let real_rows = num_events * NUM_BITS_MAX_PLUS_ONE;
        // Match CPU `pad_rows_fixed` (next_power_of_two of the real row count, 16-floor). Padding rows
        // (result = result_multiplier = 1) are written by the same kernel launch.
        let padded_nb_rows = next_power_of_two(real_rows, input.fixed_log2_rows(&self.name()));

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_EXP_BITS_LEN_COLS;
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

        // Allocate at least one element so the device pointer is non-null even with zero events
        // (all rows are then padding rows, filled by the kernel).
        let mut d_events = DevicePoolAllocation::<ExpBitsLenFlatEvent<F>>::alloc_from_pool_async(
            num_events.max(1),
            mem_pool,
            stream,
        )
        .unwrap();
        unsafe {
            if num_events > 0 {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    num_events * size_of::<ExpBitsLenFlatEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }

            cuda_exp_bits_len_generate_main(
                d_events.as_ptr() as *const _,
                num_events,
                d_trace.as_mut_ptr() as *mut _,
                NUM_EXP_BITS_LEN_COLS,
                padded_nb_rows,
                stream.into(),
            );
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[exp-bits-len-chip] generate_main on GPU");

        TraceData::Gpu(NUM_EXP_BITS_LEN_COLS, d_trace)
    }
}
