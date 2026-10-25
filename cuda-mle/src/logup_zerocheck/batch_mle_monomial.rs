//! Monomial-form MLE evaluation for zerocheck and logup, batched over AIRs.
//!
//! The evaluators here group many traces into a single GPU kernel launch instead of launching
//! once per trace.

use crate::runtime::{
    copy::MemCopyH2D,
    d_buffer::DeviceBuffer,
    error::{CudaError, MemCopyError},
};
use mle_core::prover::{fractional_sumcheck_gkr::Frac, DeviceMultiStarkProvingKey};
use p3_field::PrimeCharacteristicRing;
use tracing::debug;

use crate::{
    cuda::{
        field_kernels::FieldKernels,
        logup_zerocheck::{
            BlockCtx, EvalCoreCtx, LogupMonomialCommonCtx, LogupMonomialCtx, MainMatrixPtrs,
            MonomialAirCtx,
        },
    },
    error::KernelError,
    gpu_backend::GenericGpuBackend,
    hash_scheme::GpuHashScheme,
    logup_zerocheck::batch_mle::TraceCtx,
    prelude::{EF, F},
};

const THREADS_PER_BLOCK: u32 = 256;

/// Whether this trace qualifies for the monomial evaluation path: it must have constraints and
/// its AIR must carry a non-empty expanded monomial list.
pub(crate) fn trace_has_monomials<FK: FieldKernels, HS: GpuHashScheme>(
    trace: &TraceCtx<FK>,
    pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
) -> bool {
    trace.has_constraints
        && pk.per_air[trace.air_idx]
            .other_data
            .zerocheck_monomials
            .as_ref()
            .map(|m| m.num_monomials > 0)
            .unwrap_or(false)
}

/// Monomial count of the trace's AIR (0 when the AIR has no expanded monomials).
pub(crate) fn get_num_monomials<FK: FieldKernels, HS: GpuHashScheme>(
    trace: &TraceCtx<FK>,
    pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
) -> u32 {
    pk.per_air[trace.air_idx]
        .other_data
        .zerocheck_monomials
        .as_ref()
        .map(|m| m.num_monomials)
        .unwrap_or(0)
}

/// Number of rules in the zerocheck DAG of the trace's AIR.
pub(crate) fn get_zerocheck_rules_len<FK: FieldKernels, HS: GpuHashScheme>(
    tctx: &TraceCtx<FK>,
    pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
) -> usize {
    pk.per_air[tctx.air_idx]
        .other_data
        .zerocheck_mle
        .inner
        .d_rules
        .len()
}

/// Folds the constraint-batching powers of lambda into one coefficient per monomial of one AIR.
///
/// The returned buffer has `num_monomials` entries; entry `m` equals
/// `sum_l(coefficient_l * lambda_pows[constraint_idx_l])` taken over the terms of monomial `m`.
///
/// Panics unless the AIR carries expanded monomials.
pub(crate) fn compute_lambda_combinations<
    FK: FieldKernels,
    HS: GpuHashScheme<BaseField = FK::Val, ExtField = FK::ValExt>,
>(
    pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
    air_idx: usize,
    lambda_pows: &DeviceBuffer<FK::ValExt>,
) -> Result<crate::scratch::Scratch<FK::ValExt>, CudaError> {
    let zc_mono = pk.per_air[air_idx]
        .other_data
        .zerocheck_monomials
        .as_ref()
        .expect("zerocheck monomials missing for this AIR");
    let mut coeffs = crate::scratch::alloc::<FK::ValExt>(zc_mono.num_monomials as usize);
    unsafe {
        FK::precompute_lambda_combinations(
            &mut coeffs,
            zc_mono.d_headers.as_ptr(),
            zc_mono.d_lambda_terms.as_ptr(),
            lambda_pows,
            zc_mono.num_monomials,
        )?;
    }
    Ok(coeffs)
}

/// Zerocheck evaluator over expanded monomials for a group of traces.
///
/// All per-trace GPU contexts are assembled up front so the whole group is evaluated by one
/// kernel launch. Only traces accepted by [`trace_has_monomials`] may be passed in, and at least
/// one is needed.
///
/// Because the batch borrows each `TraceCtx`, the device memory those contexts point at
/// (`main_ptrs_dev` among it) cannot be freed while the batch exists.
pub(crate) struct ZerocheckMonomialBatch<'a, FK: FieldKernels> {
    traces: Vec<&'a TraceCtx<FK>>,
    block_ctxs: crate::scratch::Scratch<BlockCtx>,
    air_ctxs: crate::scratch::Scratch<MonomialAirCtx>,
    air_offsets: crate::scratch::Scratch<u32>,
}

impl<'a, FK: FieldKernels> ZerocheckMonomialBatch<'a, FK> {
    /// Builds the batch for the given traces.
    ///
    /// `lambda_combinations[i]` is the [`compute_lambda_combinations`] output for the `i`-th
    /// trace yielded by `trace_list`.
    ///
    /// # Panics
    ///
    /// When `trace_list` yields nothing, or the two inputs differ in length.
    pub fn new<HS: GpuHashScheme>(
        trace_list: impl IntoIterator<Item = &'a TraceCtx<FK>>,
        pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
        lambda_combinations: &[&crate::scratch::Scratch<FK::ValExt>],
    ) -> Result<Self, MemCopyError> {
        let trace_list: Vec<_> = trace_list.into_iter().collect();
        assert!(
            !trace_list.is_empty(),
            "ZerocheckMonomialBatch requires at least one trace"
        );
        assert_eq!(
            trace_list.len(),
            lambda_combinations.len(),
            "lambda_combinations must have one buffer per trace"
        );

        let tpb = THREADS_PER_BLOCK;

        // Lay out the grid: AIR `a` owns `ceil(num_monomials / tpb) * num_y` consecutive blocks,
        // and `offsets[a]..offsets[a + 1]` is that AIR's slice of the block list. Inside the slice
        // a block's local index is `y_int * tiles_per_y + tile`.
        let mut host_blocks: Vec<BlockCtx> = Vec::new();
        let mut offsets: Vec<u32> = Vec::with_capacity(trace_list.len() + 1);
        offsets.push(0);

        for (slot, trace_ctx) in trace_list.iter().enumerate() {
            let zc_mono = pk.per_air[trace_ctx.air_idx]
                .other_data
                .zerocheck_monomials
                .as_ref()
                .unwrap();
            let tiles_per_y = zc_mono.num_monomials.div_ceil(tpb);
            let air_block_count = tiles_per_y * trace_ctx.num_y;

            for idx in 0..air_block_count {
                host_blocks.push(BlockCtx {
                    local_block_idx_x: idx,
                    air_idx: slot as u32,
                });
            }
            offsets.push(host_blocks.len() as u32);
        }

        // One MonomialAirCtx per trace. The FFI structs are declared over the prelude EF / F,
        // so the generic FK::ValExt / FK::Val pointers are cast to those. This only relabels
        // memory: every field type is a #[repr(transparent)] u32 and the degree-4 extension is a
        // plain [u32; 4].
        let host_airs: Vec<MonomialAirCtx> = trace_list
            .iter()
            .zip(lambda_combinations)
            .map(|(trace_ctx, coeffs)| {
                let zc_mono = pk.per_air[trace_ctx.air_idx]
                    .other_data
                    .zerocheck_monomials
                    .as_ref()
                    .unwrap();

                let ectx = EvalCoreCtx {
                    d_selectors: trace_ctx.sels_ptr as *const EF,
                    d_preprocessed: MainMatrixPtrs {
                        data: trace_ctx.prep_ptr.data as *const EF,
                        air_width: trace_ctx.prep_ptr.air_width,
                    },
                    d_main: trace_ctx.main_ptrs_dev.as_ptr() as *const MainMatrixPtrs<EF>,
                    d_public: trace_ctx.public_ptr as *const F,
                };

                MonomialAirCtx {
                    d_headers: zc_mono.d_headers.as_ptr(),
                    d_variables: zc_mono.d_variables.as_ptr(),
                    d_lambda_combinations: coeffs.as_ptr() as *const EF,
                    num_monomials: zc_mono.num_monomials,
                    eval_ctx: ectx,
                    d_eq_xi: trace_ctx.eq_xi_ptr as *const EF,
                    num_y: trace_ctx.num_y,
                }
            })
            .collect();

        // Copy the host-side tables to the GPU.
        let d_blocks = crate::scratch::upload(&host_blocks)?;
        let d_airs = crate::scratch::upload(&host_airs)?;
        let offsets = crate::scratch::upload(&offsets)?;

        debug!(
            num_airs = trace_list.len(),
            num_blocks = d_blocks.len(),
            "ZerocheckMonomialBatch created"
        );

        Ok(Self {
            traces: trace_list,
            block_ctxs: d_blocks,
            air_ctxs: d_airs,
            air_offsets: offsets,
        })
    }

    /// `trace_idx` of every trace in the batch, in batch order.
    pub fn trace_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.traces
            .iter()
            .map(|trace_ctx_ref| trace_ctx_ref.trace_idx)
    }

    /// Runs the kernel and returns the device buffer it filled.
    ///
    /// It holds `num_airs * num_x` values, AIR-major: all x for AIR 0, then all x for AIR 1, ...
    /// Async-free and peak-memory behaviour is described in the [`crate::logup_zerocheck`] docs.
    pub fn evaluate(&self, num_x: u32) -> Result<crate::scratch::Scratch<FK::ValExt>, KernelError> {
        let num_blocks = self.block_ctxs.len();
        let num_airs = self.air_ctxs.len();

        debug!(
            %num_blocks,
            %num_x,
            %num_airs,
            "zerocheck_monomial_batched"
        );

        let mut partials = crate::scratch::alloc::<EF>(num_blocks * num_x as usize);
        let mut out_buf = crate::scratch::alloc::<EF>(num_airs * num_x as usize);

        debug_assert_eq!(
            self.air_offsets.len(),
            num_airs + 1,
            "air_offsets must have num_airs + 1 elements"
        );
        // SAFETY: the pointers stored in block_ctxs / air_ctxs come from device buffers that
        // stay alive for the whole call (borrowed TraceCtx data, the pk's monomial tables and
        // the lambda coefficient buffers), and air_offsets holds exactly num_airs + 1 entries.
        unsafe {
            FK::zerocheck_monomial_batched(
                &mut partials,
                &mut out_buf,
                &self.block_ctxs,
                &self.air_ctxs,
                &self.air_offsets,
                num_blocks as u32,
                num_x,
                num_airs as u32,
                THREADS_PER_BLOCK,
            )?;
        }

        // Hand the result back typed as FK::ValExt; it is laid out identically to EF (four
        // u32 limbs), so the transmute is a relabel only.
        Ok(unsafe {
            std::mem::transmute::<crate::scratch::Scratch<EF>, crate::scratch::Scratch<FK::ValExt>>(
                out_buf,
            )
        })
    }
}

// Tuning for the par-y kernel. PAR_Y_TPB has to match PAR_Y_BLOCK, the `__launch_bounds__`
// width of that kernel in pico-gpu's src/prover/logup_zerocheck/batch_mle_monomial.cu; the C++
// entry point refuses any other block size.
const PAR_Y_TPB: u32 = 128;
const PAR_Y_MONO_CAP: u32 = 64;
const PAR_Y_MIN_WAVES: u32 = 4;

/// Zerocheck monomial evaluator that spreads the work over y_int instead of over monomials.
///
/// Meant for traces with a large `num_y`: one thread owns one y_int and walks a chunk of the
/// monomial list. How many monomials go into a chunk is chosen from the SM count.
///
/// Only traces accepted by [`trace_has_monomials`] may be passed in, and at least one is needed.
pub(crate) struct ZerocheckMonomialParYBatch<'a, FK: FieldKernels> {
    traces: Vec<&'a TraceCtx<FK>>,
    block_ctxs: crate::scratch::Scratch<BlockCtx>,
    air_ctxs: crate::scratch::Scratch<MonomialAirCtx>,
    air_offsets: crate::scratch::Scratch<u32>,
    num_blocks: u32,
    chunk_size: u32,
}

impl<'a, FK: FieldKernels> ZerocheckMonomialParYBatch<'a, FK> {
    /// Builds the batch for the given traces.
    ///
    /// `lambda_combinations[i]` is the [`compute_lambda_combinations`] output for the `i`-th
    /// trace yielded by `trace_list`. `sm_count` and `num_x` feed the heuristic that sizes the
    /// monomial chunks so the device stays busy.
    ///
    /// # Panics
    ///
    /// When `trace_list` yields nothing, or the two inputs differ in length.
    #[allow(clippy::too_many_arguments)]
    pub fn new<HS: GpuHashScheme>(
        trace_list: impl IntoIterator<Item = &'a TraceCtx<FK>>,
        pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
        lambda_combinations: &[&crate::scratch::Scratch<FK::ValExt>],
        sm_count: u32,
        num_x: u32,
        max_monomials_per_thread: Option<u32>,
    ) -> Result<Self, MemCopyError> {
        let trace_list: Vec<_> = trace_list.into_iter().collect();
        assert!(
            !trace_list.is_empty(),
            "ZerocheckMonomialParYBatch requires at least one trace"
        );
        assert_eq!(
            trace_list.len(),
            lambda_combinations.len(),
            "lambda_combinations must have one buffer per trace"
        );

        let tpb = PAR_Y_TPB;
        let mono_cap = max_monomials_per_thread.unwrap_or(PAR_Y_MONO_CAP);

        // Gather (y_tiles, num_monomials) for each AIR before choosing the chunk size.
        let mut air_shapes: Vec<(u32, u32)> = Vec::new();
        let mut max_monomials = 0u32;

        for trace_ctx in trace_list.iter() {
            let zc_mono = pk.per_air[trace_ctx.air_idx]
                .other_data
                .zerocheck_monomials
                .as_ref()
                .expect("AIR with constraints must have monomials");

            let y_tiles = trace_ctx.num_y.div_ceil(tpb);
            max_monomials = max_monomials.max(zc_mono.num_monomials);
            air_shapes.push((y_tiles, zc_mono.num_monomials));
        }

        // Pick chunk_size (monomials per thread). It never exceeds mono_cap, and it is halved
        // until the launch is wide enough to fill the GPU:
        //   grid_blocks * num_x >= sm_count * PAR_Y_MIN_WAVES,
        // where grid_blocks sums y_tiles * ceil(num_monomials / chunk_size) over the AIRs.
        let min_blocks = sm_count * PAR_Y_MIN_WAVES;

        let mut chunk_size = mono_cap;
        loop {
            let grid_blocks: u32 = air_shapes
                .iter()
                .map(|(y_tiles, n_mono)| {
                    let chunks_per_y = n_mono.div_ceil(chunk_size);
                    y_tiles * chunks_per_y
                })
                .sum();

            if grid_blocks * num_x >= min_blocks || chunk_size <= 1 {
                break;
            }
            // Still too few blocks; split the monomials finer.
            chunk_size = (chunk_size / 2).max(1);
        }

        // Emit the per-AIR block lists; inside one AIR the local index is
        // `y_tile_idx * chunks_per_y + mono_chunk_idx`.
        let mut host_blocks: Vec<BlockCtx> = Vec::new();
        let mut offsets: Vec<u32> = Vec::with_capacity(trace_list.len() + 1);
        offsets.push(0);

        for (slot, (y_tiles, n_mono)) in air_shapes.iter().enumerate() {
            let chunks_per_y = n_mono.div_ceil(chunk_size);

            for y_tile_idx in 0..*y_tiles {
                for mono_chunk_idx in 0..chunks_per_y {
                    let idx = y_tile_idx * chunks_per_y + mono_chunk_idx;
                    host_blocks.push(BlockCtx {
                        local_block_idx_x: idx,
                        air_idx: slot as u32,
                    });
                }
            }
            offsets.push(host_blocks.len() as u32);
        }

        let num_blocks = host_blocks.len() as u32;

        // One MonomialAirCtx per trace. The FFI structs are declared over the prelude EF / F,
        // so the generic FK::ValExt / FK::Val pointers are cast to those. This only relabels
        // memory: every field type is a #[repr(transparent)] u32 and the degree-4 extension is a
        // plain [u32; 4].
        let host_airs: Vec<MonomialAirCtx> = trace_list
            .iter()
            .zip(lambda_combinations)
            .map(|(trace_ctx, coeffs)| {
                let zc_mono = pk.per_air[trace_ctx.air_idx]
                    .other_data
                    .zerocheck_monomials
                    .as_ref()
                    .unwrap();

                let ectx = EvalCoreCtx {
                    d_selectors: trace_ctx.sels_ptr as *const EF,
                    d_preprocessed: MainMatrixPtrs {
                        data: trace_ctx.prep_ptr.data as *const EF,
                        air_width: trace_ctx.prep_ptr.air_width,
                    },
                    d_main: trace_ctx.main_ptrs_dev.as_ptr() as *const MainMatrixPtrs<EF>,
                    d_public: trace_ctx.public_ptr as *const F,
                };

                MonomialAirCtx {
                    d_headers: zc_mono.d_headers.as_ptr(),
                    d_variables: zc_mono.d_variables.as_ptr(),
                    d_lambda_combinations: coeffs.as_ptr() as *const EF,
                    num_monomials: zc_mono.num_monomials,
                    eval_ctx: ectx,
                    d_eq_xi: trace_ctx.eq_xi_ptr as *const EF,
                    num_y: trace_ctx.num_y,
                }
            })
            .collect();

        // Copy the host-side tables to the GPU.
        let d_blocks = crate::scratch::upload(&host_blocks)?;
        let d_airs = crate::scratch::upload(&host_airs)?;
        let offsets = crate::scratch::upload(&offsets)?;

        debug!(
            num_airs = trace_list.len(),
            num_blocks, chunk_size, max_monomials, "ZerocheckMonomialParYBatch created"
        );

        Ok(Self {
            traces: trace_list,
            block_ctxs: d_blocks,
            air_ctxs: d_airs,
            air_offsets: offsets,
            num_blocks,
            chunk_size,
        })
    }

    /// `trace_idx` of every trace in the batch, in batch order.
    pub fn trace_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.traces
            .iter()
            .map(|trace_ctx_ref| trace_ctx_ref.trace_idx)
    }

    /// Runs the kernel and returns the device buffer it filled.
    ///
    /// It holds `num_airs * num_x` values, AIR-major: all x for AIR 0, then all x for AIR 1, ...
    /// Async-free and peak-memory behaviour is described in the [`crate::logup_zerocheck`] docs.
    pub fn evaluate(&self, num_x: u32) -> Result<crate::scratch::Scratch<FK::ValExt>, KernelError> {
        let num_airs = self.air_ctxs.len();

        debug!(
            num_blocks = %self.num_blocks,
            %num_x,
            %num_airs,
            chunk_size = %self.chunk_size,
            "zerocheck_monomial_par_y_batched"
        );

        let mut partials = crate::scratch::alloc::<EF>(self.num_blocks as usize * num_x as usize);
        let mut out_buf = crate::scratch::alloc::<EF>(num_airs * num_x as usize);

        debug_assert_eq!(
            self.air_offsets.len(),
            num_airs + 1,
            "air_offsets must have num_airs + 1 elements"
        );
        // SAFETY: the pointers stored in block_ctxs / air_ctxs come from device buffers that
        // stay alive for the whole call (borrowed TraceCtx data, the pk's monomial tables and
        // the lambda coefficient buffers), and air_offsets holds exactly num_airs + 1 entries.
        unsafe {
            FK::zerocheck_monomial_par_y_batched(
                &mut partials,
                &mut out_buf,
                &self.block_ctxs,
                &self.air_ctxs,
                &self.air_offsets,
                self.num_blocks,
                num_x,
                num_airs as u32,
                self.chunk_size,
                PAR_Y_TPB,
            )?;
        }

        // Hand the result back typed as FK::ValExt; it is laid out identically to EF (four
        // u32 limbs), so the transmute is a relabel only.
        Ok(unsafe {
            std::mem::transmute::<crate::scratch::Scratch<EF>, crate::scratch::Scratch<FK::ValExt>>(
                out_buf,
            )
        })
    }
}

// ============================================================================
// LOGUP MONOMIAL EVALUATION
// ============================================================================

/// Logup coefficients of one AIR, folded ahead of the batched kernel.
pub(crate) struct LogupCombinations<FK: FieldKernels> {
    pub(crate) d_numer_combinations: DeviceBuffer<FK::ValExt>,
    pub(crate) d_denom_combinations: DeviceBuffer<FK::ValExt>,
    pub(crate) bus_term_sum: FK::ValExt,
}

/// Folds eq_3bs (and, for denominators, the beta powers) into one coefficient per interaction
/// monomial of one AIR, and sums the constant bus term on the host.
///
/// Panics unless the AIR carries interaction monomials.
pub(crate) fn compute_logup_combinations<
    FK: FieldKernels,
    HS: GpuHashScheme<BaseField = FK::Val, ExtField = FK::ValExt>,
>(
    pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
    air_idx: usize,
    d_beta_pows: &DeviceBuffer<FK::ValExt>,
    d_eq_3bs: &DeviceBuffer<FK::ValExt>,
    eq_3bs_host: &[FK::ValExt],
    beta_pows_host: &[FK::ValExt],
) -> Result<LogupCombinations<FK>, CudaError> {
    let ix_mono = pk.per_air[air_idx]
        .other_data
        .interaction_monomials
        .as_ref()
        .expect("AIR must have interaction monomials");

    // Numerator side: per monomial, sum_i(coeff_i * eq_3bs[interaction_idx_i]).
    let numer_coeffs = if ix_mono.num_numer_monomials > 0 {
        let mut dst =
            DeviceBuffer::<FK::ValExt>::with_capacity(ix_mono.num_numer_monomials as usize);
        unsafe {
            FK::precompute_logup_numer_combinations(
                &mut dst,
                ix_mono.d_numer_headers.as_ptr(),
                ix_mono.d_numer_terms.as_ptr(),
                d_eq_3bs,
                ix_mono.num_numer_monomials,
            )?;
        }
        dst
    } else {
        DeviceBuffer::new()
    };

    // Denominator side, which additionally folds in the powers of beta.
    let denom_coeffs = if ix_mono.num_denom_monomials > 0 {
        let mut dst =
            DeviceBuffer::<FK::ValExt>::with_capacity(ix_mono.num_denom_monomials as usize);
        unsafe {
            FK::precompute_logup_denom_combinations(
                &mut dst,
                ix_mono.d_denom_headers.as_ptr(),
                ix_mono.d_denom_terms.as_ptr(),
                d_beta_pows,
                d_eq_3bs,
                ix_mono.num_denom_monomials,
            )?;
        }
        dst
    } else {
        DeviceBuffer::new()
    };

    // The constant bus term is cheap enough for the host:
    // sum_i(beta_pows[message_len_i] * (bus_idx[i] + 1) * eq_3bs[i]).
    let ints = &pk.per_air[air_idx].vk.symbolic_constraints.interactions;
    debug_assert_eq!(
        ints.len(),
        eq_3bs_host.len(),
        "interaction count must match eq_3bs"
    );
    let mut acc = FK::ValExt::ZERO;
    for (k, it) in ints.iter().enumerate() {
        let beta_pow = beta_pows_host[it.message.len()];
        let bus_id = it.kind as u32;
        acc += beta_pow * FK::ValExt::from_u32(bus_id + 1) * eq_3bs_host[k];
    }

    Ok(LogupCombinations {
        d_numer_combinations: numer_coeffs,
        d_denom_combinations: denom_coeffs,
        bus_term_sum: acc,
    })
}

const THREADS_PER_BLOCK_LOGUP: u32 = 128;

/// Logup evaluator over interaction monomials for a group of traces.
///
/// A block handles one (y_int, monomial tile) pair and writes a FracExt partial that the usual
/// reduction then folds.
pub(crate) struct LogupMonomialBatch<'a, FK: FieldKernels> {
    traces: Vec<&'a TraceCtx<FK>>,
    block_ctxs: crate::scratch::Scratch<BlockCtx>,
    shared_tbl: crate::scratch::Scratch<LogupMonomialCommonCtx>,
    numer_tbl: crate::scratch::Scratch<LogupMonomialCtx>,
    denom_tbl: crate::scratch::Scratch<LogupMonomialCtx>,
    air_offsets: crate::scratch::Scratch<u32>,
    num_blocks: u32,
}

impl<'a, FK: FieldKernels> LogupMonomialBatch<'a, FK> {
    /// Builds the batch for the given traces.
    ///
    /// `logup_combinations[i]` is the [`compute_logup_combinations`] output for the `i`-th
    /// trace yielded by `trace_list`.
    ///
    /// # Panics
    ///
    /// When `trace_list` yields nothing, or the two inputs differ in length.
    pub fn new<HS: GpuHashScheme>(
        trace_list: impl IntoIterator<Item = &'a TraceCtx<FK>>,
        pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
        logup_combinations: &[&LogupCombinations<FK>],
    ) -> Result<Self, MemCopyError> {
        let trace_list: Vec<_> = trace_list.into_iter().collect();
        assert!(
            !trace_list.is_empty(),
            "LogupMonomialBatch requires at least one trace"
        );
        assert_eq!(
            trace_list.len(),
            logup_combinations.len(),
            "logup_combinations must have one entry per trace"
        );

        let tpb = THREADS_PER_BLOCK_LOGUP;

        // Every trace gets num_y * tiles blocks; block (y, tile) of a trace has the local
        // index `y * tiles + tile`.
        let mut host_blocks: Vec<BlockCtx> = Vec::new();
        let mut offsets: Vec<u32> = Vec::with_capacity(trace_list.len() + 1);
        offsets.push(0);

        for (slot, trace_ctx) in trace_list.iter().enumerate() {
            let ix_mono = pk.per_air[trace_ctx.air_idx]
                .other_data
                .interaction_monomials
                .as_ref()
                .unwrap();
            let widest = ix_mono.num_numer_monomials.max(ix_mono.num_denom_monomials);
            let tiles = widest.div_ceil(tpb).max(1);
            for y in 0..trace_ctx.num_y {
                for tile in 0..tiles {
                    host_blocks.push(BlockCtx {
                        local_block_idx_x: y * tiles + tile,
                        air_idx: slot as u32,
                    });
                }
            }
            offsets.push(host_blocks.len() as u32);
        }

        let num_blocks = host_blocks.len() as u32;

        // Per-trace logup contexts (shared part, numerator side, denominator side). The FFI
        // structs are declared over the prelude EF / F, so the generic FK::ValExt / FK::Val
        // pointers are cast to those; every field type is a #[repr(transparent)] u32 and the
        // degree-4 extension is a plain [u32; 4], so the casts only relabel memory.
        let host_common: Vec<LogupMonomialCommonCtx> = trace_list
            .iter()
            .zip(logup_combinations)
            .map(|(trace_ctx, comb)| {
                let ix_mono = pk.per_air[trace_ctx.air_idx]
                    .other_data
                    .interaction_monomials
                    .as_ref()
                    .unwrap();
                let widest = ix_mono.num_numer_monomials.max(ix_mono.num_denom_monomials);
                let tiles = widest.div_ceil(tpb).max(1);

                let ectx = EvalCoreCtx {
                    d_selectors: trace_ctx.sels_ptr as *const EF,
                    d_preprocessed: MainMatrixPtrs {
                        data: trace_ctx.prep_ptr.data as *const EF,
                        air_width: trace_ctx.prep_ptr.air_width,
                    },
                    d_main: trace_ctx.main_ptrs_dev.as_ptr() as *const MainMatrixPtrs<EF>,
                    d_public: trace_ctx.public_ptr as *const F,
                };

                // Reinterpret the scalar bus term as EF (both types are four u32 limbs).
                let bus_sum: EF = unsafe { std::mem::transmute_copy(&comb.bus_term_sum) };

                LogupMonomialCommonCtx {
                    eval_ctx: ectx,
                    d_eq_xi: trace_ctx.eq_xi_ptr as *const EF,
                    bus_term_sum: bus_sum,
                    num_y: trace_ctx.num_y,
                    mono_blocks: tiles,
                }
            })
            .collect();
        let host_numer: Vec<LogupMonomialCtx> = trace_list
            .iter()
            .zip(logup_combinations)
            .map(|(trace_ctx, comb)| {
                let ix_mono = pk.per_air[trace_ctx.air_idx]
                    .other_data
                    .interaction_monomials
                    .as_ref()
                    .unwrap();
                LogupMonomialCtx {
                    d_headers: ix_mono.d_numer_headers.as_ptr(),
                    d_variables: ix_mono.d_numer_variables.as_ptr(),
                    d_combinations: comb.d_numer_combinations.as_ptr() as *const EF,
                    num_monomials: ix_mono.num_numer_monomials,
                }
            })
            .collect();
        let host_denom: Vec<LogupMonomialCtx> = trace_list
            .iter()
            .zip(logup_combinations)
            .map(|(trace_ctx, comb)| {
                let ix_mono = pk.per_air[trace_ctx.air_idx]
                    .other_data
                    .interaction_monomials
                    .as_ref()
                    .unwrap();
                LogupMonomialCtx {
                    d_headers: ix_mono.d_denom_headers.as_ptr(),
                    d_variables: ix_mono.d_denom_variables.as_ptr(),
                    d_combinations: comb.d_denom_combinations.as_ptr() as *const EF,
                    num_monomials: ix_mono.num_denom_monomials,
                }
            })
            .collect();

        // Copy the host-side tables to the GPU.
        let d_blocks = crate::scratch::upload(&host_blocks)?;
        let d_common = crate::scratch::upload(&host_common)?;
        let d_numer = crate::scratch::upload(&host_numer)?;
        let d_denom = crate::scratch::upload(&host_denom)?;
        let offsets = crate::scratch::upload(&offsets)?;

        debug!(
            num_airs = trace_list.len(),
            num_blocks, "LogupMonomialBatch created"
        );

        Ok(Self {
            traces: trace_list,
            block_ctxs: d_blocks,
            shared_tbl: d_common,
            numer_tbl: d_numer,
            denom_tbl: d_denom,
            air_offsets: offsets,
            num_blocks,
        })
    }

    /// `trace_idx` of every trace in the batch, in batch order.
    pub fn trace_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.traces
            .iter()
            .map(|trace_ctx_ref| trace_ctx_ref.trace_idx)
    }

    /// Runs the kernel and returns the device buffer it filled.
    ///
    /// It holds `num_airs * num_x` FracExt values, AIR-major: all x for AIR 0, then AIR 1, ...
    /// Async-free and peak-memory behaviour is described in the [`crate::logup_zerocheck`] docs.
    pub fn evaluate(
        &self,
        num_x: u32,
    ) -> Result<crate::scratch::Scratch<Frac<FK::ValExt>>, KernelError> {
        let num_airs = self.shared_tbl.len();

        debug!(
            num_blocks = %self.num_blocks,
            %num_x,
            %num_airs,
            "logup_monomial_batched"
        );

        let mut partials =
            crate::scratch::alloc::<Frac<EF>>(self.num_blocks as usize * num_x as usize);
        let mut out_buf = crate::scratch::alloc::<Frac<EF>>(num_airs * num_x as usize);

        debug_assert_eq!(
            self.air_offsets.len(),
            num_airs + 1,
            "air_offsets must have num_airs + 1 elements"
        );

        // SAFETY: every pointer in the context tables refers to a device buffer that is still
        // alive while the kernel runs.
        unsafe {
            FK::logup_monomial_batched(
                &mut partials,
                &mut out_buf,
                &self.block_ctxs,
                &self.shared_tbl,
                &self.numer_tbl,
                &self.denom_tbl,
                &self.air_offsets,
                self.num_blocks,
                num_x,
                num_airs as u32,
                THREADS_PER_BLOCK_LOGUP,
            )?;
        }

        // Relabel the output as Frac<FK::ValExt>: both Frac types are a pair of [u32; 4], so
        // the layouts agree.
        Ok(unsafe {
            std::mem::transmute::<
                crate::scratch::Scratch<Frac<EF>>,
                crate::scratch::Scratch<Frac<FK::ValExt>>,
            >(out_buf)
        })
    }
}
