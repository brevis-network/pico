//! Grouped (multi-AIR) MLE evaluation for the zerocheck and logup sumchecks.
//!
//! The builders below pack the evaluation work of many AIRs into one context table so a
//! single kernel launch covers all of them instead of one launch per trace.

use crate::runtime::{
    copy::{MemCopyD2H, MemCopyH2D},
    d_buffer::DeviceBuffer,
    error::MemCopyError,
};
use mle_core::prover::{fractional_sumcheck_gkr::Frac, DeviceMultiStarkProvingKey};

use crate::{
    cuda::{
        field_kernels::FieldKernels,
        logup_zerocheck::{BlockCtx, EvalCoreCtx, LogupCtx, MainMatrixPtrs, ZerocheckCtx},
    },
    error::KernelError,
    gpu_backend::GenericGpuBackend,
    hash_scheme::GpuHashScheme,
    logup_zerocheck::{
        batch_mle_monomial::{LogupCombinations, LogupMonomialBatch},
        mle_round::{evaluate_mle_constraints_gpu, evaluate_mle_interactions_gpu},
    },
    prelude::{EF, F},
};

const MAX_THREADS_PER_BLOCK: u32 = 128;

// ----------------------------------------------------------------------------
// Scratch-size estimates
// ----------------------------------------------------------------------------

/// Bytes of DAG-interpreter scratch the batched zerocheck kernel needs for one trace.
fn zerocheck_batch_mle_intermediates_buffer_bytes<FK: FieldKernels>(
    buffer_size: u32,
    num_x: u32,
    num_y: u32,
) -> usize {
    FK::zerocheck_batch_mle_intermediates_buffer_size(buffer_size, num_x, num_y)
        * std::mem::size_of::<FK::ValExt>()
}

/// Bytes of DAG-interpreter scratch the batched logup kernel needs for one trace.
fn logup_batch_mle_intermediates_buffer_bytes<FK: FieldKernels>(
    buffer_size: u32,
    num_x: u32,
    num_y: u32,
) -> usize {
    FK::logup_batch_mle_intermediates_buffer_size(buffer_size, num_x, num_y)
        * std::mem::size_of::<FK::ValExt>()
}

// ----------------------------------------------------------------------------
// Grouping under a memory cap
// ----------------------------------------------------------------------------

/// Greedily takes a prefix of `items` whose summed cost stays within `cap_bytes`.
/// Yields `(prefix length, summed cost)`; the prefix is never empty, even if item 0 alone is over.
fn find_batch_end<T, M>(items: &[T], cost_of: M, cap_bytes: usize) -> (usize, usize)
where
    M: Fn(&T) -> usize,
{
    let mut n_taken = 0;
    let mut acc_bytes = 0usize;

    while n_taken < items.len() {
        let cost = cost_of(&items[n_taken]);

        if n_taken == 0 {
            // The head item is always taken, over budget or not.
            acc_bytes = cost;
            n_taken = 1;
            if cost > cap_bytes {
                break; // it alone is already over the cap
            }
        } else if acc_bytes + cost <= cap_bytes {
            acc_bytes += cost;
            n_taken += 1;
        } else {
            break; // adding this item would overflow the cap
        }
    }
    (n_taken, acc_bytes)
}

/// Per-trace pointers and metadata consumed by the grouped MLE evaluators.
pub(crate) struct TraceCtx<FK: FieldKernels> {
    pub trace_idx: usize,
    pub air_idx: usize,
    #[allow(dead_code)]
    pub n_lift: usize,
    pub num_y: u32,
    pub has_constraints: bool,
    pub has_interactions: bool,
    pub norm_factor: FK::Val,
    // evaluation inputs shared by the zerocheck and logup paths
    pub eq_xi_ptr: *const FK::ValExt,
    pub sels_ptr: *const FK::ValExt,
    pub prep_ptr: MainMatrixPtrs<FK::ValExt>,
    pub main_ptrs_dev: crate::scratch::Scratch<MainMatrixPtrs<FK::ValExt>>,
    pub public_ptr: *const FK::Val,
    pub eq_3bs_ptr: *const FK::ValExt,
}

// NOTE: zerocheck normally goes through monomial_par_y, so this path is rarely hit; the
// DAG evaluator mostly serves Poseidon2Air. One of the batch / non-batch DAG variants could be
// removed to cut the duplication.
/// Groups traces for one zerocheck DAG-evaluation launch.
///
/// All GPU contexts are assembled at construction time; `evaluate` then issues one kernel.
pub(crate) struct ZerocheckMleBatchBuilder<'a, FK: FieldKernels> {
    trace_list: Vec<&'a TraceCtx<FK>>,
    d_blocks: crate::scratch::Scratch<BlockCtx>,
    d_zc: crate::scratch::Scratch<ZerocheckCtx>,
    offsets: crate::scratch::Scratch<u32>,
    tpb: u32,
    _intermediates_keepalive: Vec<DeviceBuffer<EF>>,
}

impl<'a, FK: FieldKernels> ZerocheckMleBatchBuilder<'a, FK> {
    /// Keeps only the traces that have constraints, picks the block width, fills the per-block
    /// and per-AIR context tables and copies them to the device.
    pub fn new<HS: GpuHashScheme>(
        trace_list: impl Iterator<Item = &'a TraceCtx<FK>>,
        pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
        num_x: u32,
    ) -> Result<Self, MemCopyError> {
        let trace_list: Vec<&TraceCtx<FK>> = trace_list
            .filter(|trace_ctx| trace_ctx.has_constraints)
            .collect();

        if trace_list.is_empty() {
            return Ok(Self {
                trace_list: vec![],
                d_blocks: crate::scratch::Scratch::owned(DeviceBuffer::new()),
                d_zc: crate::scratch::Scratch::owned(DeviceBuffer::new()),
                offsets: crate::scratch::Scratch::owned(DeviceBuffer::new()),
                tpb: 0,
                _intermediates_keepalive: vec![],
            });
        }

        // Block width follows the tallest trace, capped at MAX_THREADS_PER_BLOCK.
        let widest_y = trace_list
            .iter()
            .map(|trace_ctx| trace_ctx.num_y)
            .max()
            .unwrap_or(0);
        let tpb = widest_y.min(MAX_THREADS_PER_BLOCK);

        // Per-AIR block lists; offsets[a]..offsets[a + 1] are the blocks of AIR `a`.
        let mut host_blocks: Vec<BlockCtx> = Vec::new();
        let mut offsets: Vec<u32> = Vec::with_capacity(trace_list.len() + 1);
        offsets.push(0);

        for (slot, trace_ctx) in trace_list.iter().enumerate() {
            let tiles = trace_ctx.num_y.div_ceil(tpb);
            for block_x in 0..tiles {
                host_blocks.push(BlockCtx {
                    local_block_idx_x: block_x,
                    air_idx: slot as u32,
                });
            }
            offsets.push(host_blocks.len() as u32);
        }

        // Per-AIR ZerocheckCtx; scratch buffers are kept alive in `keep`.
        let mut keep: Vec<DeviceBuffer<EF>> = Vec::new();
        let mut host_zc: Vec<ZerocheckCtx> = Vec::with_capacity(trace_list.len());

        for trace_ctx in trace_list.iter() {
            let air_pk = &pk.per_air[trace_ctx.air_idx];
            let buf_sz = air_pk.other_data.zerocheck_mle.inner.buffer_size;

            let d_scratch = if buf_sz > 0 {
                let scratch_len = FK::zerocheck_batch_mle_intermediates_buffer_size(
                    buf_sz,
                    num_x,
                    trace_ctx.num_y,
                );
                let dbuf = DeviceBuffer::<EF>::with_capacity(scratch_len);
                let raw = dbuf.as_mut_ptr();
                keep.push(dbuf);
                raw
            } else {
                std::ptr::null_mut()
            };

            // The FFI structs are declared over the prelude EF / F, so the FK::ValExt / FK::Val
            // pointers are cast to those. Each field type is a #[repr(transparent)] u32 and the
            // degree-4 extension is a plain [u32; 4], so this only relabels memory.
            let ectx = EvalCoreCtx {
                d_selectors: trace_ctx.sels_ptr as *const EF,
                d_preprocessed: MainMatrixPtrs {
                    data: trace_ctx.prep_ptr.data as *const EF,
                    air_width: trace_ctx.prep_ptr.air_width,
                },
                d_main: trace_ctx.main_ptrs_dev.as_ptr() as *const MainMatrixPtrs<EF>,
                d_public: trace_ctx.public_ptr as *const F,
            };

            host_zc.push(ZerocheckCtx {
                eval_ctx: ectx,
                d_intermediates: d_scratch,
                num_y: trace_ctx.num_y,
                d_eq_xi: trace_ctx.eq_xi_ptr as *const EF,
                d_rules: air_pk.other_data.zerocheck_mle.inner.d_rules.as_raw_ptr(),
                rules_len: air_pk.other_data.zerocheck_mle.inner.d_rules.len(),
                d_used_nodes: air_pk.other_data.zerocheck_mle.inner.d_used_nodes.as_ptr(),
                used_nodes_len: air_pk.other_data.zerocheck_mle.inner.d_used_nodes.len(),
                buffer_size: buf_sz,
            });
        }

        // Copy the host-side tables to the GPU.
        let d_blocks = crate::scratch::upload(&host_blocks)?;
        let d_zc = crate::scratch::upload(&host_zc)?;
        let offsets = crate::scratch::upload(&offsets)?;

        Ok(Self {
            trace_list,
            d_blocks,
            d_zc,
            offsets,
            tpb,
            _intermediates_keepalive: keep,
        })
    }

    /// `trace_idx` of every trace in the group, in group order.
    pub fn trace_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.trace_list.iter().map(|tc| tc.trace_idx)
    }

    /// Runs the kernel and returns the device buffer it filled.
    ///
    /// It holds `num_airs * num_x` values, AIR-major: all x for AIR 0, then all x for AIR 1, ...
    pub fn evaluate(
        &self,
        lambda_pows: &DeviceBuffer<FK::ValExt>,
        num_x: u32,
    ) -> Result<DeviceBuffer<FK::ValExt>, KernelError> {
        if self.trace_list.is_empty() {
            return Ok(DeviceBuffer::new());
        }

        // The batch FFI takes the prelude EF; FK::ValExt has the same [u32; 4] layout, so view
        // the buffer through that type.
        let lam_ef = unsafe {
            &*(lambda_pows as *const DeviceBuffer<FK::ValExt> as *const DeviceBuffer<EF>)
        };

        let raw_out = evaluate_mle_constraints_gpu_batch::<FK>(
            &self.d_blocks,
            &self.d_zc,
            &self.offsets,
            lam_ef,
            lambda_pows.len(),
            num_x,
            self.tpb,
        )?;

        // Same layout argument in the other direction for the result.
        Ok(unsafe { std::mem::transmute::<DeviceBuffer<EF>, DeviceBuffer<FK::ValExt>>(raw_out) })
    }
}

/// Groups traces for one logup DAG-evaluation launch.
///
/// All GPU contexts are assembled at construction time; `evaluate` then issues one kernel.
pub(crate) struct LogupMleBatchBuilder<'a, FK: FieldKernels> {
    trace_list: Vec<&'a TraceCtx<FK>>,
    d_blocks: crate::scratch::Scratch<BlockCtx>,
    d_lg: crate::scratch::Scratch<LogupCtx>,
    offsets: crate::scratch::Scratch<u32>,
    tpb: u32,
    _intermediates_keepalive: Vec<DeviceBuffer<EF>>,
}

impl<'a, FK: FieldKernels> LogupMleBatchBuilder<'a, FK> {
    /// Keeps only the traces that have interactions, picks the block width, fills the per-block
    /// and per-AIR context tables and copies them to the device.
    pub fn new<HS: GpuHashScheme>(
        trace_list: impl Iterator<Item = &'a TraceCtx<FK>>,
        pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
        d_challenges_ptr: *const FK::ValExt,
        num_x: u32,
    ) -> Result<Self, MemCopyError> {
        let trace_list: Vec<&TraceCtx<FK>> = trace_list
            .filter(|trace_ctx| trace_ctx.has_interactions)
            .collect();

        if trace_list.is_empty() {
            return Ok(Self {
                trace_list: vec![],
                d_blocks: crate::scratch::Scratch::owned(DeviceBuffer::new()),
                d_lg: crate::scratch::Scratch::owned(DeviceBuffer::new()),
                offsets: crate::scratch::Scratch::owned(DeviceBuffer::new()),
                tpb: 0,
                _intermediates_keepalive: vec![],
            });
        }

        // Block width follows the tallest trace, capped at MAX_THREADS_PER_BLOCK.
        let widest_y = trace_list
            .iter()
            .map(|trace_ctx| trace_ctx.num_y)
            .max()
            .unwrap_or(0);
        let tpb = widest_y.min(MAX_THREADS_PER_BLOCK);

        // Per-AIR block lists; offsets[a]..offsets[a + 1] are the blocks of AIR `a`.
        let mut host_blocks: Vec<BlockCtx> = Vec::new();
        let mut offsets: Vec<u32> = Vec::with_capacity(trace_list.len() + 1);
        offsets.push(0);

        for (slot, trace_ctx) in trace_list.iter().enumerate() {
            let tiles = trace_ctx.num_y.div_ceil(tpb);
            for block_x in 0..tiles {
                host_blocks.push(BlockCtx {
                    local_block_idx_x: block_x,
                    air_idx: slot as u32,
                });
            }
            offsets.push(host_blocks.len() as u32);
        }

        // Per-AIR LogupCtx; scratch buffers are kept alive in `keep`.
        let mut keep: Vec<DeviceBuffer<EF>> = Vec::new();
        let mut host_lg: Vec<LogupCtx> = Vec::with_capacity(trace_list.len());

        for trace_ctx in trace_list.iter() {
            let air_pk = &pk.per_air[trace_ctx.air_idx];
            let buf_sz = air_pk.other_data.interaction_rules.inner.buffer_size;

            let d_scratch = if buf_sz > 0 {
                let scratch_len =
                    FK::logup_batch_mle_intermediates_buffer_size(buf_sz, num_x, trace_ctx.num_y);
                let dbuf = DeviceBuffer::<EF>::with_capacity(scratch_len);
                let raw = dbuf.as_mut_ptr();
                keep.push(dbuf);
                raw
            } else {
                std::ptr::null_mut()
            };

            // The FFI structs are declared over the prelude EF / F, so the FK::ValExt / FK::Val
            // pointers are cast to those. Each field type is a #[repr(transparent)] u32 and the
            // degree-4 extension is a plain [u32; 4], so this only relabels memory.
            let ectx = EvalCoreCtx {
                d_selectors: trace_ctx.sels_ptr as *const EF,
                d_preprocessed: MainMatrixPtrs {
                    data: trace_ctx.prep_ptr.data as *const EF,
                    air_width: trace_ctx.prep_ptr.air_width,
                },
                d_main: trace_ctx.main_ptrs_dev.as_ptr() as *const MainMatrixPtrs<EF>,
                d_public: trace_ctx.public_ptr as *const F,
            };

            let air_rules = &air_pk.other_data.interaction_rules;
            host_lg.push(LogupCtx {
                eval_ctx: ectx,
                d_intermediates: d_scratch,
                num_y: trace_ctx.num_y,
                d_eq_xi: trace_ctx.eq_xi_ptr as *const EF,
                d_challenges: d_challenges_ptr as *const EF,
                d_eq_3bs: trace_ctx.eq_3bs_ptr as *const EF,
                d_rules: air_rules.inner.d_rules.as_raw_ptr(),
                rules_len: air_rules.inner.d_rules.len(),
                d_used_nodes: air_rules.inner.d_used_nodes.as_ptr(),
                d_pair_idxs: air_rules.d_pair_idxs.as_ptr(),
                used_nodes_len: air_rules.inner.d_used_nodes.len(),
                buffer_size: buf_sz,
            });
        }

        // Copy the host-side tables to the GPU.
        let d_blocks = crate::scratch::upload(&host_blocks)?;
        let d_lg = crate::scratch::upload(&host_lg)?;
        let offsets = crate::scratch::upload(&offsets)?;

        Ok(Self {
            trace_list,
            d_blocks,
            d_lg,
            offsets,
            tpb,
            _intermediates_keepalive: keep,
        })
    }

    /// `(trace_idx, norm_factor)` of every trace in the group, in group order.
    pub fn trace_info(&self) -> impl Iterator<Item = (usize, FK::Val)> + '_ {
        self.trace_list
            .iter()
            .map(|tc| (tc.trace_idx, tc.norm_factor))
    }

    /// Runs the kernel and returns the device buffer it filled.
    ///
    /// It holds `num_airs * num_x` fractions, AIR-major: all x for AIR 0, then AIR 1, ...
    pub fn evaluate(&self, num_x: u32) -> Result<DeviceBuffer<Frac<FK::ValExt>>, KernelError> {
        if self.trace_list.is_empty() {
            return Ok(DeviceBuffer::new());
        }

        let raw_out = evaluate_mle_interactions_gpu_batch::<FK>(
            &self.d_blocks,
            &self.d_lg,
            &self.offsets,
            num_x,
            self.tpb,
        )?;

        // Relabel as Frac<FK::ValExt>: both Frac types are a pair of [u32; 4] values.
        Ok(unsafe {
            std::mem::transmute::<DeviceBuffer<Frac<EF>>, DeviceBuffer<Frac<FK::ValExt>>>(raw_out)
        })
    }
}

// ----------------------------------------------------------------------------
// Entry points that split the work into memory-bounded groups
// ----------------------------------------------------------------------------

pub(crate) fn evaluate_zerocheck_batched<'a, FK: FieldKernels, HS: GpuHashScheme>(
    trace_iter: impl IntoIterator<Item = &'a TraceCtx<FK>>,
    pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
    lambda_pows: &DeviceBuffer<FK::ValExt>,
    num_x: u32,
    zc_out: &mut [Vec<FK::ValExt>],
    memory_limit_bytes: usize,
) -> Result<(), KernelError> {
    // Traces that have constraints, paired with their scratch requirement.
    let mut zc_sized: Vec<(&TraceCtx<FK>, usize)> = trace_iter
        .into_iter()
        .filter(|trace_ctx| trace_ctx.has_constraints)
        .map(|trace_ctx| {
            let buf_sz = pk.per_air[trace_ctx.air_idx]
                .other_data
                .zerocheck_mle
                .inner
                .buffer_size;
            let need = zerocheck_batch_mle_intermediates_buffer_bytes::<FK>(
                buf_sz,
                num_x,
                trace_ctx.num_y,
            );
            (trace_ctx, need)
        })
        .collect();
    if zc_sized.is_empty() {
        return Ok(());
    }

    // Largest first, so the greedy grouping packs better (first-fit decreasing).
    zc_sized.sort_by(|lhs, rhs| rhs.1.cmp(&lhs.1));

    let x_len = num_x as usize;
    let mut cursor = 0;

    while cursor < zc_sized.len() {
        let (taken, batch_memory) =
            find_batch_end(&zc_sized[cursor..], |(_, need)| *need, memory_limit_bytes);
        let group: Vec<&TraceCtx<FK>> = zc_sized[cursor..cursor + taken]
            .iter()
            .map(|(trace_ctx, _)| *trace_ctx)
            .collect();

        if group.len() == 1 {
            // A lone trace runs through the per-trace kernel (FK-generic in mle_round).
            let trace_ctx = group[0];
            if batch_memory > memory_limit_bytes {
                tracing::warn!(
                    air_idx = trace_ctx.air_idx,
                    air = %pk.per_air[trace_ctx.air_idx].air_name,
                    intermediate_buffer_bytes = batch_memory,
                    memory_limit_bytes,
                    "zerocheck: trace exceeds memory limit, using non-batch kernel"
                );
            }
            let zc_rules = &pk.per_air[trace_ctx.air_idx].other_data.zerocheck_mle;
            let dev_out = evaluate_mle_constraints_gpu::<FK>(
                trace_ctx.eq_xi_ptr,
                trace_ctx.sels_ptr,
                trace_ctx.prep_ptr,
                &trace_ctx.main_ptrs_dev,
                trace_ctx.public_ptr,
                lambda_pows,
                zc_rules,
                trace_ctx.num_y,
                num_x,
            )?;
            let host_vals = dev_out.to_host()?;
            zc_out[trace_ctx.trace_idx].copy_from_slice(&host_vals);
        } else {
            // Several traces fit: one grouped launch.
            tracing::debug!(
                batch_size = group.len(),
                batch_memory,
                memory_limit_bytes,
                "zerocheck: batching traces"
            );
            let batch_builder = ZerocheckMleBatchBuilder::new(group.iter().copied(), pk, num_x)?;
            let dev_out = batch_builder.evaluate(lambda_pows, num_x)?;
            let evals_host = dev_out.to_host()?;

            for (k, tidx) in batch_builder.trace_indices().enumerate() {
                let row = &evals_host[(k * x_len)..((k + 1) * x_len)];
                zc_out[tidx].copy_from_slice(row);
            }
        }
        cursor += taken;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_logup_batched<FK: FieldKernels, HS: GpuHashScheme>(
    all_traces: &[TraceCtx<FK>],
    pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
    d_challenges_ptr: *const FK::ValExt,
    num_x: u32,
    monomial_num_y_threshold: u32,
    logup_combinations: &[Option<LogupCombinations<FK>>],
    logup_out: &mut [[Vec<FK::ValExt>; 2]],
    logup_tilde_evals: &mut [[FK::ValExt; 2]],
    memory_limit_bytes: usize,
) -> Result<(), KernelError> {
    let (small_y, large_y): (Vec<&TraceCtx<FK>>, Vec<&TraceCtx<FK>>) = all_traces
        .iter()
        .filter(|trace_ctx| trace_ctx.has_interactions)
        .partition(|trace_ctx| trace_ctx.num_y <= monomial_num_y_threshold);

    if !small_y.is_empty() {
        let combs: Vec<_> = small_y
            .iter()
            .map(|trace_ctx| logup_combinations[trace_ctx.trace_idx].as_ref().unwrap())
            .collect();
        let group = LogupMonomialBatch::new(small_y.iter().copied(), pk, &combs)?;
        let dev_out = group.evaluate(num_x)?;
        let evals_host = dev_out.to_host()?;
        let x_len = num_x as usize;
        for (k, tidx) in group.trace_indices().enumerate() {
            let row = &evals_host[(k * x_len)..((k + 1) * x_len)];
            let norm = small_y[k].norm_factor;
            if num_x == 1 {
                logup_tilde_evals[tidx][0] = row[0].p * norm;
                logup_tilde_evals[tidx][1] = row[0].q;
            } else {
                for (col, frac) in row.iter().enumerate() {
                    logup_out[tidx][0][col] = frac.p * norm;
                    logup_out[tidx][1][col] = frac.q;
                }
            }
        }
    }

    if large_y.is_empty() {
        return Ok(());
    }

    // Large-num_y traces, paired with their scratch requirement.
    let mut lg_sized: Vec<(&TraceCtx<FK>, usize)> = large_y
        .iter()
        .copied()
        .map(|trace_ctx| {
            let buf_sz = pk.per_air[trace_ctx.air_idx]
                .other_data
                .interaction_rules
                .inner
                .buffer_size;
            let need =
                logup_batch_mle_intermediates_buffer_bytes::<FK>(buf_sz, num_x, trace_ctx.num_y);
            (trace_ctx, need)
        })
        .collect();

    // Largest first, so the greedy grouping packs better (first-fit decreasing).
    lg_sized.sort_by(|lhs, rhs| rhs.1.cmp(&lhs.1));

    let x_len = num_x as usize;
    let mut cursor = 0;

    while cursor < lg_sized.len() {
        let (taken, batch_memory) =
            find_batch_end(&lg_sized[cursor..], |(_, need)| *need, memory_limit_bytes);
        let group: Vec<&TraceCtx<FK>> = lg_sized[cursor..cursor + taken]
            .iter()
            .map(|(trace_ctx, _)| *trace_ctx)
            .collect();

        if group.len() == 1 && batch_memory > memory_limit_bytes {
            // Too big to group: fall back to the per-trace kernel.
            let trace_ctx = group[0];
            tracing::warn!(
                air_idx = trace_ctx.air_idx,
                air = %pk.per_air[trace_ctx.air_idx].air_name,
                intermediate_buffer_bytes = batch_memory,
                memory_limit_bytes,
                "logup: trace exceeds memory limit, using non-batch kernel"
            );
            evaluate_single_logup::<FK, HS>(
                trace_ctx,
                pk,
                d_challenges_ptr,
                num_x,
                &mut logup_out[trace_ctx.trace_idx],
                &mut logup_tilde_evals[trace_ctx.trace_idx],
            )?;
        } else {
            // One grouped launch for the whole group.
            tracing::debug!(
                batch_size = group.len(),
                batch_memory,
                memory_limit_bytes,
                "logup: batching traces"
            );
            let batch_builder =
                LogupMleBatchBuilder::new(group.iter().copied(), pk, d_challenges_ptr, num_x)?;
            let dev_out = batch_builder.evaluate(num_x)?;
            let evals_host = dev_out.to_host()?;

            for (k, (tidx, scale)) in batch_builder.trace_info().enumerate() {
                let row = &evals_host[(k * x_len)..((k + 1) * x_len)];
                if num_x == 1 {
                    logup_tilde_evals[tidx][0] = row[0].p * scale;
                    logup_tilde_evals[tidx][1] = row[0].q;
                } else {
                    let nums: Vec<FK::ValExt> = row.iter().map(|v| v.p * scale).collect();
                    let dens: Vec<FK::ValExt> = row.iter().map(|v| v.q).collect();
                    logup_out[tidx] = [nums, dens];
                }
            }
        }
        cursor += taken;
    }
    Ok(())
}

/// Logup for one trace through the per-trace (non-grouped) kernel.
fn evaluate_single_logup<FK: FieldKernels, HS: GpuHashScheme>(
    trace_ctx: &TraceCtx<FK>,
    pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
    d_challenges_ptr: *const FK::ValExt,
    num_x: u32,
    logup_out: &mut [Vec<FK::ValExt>; 2],
    logup_tilde_eval: &mut [FK::ValExt; 2],
) -> Result<(), KernelError> {
    let air_pk = &pk.per_air[trace_ctx.air_idx];
    let dev_out = evaluate_mle_interactions_gpu::<FK>(
        trace_ctx.eq_xi_ptr,
        trace_ctx.sels_ptr,
        trace_ctx.prep_ptr,
        &trace_ctx.main_ptrs_dev,
        trace_ctx.public_ptr,
        d_challenges_ptr,
        trace_ctx.eq_3bs_ptr,
        &air_pk.other_data.interaction_rules,
        trace_ctx.num_y,
        num_x,
    )?;
    let vals = dev_out.to_host()?;

    if num_x == 1 {
        logup_tilde_eval[0] = vals[0].p * trace_ctx.norm_factor;
        logup_tilde_eval[1] = vals[0].q;
        // logup_out stays untouched here; compute_batch_s reads the tilde evals directly
    } else {
        let nums: Vec<FK::ValExt> = vals.iter().map(|v| v.p * trace_ctx.norm_factor).collect();
        let dens: Vec<FK::ValExt> = vals.iter().map(|v| v.q).collect();
        *logup_out = [nums, dens];
    }
    Ok(())
}

// ============================================================================
// FFI wrappers
// ============================================================================

/// Async-free and peak-memory behaviour: see the [`crate::logup_zerocheck`] docs.
fn evaluate_mle_constraints_gpu_batch<FK: FieldKernels>(
    blocks: &DeviceBuffer<BlockCtx>,
    zc_tbl: &DeviceBuffer<ZerocheckCtx>,
    offsets: &DeviceBuffer<u32>,
    lambda_pows: &DeviceBuffer<EF>,
    lambda_len: usize,
    num_x: u32,
    threads_per_block: u32,
) -> Result<DeviceBuffer<EF>, KernelError> {
    let num_blocks = blocks.len();
    let num_airs = zc_tbl.len();
    tracing::debug!(
        %num_blocks,
        %num_x,
        %threads_per_block,
        %num_airs,
        "zerocheck_batch_eval_mle"
    );
    // one partial-sum slot per (block, x)
    let mut scratch_sums = DeviceBuffer::<EF>::with_capacity(num_blocks * num_x as usize);
    let mut out_sums = DeviceBuffer::<EF>::with_capacity(num_airs * num_x as usize);
    unsafe {
        FK::zerocheck_batch_eval_mle(
            &mut scratch_sums,
            &mut out_sums,
            blocks,
            zc_tbl,
            offsets,
            lambda_pows,
            lambda_len,
            num_blocks as u32,
            num_x,
            num_airs as u32,
            threads_per_block,
        )?;
    }
    Ok(out_sums)
}

/// Async-free and peak-memory behaviour: see the [`crate::logup_zerocheck`] docs.
fn evaluate_mle_interactions_gpu_batch<FK: FieldKernels>(
    blocks: &DeviceBuffer<BlockCtx>,
    lg_tbl: &DeviceBuffer<LogupCtx>,
    offsets: &DeviceBuffer<u32>,
    num_x: u32,
    threads_per_block: u32,
) -> Result<DeviceBuffer<Frac<EF>>, KernelError> {
    let num_blocks = blocks.len();
    let num_airs = lg_tbl.len();
    // one partial-sum slot per (block, x)
    let mut scratch_sums = DeviceBuffer::<Frac<EF>>::with_capacity(num_blocks * num_x as usize);
    let mut out_sums = DeviceBuffer::<Frac<EF>>::with_capacity(num_airs * num_x as usize);
    unsafe {
        FK::logup_batch_eval_mle(
            &mut scratch_sums,
            &mut out_sums,
            blocks,
            lg_tbl,
            offsets,
            num_blocks as u32,
            num_x,
            num_airs as u32,
            threads_per_block,
        )?;
    }
    Ok(out_sums)
}
