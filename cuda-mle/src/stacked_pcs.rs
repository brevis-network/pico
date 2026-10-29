//! GPU stacked polynomial commitment: pack every trace column into one tall
//! column-major matrix, Reed-Solomon-encode each stacked column, and Merkle-commit. The device
//! sibling of [`mle_core::prover::stacked_pcs`] (the col-major reference oracle) — roots and digest
//! layers are computed identically on both sides, so a GPU root is interchangeable with a host one.
//!
//! Code ↔ counterpart:
//! - [`get_stacked_layout`] / [`stack_traces`] — the injection ι and the stacked trace matrix
//!   `Q_T`. Shares the host [`StackedLayout`]; a column shorter than `2^l_skip` is lifted
//!   to a `2^l_skip` slot and written strided. CPU twin: `stacked_matrix`, whose single-call shape
//!   the test-only `stacked_matrix` wrapper below reproduces for the parity tests.
//! - [`rs_code_matrix`] — RS encoding: per column, eval→coeff (per-`2^l_skip`-chunk iNTT
//!   + subset-zeta transform), zero-pad by `2^log_blowup`, forward DFT. CPU twin: `rs_code_matrix`.
//! - [`stacked_commit`] — the matrix commitment `Com_stack,k`. CPU twin: `stacked_commit`.
//!
//! Live vs. unreachable arms (production RISCV config: `l_skip = 4`, `cache_stacked_matrix = false`,
//! `cache_rs_code_matrix = false`):
//! - **Stacking:** [`stack_traces_gathered`] (one-pass gather) is the default; the staged
//!   [`stack_traces_into_expanded`] runs only under `STACK_GATHER_OFF=1` and is the differential
//!   reference the `stack_gather` tests compare against. Two kernels sit behind one entry point —
//!   a 4-wide one and a scalar fallback — selected by [`gather_is_vectorizable`]; both are covered
//!   by differential tests.
//! - **Zeta stages:** [`GpuNttField::batch_intt_zeta_fused`] owns them by default (it sets a local
//!   `zeta_done`), so `Val::mle_interpolate_stages` — the base-field 2-D interpolate family — runs
//!   **only** on the `cache_stacked_matrix` arm, under `C1_FUSED_OFF=1`, or under `C1_VERIFY=1`.
//!   That family is therefore the *bit-exact reference oracle* for the hot fused kernel, not dead
//!   code; `C1_VERIFY` (and the same flag on the RS/NTT fast path) is the switch that exercises it.
//! - **Caching:** [`StackedPcsDataGpu::matrix`] (`Option<PleMatrix>`) is `Some` only when
//!   `cache_stacked_matrix` is set — a wired but off-by-default memory/perf trade-off that lets the
//!   WHIR-open recompute (`whir.rs`, [`rs_code_matrix`]'s `Some` arm) skip re-stacking. Production
//!   leaves it `None` and recomputes from traces.
//!
//! Invariant relied on by [`stack_traces_gathered`]: the descriptor table is **strictly
//! non-overlapping** in `dst_start` (`dst_start[i] + len[i] ≤ dst_start[i+1]`) — the gather kernel
//! binary-searches for the last descriptor at or below each output cell. [`StackedLayout::new`]
//! guarantees it by construction (non-increasing-height packing, contiguous per-column blocks).

use std::{ffi::c_void, sync::Arc};

use crate::runtime::{copy::cuda_memcpy, d_buffer::DeviceBuffer, memory_manager::MemTracker};
use getset::Getters;
use itertools::Itertools;
use mle_core::{
    p3_util::log2_strict_usize, poly::matrix::MatrixDimensions, protocol::stacking::StackedLayout,
};
use tracing::instrument;

use crate::{
    base::{DeviceMatrix, DeviceMatrixView},
    cuda::matrix::{batch_expand_pad_any, batch_expand_pad_wide_any},
    hash_scheme::{GpuMerkleHash, StreamingMerkleHash},
    merkle_tree::{MerkleTreeConstructor, MerkleTreeGpu},
    ntt_field::GpuNttField,
    poly::PleMatrix,
    GpuProverConfig, MerkleTreeError, ProverError, RsCodeMatrixError, StackTracesError,
};

#[derive(Getters)]
pub struct StackedPcsDataGpu<F, Digest> {
    /// Where each original (unstacked) matrix column lives inside the stacked matrix.
    #[getset(get = "pub")]
    pub(crate) layout: StackedLayout,
    /// Stacked matrix of height `2^{l_skip + n_stack}`, kept only if the prover config asks for it.
    /// Keeping it costs peak GPU memory; dropping it means stacked reduction has to rebuild it
    /// from the traces, which is slower but lighter on memory.
    #[getset(get = "pub")]
    pub(crate) matrix: Option<PleMatrix<F>>,
    /// Merkle commitment to the stacked matrix's Reed-Solomon codewords (leaf grouping is set by
    /// `k_whir`).
    #[getset(get = "pub")]
    pub(crate) tree: MerkleTreeGpu<F, Digest>,
}

#[allow(clippy::type_complexity)]
#[instrument(level = "info", skip_all)]
pub fn stacked_commit<
    Val: GpuNttField,
    MH: GpuMerkleHash<BaseField = Val> + MerkleTreeConstructor,
>(
    l_skip: usize,
    n_stack: usize,
    log_blowup: usize,
    k_whir: usize,
    traces: &[&DeviceMatrix<Val>],
    prover_config: GpuProverConfig,
) -> Result<(MH::Digest, StackedPcsDataGpu<Val, MH::Digest>), ProverError> {
    let mut tracker = MemTracker::start("prover.stacked_commit");
    tracker.tracing_info("before stacked_commit");
    tracker.reset_peak();
    let stk_layout = get_stacked_layout(l_skip, n_stack, traces);
    tracing::info!(
        height = stk_layout.height(),
        width = stk_layout.width(),
        "stacked_matrix_dimensions"
    );
    let cached_mat = if prover_config.cache_stacked_matrix {
        Some(stack_traces(&stk_layout, traces)?)
    } else {
        None
    };
    // [rsprof] synced merkle timing, same gate/style as the rs_code sub-step timers.
    let rs_prof = std::env::var("RS_PROF").is_ok();
    // Streaming column-block commit (RS_STREAM_BLOCKS=N): never materializes the full RS codeword
    // matrix. Only supported on the non-cached-stacked-matrix path (the default prove config).
    let sblk = crate::rs_stream::blocks();
    let query_rows = 1 << k_whir;
    // `new_merkle_tree_streamed` returns `None` for a scheme without the streaming kernels, so a
    // non-streaming scheme falls back to the monolithic path instead of failing at run time. The
    // sync + timer bracket the call itself, since the call *is* the commit.
    let streamed = if let (Some(nblk), None) = (sblk, cached_mat.as_ref()) {
        if rs_prof {
            let _ = crate::runtime::stream::current_stream_sync();
        }
        let t_tree = std::time::Instant::now();
        MH::new_merkle_tree_streamed(log_blowup, &stk_layout, traces, query_rows, nblk)
            .map(|built| (built, t_tree))
    } else {
        None
    };
    let mtree = if let Some((built, t_tree)) = streamed {
        let mtree = built?;
        if rs_prof {
            let _ = crate::runtime::stream::current_stream_sync();
            tracing::info!(target: "bench", "[rsprof][{}] stream_commit={}us", crate::prove_phase(), t_tree.elapsed().as_micros());
        }
        // RS_STREAM_VERIFY: rebuild via the monolithic path and assert the roots match bit-exactly.
        if crate::rs_stream::verify() {
            let codeword_mat = rs_code_matrix(log_blowup, &stk_layout, traces, &None)?;
            let mono_tree = MerkleTreeGpu::<Val, MH::Digest>::new_with_hash::<MH>(
                codeword_mat,
                query_rows,
                false,
            )?;
            if mono_tree.root() != mtree.root() {
                return Err(RsCodeMatrixError::StreamRootMismatch.into());
            }
            tracing::info!(target: "bench", "[streamverify] OK: streamed root == monolithic root");
        }
        mtree
    } else {
        let codeword_mat = rs_code_matrix(log_blowup, &stk_layout, traces, &cached_mat)?;
        if rs_prof {
            let _ = crate::runtime::stream::current_stream_sync();
        }
        let t_tree = std::time::Instant::now();
        let mtree = MerkleTreeGpu::<Val, MH::Digest>::new_with_hash::<MH>(
            codeword_mat,
            query_rows,
            prover_config.cache_rs_code_matrix,
        )?;
        if rs_prof {
            let _ = crate::runtime::stream::current_stream_sync();
            tracing::info!(target: "bench", "[rsprof][{}] merkle={}us", crate::prove_phase(), t_tree.elapsed().as_micros());
        }
        mtree
    };
    let commit_root = mtree.root();
    let pcs_data = StackedPcsDataGpu {
        layout: stk_layout,
        matrix: cached_mat,
        tree: mtree,
    };
    tracker.emit_metrics();
    Ok((commit_root, pcs_data))
}

/// Layout + stack in one call, matching the host `mle_core::prover::stacked_pcs::stacked_matrix`
/// signature so the parity tests can compare the two directly.
///
/// Test-only: production splits the two steps, because [`stacked_commit`] needs the layout before
/// it can decide whether to stack at all (`cache_stacked_matrix`).
///
/// Callers must pass `traces` already sorted by height.
///
/// This function is generic over any field `Val` and only relies on CUDA memory operations.
#[cfg(test)]
#[instrument(skip_all)]
pub(crate) fn stacked_matrix<Val: GpuNttField>(
    l_skip: usize,
    n_stack: usize,
    traces: &[&DeviceMatrix<Val>],
) -> Result<(PleMatrix<Val>, StackedLayout), ProverError> {
    let layout = get_stacked_layout(l_skip, n_stack, traces);
    let matrix = stack_traces(&layout, traces)?;
    Ok((matrix, layout))
}

pub(crate) fn get_stacked_layout<Val: Copy>(
    l_skip: usize,
    n_stack: usize,
    mats: &[&DeviceMatrix<Val>],
) -> StackedLayout {
    let dims = mats
        .iter()
        .map(|m| {
            // log2_strict panics on a zero height, which cannot occur here
            let log_h = log2_strict_usize(m.height());
            (m.width(), log_h)
        })
        .collect_vec();
    debug_assert!(dims.is_sorted_by(|x, y| x.1 >= y.1));
    // `StackedLayout::new` only errors on a trace taller than `2^(l_skip + n_stack)` or a packing
    // that does not fill a stacked column exactly — both are keygen-shape invariants the caller has
    // already validated (`GpuDevice::new` bounds `l_skip`, and the trace heights come from the fixed
    // VK layout), so a failure here is a programmer error, not a runtime condition.
    StackedLayout::new(l_skip, l_skip + n_stack, dims)
        .expect("stacked layout: a trace exceeds 2^(l_skip+n_stack) or does not pack exactly")
}

pub(crate) fn stack_traces<Val: GpuNttField>(
    layout: &StackedLayout,
    traces: &[&DeviceMatrix<Val>],
) -> Result<PleMatrix<Val>, StackTracesError> {
    let mem = MemTracker::start("prover.stack_traces");
    let l_skip = layout.l_skip();
    let height = layout.height();
    let width = layout.width();
    let mut q_evals = DeviceBuffer::<Val>::with_capacity(width.checked_mul(height).unwrap());
    stack_traces_into_expanded(layout, traces, &mut q_evals, height)?;
    mem.emit_metrics();
    Ok(PleMatrix::from_evals(l_skip, q_evals, height, width))
}

/// Whether the 4-wide gather kernel's precondition holds: the output is a whole number of 4-cell
/// groups and every slice starts and ends on a 4-cell boundary, so a group never straddles a
/// descriptor and its accesses are 16-byte aligned.
///
/// **Checked, never derived** — `StackedLayout::new` satisfies it at `l_skip >= 2` but
/// `from_raw_parts` need not. A false negative only costs speed; a false positive corrupts silently.
fn gather_is_vectorizable(
    descs: &[crate::cuda::matrix::StackGatherDesc],
    total_cells: usize,
) -> bool {
    total_cells.is_multiple_of(4)
        && descs
            .iter()
            .all(|d| d.dst_start.is_multiple_of(4) && d.len.is_multiple_of(4))
}

/// One-pass gather variant of [`stack_traces_into_expanded`]: builds a descriptor table from the
/// layout and launches a single kernel that writes every output cell (gathered value or inline zero
/// padding), replacing the full-buffer memset + one memcpy/expand-pad launch per unstacked column.
/// Bit-exact with the staged version — the `stack_gather_matches_staged_stack` test compares them.
pub(crate) fn stack_traces_gathered<Val: Copy>(
    layout: &StackedLayout,
    traces: &[&DeviceMatrix<Val>],
    buffer: &mut DeviceBuffer<Val>,
    padded_height: usize,
) -> Result<(), StackTracesError> {
    use crate::cuda::matrix::{stack_gather_any, StackGatherDesc};
    let l_skip = layout.l_skip();
    debug_assert_eq!(padded_height % layout.height(), 0);
    let mut descs: Vec<StackGatherDesc> = Vec::with_capacity(layout.sorted_cols.len());
    for col in &layout.sorted_cols {
        let (mat_idx, j, s) = (&col.mat_idx, &col.src_col_idx, &col.slice);
        let trace = traces[*mat_idx];
        let s_len = s.len(l_skip);
        let dst_start = (s.col_idx * padded_height + s.row_idx) as u64;
        // SAFETY: `col.src_col_idx` (`j`) is `< trace.width()` by construction of the layout, and
        // each source column occupies `trace.height()` contiguous cells in the col-major buffer, so
        // the offset is in bounds. The resulting pointer is only read by the gather kernel.
        let (src, stride) = if s.log_height() >= l_skip {
            debug_assert_eq!(trace.height(), s_len);
            (
                unsafe { trace.buffer().as_ptr().add(*j * s_len) } as u64,
                1u32,
            )
        } else {
            let stride = s.stride(l_skip);
            debug_assert_eq!(stride * trace.height(), s_len);
            (
                unsafe { trace.buffer().as_ptr().add(*j * trace.height()) } as u64,
                stride as u32,
            )
        };
        // The gather kernel binary-searches `descs` for the last descriptor with
        // `dst_start <= idx`, so the table must be strictly **non-overlapping** in `dst_start`
        // (`prev.dst_start + prev.len <= dst_start`). This holds by construction for a layout from
        // `StackedLayout::new` (non-increasing-height packing), but `from_raw_parts` layouts take
        // slice positions as-is — check it rather than trust a release-compiled `debug_assert!`.
        if let Some(prev) = descs.last() {
            let prev_end = prev.dst_start + prev.len as u64;
            if prev_end > dst_start {
                return Err(StackTracesError::GatherDescriptorOverlap {
                    index: descs.len(),
                    prev_end,
                    dst_start,
                });
            }
        }
        descs.push(StackGatherDesc {
            src,
            dst_start,
            len: s_len as u32,
            stride,
        });
    }
    let vectorizable = gather_is_vectorizable(&descs, buffer.len());
    use crate::runtime::copy::MemCopyH2D;
    let d_descs = descs.to_device()?;
    // SAFETY: descriptor pointers reference live trace buffers; `buffer` holds
    // `padded_height * width` cells and the kernel writes each exactly once.
    unsafe {
        stack_gather_any(
            buffer.as_mut_ptr(),
            d_descs.as_ptr() as *const std::ffi::c_void,
            descs.len() as u32,
            buffer.len(),
            vectorizable,
        )
        .map_err(StackTracesError::StackGather)?;
    }
    Ok(())
}

/// Writes the stacked traces into `out`, a column-major `padded_height x width` buffer whose width
/// equals the stacked width; `padded_height` has to be a multiple of the stacked height.
pub(crate) fn stack_traces_into_expanded<Val: Copy>(
    lay: &StackedLayout,
    mats: &[&DeviceMatrix<Val>],
    out: &mut DeviceBuffer<Val>,
    padded_height: usize,
) -> Result<(), StackTracesError> {
    let l_skip = lay.l_skip();
    debug_assert_eq!(padded_height % lay.height(), 0);
    debug_assert_eq!(out.len() % padded_height, 0);
    debug_assert_eq!(out.len() / padded_height, lay.width());
    out.fill_zero().map_err(StackTracesError::FillZero)?;
    let mut pos = 0;
    while pos < lay.sorted_cols.len() {
        let c = &lay.sorted_cols[pos];
        let (src_mat_idx, src_col, col_slice) = (&c.mat_idx, &c.src_col_idx, &c.slice);
        let dst_off = col_slice.col_idx * padded_height + col_slice.row_idx;
        let src_mat = mats[*src_mat_idx];
        let sl_len = col_slice.len(l_skip);
        debug_assert_eq!(src_mat.height(), 1 << col_slice.log_height());
        if col_slice.log_height() >= l_skip {
            debug_assert_eq!(src_mat.height(), sl_len);
            // Run-length-merge the maximal run of following columns that share this column's
            // source matrix and height, are the next source columns in order, and land
            // immediately after this one in the destination: the run is contiguous on both
            // sides, so a single D2D memcpy replaces one launch per column.
            let mut run_len = sl_len;
            let mut run_end = pos + 1;
            while run_end < lay.sorted_cols.len() {
                let next_col = &lay.sorted_cols[run_end];
                let (next_mat_idx, next_src_col, next_slice) =
                    (&next_col.mat_idx, &next_col.src_col_idx, &next_col.slice);
                if *next_mat_idx != *src_mat_idx
                    || next_slice.log_height() != col_slice.log_height()
                {
                    break;
                }
                let expected_src_col = *src_col + (run_end - pos);
                let next_len = next_slice.len(l_skip);
                let next_start = next_slice.col_idx * padded_height + next_slice.row_idx;
                if *next_src_col != expected_src_col
                    || next_len != sl_len
                    || next_start != dst_off + run_len
                {
                    break;
                }
                run_len += next_len;
                run_end += 1;
            }

            // SAFETY: both buffers are sized from the layout:
            // - the slice is not lifted here, so `src_mat.height() == sl_len`
            // - `out` covers every slice position the stacked layout can produce
            // - the merged run is contiguous on both sides, so `run_len` cells from `from` / `to`
            //   stay inside their buffers
            unsafe {
                let from = src_mat.buffer().as_ptr().add(*src_col * sl_len);
                let to = out.as_mut_ptr().add(dst_off);
                // D2D memcpy
                cuda_memcpy::<true, true>(
                    to as *mut c_void,
                    from as *const c_void,
                    run_len * size_of::<Val>(),
                )?;
            }
            pos = run_end;
        } else {
            let pitch = col_slice.stride(l_skip);
            debug_assert_eq!(pitch * src_mat.height(), sl_len);
            // SAFETY: both buffers are sized from the layout:
            // - `out` covers every slice position the stacked layout can produce
            // - `batch_expand_pad` is borrowed with `poly_count = src_mat.height()` to spread the
            //   column out with spacing `pitch`, giving `sl_len = pitch * src_mat.height()` cells
            unsafe {
                let from = src_mat.buffer().as_ptr().add(*src_col * src_mat.height());
                let to = out.as_mut_ptr().add(dst_off);
                batch_expand_pad_wide_any(to, from, src_mat.height() as u32, pitch as u32, 1)
                    .map_err(StackTracesError::BatchExpandPadWide)?;
            }
            pos += 1;
        }
    }
    Ok(())
}

/// Assert that a `batch_intt_zeta_fused` result is bit-exact with the staged
/// `batch_ntt_small(intt)` + `mle_interpolate_stages(coeffs→evals)` pipeline run on the same
/// pre-fused input, panicking on any byte mismatch.
///
/// `fused` is the buffer after `batch_intt_zeta_fused`; `staged_scratch` must be a copy of that
/// buffer as it was *before* the fused call. This runs the staged pipeline on `staged_scratch` in
/// place and compares. Shared by the `C1_VERIFY` runtime switch (a bit-exactness gate; the
/// RS/NTT fast path reads the same env var to step aside for it) and the
/// `fused_intt_zeta_matches_staged_pipeline` test — one definition of "fused == staged".
fn assert_fused_matches_staged<Val: GpuNttField>(
    fused: &DeviceBuffer<Val>,
    staged_scratch: &mut DeviceBuffer<Val>,
    l_skip: usize,
    codeword_height: usize,
    log_blowup: usize,
    width: usize,
) -> Result<(), RsCodeMatrixError> {
    let num_uni_poly = width * (codeword_height >> l_skip);
    Val::batch_ntt_small(staged_scratch, l_skip, num_uni_poly, true)
        .map_err(RsCodeMatrixError::CustomBatchIntt)?;
    // SAFETY: `staged_scratch` holds `codeword_height * width` elements; the stages stay within
    // `2^l_skip` chunk boundaries.
    unsafe {
        Val::mle_interpolate_stages(
            staged_scratch.as_mut_ptr(),
            width,
            codeword_height as u32,
            log_blowup as u32,
            0,
            l_skip as u32 - 1,
            false,
            false,
        )
        .map_err(RsCodeMatrixError::MleInterpolateStages)?;
    }
    use crate::runtime::copy::MemCopyD2H;
    let a = fused.to_host().expect("fused verify d2h");
    let b = staged_scratch.to_host().expect("staged verify d2h");
    // `Val` is an opaque 4-byte field element here (no `PartialEq` bound) — compare the raw bytes,
    // which is exactly the bit-exactness we are asserting.
    // SAFETY: `a`/`b` are live `Vec<Val>`s; reading them as `size_of_val` bytes reinterprets the
    // same allocation and never reads past it (`u8` has weaker alignment than `Val`).
    let ab: &[u8] =
        unsafe { std::slice::from_raw_parts(a.as_ptr() as *const u8, size_of_val(&a[..])) };
    let bb: &[u8] =
        unsafe { std::slice::from_raw_parts(b.as_ptr() as *const u8, size_of_val(&b[..])) };
    let mism = ab.iter().zip(bb.iter()).filter(|(x, y)| x != y).count();
    if mism > 0 {
        let first = ab.iter().zip(bb.iter()).position(|(x, y)| x != y).unwrap();
        panic!(
            "fused intt+zeta mismatches staged pipeline: {mism} of {} bytes differ; \
             first at byte {first}",
            ab.len()
        );
    }
    Ok(())
}

/// Reed-Solomon encodes every column of the stacked matrix at rate `2^{-log_blowup}`, reading each
/// column as the evaluations of a prismalinear polynomial over the hyperprism.
///
/// Starts from the cached `stacked_matrix` when there is one; otherwise `traces` are stacked
/// straight into the codeword buffer.
#[instrument(skip_all)]
pub fn rs_code_matrix<Val: GpuNttField>(
    log_blowup: usize,
    layout: &StackedLayout,
    traces: &[&DeviceMatrix<Val>],
    stacked_matrix: &Option<PleMatrix<Val>>,
) -> Result<DeviceMatrix<Val>, RsCodeMatrixError> {
    let mem = MemTracker::start_and_reset_peak("prover.rs_code_matrix");
    // [rsprof] env-gated sub-step timing of the rs_code pipeline: stack / iNTT / zeta / bitrev / NTT,
    // each synced. RS_PROF is the crate-wide profiling convention (cf. STEP_PROF, WHIR_PROF).
    let rs_prof = std::env::var("RS_PROF").is_ok();
    let l_skip = layout.l_skip();
    let height = layout.height();
    let width = layout.width();
    debug_assert!(height >= (1 << l_skip));
    let codeword_height = height.checked_shl(log_blowup as u32).unwrap();
    // The single biggest allocation of the commit: the whole RS codeword matrix in one buffer.
    // Log the exact request AND the device free bytes *before* allocating, so an OOM here is
    // diagnosable (the MemTracker delta only prints post-alloc and is lost when this panics).
    {
        let want = codeword_height * width * std::mem::size_of::<Val>();
        let (dev_free, dev_total) = crate::runtime::memory_manager::device_mem_info();
        tracing::info!(
            "rs_code_matrix: allocating RS codeword buffer {} ({}x{} x {}B) | dev free={}/{}",
            bytesize::ByteSize::b(want as u64),
            codeword_height,
            width,
            std::mem::size_of::<Val>(),
            bytesize::ByteSize::b(dev_free as u64),
            bytesize::ByteSize::b(dev_total as u64),
        );
    }
    let mut codewords =
        DeviceBuffer::<Val>::with_capacity(codeword_height.checked_mul(width).unwrap());
    // Set when the fused iNTT+zeta kernel already applied the zeta stages, so the staged
    // `mle_interpolate_stages` pass below is skipped (it is then only the differential oracle).
    let mut zeta_done = false;
    // The steps below take each of the `width` stacked columns from its `height`-point domain,
    // interpolate it, and evaluate it on the `codeword_height`-point RS domain.
    if let Some(stacked_matrix) = stacked_matrix.as_ref() {
        // SAFETY: `codewords` has room for `width` columns of `codeword_height` elements, and
        // `stacked_matrix.mixed` supplies `width` columns of `height` elements.
        unsafe {
            batch_expand_pad_any(
                codewords.as_mut_ptr(),
                stacked_matrix.mixed.as_ptr(),
                width as u32,
                codeword_height as u32,
                height as u32,
            )
            .map_err(RsCodeMatrixError::BatchExpandPad)?;
        }
    } else {
        let t = std::time::Instant::now();
        if std::env::var("STACK_GATHER_OFF").is_err() {
            // One-pass gather (binary-searched descriptor table, zeros written inline) replacing
            // the memset + ~per-column memcpy/expand-pad launches. The gather-vs-staged
            // bit-exactness that `STACK_GATHER_VERIFY` used to check at runtime is now the
            // `stack_gather_matches_staged_stack` unit test.
            stack_traces_gathered(layout, traces, &mut codewords, codeword_height)
                .map_err(RsCodeMatrixError::StackTraces)?;
        } else {
            // Documented fallback: the staged stacker is kept both as a kill-switch and as the
            // differential reference the gather test compares against.
            stack_traces_into_expanded(layout, traces, &mut codewords, codeword_height)
                .map_err(RsCodeMatrixError::StackTraces)?;
        }
        if rs_prof {
            let _ = crate::runtime::stream::current_stream_sync();
            tracing::info!(target: "bench", "[rsprof][{}] stack+pad={}us", crate::prove_phase(), t.elapsed().as_micros());
        }
        // `codewords` now holds the stacked, zero-padded columns as evaluations over the
        // hyperprism. Bringing them into mixed form here does the job of `PleMatrix::from_evals`
        // in place.
        if l_skip > 0 {
            let t = std::time::Instant::now();
            if std::env::var("C1_FUSED_OFF").is_err() {
                // Fused per-chunk iNTT + zeta stages with RS pad-skip — one pass replacing the
                // staged `batch_ntt_small` + `mle_interpolate_stages` below.
                let chunks_per_col = codeword_height >> l_skip;
                let real_chunks_per_col = height >> l_skip;
                // C1_VERIFY=1: keep a pre-fused copy so we can assert the fused kernel is bit-exact
                // with the staged pipeline below. The RS/NTT fast path reads the same env var
                // to step aside for this check; keep the switch even though `zeta_done` makes the
                // staged path production-dead. The equivalent CI check is
                // `fused_intt_zeta_matches_staged_pipeline`.
                let verify_scratch = if crate::cuda::jit::env_flag("C1_VERIFY", false) {
                    let scratch = DeviceBuffer::<Val>::with_capacity(codewords.len());
                    // SAFETY: `scratch` and `codewords` are both `codewords.len()` elements on
                    // device; this D2D copy stays within both.
                    unsafe {
                        cuda_memcpy::<true, true>(
                            scratch.as_mut_raw_ptr(),
                            codewords.as_ptr() as *const c_void,
                            codewords.len() * size_of::<Val>(),
                        )
                        .expect("C1_VERIFY: d2d scratch copy");
                    }
                    Some(scratch)
                } else {
                    None
                };
                Val::batch_intt_zeta_fused(
                    &mut codewords,
                    l_skip,
                    chunks_per_col,
                    real_chunks_per_col,
                    width,
                )
                .map_err(RsCodeMatrixError::CustomBatchIntt)?;
                if let Some(mut scratch) = verify_scratch {
                    assert_fused_matches_staged(
                        &codewords,
                        &mut scratch,
                        l_skip,
                        codeword_height,
                        log_blowup,
                        width,
                    )?;
                    tracing::info!(target: "bench", "[c1verify] OK ({} cells bit-exact)", codewords.len());
                }
                zeta_done = true;
            } else {
                // Staged pipeline (fallback): per-chunk iNTT here; zeta stages below.
                // PERF: does wasted work on the padded zero part.
                let num_uni_poly = width * (codeword_height >> l_skip);
                Val::batch_ntt_small(&mut codewords, l_skip, num_uni_poly, true)
                    .map_err(RsCodeMatrixError::CustomBatchIntt)?;
            }
            if rs_prof {
                let _ = crate::runtime::stream::current_stream_sync();
                tracing::info!(target: "bench", "[rsprof][{}] intt_small={}us", crate::prove_phase(), t.elapsed().as_micros());
            }
        }
    }
    // Eval-to-coeff RS encoding skips the full (log_height - l_skip)-stage evals→coeffs MLE
    // interpolation: only the l_skip coeffs→evals (subset-zeta) stages inside each 2^l_skip chunk
    // are needed, e.g. 2 stages instead of 15 when log_height = 17 and l_skip = 2.
    let log_codeword_height = log2_strict_usize(codeword_height);

    // The iNTT left Z-monomial coefficients in every 2^l_skip chunk; the l_skip subset-zeta
    // stages turn them into evaluations over the Z-bit hypercube.
    let t = std::time::Instant::now();
    if l_skip > 0 && !zeta_done {
        // SAFETY: the stacking step above wrote every element of `codewords`, whose shape is
        // `width` columns of `codeword_height`.
        // Steps 2^0, 2^1, ..., 2^(l_skip-1) stay within chunk boundaries. Routes per-field to the
        // correct GPU base-field kernels (KoalaBear → `_kb_` launchers).
        unsafe {
            Val::mle_interpolate_stages(
                codewords.as_mut_ptr(),
                width,
                codeword_height as u32,
                log_blowup as u32,
                0,                 // start_log_step
                l_skip as u32 - 1, // end_log_step (inclusive)
                false,             // coeffs to evals (NOT eval to coeff)
                false,             // right_pad
            )
            .map_err(RsCodeMatrixError::MleInterpolateStages)?;
        }
    }
    if rs_prof {
        let _ = crate::runtime::stream::current_stream_sync();
        tracing::info!(target: "bench", "[rsprof][{}] zeta_stages={}us", crate::prove_phase(), t.elapsed().as_micros());
    }

    // The NTT below takes bit-reversed input, so permute every column in place first.
    let t = std::time::Instant::now();
    Val::bit_rev(
        &codewords,
        &codewords,
        log_codeword_height as u32,
        codeword_height as u32,
        width as u32,
    )
    .map_err(RsCodeMatrixError::BitRev)?;
    if rs_prof {
        let _ = crate::runtime::stream::current_stream_sync();
        tracing::info!(target: "bench", "[rsprof][{}] bit_rev={}us", crate::prove_phase(), t.elapsed().as_micros());
    }

    // A forward NTT of each column over the whole codeword domain gives its RS codeword.
    let t = std::time::Instant::now();
    Val::batch_ntt(
        &codewords,
        log_codeword_height as u32,
        0u32,
        width as u32,
        false, // bit-reversal already done
        false,
    );
    if rs_prof {
        let _ = crate::runtime::stream::current_stream_sync();
        tracing::info!(target: "bench", "[rsprof][{}] big_ntt={}us", crate::prove_phase(), t.elapsed().as_micros());
    }
    let code_matrix = DeviceMatrix::new(Arc::new(codewords), codeword_height, width);
    mem.emit_metrics();

    Ok(code_matrix)
}

/// KoalaBear Poseidon2 sponge state width (CELLS in the CUDA kernels). The streaming per-row
/// sponge state buffer holds this many base-field elements per codeword row.
const STREAM_SPONGE_CELLS: usize = 16;
/// Poseidon2 sponge rate — block widths (except the last) must be a multiple of this so the
/// streamed absorb resumes exactly on a permute boundary and stays bit-identical to the fused
/// leaf hash.
const STREAM_SPONGE_RATE: usize = 8;

/// Column-subrange variant of [`stack_traces_gathered`]: stacks only destination columns in
/// `[col_start, col_start + width_block)` into a `padded_height x width_block` buffer (columns
/// rebased so the block starts at column 0). Padding cells are zero-filled by the gather kernel,
/// same as the full-width path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn stack_traces_gathered_cols<Val: Copy>(
    layout: &StackedLayout,
    traces: &[&DeviceMatrix<Val>],
    buffer: &mut DeviceBuffer<Val>,
    padded_height: usize,
    col_start: usize,
    width_block: usize,
) -> Result<(), StackTracesError> {
    use crate::cuda::matrix::{stack_gather_any, StackGatherDesc};
    let l_skip = layout.l_skip();
    debug_assert_eq!(padded_height % layout.height(), 0);
    let mut descs = Vec::new();
    for col in &layout.sorted_cols {
        let (mat_idx, j, s) = (&col.mat_idx, &col.src_col_idx, &col.slice);
        if s.col_idx < col_start || s.col_idx >= col_start + width_block {
            continue;
        }
        let trace = traces[*mat_idx];
        let s_len = s.len(l_skip);
        let dst_start = ((s.col_idx - col_start) * padded_height + s.row_idx) as u64;
        let (src, stride) = if s.log_height() >= l_skip {
            debug_assert_eq!(trace.height(), s_len);
            (
                unsafe { trace.buffer().as_ptr().add(*j * s_len) } as u64,
                1u32,
            )
        } else {
            let stride = s.stride(l_skip);
            debug_assert_eq!(stride * trace.height(), s_len);
            (
                unsafe { trace.buffer().as_ptr().add(*j * trace.height()) } as u64,
                stride as u32,
            )
        };
        descs.push(StackGatherDesc {
            src,
            dst_start,
            len: s_len as u32,
            stride,
        });
    }
    let vectorizable = gather_is_vectorizable(&descs, buffer.len());
    use crate::runtime::copy::MemCopyH2D;
    let d_descs = descs.to_device()?;
    // SAFETY: descriptor pointers reference live trace buffers; `buffer` holds
    // `padded_height * width_block` cells and the kernel writes each exactly once.
    unsafe {
        stack_gather_any(
            buffer.as_mut_ptr(),
            d_descs.as_ptr() as *const std::ffi::c_void,
            descs.len() as u32,
            buffer.len(),
            vectorizable,
        )
        .map_err(StackTracesError::StackGather)?;
    }
    Ok(())
}

/// In-place RS encode of one column-block (`width_block` columns of `codeword_height` each) that
/// was already stacked+padded into `block`. Mirrors the encode stages of [`rs_code_matrix`]
/// (fused iNTT+zeta → bit-reverse → coset NTT), just scoped to a column subrange — each column is
/// independent, so this is bit-identical to encoding the full matrix.
fn rs_encode_block_in_place<Val: GpuNttField>(
    block: &mut DeviceBuffer<Val>,
    l_skip: usize,
    height: usize,
    codeword_height: usize,
    log_blowup: usize,
    width_block: usize,
) -> Result<(), RsCodeMatrixError> {
    let log_codeword_height = log2_strict_usize(codeword_height);
    if l_skip > 0 {
        let chunks_per_col = codeword_height >> l_skip;
        let real_chunks_per_col = height >> l_skip;
        Val::batch_intt_zeta_fused(
            block,
            l_skip,
            chunks_per_col,
            real_chunks_per_col,
            width_block,
        )
        .map_err(RsCodeMatrixError::CustomBatchIntt)?;
    }
    Val::bit_rev(
        block,
        block,
        log_codeword_height as u32,
        codeword_height as u32,
        width_block as u32,
    )
    .map_err(RsCodeMatrixError::BitRev)?;
    Val::batch_ntt(
        block,
        log_codeword_height as u32,
        0u32,
        width_block as u32,
        false,
        false,
    );
    Ok(())
}

/// Streaming (column-block) fused RS-encode + Merkle commit. Instead of materializing the whole
/// `codeword_height x width` RS codeword matrix (the commit's single biggest buffer), it encodes
/// one rate-aligned column-block at a time, folds it into a per-row Poseidon2 sponge, frees the
/// block, then tree-reduces the finished per-row digests. Peak GPU memory drops from the full
/// matrix to `one block + state` (state = `codeword_height * 16` base elems).
///
/// Selected by `RS_STREAM_BLOCKS`; bit-identical to the monolithic path (cross-check with
/// `RS_STREAM_VERIFY`). The [`StreamingMerkleHash`] bound is what restricts this to a scheme that
/// actually has the streaming kernels — today only the base-field KoalaBear hash.
pub fn rs_code_streamed_commit<Val, MH>(
    log_blowup: usize,
    layout: &StackedLayout,
    traces: &[&DeviceMatrix<Val>],
    rows_per_query: usize,
    n_blocks: usize,
) -> Result<MerkleTreeGpu<Val, MH::Digest>, RsCodeMatrixError>
where
    Val: GpuNttField,
    MH: StreamingMerkleHash<BaseField = Val>,
{
    use crate::runtime::copy::MemCopyD2H;
    let mem = MemTracker::start_and_reset_peak("prover.rs_code_streamed_commit");
    let l_skip = layout.l_skip();
    let height = layout.height();
    let width = layout.width();
    let codeword_height = height.checked_shl(log_blowup as u32).unwrap();

    // Rate-aligned block widths: round the per-block column count up to a multiple of the sponge
    // rate. Only the last block may be a non-multiple (it gets the trailing partial permute).
    let raw = width.div_ceil(n_blocks).max(1);
    let bw = raw.div_ceil(STREAM_SPONGE_RATE) * STREAM_SPONGE_RATE;
    let mut col_starts = Vec::new();
    let mut c = 0usize;
    while c < width {
        col_starts.push(c);
        c += bw;
    }
    let n = col_starts.len();

    {
        let block_bytes = codeword_height * bw * std::mem::size_of::<Val>();
        let state_bytes = codeword_height * STREAM_SPONGE_CELLS * std::mem::size_of::<Val>();
        let (dev_free, dev_total) = crate::runtime::memory_manager::device_mem_info();
        tracing::info!(
            "rs_code_streamed_commit: {} block(s) x <= {} cols; block buf <= {}, state {} | dev free={}/{}",
            n,
            bw,
            bytesize::ByteSize::b(block_bytes as u64),
            bytesize::ByteSize::b(state_bytes as u64),
            bytesize::ByteSize::b(dev_free as u64),
            bytesize::ByteSize::b(dev_total as u64),
        );
    }

    // Per-row sponge state (`codeword_height * 16`). Lives for the whole absorb loop.
    let mut state = DeviceBuffer::<Val>::with_capacity(codeword_height * STREAM_SPONGE_CELLS);

    for (bi, &c0) in col_starts.iter().enumerate() {
        let wb = (width - c0).min(bw);
        let is_first = bi == 0;
        let is_last = bi == n - 1;
        let mut block = DeviceBuffer::<Val>::with_capacity(codeword_height * wb);
        stack_traces_gathered_cols(layout, traces, &mut block, codeword_height, c0, wb)
            .map_err(RsCodeMatrixError::StackTraces)?;
        rs_encode_block_in_place::<Val>(
            &mut block,
            l_skip,
            height,
            codeword_height,
            log_blowup,
            wb,
        )?;
        // SAFETY: `state` holds codeword_height*16 elems; `block` holds wb*codeword_height elems.
        unsafe {
            MH::absorb_columns(&mut state, &block, wb, codeword_height, is_first, is_last)
                .map_err(RsCodeMatrixError::AbsorbColumns)?;
        }
        // `block` freed here → peak stays at one block + state.
    }

    // Finalize: tree-reduce per-row digests into `query_stride` leaves.
    let query_stride = codeword_height / rows_per_query;
    let log_rows_per_query = log2_strict_usize(rows_per_query);
    let mut query_layer = DeviceBuffer::<MH::Digest>::with_capacity(query_stride);
    // SAFETY: `query_layer` holds query_stride digests; `state` is the finished sponge buffer.
    unsafe {
        MH::finalize_leaf_digests(&mut query_layer, &state, query_stride, log_rows_per_query)
            .map_err(RsCodeMatrixError::FinalizeLeaf)?;
    }
    drop(state);

    // Build inner Merkle layers (same loop as `MerkleTreeGpu::new_generic_with_hash`).
    let mut digest_layers = vec![query_layer];
    while digest_layers.last().unwrap().len() > 1 {
        let prev_layer = digest_layers.last().unwrap();
        let mut layer = DeviceBuffer::<MH::Digest>::with_capacity(prev_layer.len() / 2);
        let layer_len = layer.len();
        let layer_idx = digest_layers.len();
        // SAFETY: `layer` is half of `prev_layer` and does not overlap it.
        unsafe {
            MH::compress_layer(&mut layer, prev_layer, layer_len).map_err(|error| {
                MerkleTreeError::AdjacentCompressLayer {
                    error,
                    layer: layer_idx,
                }
            })?;
        }
        digest_layers.push(layer);
    }
    let root = digest_layers.last().unwrap().to_host()?.pop().unwrap();
    mem.emit_metrics();
    Ok(MerkleTreeGpu::from_digest_layers(
        digest_layers,
        rows_per_query,
        root,
    ))
}

/// Streaming (column-block) equivalent of `rs_code_matrix` + `batch_open_rows`: opens the queried
/// rows of the RS codeword WITHOUT materializing the full codeword matrix. WHIR round 0 only needs
/// the codeword values at `query_indices` (and their `rows_per_query` strided siblings), so this
/// encodes one column-block at a time, extracts just those rows for the block's columns, frees the
/// block, and reassembles the per-query rows on the host.
///
/// Returns one entry per query index, each the `rows_per_query * width` opened values concatenated
/// row-major — byte-for-byte the same layout `MerkleTreeGpu::batch_open_rows` produces for one
/// commit. Peak GPU memory is one block instead of the whole matrix.
/// The distinct `q mod 2^14` fiber residues in first-seen order, plus the slot each query reads.
///
/// The pruned pass A materializes only the fibers the gather actually touches, so `residues[s]` is
/// the residue held in compact slot `s` and `qslots[qi]` is the slot query `qi` reads from. A query's
/// `rows_per_query` siblings differ by multiples of `query_stride`, which the caller has already
/// checked is a multiple of 2^14, so siblings share a residue and `residues.len() <= qslots.len()`.
fn residue_slots(query_indices: &[usize]) -> (Vec<u32>, Vec<u32>) {
    let mut slot_of = std::collections::HashMap::<u32, u32>::with_capacity(query_indices.len());
    let mut residues: Vec<u32> = Vec::with_capacity(query_indices.len());
    let mut qslots: Vec<u32> = Vec::with_capacity(query_indices.len());
    for &q in query_indices {
        let g = (q & ((1usize << 14) - 1)) as u32;
        let next = residues.len() as u32;
        let slot = *slot_of.entry(g).or_insert_with(|| {
            residues.push(g);
            next
        });
        qslots.push(slot);
    }
    (residues, qslots)
}

#[allow(clippy::too_many_arguments)]
pub fn rs_code_streamed_open<Val: GpuNttField>(
    log_blowup: usize,
    layout: &StackedLayout,
    traces: &[&DeviceMatrix<Val>],
    query_indices: &[usize],
    query_stride: usize,
    rows_per_query: usize,
    n_blocks: usize,
) -> Result<Vec<Vec<Val>>, RsCodeMatrixError> {
    use crate::{cuda::matrix::matrix_get_rows_fp_kernel, runtime::copy::MemCopyD2H};
    if query_indices.is_empty() {
        return Ok(Vec::new());
    }
    let l_skip = layout.l_skip();
    let height = layout.height();
    let width = layout.width();
    let codeword_height = height.checked_shl(log_blowup as u32).unwrap();

    // Same strided row indices `batch_open_rows_f` uses: for each query, its `rows_per_query`
    // siblings at stride `query_stride`. Order is query-major, then row-offset.
    let row_idxs: Vec<u32> = query_indices
        .iter()
        .flat_map(|&q| {
            debug_assert!(q < query_stride);
            (0..rows_per_query).map(move |ro| (ro * query_stride + q) as u32)
        })
        .collect();
    let n_rows = row_idxs.len();
    let d_row_idxs = {
        use crate::runtime::copy::MemCopyH2D;
        row_idxs.to_device()?
    };

    // Rate-aligned block widths (same rule as the streamed commit).
    let raw = width.div_ceil(n_blocks).max(1);
    let bw = raw.div_ceil(STREAM_SPONGE_RATE) * STREAM_SPONGE_RATE;

    // Answer the round-0 queries straight
    // from the pass-A NTT intermediate instead of finishing the full 2^24-row codeword.
    // Pass B of the RS-encode NTT never mixes low-14-bit row offsets, so each queried row
    // is an exact 1024-term dot product over its pass-A fiber (see `_rs2_open_dot` in
    // rs_ntt_fastpath.cu for the derivation) — bit-exact vs the full re-encode
    // (`RS_STREAM_VERIFY=1` A/B-compares the opened rows against the monolithic path).
    // MLE_STREAMED_OPEN_GATHER: unset/other → D-full (pass A additionally writes only the
    // queried residue fibers, the default), "lite" → D-lite (full pass-A write +
    // gather-dot), "0" → legacy full re-encode (the previous behavior). The gather also
    // silently degrades to the full pipeline whenever the dense RS fastpath does not
    // engage (RS_DENSE=0, C1_VERIFY, non-2^24 shapes, wide blocks).
    let gather_mode: u8 = match std::env::var("MLE_STREAMED_OPEN_GATHER").as_deref() {
        Ok("0") => 0,
        Ok("lite") => 1,
        _ => 2,
    };
    let n_queries = query_indices.len();
    let log_codeword_height = log2_strict_usize(codeword_height);
    // Structural gates for the gather kernel: the pass-A fiber layout is 2^14 x 2^10
    // (2^24 rows only), and the `rows_per_query` sibling rows of one query must share
    // their low-14-bit offset — they differ by multiples of `query_stride`.
    let gather_ok = gather_mode > 0
        && log_codeword_height == 24
        && rows_per_query > 0
        && query_stride.is_multiple_of(1 << 14)
        && query_stride.checked_mul(rows_per_query) == Some(codeword_height);
    // D-full residue tables: the gather only ever reads the fibers at the distinct
    // `q mod 2^14` (sibling rows share their residue), so the pruned pass A materializes
    // just those `n_res <= n_queries` fibers per column into a compact
    // `[col][residue][segment]` buffer instead of writing the whole 2^24-row block.
    // `qslots[qi]` maps each query to its residue slot in that buffer.
    let (d_res, d_qslot) = if gather_ok && gather_mode == 2 {
        use crate::runtime::copy::MemCopyH2D;
        let (residues, qslots) = residue_slots(query_indices);
        (Some(residues.to_device()?), Some(qslots.to_device()?))
    } else {
        (None, None)
    };
    let n_res = d_res.as_ref().map_or(0, |r| r.len());

    // One growable row buffer per extracted row; column-blocks append in ascending column order,
    // so each row ends up with the full-width codeword row (small: n_rows * width host elements).
    let mut rows: Vec<Vec<Val>> = (0..n_rows).map(|_| Vec::with_capacity(width)).collect();

    let mut c0 = 0usize;
    while c0 < width {
        let wb = (width - c0).min(bw);
        let mut block = DeviceBuffer::<Val>::with_capacity(codeword_height * wb);
        stack_traces_gathered_cols(layout, traces, &mut block, codeword_height, c0, wb)
            .map_err(RsCodeMatrixError::StackTraces)?;
        let mut gathered: Option<Vec<Val>> = None;
        if gather_ok {
            // Same encode prefix as `rs_encode_block_in_place` (fused iNTT+zeta, bitrev);
            // on the KB fastpath these two stage the dense scratch instead of touching
            // `block`, and `rs_open_pass_a` picks that handshake up.
            if l_skip > 0 {
                Val::batch_intt_zeta_fused(
                    &mut block,
                    l_skip,
                    codeword_height >> l_skip,
                    height >> l_skip,
                    wb,
                )
                .map_err(RsCodeMatrixError::CustomBatchIntt)?;
            }
            Val::bit_rev(
                &block,
                &block,
                log_codeword_height as u32,
                codeword_height as u32,
                wb as u32,
            )
            .map_err(RsCodeMatrixError::BitRev)?;
            // D-full compact pass-A output: `n_res` fibers of `2^10` segments per
            // column. Tiny (~n_res * 4 KiB per column) vs the 2^24-row block.
            let compact = if gather_mode == 2 {
                Some(DeviceBuffer::<Val>::with_capacity(
                    wb * n_res * (codeword_height >> 14),
                ))
            } else {
                None
            };
            let engaged = unsafe {
                Val::rs_open_pass_a(
                    &mut block,
                    compact.as_ref().map(|c| (c, d_res.as_ref().unwrap())),
                    codeword_height as u32,
                    wb as u32,
                )
            }
            .map_err(RsCodeMatrixError::OpenPassA)?;
            if engaged {
                let d_out = DeviceBuffer::<Val>::with_capacity(n_rows * wb);
                let (src, qslot) = match compact.as_ref() {
                    Some(c) => (c, d_qslot.as_ref()),
                    None => (&block, None),
                };
                // SAFETY: `d_out` holds n_rows*wb elems; `src` holds the pass-A
                // intermediate (full block or compact residue fibers); row indices are
                // query-major with `rows_per_query` siblings sharing q mod 2^14.
                unsafe {
                    Val::rs_open_gather_rows(
                        &d_out,
                        src,
                        &d_row_idxs,
                        qslot,
                        n_res,
                        n_queries,
                        rows_per_query,
                        codeword_height as u32,
                        wb as u32,
                    )
                }
                .map_err(RsCodeMatrixError::OpenGatherDot)?;
                gathered = Some(d_out.to_host()?);
            } else {
                // Dense fastpath not engaged: `block` is exactly post-bitrev, i.e. the
                // same state `rs_encode_block_in_place` has there — finish its full NTT
                // and fall through to the row-gather kernel below.
                Val::batch_ntt(
                    &block,
                    log_codeword_height as u32,
                    0u32,
                    wb as u32,
                    false,
                    false,
                );
            }
        } else {
            rs_encode_block_in_place::<Val>(
                &mut block,
                l_skip,
                height,
                codeword_height,
                log_blowup,
                wb,
            )?;
        }
        let host = if let Some(host) = gathered {
            host
        } else {
            // Extract the queried rows for this block's columns. `matrix_get_rows_fp` is
            // field-agnostic (a 4-byte row/col gather); reinterpret the KoalaBear buffers as
            // the crate's `F` exactly as `MerkleTreeGpu::batch_open_rows` does.
            let d_out = DeviceBuffer::<Val>::with_capacity(n_rows * wb);
            let out_f = unsafe {
                &*(&d_out as *const DeviceBuffer<Val> as *const DeviceBuffer<crate::prelude::F>)
            };
            let in_f = unsafe {
                &*(&block as *const DeviceBuffer<Val> as *const DeviceBuffer<crate::prelude::F>)
            };
            // SAFETY: out holds n_rows*wb elems; row indices are < codeword_height.
            unsafe {
                matrix_get_rows_fp_kernel(
                    out_f,
                    in_f,
                    &d_row_idxs,
                    wb as u64,
                    codeword_height as u64,
                    n_rows,
                )
                .map_err(RsCodeMatrixError::OpenGetRows)?;
            }
            d_out.to_host()?
        };
        for (r, row) in rows.iter_mut().enumerate() {
            row.extend_from_slice(&host[r * wb..r * wb + wb]);
        }
        c0 += bw;
        // `block` and `d_out` freed here.
    }

    // Group `rows_per_query` consecutive rows per query, concatenated — matches batch_open_rows_f.
    Ok(rows
        .chunks(rows_per_query)
        .map(|grp| grp.concat())
        .collect())
}

impl<F, Digest> StackedPcsDataGpu<F, Digest> {
    /// Mixed-form view of one original (unstacked) matrix inside the cached stacked matrix, or
    /// `None` when the stacked matrix was not kept.
    ///
    /// `n_cols` has to equal that matrix's width. If the matrix was lifted with a stride, the
    /// caller is responsible for stepping over it.
    pub fn mixed_view<'a>(
        &'a self,
        mat_idx: usize,
        n_cols: usize,
    ) -> Option<DeviceMatrixView<'a, F>> {
        if let Some(stacked) = self.matrix.as_ref() {
            debug_assert_eq!(self.layout.width_of(mat_idx), n_cols);
            let col_slice = self
                .layout
                .get(mat_idx, 0)
                .unwrap_or_else(|| panic!("Invalid matrix index: {mat_idx}"));
            let l_skip = self.layout.l_skip();
            let slice_rows = col_slice.len(l_skip);
            let off = col_slice.col_idx * stacked.height() + col_slice.row_idx;
            // SAFETY: the layout places this matrix inside the stacked buffer, so `base` points at
            // `slice_rows * n_cols` allocated elements.
            unsafe {
                let base = stacked.mixed.as_ptr().add(off);
                Some(DeviceMatrixView::from_raw_parts(base, slice_rows, n_cols))
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use mle_core::{
        config::koala_bear_poseidon2::{KoalaBearPoseidon2Config as SC, F},
        poly::matrix::ColMajorMatrix,
        test_utils::{InteractionsFixture11, TestFixture},
    };
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::data_transporter::{transport_matrix_d2h_col_major, transport_matrix_h2d_col_major};

    #[test]
    fn test_stacked_matrix_manual_0() {
        let columns = [vec![1, 2, 3, 4], vec![5, 6], vec![7]]
            .map(|v| v.into_iter().map(F::from_u32).collect_vec());
        let mats = columns
            .into_iter()
            .map(|c| transport_matrix_h2d_col_major(&ColMajorMatrix::new(c, 1)).unwrap())
            .collect_vec();
        let mat_refs = mats.iter().collect_vec();
        let l_skip = 0;
        let (stacked_mat, _layout) = stacked_matrix(0, 2, &mat_refs).unwrap();
        assert_eq!(stacked_mat.height(), 4);
        assert_eq!(stacked_mat.width(), 2);
        let stacked_h_mat =
            transport_matrix_d2h_col_major(&stacked_mat.to_evals(l_skip).unwrap()).unwrap();
        assert_eq!(
            stacked_h_mat.values,
            [1, 2, 3, 4, 5, 6, 7, 0].map(F::from_u32).to_vec()
        );
    }

    #[test]
    fn test_stacked_matrix_manual_1() {
        let ctx = TestFixture::<SC>::generate_proving_ctx(&InteractionsFixture11);
        let [send_trace, rcv_trace] = [0, 1]
            .map(|i| transport_matrix_h2d_col_major(&ctx.per_trace[i].1.common_main).unwrap());
        let l_skip = 2;
        let n_stack = 8;
        let (stacked_mat, _layout) =
            stacked_matrix(l_skip, n_stack, &[&rcv_trace, &send_trace]).unwrap();
        assert_eq!(stacked_mat.height(), 1 << (l_skip + n_stack));
        assert_eq!(stacked_mat.width(), 1);
        let stacked_h_mat =
            transport_matrix_d2h_col_major(&stacked_mat.to_evals(l_skip).unwrap()).unwrap();
        let mut expected = vec![F::ZERO; 1 << (l_skip + n_stack)];
        expected[..24].copy_from_slice(
            &[
                1, 3, 4, 2, 0, 545, 1, 0, 5, 4, 4, 5, 123, 889, 889, 456, 0, 3, 7, 546, 1, 5, 4,
                889,
            ]
            .map(F::from_u32),
        );
        assert_eq!(stacked_h_mat.values, expected);
    }

    #[test]
    fn test_stacked_matrix_manual_strided_0() {
        let columns = [vec![1, 2, 3, 4], vec![5, 6], vec![7]]
            .map(|v| v.into_iter().map(F::from_u32).collect_vec());
        let mats = columns
            .into_iter()
            .map(|c| transport_matrix_h2d_col_major(&ColMajorMatrix::new(c, 1)).unwrap())
            .collect_vec();
        let mat_refs = mats.iter().collect_vec();
        let l_skip = 2;
        let (stacked_mat, _layout) = stacked_matrix(l_skip, 0, &mat_refs).unwrap();
        assert_eq!(stacked_mat.height(), 4);
        assert_eq!(stacked_mat.width(), 3);
        let stacked_h_mat =
            transport_matrix_d2h_col_major(&stacked_mat.to_evals(l_skip).unwrap()).unwrap();
        assert_eq!(
            stacked_h_mat.values,
            [1, 2, 3, 4, 5, 0, 6, 0, 7, 0, 0, 0]
                .map(F::from_u32)
                .to_vec()
        );
    }

    #[test]
    fn test_stacked_matrix_manual_strided_1() {
        let columns = [vec![1, 2, 3, 4], vec![5, 6], vec![7]]
            .map(|v| v.into_iter().map(F::from_u32).collect_vec());
        let mats = columns
            .into_iter()
            .map(|c| transport_matrix_h2d_col_major(&ColMajorMatrix::new(c, 1)).unwrap())
            .collect_vec();
        let mat_refs = mats.iter().collect_vec();
        let l_skip = 3;
        let (stacked_mat, _layout) = stacked_matrix(l_skip, 0, &mat_refs).unwrap();
        assert_eq!(stacked_mat.height(), 8);
        assert_eq!(stacked_mat.width(), 3);
        let stacked_h_mat =
            transport_matrix_d2h_col_major(&stacked_mat.to_evals(l_skip).unwrap()).unwrap();
        assert_eq!(
            stacked_h_mat.values,
            [
                [1, 0, 2, 0, 3, 0, 4, 0],
                [5, 0, 0, 0, 6, 0, 0, 0],
                [7, 0, 0, 0, 0, 0, 0, 0]
            ]
            .into_iter()
            .flatten()
            .map(F::from_u32)
            .collect_vec()
        );
    }

    // ── GPU differential tests (formerly the STACK_GATHER_VERIFY / C1_VERIFY env harnesses) ──
    // Each compares two independent GPU implementations of the same transform on a non-uniform
    // fixture with `l_skip > 0` (both the contiguous placement arm and the strided arm fire) and a
    // stacked width that is not a multiple of the CUDA block size. These are GPU-vs-GPU differential
    // checks (two distinct kernels, not a tautology); the CPU-oracle parity tests are separate.

    /// Three traces of decreasing height, one shorter than `2^l_skip` (strided) and two taller
    /// (contiguous), packed so the stacked width is 3. Returns the device traces (kept alive by the
    /// caller), the derived layout, `l_skip`, and `log_blowup`.
    fn diff_fixture<Val: GpuNttField>(
        mk: impl Fn(u32) -> Val,
    ) -> (Vec<DeviceMatrix<Val>>, StackedLayout, usize, usize) {
        let (l_skip, n_stack, log_blowup) = (2usize, 2usize, 1usize); // stacked height 2^4 = 16
                                                                      // (width, height); heights non-increasing (get_stacked_layout debug-asserts it). (2,2) has
                                                                      // log_height 1 < l_skip → strided; the others are contiguous. Widths 2/3/2 are not
                                                                      // block-sized, and the slices tile each height-16 column exactly (no LayoutRowOverflow).
        let specs = [(2usize, 8usize), (3, 4), (2, 2)];
        let mats: Vec<DeviceMatrix<Val>> = specs
            .iter()
            .map(|&(w, h)| {
                let values: Vec<Val> = (0..(w * h) as u32).map(|v| mk(v + 1)).collect();
                transport_matrix_h2d_col_major(&ColMajorMatrix::new(values, w)).unwrap()
            })
            .collect();
        let refs: Vec<&DeviceMatrix<Val>> = mats.iter().collect();
        let layout = get_stacked_layout(l_skip, n_stack, &refs);
        assert_eq!(layout.width(), 3, "fixture should pack to stacked width 3");
        (mats, layout, l_skip, log_blowup)
    }

    /// `l_skip = 1` twin of [`diff_fixture`]: lengths are multiples of 2 but not 4, so the
    /// vectorizability check fails and the **scalar** kernel runs — otherwise it would be uncovered.
    fn diff_fixture_unaligned<Val: GpuNttField>(
        mk: impl Fn(u32) -> Val,
    ) -> (Vec<DeviceMatrix<Val>>, StackedLayout, usize, usize) {
        let (l_skip, n_stack, log_blowup) = (1usize, 3usize, 1usize); // stacked height 2^4 = 16
                                                                      // (width, height), heights non-increasing. (2,1) has log_height 0 < l_skip → strided.
        let specs = [(2usize, 8usize), (3, 2), (2, 1)];
        let mats: Vec<DeviceMatrix<Val>> = specs
            .iter()
            .map(|&(w, h)| {
                let values: Vec<Val> = (0..(w * h) as u32).map(|v| mk(v + 1)).collect();
                transport_matrix_h2d_col_major(&ColMajorMatrix::new(values, w)).unwrap()
            })
            .collect();
        let refs: Vec<&DeviceMatrix<Val>> = mats.iter().collect();
        let layout = get_stacked_layout(l_skip, n_stack, &refs);
        (mats, layout, l_skip, log_blowup)
    }

    /// The scalar kernel must match the staged stacker byte-for-byte, as the vector path does.
    fn check_stack_gather_unaligned_matches_staged<Val: GpuNttField>(mk: impl Fn(u32) -> Val) {
        let (mats, layout, _l_skip, log_blowup) = diff_fixture_unaligned(mk);
        let refs: Vec<&DeviceMatrix<Val>> = mats.iter().collect();
        let codeword_height = layout.height() << log_blowup;
        let width = layout.width();
        let mut gathered = DeviceBuffer::<Val>::with_capacity(codeword_height * width);
        stack_traces_gathered(&layout, &refs, &mut gathered, codeword_height).unwrap();
        let mut staged = DeviceBuffer::<Val>::with_capacity(codeword_height * width);
        stack_traces_into_expanded(&layout, &refs, &mut staged, codeword_height).unwrap();
        use crate::runtime::copy::MemCopyD2H;
        let (a, b) = (gathered.to_host().unwrap(), staged.to_host().unwrap());
        // SAFETY: reinterpreting each live `Vec<Val>` as `size_of_val` bytes — same allocation,
        // never read past, `u8` has weaker alignment than `Val`.
        let ab: &[u8] =
            unsafe { std::slice::from_raw_parts(a.as_ptr() as *const u8, size_of_val(&a[..])) };
        let bb: &[u8] =
            unsafe { std::slice::from_raw_parts(b.as_ptr() as *const u8, size_of_val(&b[..])) };
        assert_eq!(ab, bb, "scalar gather differs from staged stack");
    }

    fn check_stack_gather_matches_staged<Val: GpuNttField>(mk: impl Fn(u32) -> Val) {
        let (mats, layout, _l_skip, log_blowup) = diff_fixture(mk);
        let refs: Vec<&DeviceMatrix<Val>> = mats.iter().collect();
        let codeword_height = layout.height() << log_blowup;
        let width = layout.width();
        let mut gathered = DeviceBuffer::<Val>::with_capacity(codeword_height * width);
        stack_traces_gathered(&layout, &refs, &mut gathered, codeword_height).unwrap();
        let mut staged = DeviceBuffer::<Val>::with_capacity(codeword_height * width);
        stack_traces_into_expanded(&layout, &refs, &mut staged, codeword_height).unwrap();
        use crate::runtime::copy::MemCopyD2H;
        let a = gathered.to_host().unwrap();
        let b = staged.to_host().unwrap();
        // SAFETY: reinterpreting each live `Vec<Val>` as `size_of_val` bytes — same allocation,
        // never read past, `u8` has weaker alignment than `Val`.
        let ab: &[u8] =
            unsafe { std::slice::from_raw_parts(a.as_ptr() as *const u8, size_of_val(&a[..])) };
        let bb: &[u8] =
            unsafe { std::slice::from_raw_parts(b.as_ptr() as *const u8, size_of_val(&b[..])) };
        assert_eq!(ab, bb, "one-pass gather differs from staged stack");
    }

    fn check_fused_intt_zeta_matches_staged<Val: GpuNttField>(mk: impl Fn(u32) -> Val) {
        let (mats, layout, l_skip, log_blowup) = diff_fixture(mk);
        let refs: Vec<&DeviceMatrix<Val>> = mats.iter().collect();
        let height = layout.height();
        let codeword_height = height << log_blowup;
        let width = layout.width();
        // Post-stack, pre-fused evals.
        let mut codewords = DeviceBuffer::<Val>::with_capacity(codeword_height * width);
        stack_traces_gathered(&layout, &refs, &mut codewords, codeword_height).unwrap();
        // Scratch = copy of the pre-fused buffer.
        let mut scratch = DeviceBuffer::<Val>::with_capacity(codewords.len());
        // SAFETY: both buffers hold `codewords.len()` device elements; the D2D copy stays within.
        unsafe {
            cuda_memcpy::<true, true>(
                scratch.as_mut_raw_ptr(),
                codewords.as_ptr() as *const c_void,
                codewords.len() * size_of::<Val>(),
            )
            .unwrap();
        }
        let chunks_per_col = codeword_height >> l_skip;
        let real_chunks_per_col = height >> l_skip;
        Val::batch_intt_zeta_fused(
            &mut codewords,
            l_skip,
            chunks_per_col,
            real_chunks_per_col,
            width,
        )
        .unwrap();
        assert_fused_matches_staged(
            &codewords,
            &mut scratch,
            l_skip,
            codeword_height,
            log_blowup,
            width,
        )
        .unwrap();
    }

    /// Both kernels are bit-exact, so a passing differential test cannot say which one ran; this
    /// pins the dispatch decision itself. Host-only.
    #[test]
    fn gather_vectorizability_predicate() {
        use crate::cuda::matrix::StackGatherDesc;
        let d = |dst_start: u64, len: u32| StackGatherDesc {
            src: 0,
            dst_start,
            len,
            stride: 1,
        };
        assert!(gather_is_vectorizable(&[d(0, 16), d(16, 32)], 64)); // production `l_skip = 4`
        assert!(gather_is_vectorizable(&[], 64)); // all-padding
        assert!(!gather_is_vectorizable(&[d(0, 2)], 64)); // `len` straddles a group
        assert!(!gather_is_vectorizable(&[d(2, 16)], 64)); // `dst_start` misaligned
        assert!(!gather_is_vectorizable(&[d(0, 16)], 66)); // tail cells unwritten
    }

    #[test]
    fn stack_gather_matches_staged_stack_kb() {
        use p3_koala_bear::KoalaBear;
        check_stack_gather_matches_staged::<KoalaBear>(KoalaBear::from_u32);
    }

    #[test]
    fn stack_gather_unaligned_matches_staged_stack_kb() {
        use p3_koala_bear::KoalaBear;
        check_stack_gather_unaligned_matches_staged::<KoalaBear>(KoalaBear::from_u32);
    }

    #[test]
    fn fused_intt_zeta_matches_staged_pipeline_kb() {
        use p3_koala_bear::KoalaBear;
        check_fused_intt_zeta_matches_staged::<KoalaBear>(KoalaBear::from_u32);
    }

    /// F10 negative test: a descriptor table that is not strictly non-overlapping must return
    /// `GatherDescriptorOverlap`, not silently produce a wrong buffer (the gather kernel would
    /// binary-search a table it assumes sorted). `StackedLayout::new` never emits such a layout, so
    /// this uses `from_raw_parts`, which takes slice positions as-is.
    #[test]
    fn gather_rejects_overlapping_descriptors() {
        use mle_core::protocol::stacking::{StackedColumn, StackedSlice};
        let (l_skip, log_stacked_height) = (2usize, 3usize); // stacked height 8
                                                             // Two columns of one height-4 trace deliberately overlapping in stacked column 0:
                                                             // col0 → rows [0, 4), col1 → rows [2, 6).
        let cols = vec![
            StackedColumn::new(0, 0, StackedSlice::new(0, 0, 2)),
            StackedColumn::new(0, 1, StackedSlice::new(0, 2, 2)),
        ];
        let layout = StackedLayout::from_raw_parts(l_skip, log_stacked_height, cols).unwrap();
        // A real backing trace (width 2, height 4) so descriptor building can read its dims.
        let values: Vec<F> = (0..8).map(F::from_u32).collect();
        let trace = transport_matrix_h2d_col_major(&ColMajorMatrix::new(values, 2)).unwrap();
        let refs: Vec<&DeviceMatrix<F>> = vec![&trace];
        let padded_height = layout.height();
        let mut buffer = DeviceBuffer::<F>::with_capacity(padded_height * layout.width());
        let err = stack_traces_gathered(&layout, &refs, &mut buffer, padded_height).unwrap_err();
        assert!(
            matches!(
                err,
                StackTracesError::GatherDescriptorOverlap {
                    index: 1,
                    prev_end: 4,
                    dst_start: 2
                }
            ),
            "expected GatherDescriptorOverlap {{ index: 1, prev_end: 4, dst_start: 2 }}, got {err:?}"
        );
    }

    // ── Task 6: CPU↔GPU element-wise parity vs the mle-core / mle-cpu oracle ──
    // These are the acceptance deliverable. The oracle is always an independent host computation
    // (`mle_core::prover::stacked_pcs::*`, `mle_core::poly::mle::Mle`), never `prover == prover`.

    /// GPU `mle_interpolate_stages` (the unified base-field 2-D driver) vs the mle-core per-`2^l_skip`
    /// -chunk transform, both directions. `log_stride = 0` ⇒ the whole `padded_height` is meaningful,
    /// so each column is `padded_height / 2^l_skip` independent chunks — exactly what the host oracle
    /// applies. Covers `l_skip == 1` (the shared-memory kernel, reachable only here) and `l_skip == 2`
    /// (the warp-shuffle fused kernel).
    ///
    /// `log_stride > 0` exercises the `right_pad = true` (strided) mode (F15): the meaningful cells
    /// sit at physical positions `t << log_stride` and the transform runs over them in logical order.
    fn check_mle_interpolate_matches_host<Val>(
        mk: impl Fn(u32) -> Val,
        l_skip: usize,
        is_eval_to_coeff: bool,
        log_stride: u32,
    ) where
        Val: GpuNttField + p3_field::Field,
    {
        use crate::runtime::copy::{MemCopyD2H, MemCopyH2D};
        use mle_core::poly::mle::Mle;

        let right_pad = log_stride > 0;
        let width = 3usize;
        let chunk = 1usize << l_skip;
        let meaningful = chunk * 2; // two 2^l_skip chunks of meaningful cells per column
        let stride = 1usize << log_stride;
        let padded_height = meaningful * stride;
        let host_in: Vec<Val> = (0..(width * padded_height) as u32)
            .map(|v| mk(v + 1))
            .collect();

        // GPU: in-place stages [0, l_skip-1] over the col-major width×padded_height buffer.
        let dbuf = host_in.as_slice().to_device().unwrap();
        // SAFETY: `dbuf` holds `width * padded_height` device elements; the stages stay within
        // `2^l_skip` chunk boundaries.
        unsafe {
            Val::mle_interpolate_stages(
                dbuf.as_mut_ptr(),
                width,
                padded_height as u32,
                log_stride,
                0,
                l_skip as u32 - 1,
                is_eval_to_coeff,
                right_pad,
            )
            .unwrap();
        }
        let gpu_out = dbuf.to_host().unwrap();

        // CPU oracle: gather each column's strided meaningful cells (`t << log_stride`, logical
        // order), transform per 2^l_skip chunk, scatter back. `stride == 1` is the contiguous case.
        let mut host_out = host_in.clone();
        for col in host_out.chunks_exact_mut(padded_height) {
            let mut logical: Vec<Val> = (0..meaningful).map(|t| col[t * stride]).collect();
            for ch in logical.chunks_exact_mut(chunk) {
                if is_eval_to_coeff {
                    Mle::evals_to_coeffs_inplace(ch);
                } else {
                    Mle::coeffs_to_evals_inplace(ch);
                }
            }
            for (t, v) in logical.iter().enumerate() {
                col[t * stride] = *v;
            }
        }
        assert_eq!(
            gpu_out, host_out,
            "mle_interpolate_stages != host oracle (l_skip={l_skip}, e2c={is_eval_to_coeff}, log_stride={log_stride})"
        );
    }

    #[test]
    fn gpu_mle_interpolate_matches_host_kb() {
        use p3_koala_bear::KoalaBear;
        for l_skip in [1usize, 2] {
            for e2c in [false, true] {
                for log_stride in [0u32, 1] {
                    check_mle_interpolate_matches_host::<KoalaBear>(
                        KoalaBear::from_u32,
                        l_skip,
                        e2c,
                        log_stride,
                    );
                }
            }
        }
    }

    /// GPU `stacked_matrix` (stack + PLE round-trip back to eval form) vs
    /// `mle_core::prover::stacked_pcs::stacked_matrix`, element-wise, on a non-uniform fixture (one
    /// trace shorter than `2^l_skip`, so the strided placement fires).
    #[test]
    fn gpu_stacked_matrix_matches_host_kb() {
        use mle_core::prover::stacked_pcs::stacked_matrix as host_stacked_matrix;
        use p3_koala_bear::KoalaBear;

        let (l_skip, n_stack) = (2usize, 2usize);
        let specs = [(2usize, 8usize), (3, 4), (2, 2)];
        let host_traces: Vec<ColMajorMatrix<KoalaBear>> = specs
            .iter()
            .map(|&(w, h)| {
                ColMajorMatrix::new((0..(w * h) as u32).map(KoalaBear::from_u32).collect(), w)
            })
            .collect();
        let host_refs: Vec<&ColMajorMatrix<KoalaBear>> = host_traces.iter().collect();
        let dev_traces: Vec<DeviceMatrix<KoalaBear>> = host_traces
            .iter()
            .map(|m| transport_matrix_h2d_col_major(m).unwrap())
            .collect();
        let dev_refs: Vec<&DeviceMatrix<KoalaBear>> = dev_traces.iter().collect();

        let (gpu_ple, _layout) = stacked_matrix(l_skip, n_stack, &dev_refs).unwrap();
        let gpu_evals = transport_matrix_d2h_col_major(&gpu_ple.to_evals(l_skip).unwrap()).unwrap();
        let (host_mat, _host_layout) = host_stacked_matrix(l_skip, n_stack, &host_refs).unwrap();

        assert_eq!(
            (gpu_evals.height(), gpu_evals.width()),
            (host_mat.height(), host_mat.width())
        );
        assert_eq!(
            gpu_evals.values, host_mat.values,
            "GPU stacked matrix != host"
        );
    }

    /// The headline acceptance test: GPU `stacked_commit` at `l_skip > 0` vs the host oracle —
    /// commitment root, RS codeword matrix (element-wise, `cache_rs_code_matrix`), and digest layers.
    #[test]
    fn gpu_stacked_commit_matches_host_at_l_skip_nonzero() {
        use crate::{
            hash_scheme::KoalaBearPoseidon2MerkleHash, runtime::copy::MemCopyD2H,
            KoalaBearPoseidon2GpuEngine,
        };
        use mle_core::{
            prover::stacked_pcs::{
                rs_code_matrix as host_rs, stacked_commit as host_commit,
                stacked_matrix as host_stacked_matrix,
            },
            test_utils::test_system_params_small,
            StarkEngine, StarkProtocolConfig,
        };
        use p3_koala_bear::KoalaBear;

        let (l_skip, n_stack, k_whir) = (2usize, 2usize, 1usize);
        let params = test_system_params_small(l_skip, n_stack, k_whir);
        let engine = KoalaBearPoseidon2GpuEngine::new(params.clone());
        let hasher = engine.config().hasher();
        let log_blowup = params.log_blowup;

        let specs = [(2usize, 8usize), (3, 4), (2, 2)];
        let host_traces: Vec<ColMajorMatrix<KoalaBear>> = specs
            .iter()
            .map(|&(w, h)| {
                ColMajorMatrix::new((0..(w * h) as u32).map(KoalaBear::from_u32).collect(), w)
            })
            .collect();
        let host_refs: Vec<&ColMajorMatrix<KoalaBear>> = host_traces.iter().collect();
        let dev_traces: Vec<DeviceMatrix<KoalaBear>> = host_traces
            .iter()
            .map(|m| transport_matrix_h2d_col_major(m).unwrap())
            .collect();
        let dev_refs: Vec<&DeviceMatrix<KoalaBear>> = dev_traces.iter().collect();

        let (host_root, host_data) =
            host_commit(hasher, l_skip, n_stack, log_blowup, k_whir, &host_refs).unwrap();

        let cfg = GpuProverConfig {
            cache_stacked_matrix: false,
            cache_rs_code_matrix: true,
            ..Default::default()
        };
        let (gpu_root, gpu_data) = stacked_commit::<KoalaBear, KoalaBearPoseidon2MerkleHash>(
            l_skip, n_stack, log_blowup, k_whir, &dev_refs, cfg,
        )
        .unwrap();

        // 1. Commitment root — order-independent; the strongest single check.
        assert_eq!(gpu_root, host_root, "GPU stacked_commit root != host");

        // 2. RS codeword matrix, element-wise, against `mle_core::rs_code_matrix` (issue item 5).
        let host_stacked = host_stacked_matrix(l_skip, n_stack, &host_refs).unwrap().0;
        let host_codeword = host_rs(l_skip, log_blowup, &host_stacked).unwrap();
        let gpu_codeword =
            transport_matrix_d2h_col_major(gpu_data.tree.backing_matrix.as_ref().unwrap()).unwrap();
        assert_eq!(
            (gpu_codeword.height(), gpu_codeword.width()),
            (host_codeword.height(), host_codeword.width())
        );
        assert_eq!(
            gpu_codeword.values, host_codeword.values,
            "GPU RS codeword != host rs_code_matrix"
        );

        // 3. Digest layers, length asserted first so a dropped layer cannot pass vacuously.
        assert_eq!(
            gpu_data.tree.digest_layers.len(),
            host_data.tree.digest_layers().len()
        );
        for (g, h) in gpu_data
            .tree
            .digest_layers
            .iter()
            .zip(host_data.tree.digest_layers())
        {
            assert_eq!(&g.to_host().unwrap(), h);
        }
    }

    /// F4 + F6: the `cache_stacked_matrix` arm and `mixed_view` — the two surfaces 2g **kept** — get
    /// the test that justifies keeping them.
    ///
    /// 1. Drives `stacked_commit` through `cache_stacked_matrix = true`, i.e. the
    ///    `rs_code_matrix` `Some(stacked_matrix)` / `batch_expand_pad_any` branch that the default
    ///    config never takes, and checks its root against the host oracle. Without this the arm is
    ///    shipped untested.
    /// 2. Checks `mixed_view`'s offset arithmetic against `StackedLayout::mat_view` — mle-core's own
    ///    unstacking of the *same* buffer, so the oracle is independent of the GPU pointer math.
    ///
    /// Fixture note: every trace is full stacked height, so each occupies whole stacked columns and
    /// its slices are contiguous (stride 1). That is the regime in which `mixed_view`'s
    /// `lifted_height × width` contiguous interpretation is exact — its doc leaves striding to the
    /// caller, so a strided fixture would be testing the caller's contract, not the view's.
    #[test]
    fn cached_arm_and_mixed_view_match_host_kb() {
        use crate::{
            hash_scheme::KoalaBearPoseidon2MerkleHash, runtime::copy::MemCopyD2H,
            KoalaBearPoseidon2GpuEngine,
        };
        use mle_core::{
            prover::stacked_pcs::stacked_commit as host_commit,
            test_utils::test_system_params_small, StarkEngine, StarkProtocolConfig,
        };
        use p3_koala_bear::KoalaBear;

        let (l_skip, n_stack, k_whir) = (2usize, 2usize, 1usize);
        let stacked_height = 1usize << (l_skip + n_stack); // 16
        let params = test_system_params_small(l_skip, n_stack, k_whir);
        let engine = KoalaBearPoseidon2GpuEngine::new(params.clone());
        let hasher = engine.config().hasher();
        let log_blowup = params.log_blowup;

        // Each trace is full stacked height ⇒ whole stacked columns, stride 1 (see the doc above).
        let specs = [(2usize, stacked_height), (1, stacked_height)];
        let host_traces: Vec<ColMajorMatrix<KoalaBear>> = specs
            .iter()
            .map(|&(w, h)| {
                ColMajorMatrix::new((0..(w * h) as u32).map(KoalaBear::from_u32).collect(), w)
            })
            .collect();
        let host_refs: Vec<&ColMajorMatrix<KoalaBear>> = host_traces.iter().collect();
        let dev_traces: Vec<DeviceMatrix<KoalaBear>> = host_traces
            .iter()
            .map(|m| transport_matrix_h2d_col_major(m).unwrap())
            .collect();
        let dev_refs: Vec<&DeviceMatrix<KoalaBear>> = dev_traces.iter().collect();

        let (host_root, _host_data) =
            host_commit(hasher, l_skip, n_stack, log_blowup, k_whir, &host_refs).unwrap();

        let cached_cfg = GpuProverConfig {
            cache_stacked_matrix: true,
            cache_rs_code_matrix: true,
            ..Default::default()
        };
        let (gpu_root, gpu_data) = stacked_commit::<KoalaBear, KoalaBearPoseidon2MerkleHash>(
            l_skip, n_stack, log_blowup, k_whir, &dev_refs, cached_cfg,
        )
        .unwrap();

        // 1. The cached arm reaches the same commitment as the host — this is the only coverage of
        //    `rs_code_matrix`'s `batch_expand_pad_any` branch.
        assert_eq!(
            gpu_root, host_root,
            "cache_stacked_matrix arm root != host stacked_commit"
        );
        let ple = gpu_data
            .matrix
            .as_ref()
            .expect("cached arm must retain the stacked matrix");

        // 2. `mixed_view` vs `StackedLayout::mat_view` over the same (mixed-form) buffer.
        let mixed_host_vals = ple.mixed().to_host().unwrap();
        let stacked_width = ple.width();
        assert_eq!(mixed_host_vals.len(), stacked_width * stacked_height);
        let mixed_host = ColMajorMatrix::new(mixed_host_vals.clone(), stacked_width);
        let base_ptr = ple.mixed().as_ptr() as usize;

        for (mat_idx, &(w, _)) in specs.iter().enumerate() {
            let view = gpu_data
                .mixed_view(mat_idx, w)
                .expect("mixed_view must be Some on the cached arm");
            assert_eq!((view.height(), view.width()), (stacked_height, w));

            // The GPU's offset arithmetic, read off the returned pointer.
            let byte_off = view.as_ptr() as usize - base_ptr;
            assert_eq!(byte_off % size_of::<KoalaBear>(), 0);
            let off = byte_off / size_of::<KoalaBear>();
            let gpu_block = &mixed_host_vals[off..off + stacked_height * w];

            // Independent oracle: mle-core unstacks the same buffer itself.
            let expected = gpu_data.layout.mat_view(mat_idx, &mixed_host).to_matrix();
            assert_eq!(
                gpu_block,
                expected.values.as_slice(),
                "mixed_view({mat_idx}) != StackedLayout::mat_view over the same buffer"
            );
        }
    }

    // ── Streaming Merkle commit parity ────────────────────────────────────────────────────
    // `rs_code_streamed_commit` (`absorb_columns` + `finalize_leaf_digests`) has zero test
    // coverage reachable without `RS_STREAM_BLOCKS` set — the only default is
    // `single_node_mle.sh`, not Rust, so `cargo test` never took this arm before. Every test
    // below calls the streaming entry point directly; none of them read or set an env var.
    mod streaming {
        use test_case::test_case;

        use super::*;
        use crate::{hash_scheme::KoalaBearPoseidon2MerkleHash, runtime::copy::MemCopyD2H};
        use p3_koala_bear::KoalaBear;

        type KbDigest = mle_core::config::koala_bear_poseidon2::Digest;

        /// A single trace at the full stacked height, so every column occupies one whole
        /// stacked column (stride 1) and the layout's width is exactly `width` — letting the
        /// streaming sweep vary `width` freely without perturbing the packing. Returns the host
        /// values (so the CPU oracle can build an identical trace), the uploaded device matrix,
        /// and the derived layout.
        fn full_height_trace(
            l_skip: usize,
            n_stack: usize,
            width: usize,
        ) -> (Vec<KoalaBear>, DeviceMatrix<KoalaBear>, StackedLayout) {
            let height = 1usize << (l_skip + n_stack);
            let values: Vec<KoalaBear> = (0..(width * height) as u32)
                .map(|v| KoalaBear::from_u32(v + 1))
                .collect();
            let mat = transport_matrix_h2d_col_major(&ColMajorMatrix::new(values.clone(), width))
                .unwrap();
            let layout = get_stacked_layout(l_skip, n_stack, &[&mat]);
            (values, mat, layout)
        }

        /// P-6 — the streaming leaf hash must be bit-identical, layer for layer, to the
        /// monolithic path it replaces (F18's acceptance test; also what would catch an F16
        /// rate-alignment violation). Root-only equality would be weaker than the
        /// `RS_STREAM_VERIFY` env harness this replaces, so every digest layer is compared
        /// element-wise, with the layer *count* asserted first so a dropped layer cannot pass
        /// vacuously.
        ///
        /// `width = 37` is prime, so none of the swept `n_blocks` divide it and every split
        /// leaves a short final block; it is also not a multiple of `STREAM_SPONGE_RATE` (8), so
        /// the trailing partial permute fires on every `w37` case. Block splits (verified by
        /// hand against the `bw = ceil(ceil(width/n_blocks)/8)*8` arithmetic in
        /// `rs_code_streamed_commit`):
        /// - `n_blocks=1`: one block, width 37 (no interior block at all).
        /// - `n_blocks=2`: `[24, 13]` — interior block rate-aligned, final block short.
        /// - `n_blocks=3`: `[16, 16, 5]` — two rate-aligned interior blocks, final block short.
        /// - `n_blocks=8`: `[8, 8, 8, 8, 5]` — four rate-aligned interior blocks (the most
        ///   splitting in the sweep), final block short.
        ///
        /// `w16_exact` is the complementary edge the prime-width cases cannot reach: width 16
        /// (a multiple of 8) split 2 ways is `[8, 8]` — the *final* block is itself rate-aligned,
        /// i.e. there is no short tail at all.
        #[test_case(1, 37; "n_blocks_1_w37")]
        #[test_case(2, 37; "n_blocks_2_w37")]
        #[test_case(3, 37; "n_blocks_3_w37")]
        #[test_case(8, 37; "n_blocks_8_w37")]
        #[test_case(2, 16; "n_blocks_2_w16_exact")]
        fn streamed_commit_matches_monolithic_kb(n_blocks: usize, width: usize) {
            let (l_skip, n_stack, log_blowup, k_whir) = (2usize, 2usize, 1usize, 1usize);
            let (_values, mat, layout) = full_height_trace(l_skip, n_stack, width);
            let refs: Vec<&DeviceMatrix<KoalaBear>> = vec![&mat];
            let rows_per_query = 1usize << k_whir;

            let streamed = rs_code_streamed_commit::<KoalaBear, KoalaBearPoseidon2MerkleHash>(
                log_blowup,
                &layout,
                &refs,
                rows_per_query,
                n_blocks,
            )
            .unwrap();

            let rs_matrix = rs_code_matrix(log_blowup, &layout, &refs, &None).unwrap();
            let monolithic = MerkleTreeGpu::<KoalaBear, KbDigest>::new_with_hash::<
                KoalaBearPoseidon2MerkleHash,
            >(rs_matrix, rows_per_query, false)
            .unwrap();

            assert_eq!(
                streamed.digest_layers.len(),
                monolithic.digest_layers.len(),
                "layer COUNT differs (n_blocks={n_blocks}, width={width}) — a dropped layer \
                 must not pass vacuously"
            );
            for (i, (s, m)) in streamed
                .digest_layers
                .iter()
                .zip_eq(monolithic.digest_layers.iter())
                .enumerate()
            {
                assert_eq!(
                    s.to_host().unwrap(),
                    m.to_host().unwrap(),
                    "digest layer {i} differs (n_blocks={n_blocks}, width={width})"
                );
            }
            assert_eq!(
                streamed.root(),
                monolithic.root(),
                "root differs (n_blocks={n_blocks}, width={width})"
            );
        }

        /// P-7 — P-6 only proves GPU ≡ GPU (streamed vs. monolithic, both `cuda-mle`). This pins
        /// the streamed digest layers directly to the CPU oracle,
        /// `mle_core::prover::stacked_pcs`'s own `ColMajorMerkleTree`, computed over the
        /// identical RS codeword by an independent host pipeline — so the streaming path is
        /// checked against the protocol itself, not merely against its GPU sibling.
        ///
        /// One shape is enough once P-6 has swept the shapes: reuses P-6's `n_blocks=3, width=37`
        /// (two rate-aligned interior blocks plus one short, non-aligned final block).
        #[test]
        fn streamed_commit_matches_cpu_oracle_kb() {
            use mle_core::{
                config::koala_bear_poseidon2::default_koalabear_hasher,
                prover::stacked_pcs::{
                    rs_code_matrix as host_rs, stacked_matrix as host_stacked_matrix,
                    ColMajorMerkleTree,
                },
            };

            let (l_skip, n_stack, log_blowup, k_whir) = (2usize, 2usize, 1usize, 1usize);
            let (n_blocks, width) = (3usize, 37usize);
            let (values, mat, layout) = full_height_trace(l_skip, n_stack, width);
            let refs: Vec<&DeviceMatrix<KoalaBear>> = vec![&mat];
            let rows_per_query = 1usize << k_whir;

            let streamed = rs_code_streamed_commit::<KoalaBear, KoalaBearPoseidon2MerkleHash>(
                log_blowup,
                &layout,
                &refs,
                rows_per_query,
                n_blocks,
            )
            .unwrap();

            // Independent CPU oracle: host stack -> host RS-encode -> ColMajorMerkleTree::new.
            // None of this touches cuda-mle's own code.
            let host_traces = [ColMajorMatrix::new(values, width)];
            let host_refs: Vec<&ColMajorMatrix<KoalaBear>> = host_traces.iter().collect();
            let host_stacked = host_stacked_matrix(l_skip, n_stack, &host_refs).unwrap().0;
            let host_codeword = host_rs(l_skip, log_blowup, &host_stacked).unwrap();
            let hasher = default_koalabear_hasher();
            let cpu_tree = ColMajorMerkleTree::new(&hasher, host_codeword, rows_per_query).unwrap();

            assert_eq!(
                streamed.digest_layers.len(),
                cpu_tree.digest_layers().len(),
                "layer COUNT differs — a dropped layer must not pass vacuously"
            );
            for (i, (s, c)) in streamed
                .digest_layers
                .iter()
                .zip_eq(cpu_tree.digest_layers())
                .enumerate()
            {
                assert_eq!(&s.to_host().unwrap(), c, "digest layer {i} != CPU oracle");
            }
            assert_eq!(
                streamed.root(),
                cpu_tree.root().unwrap(),
                "root != CPU oracle"
            );
        }
    }

    /// The pruned gather's compact residue buffer is addressed by slot, not by query, so the
    /// kernel is only correct if `residues[qslots[qi]]` is query `qi`'s own low-14-bit residue.
    /// Cheap to state here; otherwise a wrong mapping surfaces only as a verification failure
    /// minutes into a proof.
    #[test]
    fn residue_slots_shares_one_slot_per_distinct_low_14_bits() {
        const FIBER: usize = 1 << 14;
        // 5 and 5 + 3*FIBER are siblings (same residue); so are 7 and 7 + FIBER.
        let queries = [5usize, 7, 5 + 3 * FIBER, 7 + FIBER, 9];
        let (residues, qslots) = residue_slots(&queries);

        assert_eq!(
            residues,
            vec![5, 7, 9],
            "one slot per residue, in first-seen order"
        );
        assert_eq!(
            qslots,
            vec![0, 1, 0, 1, 2],
            "siblings resolve to the same slot"
        );
        assert!(residues.len() <= qslots.len());
        for (qi, &q) in queries.iter().enumerate() {
            assert_eq!(
                residues[qslots[qi] as usize],
                (q & (FIBER - 1)) as u32,
                "slot for query {qi} does not hold its residue"
            );
        }
    }
}
