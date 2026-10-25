use std::{iter::zip, sync::Arc};

use crate::runtime::{
    copy::{MemCopyD2H, MemCopyH2D},
    d_buffer::DeviceBuffer,
    memory_manager::MemTracker,
};
use itertools::Itertools;
use mle_core::{
    poly::matrix::MatrixDimensions,
    proof::{MerkleProof, WhirProof},
    SystemParams,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, TwoAdicField};
use p3_util::log2_strict_usize;
use tracing::instrument;

use crate::{
    base::DeviceMatrix,
    cuda::field_kernels::FieldKernels,
    hash_scheme::GpuHashScheme,
    merkle_tree::{MerkleTreeConstructor, MerkleTreeGpu},
    ntt_field::GpuNttField,
    sponge::GpuFiatShamirTranscript,
    stacked_pcs::{rs_code_matrix, rs_code_streamed_open},
    stacked_reduction::StackedPcsData2,
    WhirProverError,
};

/// One unstacked trace, as `whir_algebraic_batch_traces_kernel` needs to see it.
///
/// Field order and types must match `struct BatchingTracePacket` in `cuda/src/whir.cu`; the two new
/// shift fields are appended so the shared prefix stays put.
///
/// The kernel indexes with shift/mask rather than div/mod (nvcc lowers a runtime 64-bit integer
/// division to a slow software helper), which is only valid for power-of-two divisors. Rather than
/// have the kernel re-derive `lifted_height` and `stride` from `skip_domain` -- a formula that then
/// has to stay in lockstep with the host's power-of-two checks -- the host derives both here and
/// passes only their `log2`. `skip_domain` is consequently not a kernel argument at all.
#[repr(C)]
pub struct BatchingTracePacket<Val: Copy> {
    /// Device address of the trace data
    ptr: *const Val,
    /// Trace height
    height: u32,
    /// Trace width
    width: u32,
    /// First stacked-matrix row this trace occupies
    stacked_row_start: u32,
    /// Index in mu powers
    mu_idx: u32,
    /// `log2(max(height, skip_domain))` -- the trace's height once lifted to the skip domain.
    lifted_height_shift: u32,
    /// `log2(max(skip_domain / height, 1))` -- the stacking stride for this trace; 0 when the trace
    /// is at least as tall as the skip domain.
    stride_shift: u32,
}

/// `log2` of a power of two, for deriving the packet shifts.
///
/// Panics on a non-power-of-two rather than rounding: the kernel's shift/mask indexing is only
/// equivalent to div/mod for exact powers of two, so a violated assumption has to stop the proof
/// instead of silently producing a wrong batched column.
fn log2_pow2(what: &str, value: usize) -> u32 {
    assert!(
        value.is_power_of_two(),
        "whir batch: {what} {value} is not a power of two; the batch kernel's shift/mask \
         indexing requires it"
    );
    value.trailing_zeros()
}

#[instrument(
    name = "prover.openings.whir",
    level = "info",
    skip_all,
    fields(phase = "prover")
)]
pub fn prove_whir_opening_gpu<FK, HS, TS>(
    params: &SystemParams,
    transcript: &mut TS,
    mut commits_data: Vec<StackedPcsData2<FK::Val, HS::Digest>>,
    u: &[FK::ValExt],
) -> Result<WhirProof<HS::SC>, WhirProverError>
where
    FK: FieldKernels,
    FK::ValExt: BasedVectorSpace<FK::Val>,
    HS: GpuHashScheme<BaseField = FK::Val, ExtField = FK::ValExt>,
    TS: GpuFiatShamirTranscript<HS::SC>,
    HS::MerkleHash: MerkleTreeConstructor,
{
    let mem_tracker = MemTracker::start("prover.prove_whir_opening");
    let l_skip = params.l_skip;
    let log_blowup = params.log_blowup;
    let k_whir = params.k_whir();
    let wparams = params.whir();
    let log_fin_len = params.log_final_poly_len();

    // [whirprof] attribute whir_open's run-to-run jitter (grind vs merkle
    // query extraction vs the rest). All timed calls block on D2H already, so accumulating
    // wall time adds no syncs. OFF by default; WHIR_PROF=1 to enable.
    let whir_prof = std::env::var("WHIR_PROF").is_ok();
    let t_whir_total = std::time::Instant::now();
    let mut us_grind = 0u128;
    let mut us_merkle_q = 0u128;

    let stacked_rows = commits_data[0].layout().height();
    debug_assert!(commits_data
        .iter()
        .all(|commit_data| commit_data.layout().height() == stacked_rows));
    let mut m = log2_strict_usize(stacked_rows);
    assert_eq!(m, u.len());
    debug_assert!(m >= l_skip);

    // Grind before drawing the μ batching challenge; the proof of work boosts the soundness of
    // that first batching step.
    let t_g = std::time::Instant::now();
    let mu_pow = transcript
        .grind_gpu(wparams.mu_pow_bits)
        .map_err(WhirProverError::MuGrind)?;
    us_grind += t_g.elapsed().as_micros();
    // μ combines the \hat{q}_j codewords into one, and that happens before WHIR proper starts.
    let mu_challenge = transcript.sample_ext();
    let n_commits = commits_data.len();

    // Base-field limbs per extension element.
    let d_ef = <FK::ValExt as BasedVectorSpace<FK::Val>>::DIMENSION;
    // `whir_algebraic_batch_traces_kernel` writes its result back as a hard-coded 4 base-field
    // limbs per row (`for (int i = 0; i < 4; i++)` in cuda/src/whir.cu) while everything on this
    // side sizes buffers by `d_ef`. Both live fields have D == 4, so the two agree today; a third
    // field with a different extension degree would silently write the wrong number of limbs, so
    // pin the assumption where it is introduced rather than let it corrupt a buffer.
    assert_eq!(
        d_ef, 4,
        "whir_algebraic_batch_traces_kernel hard-codes 4 base-field limbs per row; \
         extension degree {d_ef} needs the kernel updated in lockstep"
    );
    let mut ple_buf = DeviceBuffer::<FK::Val>::with_capacity(stacked_rows * d_ef);
    // Combine every committed column into one extension-field column with powers of μ, so a
    // single column is left to interpolate.
    {
        let mut pkts: Vec<BatchingTracePacket<FK::Val>> = Vec::new();
        let mut width_so_far = 0u32;
        for stacked_data in &commits_data {
            let stack_layout = stacked_data.layout();
            for (mat, &start_col) in zip(&stacked_data.traces, &stack_layout.mat_starts) {
                let col_slice = stack_layout.sorted_cols[start_col].slice;
                // Sole definition of the stacking geometry the kernel indexes with; see
                // [`BatchingTracePacket`]. `height` (== the stacked height) is already known to be
                // a power of two -- `log2_strict_usize` above would have panicked otherwise.
                let skip_domain = 1usize << l_skip;
                let trace_height = mat.height();
                // Checked for its own sake: `skip_domain / trace_height` truncates for a
                // non-power-of-two height, which would make `stride` quietly wrong rather than
                // caught by the `log2_pow2` below.
                assert!(
                    trace_height.is_power_of_two(),
                    "whir batch: trace height {trace_height} is not a power of two"
                );
                let lifted_height_shift = log2_pow2("lifted_height", trace_height.max(skip_domain));
                let stride_shift = log2_pow2("stride", (skip_domain / trace_height).max(1));
                let pkt = BatchingTracePacket {
                    ptr: mat.buffer().as_ptr(),
                    height: mat.height() as u32,
                    width: mat.width() as u32,
                    stacked_row_start: col_slice.row_idx as u32,
                    mu_idx: width_so_far + col_slice.col_idx as u32,
                    lifted_height_shift,
                    stride_shift,
                };
                pkts.push(pkt);
            }
            width_so_far += stack_layout.width() as u32;
        }
        let mu_pw = mu_challenge
            .powers()
            .take(width_so_far as usize)
            .collect_vec();
        let d_mu_pw = mu_pw.to_device()?;
        let d_packets = pkts.to_device()?;
        // SAFETY:
        // - `d_mu_pw` holds one power of μ per column, `width_so_far` in all.
        // - `ple_buf` was allocated with `stacked_rows * d_ef` base-field slots.
        // - every packet in `d_packets` was built above from a live trace and its stacked row.
        unsafe {
            FK::whir_algebraic_batch_traces(&mut ple_buf, &d_packets, &d_mu_pw)
                .map_err(WhirProverError::AlgebraicBatch)?;
        }
        for stacked_data in &mut commits_data {
            // A commit whose tree caches the RS codeword matrix no longer needs its traces;
            // release them to free device memory.
            if stacked_data.inner.tree.backing_matrix.is_some() {
                stacked_data.traces.clear();
            }
        }
    } // traces of commits with a cached codeword matrix are released by now

    // Compute \hat{f} coefficients.
    let mut poly_coeffs = DeviceBuffer::<FK::ValExt>::with_capacity(stacked_rows);
    // Step 1: iDFT per chunk of size 2^l_skip (`batch_ntt_small` with is_intt = true).
    unsafe {
        let npoly = ple_buf.len() >> l_skip;
        FK::Val::batch_ntt_small(&mut ple_buf, l_skip, npoly, true)
            .map_err(WhirProverError::CustomBatchIntt)?;
    }
    // SAFETY: `ple_buf` holds `stacked_rows * d_ef` base elements and `poly_coeffs` has
    // `stacked_rows` extension slots.
    unsafe {
        FK::transpose_fp_to_fpext_vec(&mut poly_coeffs, &ple_buf)
            .map_err(WhirProverError::Transpose)?;
    }
    drop(ple_buf);
    // Step 2: Within-chunk zeta (stages 0..l_skip) via the GPU extension-field interpolate. The
    // former `if FK::use_cpu_gkr()` CPU fallback here was dead — `use_cpu_gkr()` returns false
    // (KoalaBear overrides it explicitly after the recip_b0 fix) — and its two arms computed the
    // same field additions anyway, so this is
    // semantics-preserving. `mle_interpolate_stage_ext` is correct and live (verified by
    // `kb_arithmetic_test::test_kb_mle_interpolate_vs_cpu`).
    //
    // Where the "KB uses CPU" story came from: `GpuNttField` carries a same-named,
    // zero-call-site `use_cpu_gkr()` that *does* return true for KoalaBear, read fifteen lines
    // from the `FieldKernels` one that means something else entirely (a GKR fractional-sumcheck
    // decision). That method is deleted in this commit so the collision cannot mislead again.
    // The kernel is covered against the CPU prover by `tests::test_kb_whir_proof_matches_cpu`.
    for i in 0..l_skip {
        let step = 1u32 << i;
        unsafe {
            FK::mle_interpolate_stage_ext(&mut poly_coeffs, step, false)
                .map_err(|error| WhirProverError::MleInterpolate { error, step })?;
        }
    }

    debug_assert_eq!((m - log_fin_len) % k_whir, 0);
    let n_rounds = (m - log_fin_len) / k_whir;
    assert!(n_rounds > 0);

    // `eq_moments` tracks the moments of \hat{w}: for each subset T of the variables,
    // M[T] = \sum_{x \supseteq T} \hat{w}(x).
    // The starting weight is \hat{w} = mobius_eq(u, -), whose moment table is simply eq(u, -).
    let mut eq_moments = DeviceBuffer::<FK::ValExt>::with_capacity(1 << m);
    unsafe {
        FK::evals_eq_hypercube(&mut eq_moments, u).map_err(WhirProverError::EvalEq)?;
    }

    let mut sc_polys: Vec<[FK::ValExt; 2]> = vec![];
    let mut cw_commits = vec![];
    let mut ood_vals = vec![];
    // Indexed as [commit][query][row of the queried leaf][column].
    let mut r0_rows: Vec<Vec<Vec<Vec<FK::Val>>>> = vec![vec![]; n_commits];
    let mut r0_proofs: Vec<Vec<MerkleProof<HS::Digest>>> = vec![];
    let mut cw_rows: Vec<Vec<Vec<FK::ValExt>>> = vec![];
    let mut cw_proofs: Vec<Vec<MerkleProof<HS::Digest>>> = vec![];
    let mut fold_pows = vec![];
    let mut query_pows = vec![];
    let mut prev_tree = None;
    let mut log_dom = m + log_blowup;
    let mut fin_poly = None;

    let mut round_evals_dev = DeviceBuffer::<FK::ValExt>::with_capacity(2);
    let mut d_sc_tmp = DeviceBuffer::<FK::ValExt>::new();

    mem_tracker.tracing_info("before_whir_rounds");
    // `commits_data` (with its traces and trees) is cleared once WHIR round 0 has opened it.
    for (whir_round, round_cfg) in wparams.rounds.iter().enumerate() {
        let last = whir_round == n_rounds - 1;
        let t_wr_sc = std::time::Instant::now();
        // k_whir sumcheck rounds over `sum_{x in H_m} \hat{w}(\hat{f}(x), x)`.
        for round in 0..k_whir {
            // The live length is 2^(m - round); `poly_coeffs.len()` may exceed it.
            let live_len = 1 << (m - round);
            debug_assert!(
                poly_coeffs.len() >= live_len,
                "f_coeffs has length {}, expected 2^{} for m={m}, round={round}",
                poly_coeffs.len(),
                m - round
            );
            debug_assert!(eq_moments.len() >= live_len);
            let half_len = live_len / 2;

            let tmp_need =
                FK::whir_sumcheck_coeff_moments_required_temp_buffer_size(live_len as u32);
            if d_sc_tmp.len() < tmp_need as usize {
                d_sc_tmp = DeviceBuffer::<FK::ValExt>::with_capacity(tmp_need as usize);
            }
            let mut poly_coeffs_next = DeviceBuffer::<FK::ValExt>::with_capacity(half_len);
            let mut eq_moments_next = DeviceBuffer::<FK::ValExt>::with_capacity(half_len);
            // SAFETY:
            // - `round_evals_dev` holds 2 elements.
            // - `d_sc_tmp` was grown above to the kernel's required temp size for `live_len`.
            unsafe {
                FK::whir_sumcheck_coeff_moments_round(
                    &poly_coeffs,
                    &eq_moments,
                    &mut round_evals_dev,
                    &mut d_sc_tmp,
                    live_len as u32,
                )
                .map_err(|error| WhirProverError::SumcheckMleRound {
                    error,
                    whir_round,
                    round,
                })?;
            }
            let round_evals = round_evals_dev.to_host()?;
            for &round_eval in &round_evals {
                transcript.observe_ext(round_eval);
            }
            sc_polys.push(round_evals.try_into().unwrap());

            let t_g = std::time::Instant::now();
            fold_pows.push(
                transcript
                    .grind_gpu(wparams.folding_pow_bits)
                    .map_err(WhirProverError::FoldingGrind)?,
            );
            us_grind += t_g.elapsed().as_micros();
            let fold_challenge = transcript.sample_ext();

            // Fold \hat{f} (coefficients) and \hat{w} (moments) at `fold_challenge`.
            // SAFETY:
            // - the inputs hold at least `live_len` elements.
            // - the outputs hold `live_len / 2` elements.
            unsafe {
                FK::whir_fold_coeffs_and_moments(
                    &poly_coeffs,
                    &eq_moments,
                    &mut poly_coeffs_next,
                    &mut eq_moments_next,
                    fold_challenge,
                    live_len as u32,
                )
                .map_err(|error| WhirProverError::FoldMle {
                    error,
                    whir_round,
                    round,
                })?;
            }
            poly_coeffs = poly_coeffs_next;
            eq_moments = eq_moments_next;
        }
        let us_wr_sc = t_wr_sc.elapsed().as_micros();
        let t_wr_cm = std::time::Instant::now();
        // After k_whir folds, `poly_coeffs` holds the coefficients of
        // \hat{g} = \hat{f}(\alpha, \cdot), with \alpha this round's folding challenges. Commit to
        // RS(\hat{g}) unless this is the last round, which sends \hat{g} itself.
        let live_len = 1 << (m - k_whir);
        debug_assert!(poly_coeffs.len() >= live_len);
        debug_assert_eq!(
            std::mem::size_of::<FK::ValExt>() / std::mem::size_of::<FK::Val>(),
            d_ef
        );
        let mut g_coeffs_dev = DeviceBuffer::<FK::Val>::with_capacity(live_len * d_ef);
        // SAFETY: `g_coeffs_dev` has `live_len * d_ef` slots, enough to split the `live_len`
        // extension coefficients into `d_ef` (= 4) base-field columns.
        unsafe {
            FK::split_ext_to_base_col_major_matrix(
                &mut g_coeffs_dev,
                &poly_coeffs,
                live_len as u64,
                live_len as u32,
            )
            .map_err(|error| WhirProverError::SplitExtPoly { error, whir_round })?;
        }
        let (next_tree, ood_pt) = if !last {
            let cw_h = 1 << (log_dom - 1);
            // RS(\hat{g}) evaluated on \mathcal{L}^{(2)}, stored as `d_ef` base-field columns.
            let g_code = DeviceBuffer::<FK::Val>::with_capacity(d_ef * cw_h);
            // SAFETY:
            // - `g_coeffs_dev` is one EF polynomial viewed as `d_ef` base-field columns of
            //   2^{m-k_whir} coefficients each.
            // - Each column is zero-padded to 2^{log_dom - 1} rows, the RS domain size; padding
            //   the base columns is the same as padding the EF polynomial.
            unsafe {
                FK::batch_expand_pad(
                    g_code.as_mut_ptr(),
                    g_coeffs_dev.as_ptr(),
                    d_ef as u32,
                    cw_h as u32,
                    live_len as u32,
                )
                .map_err(|error| WhirProverError::BatchExpandPad { error, whir_round })?;

                FK::Val::batch_ntt(
                    &g_code,
                    (log_dom - 1) as u32,
                    0u32,
                    d_ef as u32,
                    true,
                    false,
                );
            }

            let next_tree = MerkleTreeGpu::<FK::Val, HS::Digest>::new_with_hash::<HS::MerkleHash>(
                DeviceMatrix::new(Arc::new(g_code), cw_h, d_ef),
                1 << k_whir,
                true,
            )
            .map_err(WhirProverError::MerkleTree)?;
            let root_g = next_tree.root();
            transcript.observe_commit(root_g);
            cw_commits.push(root_g);

            let ood_pt = transcript.sample_ext();
            // SAFETY:
            // - `g_coeffs_dev` holds the `2^{m-k_whir}` coefficients of `\hat{g}`.
            // - it is laid out column-major, one base-field column per limb.
            let g_at_z = unsafe {
                FK::eval_poly_ext_at_point_from_base(&g_coeffs_dev, 1 << (m - k_whir), ood_pt)
                    .map_err(|error| WhirProverError::EvalPolyAtPoint { error, whir_round })?
            };
            transcript.observe_ext(g_at_z);
            ood_vals.push(g_at_z);

            (Some(next_tree), Some(ood_pt))
        } else {
            // Observe the final poly
            debug_assert_eq!(log_fin_len, m - k_whir);
            let fin_len = 1 << log_fin_len;
            let flat = g_coeffs_dev.to_host()?;
            debug_assert_eq!(flat.len(), d_ef * fin_len);
            let mut fin_coeffs = Vec::with_capacity(fin_len);
            for i in 0..fin_len {
                let cf = FK::ValExt::from_basis_coefficients_fn(|j| flat[j * fin_len + i]);
                transcript.observe_ext(cf);
                fin_coeffs.push(cf);
            }
            fin_poly = Some(fin_coeffs);
            (None, None)
        };

        // `domain_gen` generates `\mathcal{L}^{(2^k)}`, the RS domain raised to the 2^k-th power.
        let us_wr_cm = t_wr_cm.elapsed().as_micros();
        let t_wr_q = std::time::Instant::now();
        let domain_gen = FK::Val::two_adic_generator(log_dom - k_whir);
        let n_q = round_cfg.num_queries;
        let mut q_idx = Vec::with_capacity(n_q);
        let t_g = std::time::Instant::now();
        query_pows.push(
            transcript
                .grind_gpu(wparams.query_phase_pow_bits)
                .map_err(WhirProverError::QueryPhaseGrind)?,
        );
        us_grind += t_g.elapsed().as_micros();
        // Draw every query position up front; each one is a leaf index of the Merkle tree.
        for _ in 0..n_q {
            let qi = transcript.sample_bits(log_dom - k_whir);
            q_idx.push(qi as usize);
        }
        if !last {
            cw_rows.push(vec![]);
            cw_proofs.push(vec![]);
        }
        if whir_round == 0 {
            // Merkle proofs for in-domain samples (uses tree digest layers only — no matrix). The
            // immutable `tree_refs` borrow is scoped so the opening loop below can take `&mut`.
            let (qstride, rows_per_q) = {
                let tree_refs: Vec<&MerkleTreeGpu<FK::Val, HS::Digest>> = commits_data
                    .iter()
                    .map(|commit_data| &commit_data.inner.tree)
                    .collect();
                let t_mq = std::time::Instant::now();
                r0_proofs = <MerkleTreeGpu<FK::Val, HS::Digest>>::batch_query_merkle_proofs(
                    tree_refs.as_slice(),
                    &q_idx,
                )
                .map_err(WhirProverError::MerkleTree)?;
                us_merkle_q += t_mq.elapsed().as_micros();
                let qstride = tree_refs[0].query_stride();
                debug_assert!(
                    tree_refs
                        .iter()
                        .all(|opened_tree| opened_tree.query_stride() == qstride),
                    "Merkle trees don't have same layer size"
                );
                let rows_per_q = tree_refs[0].rows_per_query;
                debug_assert!(
                    tree_refs
                        .iter()
                        .all(|opened_tree| opened_tree.rows_per_query == rows_per_q),
                    "Merkle trees don't have same rows_per_query"
                );
                (qstride, rows_per_q)
            };

            // Streaming open (RS_STREAM_BLOCKS=N): open the queried rows per commit without ever
            // materializing the full RS codeword matrix (WHIR round 0's biggest allocation). Falls
            // back to the monolithic re-derive + batch_open_rows when the gate is off or a backing
            // matrix is already cached. `opened_cat` is per-commit → per-query concatenated rows.
            let sblk = crate::rs_stream::blocks();
            let opened_cat: Vec<Vec<Vec<FK::Val>>> = if let Some(nblk) = sblk {
                let self_check = crate::rs_stream::verify();
                let mut opened_per = Vec::with_capacity(commits_data.len());
                for commit_data in &mut commits_data {
                    let concat_rows = if let Some(backing_mat) =
                        commit_data.inner.tree.backing_matrix.as_ref()
                    {
                        MerkleTreeGpu::<FK::Val, HS::Digest>::batch_open_rows(
                            &[backing_mat],
                            &q_idx,
                            qstride,
                            rows_per_q,
                        )
                        .map_err(WhirProverError::MerkleTree)?
                        .pop()
                        .unwrap()
                    } else {
                        let trace_refs = commit_data.traces.iter().collect_vec();
                        debug_assert!(!trace_refs.is_empty());
                        let str_rows = rs_code_streamed_open::<FK::Val>(
                            log_blowup,
                            commit_data.layout(),
                            &trace_refs,
                            &q_idx,
                            qstride,
                            rows_per_q,
                            nblk,
                        )
                        .map_err(WhirProverError::RsCodeMatrix)?;
                        if self_check {
                            let mono_m = rs_code_matrix(
                                log_blowup,
                                commit_data.layout(),
                                &trace_refs,
                                &commit_data.inner.matrix,
                            )
                            .map_err(WhirProverError::RsCodeMatrix)?;
                            let mono_rows = MerkleTreeGpu::<FK::Val, HS::Digest>::batch_open_rows(
                                &[&mono_m],
                                &q_idx,
                                qstride,
                                rows_per_q,
                            )
                            .map_err(WhirProverError::MerkleTree)?
                            .pop()
                            .unwrap();
                            if mono_rows != str_rows {
                                return Err(WhirProverError::RsCodeMatrix(
                                    crate::RsCodeMatrixError::StreamOpenMismatch,
                                ));
                            }
                            tracing::info!(target: "bench", "[streamverify] OK: whir opened rows == monolithic");
                        }
                        str_rows
                    };
                    commit_data.traces.clear();
                    opened_per.push(concat_rows);
                }
                opened_per
            } else {
                // Vector to hold owned copies of backing matrices regenerated when not cached.
                let mut owned_mats = vec![None; commits_data.len()];
                let mut mat_refs = Vec::with_capacity(commits_data.len());
                for (commit_data, slot_mat) in zip(&mut commits_data, &mut owned_mats) {
                    if let Some(backing_mat) = commit_data.inner.tree.backing_matrix.as_ref() {
                        mat_refs.push(backing_mat);
                    } else {
                        let stack_layout = commit_data.layout();
                        let trace_refs = commit_data.traces.iter().collect_vec();
                        debug_assert!(!trace_refs.is_empty());
                        let regen = rs_code_matrix(
                            log_blowup,
                            stack_layout,
                            &trace_refs,
                            &commit_data.inner.matrix,
                        )
                        .map_err(WhirProverError::RsCodeMatrix)?;
                        commit_data.traces.clear();
                        *slot_mat = Some(regen);
                        mat_refs.push(slot_mat.as_ref().unwrap());
                    }
                }
                MerkleTreeGpu::<FK::Val, HS::Digest>::batch_open_rows(
                    &mat_refs, &q_idx, qstride, rows_per_q,
                )
                .map_err(WhirProverError::MerkleTree)?
            };

            r0_rows = opened_cat
                .into_iter()
                .map(|commit_rows| {
                    commit_rows
                        .into_iter()
                        .map(|concat_rows| {
                            let w_row = concat_rows.len() / rows_per_q;
                            concat_rows
                                .chunks_exact(w_row)
                                .map(|one_row| one_row.to_vec())
                                .collect()
                        })
                        .collect()
                })
                .collect();
            debug_assert_eq!(
                Arc::strong_count(&commits_data[0].inner),
                1,
                "common_main_pcs_data should be owned"
            );
            commits_data.clear(); // this drops common_main_pcs_data
            mem_tracker.tracing_info("after_initial_whir_round");
        } else {
            let opened_tree: &MerkleTreeGpu<FK::Val, HS::Digest> = prev_tree.as_ref().unwrap();
            let t_mq = std::time::Instant::now();
            cw_proofs[whir_round - 1] =
                <MerkleTreeGpu<FK::Val, HS::Digest>>::batch_query_merkle_proofs(
                    &[opened_tree],
                    &q_idx,
                )
                .map_err(WhirProverError::MerkleTree)?
                .pop()
                .expect("exactly 1 tree");
            us_merkle_q += t_mq.elapsed().as_micros();
            cw_rows[whir_round - 1] = MerkleTreeGpu::<FK::Val, HS::Digest>::batch_open_rows(
                &[opened_tree.backing_matrix.as_ref().unwrap()],
                &q_idx,
                opened_tree.query_stride(),
                opened_tree.rows_per_query,
            )
            .map_err(WhirProverError::MerkleTree)?
            .pop()
            .unwrap()
            .into_iter()
            // Reconstitute each base-field row into extension-field elements: group every
            // `D` base coefficients into one `ValExt`.
            .map(|rowv: Vec<FK::Val>| {
                let dim = <FK::ValExt as p3_field::BasedVectorSpace<FK::Val>>::DIMENSION;
                rowv.chunks_exact(dim)
                    .map(|limbs| {
                        FK::ValExt::from_basis_coefficients_slice(limbs)
                            .expect("chunks_exact yields DIMENSION coefficients")
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        }
        prev_tree = next_tree;

        // The verifier draws a gamma even after the final round (it keeps its code uniform),
        // so the transcript must sample one here too; the moments are only refreshed when
        // another round follows.
        let batch_gamma = transcript.sample_ext();

        if !last {
            // Refresh the \hat{w} moments with the out-of-domain point and the queries:
            // M(T) += γ·z0^T + Σ_i γ^{i+1}·z_i^T, where z^T = Π_{t ∈ T} z^{2^t}.
            let lh = (m - k_whir) as u32;
            let z0_point = ood_pt.unwrap();
            let z_points_sq = q_idx
                .iter()
                .map(|&qi| domain_gen.exp_u64(qi as u64))
                .collect_vec();

            let mut z0_sq = Vec::with_capacity(lh as usize);
            let mut z0_cur = z0_point;
            for _ in 0..lh {
                z0_sq.push(z0_cur);
                z0_cur = z0_cur.square();
            }

            let mut zs_sq = Vec::with_capacity(n_q * lh as usize);
            for z_point in &z_points_sq {
                let mut zp_cur = *z_point;
                for _ in 0..lh {
                    zs_sq.push(zp_cur);
                    zp_cur = zp_cur.square();
                }
            }

            let d_z0_sq = z0_sq.to_device()?;
            let d_zs_sq = zs_sq.to_device()?;
            unsafe {
                FK::w_moments_accumulate(
                    &mut eq_moments,
                    &d_z0_sq,
                    &d_zs_sq,
                    batch_gamma,
                    n_q as u32,
                    lh,
                )
                .map_err(|error| WhirProverError::WMomentsAccumulate { error, whir_round })?;
            }
        }

        if whir_prof {
            let _ = crate::runtime::stream::current_stream_sync();
            tracing::info!(
                target: "bench",
                "[whirprof] round={whir_round} sumcheck={us_wr_sc}us commit={us_wr_cm}us \
                 query={}us",
                t_wr_q.elapsed().as_micros()
            );
        }
        m -= k_whir;
        log_dom -= 1;
    }

    if whir_prof {
        tracing::info!(
            target: "bench",
            "[whirprof] grind={us_grind}us merkle_q={us_merkle_q}us total={}us",
            t_whir_total.elapsed().as_micros()
        );
    }
    mem_tracker.emit_metrics();
    Ok(WhirProof {
        mu_pow_witness: mu_pow,
        whir_sumcheck_polys: sc_polys,
        codeword_commits: cw_commits,
        ood_values: ood_vals,
        folding_pow_witnesses: fold_pows,
        query_phase_pow_witnesses: query_pows,
        initial_round_opened_rows: r0_rows,
        initial_round_merkle_proofs: r0_proofs,
        codeword_opened_values: cw_rows,
        codeword_merkle_proofs: cw_proofs,
        final_poly: fin_poly.unwrap(),
    })
}

// No inline `mod tests` (WHIR e2e) here: those tests need helpers mle-core does not provide.
