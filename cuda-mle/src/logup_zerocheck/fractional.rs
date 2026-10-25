use std::{array::from_fn, convert::TryInto, env, ffi::c_void, mem::transmute};

use crate::runtime::{
    copy::{cuda_memcpy, MemCopyD2H},
    d_buffer::DeviceBuffer,
    memory_manager::MemTracker,
};
use mle_core::{
    poly::{eval_eq_mle, interpolate_linear_at_01, interpolate_quadratic_at_012},
    proof::GkrLayerClaims,
    prover::fractional_sumcheck_gkr::{fractional_sumcheck, Frac, FracSumcheckProof},
    FiatShamirTranscript, StarkProtocolConfig,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_util::log2_strict_usize;
use tracing::{debug_span, instrument};

use super::errors::FractionalSumcheckError;
use crate::{cuda::field_kernels::FieldKernels, poly::SqrtEqLayersFor};

const ROUND_POLY_DEG: usize = 3;
const PRECOMPUTE_WINDOW_VARS: usize = 3;
const PRECOMPUTE_DEFAULT_MIN_VARS: usize = 22;

/// Where a fused compute+fold round reads its input and writes its folded output.
#[derive(Debug, Clone, Copy)]
enum FoldDestination {
    /// Reads the segment tree, writes the folded half into the scratch buffer.
    TreeIntoScratch,
    /// Reads the scratch buffer, writes the folded half back into the segment tree.
    ScratchIntoTree,
    /// Folds the segment tree onto itself.
    TreeInPlace,
    /// Folds the scratch buffer onto itself.
    ScratchInPlace,
}

/// Tracks which of the two buffers (segment tree or scratch) currently holds the live
/// fractions during the inner rounds of one GKR layer, and decides per round whether the
/// fold can go out-of-place (ping-pong) or has to happen in place.
struct PingPongPlanner {
    /// Whether the live fractions are in the scratch buffer (`false` = segment tree).
    live_in_scratch: bool,
    /// How many fractions the scratch buffer can hold.
    scratch_capacity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InnerRoundMode {
    FusedFold,
    WindowedPrecompute,
}

const TAIL_TILE_MAX: usize = 4096;
const TAIL_TILE_MIN: usize = 256;
const DEFAULT_MIN_TAIL_BLOCKS: usize = 64;
const DEFAULT_TARGET_TAIL_BLOCKS: usize = 1024;

impl PingPongPlanner {
    /// Starts with the live fractions in the segment tree.
    fn new(scratch_capacity: usize) -> Self {
        Self {
            live_in_scratch: false,
            scratch_capacity,
        }
    }

    /// Whether a folded output of `folded_len` fractions fits into the scratch buffer.
    fn fits_in_scratch(&self, folded_len: usize) -> bool {
        folded_len <= self.scratch_capacity
    }

    /// Picks source/destination for the next fused compute+fold round.
    ///
    /// On the last outer round the planner alternates buffers whenever the output fits, so
    /// the kernel sees non-aliasing pointers. On earlier outer rounds the segment tree must
    /// stay intact for the next revert, so data moves into scratch and stays there.
    fn plan_fused_round(&mut self, folded_len: usize, last_outer_round: bool) -> FoldDestination {
        let fits_in_scratch = self.fits_in_scratch(folded_len);

        if last_outer_round {
            if fits_in_scratch {
                // alternate: write into whichever buffer is not live
                if self.live_in_scratch {
                    self.live_in_scratch = false;
                    FoldDestination::ScratchIntoTree
                } else {
                    self.live_in_scratch = true;
                    FoldDestination::TreeIntoScratch
                }
            } else {
                // output too large for scratch, so this early round must still be in the tree
                debug_assert!(
                    !self.live_in_scratch,
                    "in-place path requires data in layer"
                );
                FoldDestination::TreeInPlace
            }
        } else {
            // tree must survive for the revert of the next outer round
            if self.live_in_scratch {
                // scratch already live: keep folding it in place
                FoldDestination::ScratchInPlace
            } else {
                // first move: tree -> scratch (out-of-place)
                self.live_in_scratch = true;
                FoldDestination::TreeIntoScratch
            }
        }
    }

    /// Picks source/destination for the trailing standalone fold after the last challenge.
    fn plan_final_fold(&self, last_outer_round: bool) -> FoldDestination {
        if last_outer_round {
            if self.live_in_scratch {
                FoldDestination::ScratchInPlace
            } else {
                FoldDestination::TreeInPlace
            }
        } else {
            // earlier outer rounds never fold in the tree, it is still needed for the revert
            if self.live_in_scratch {
                FoldDestination::ScratchInPlace
            } else {
                FoldDestination::TreeIntoScratch
            }
        }
    }
}

fn windowed_precompute_requested() -> bool {
    !matches!(
        env::var("MLE_CUDA_GKR_PRECOMPUTE_M"),
        Ok(val) if matches!(val.as_str(), "0" | "false" | "FALSE" | "no" | "NO")
    )
}

fn min_tail_blocks_from_env() -> usize {
    env::var("MLE_CUDA_GKR_PRECOMPUTE_M_MIN_BLOCKS")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MIN_TAIL_BLOCKS)
        .max(1)
}

fn count_tail_blocks(vars_left: usize, window_vars: usize, tile_len: usize) -> usize {
    let tail_vars = vars_left - window_vars;
    (1usize << tail_vars).div_ceil(tile_len)
}

fn target_tail_blocks_from_env() -> usize {
    env::var("MLE_CUDA_GKR_PRECOMPUTE_M_TARGET_BLOCKS")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(DEFAULT_TARGET_TAIL_BLOCKS)
        .max(1)
}

fn tail_tile_override_from_env() -> Option<usize> {
    env::var("MLE_CUDA_GKR_PRECOMPUTE_M_TAIL_TILE")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .map(|v| v.clamp(TAIL_TILE_MIN, TAIL_TILE_MAX))
}

fn min_window_vars_from_env() -> usize {
    env::var("MLE_CUDA_GKR_PRECOMPUTE_M_MIN_N")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(PRECOMPUTE_DEFAULT_MIN_VARS)
}

fn pick_tail_tile(
    vars_left: usize,
    window_vars: usize,
    min_tail_blocks: usize,
    target_tail_blocks: usize,
    tile_override: Option<usize>,
) -> usize {
    if let Some(forced_tile) = tile_override {
        return forced_tile;
    }
    let tail_vars = vars_left - window_vars;
    let tail_len = 1usize << tail_vars;
    let target_tail_blocks = target_tail_blocks.max(min_tail_blocks).max(1);
    let ideal_tile = tail_len.div_ceil(target_tail_blocks).max(1);
    ideal_tile.clamp(TAIL_TILE_MIN, TAIL_TILE_MAX)
}

fn pick_window_width(
    vars_left: usize,
    rounds_avail: usize,
    min_tail_blocks: usize,
    target_tail_blocks: usize,
    tile_override: Option<usize>,
    min_vars: usize,
) -> Option<usize> {
    if vars_left < min_vars || rounds_avail < PRECOMPUTE_WINDOW_VARS {
        return None;
    }
    let window_vars = PRECOMPUTE_WINDOW_VARS;
    let tile_len = pick_tail_tile(
        vars_left,
        window_vars,
        min_tail_blocks,
        target_tail_blocks,
        tile_override,
    );
    (count_tail_blocks(vars_left, window_vars, tile_len) >= min_tail_blocks).then_some(window_vars)
}

fn pick_inner_round_mode(
    round: usize,
    windowed_enabled: bool,
    min_tail_blocks: usize,
    target_tail_blocks: usize,
    tile_override: Option<usize>,
    min_vars: usize,
) -> InnerRoundMode {
    if !windowed_enabled {
        return InnerRoundMode::FusedFold;
    }
    let first_base = 1usize;
    let window_stop = round.div_ceil(2);
    let vars_left = round - first_base;
    let rounds_avail = window_stop - first_base;
    if pick_window_width(
        vars_left,
        rounds_avail,
        min_tail_blocks,
        target_tail_blocks,
        tile_override,
        min_vars,
    )
    .is_none()
    {
        return InnerRoundMode::FusedFold;
    }

    InnerRoundMode::WindowedPrecompute
}

fn fill_eq_table_host<F: Field>(coords: &[F], table: &mut [F]) {
    // at most a handful of variables, so a host loop beats launching a kernel and allocating.
    let num_coords = coords.len();
    let table_len = 1usize << num_coords;
    debug_assert!(table.len() >= table_len);
    for (corner, slot) in table.iter_mut().enumerate().take(table_len) {
        let mut weight = F::ONE;
        for (i, &x) in coords.iter().enumerate() {
            let take_coord = ((corner >> (num_coords - 1 - i)) & 1) == 1;
            weight *= if take_coord { x } else { F::ONE - x };
        }
        *slot = weight;
    }
}

/// Returns (low ptr, high ptr, low stride, remaining vars) of the eq table restricted to the
/// suffix that is left after removing `skip_layers` variables. Entry `i` of the split table
/// equals `low[i mod 2^k] * high[i >> k]`.
fn eq_suffix_pointers<ValExt: p3_field::PrimeCharacteristicRing + Copy>(
    eq_layers: &SqrtEqLayersFor<ValExt>,
    skip_layers: usize,
) -> (*const ValExt, *const ValExt, usize, usize) {
    let mut high_vars = eq_layers.high_n();
    let mut low_vars = eq_layers.low_n();
    let all_vars = high_vars + low_vars;
    if skip_layers >= all_vars {
        return (std::ptr::null(), std::ptr::null(), 1, 0);
    }
    if skip_layers <= high_vars {
        high_vars -= skip_layers;
    } else {
        low_vars -= skip_layers - high_vars;
        high_vars = 0;
    }
    let tail_vars = low_vars + high_vars;
    if tail_vars == 0 {
        (std::ptr::null(), std::ptr::null(), 1, 0)
    } else {
        (
            eq_layers.low.get_ptr(low_vars),
            eq_layers.high.get_ptr(high_vars),
            1 << low_vars,
            tail_vars,
        )
    }
}

fn upload_to_device_ptr<T: Copy>(
    device_dst: *mut T,
    host_src: &[T],
) -> Result<(), FractionalSumcheckError> {
    if host_src.is_empty() {
        return Ok(());
    }
    unsafe {
        cuda_memcpy::<false, true>(
            device_dst as *mut c_void,
            host_src.as_ptr() as *const c_void,
            std::mem::size_of_val(host_src),
        )?;
    }
    Ok(())
}

/// Absorbs one inner round polynomial, draws its challenge, and updates the running claim
/// and the eq prefix product. Returns the challenge.
#[allow(clippy::too_many_arguments)]
fn absorb_round_and_sample<FK, SC, TS>(
    d_round_sums: &DeviceBuffer<FK::ValExt>,
    challenger: &mut TS,
    inner_round_polys: &mut Vec<[FK::ValExt; ROUND_POLY_DEG]>,
    sampled_rs: &mut Vec<FK::ValExt>,
    running_claim: &mut FK::ValExt,
    xi_coord: FK::ValExt,
    eq_prefix_product: &mut FK::ValExt,
) -> Result<FK::ValExt, FractionalSumcheckError>
where
    FK: FieldKernels,
    SC: StarkProtocolConfig<EF = FK::ValExt>,
    TS: FiatShamirTranscript<SC>,
{
    let (round_evals, reduced_evals) =
        expand_round_poly_evals::<FK>(d_round_sums, *running_claim, xi_coord, *eq_prefix_product)?;

    for &eval in &round_evals {
        challenger.observe_ext(eval);
    }
    inner_round_polys.push(round_evals);

    let challenge = challenger.sample_ext();
    sampled_rs.push(challenge);

    let eq_at_challenge = eval_eq_mle(&[xi_coord], &[challenge]);
    *eq_prefix_product *= eq_at_challenge;
    *running_claim = eq_at_challenge * interpolate_quadratic_at_012(&reduced_evals, challenge);

    Ok(challenge)
}

/// Inner round 0 of a layer: undoes the tree's last combine step and evaluates s'(1), s'(2)
/// in the same kernel.
#[allow(clippy::too_many_arguments)]
fn revert_and_first_inner_round<FK, SC, TS>(
    eq_layers: &mut SqrtEqLayersFor<FK::ValExt>,
    seg_tree: &mut DeviceBuffer<Frac<FK::ValExt>>,
    pq_len: usize,
    batch_lambda: FK::ValExt,
    challenger: &mut TS,
    d_round_sums: &mut DeviceBuffer<FK::ValExt>,
    block_partials: &mut DeviceBuffer<FK::ValExt>,
    inner_round_polys: &mut Vec<[FK::ValExt; ROUND_POLY_DEG]>,
    sampled_rs: &mut Vec<FK::ValExt>,
    running_claim: &mut FK::ValExt,
    xi_coord: FK::ValExt,
    eq_prefix_product: &mut FK::ValExt,
) -> Result<FK::ValExt, FractionalSumcheckError>
where
    FK: FieldKernels,
    SC: StarkProtocolConfig<EF = FK::ValExt>,
    TS: FiatShamirTranscript<SC>,
{
    unsafe {
        FK::frac_compute_round_and_revert(
            eq_layers,
            seg_tree,
            pq_len / 2,
            batch_lambda,
            d_round_sums,
            block_partials,
        )
        .map_err(FractionalSumcheckError::ComputeRound)?;
    }
    eq_layers.drop_layer();
    absorb_round_and_sample::<FK, SC, TS>(
        d_round_sums,
        challenger,
        inner_round_polys,
        sampled_rs,
        running_claim,
        xi_coord,
        eq_prefix_product,
    )
}

/// Out-of-place inner round: folds `pq_src` with the previous challenge `fold_r` into
/// `pq_dst` and evaluates s' on the folded data, all in one launch (saves a pass over
/// memory compared to a separate fold kernel).
#[allow(clippy::too_many_arguments)]
fn fused_round_out_of_place<FK, SC, TS>(
    eq_layers: &mut SqrtEqLayersFor<FK::ValExt>,
    pq_src: &DeviceBuffer<Frac<FK::ValExt>>,
    pq_dst: &mut DeviceBuffer<Frac<FK::ValExt>>,
    pq_len_before_fold: usize,
    batch_lambda: FK::ValExt,
    fold_r: FK::ValExt,
    challenger: &mut TS,
    d_round_sums: &mut DeviceBuffer<FK::ValExt>,
    block_partials: &mut DeviceBuffer<FK::ValExt>,
    inner_round_polys: &mut Vec<[FK::ValExt; ROUND_POLY_DEG]>,
    sampled_rs: &mut Vec<FK::ValExt>,
    running_claim: &mut FK::ValExt,
    xi_coord: FK::ValExt,
    eq_prefix_product: &mut FK::ValExt,
) -> Result<FK::ValExt, FractionalSumcheckError>
where
    FK: FieldKernels,
    SC: StarkProtocolConfig<EF = FK::ValExt>,
    TS: FiatShamirTranscript<SC>,
{
    unsafe {
        FK::frac_compute_round_and_fold(
            eq_layers,
            pq_src,
            pq_dst,
            pq_len_before_fold,
            batch_lambda,
            fold_r,
            d_round_sums,
            block_partials,
        )
        .map_err(FractionalSumcheckError::ComputeRound)?;
    }
    eq_layers.drop_layer();
    absorb_round_and_sample::<FK, SC, TS>(
        d_round_sums,
        challenger,
        inner_round_polys,
        sampled_rs,
        running_claim,
        xi_coord,
        eq_prefix_product,
    )
}

/// Same as [`fused_round_out_of_place`] but folds `pq_data` onto itself.
#[allow(clippy::too_many_arguments)]
fn fused_round_in_place<FK, SC, TS>(
    eq_layers: &mut SqrtEqLayersFor<FK::ValExt>,
    pq_data: &mut DeviceBuffer<Frac<FK::ValExt>>,
    pq_len_before_fold: usize,
    batch_lambda: FK::ValExt,
    fold_r: FK::ValExt,
    challenger: &mut TS,
    d_round_sums: &mut DeviceBuffer<FK::ValExt>,
    block_partials: &mut DeviceBuffer<FK::ValExt>,
    inner_round_polys: &mut Vec<[FK::ValExt; ROUND_POLY_DEG]>,
    sampled_rs: &mut Vec<FK::ValExt>,
    running_claim: &mut FK::ValExt,
    xi_coord: FK::ValExt,
    eq_prefix_product: &mut FK::ValExt,
) -> Result<FK::ValExt, FractionalSumcheckError>
where
    FK: FieldKernels,
    SC: StarkProtocolConfig<EF = FK::ValExt>,
    TS: FiatShamirTranscript<SC>,
{
    unsafe {
        FK::frac_compute_round_and_fold_inplace(
            eq_layers,
            pq_data,
            pq_len_before_fold,
            batch_lambda,
            fold_r,
            d_round_sums,
            block_partials,
        )
        .map_err(FractionalSumcheckError::ComputeRound)?;
    }
    eq_layers.drop_layer();
    absorb_round_and_sample::<FK, SC, TS>(
        d_round_sums,
        challenger,
        inner_round_polys,
        sampled_rs,
        running_claim,
        xi_coord,
        eq_prefix_product,
    )
}

/// Proves the GKR fractional-sum tree over `input_leaves` on the GPU.
#[instrument(skip_all)]
pub fn fractional_sumcheck_gpu<FK, SC, TS>(
    challenger: &mut TS,
    input_leaves: DeviceBuffer<Frac<FK::ValExt>>,
    alpha: FK::ValExt,
    assert_zero: bool,
    mem: &mut MemTracker,
) -> Result<(FracSumcheckProof<SC>, Vec<FK::ValExt>), FractionalSumcheckError>
where
    FK: FieldKernels,
    SC: StarkProtocolConfig<EF = FK::ValExt>,
    TS: FiatShamirTranscript<SC>,
{
    // Fields whose GPU GKR kernels are not trusted take the CPU prover instead: copy the
    // leaves to the host, add alpha to every denominator, and hand them to the CPU
    // fractional_sumcheck (covered by the e2e tests).
    if FK::use_cpu_gkr() {
        if input_leaves.is_empty() {
            return Ok((
                FracSumcheckProof {
                    fractional_sum: (FK::ValExt::ZERO, FK::ValExt::ONE),
                    claims_per_layer: vec![],
                    sumcheck_polys: vec![],
                },
                vec![],
            ));
        }
        // host copy, still in logical (not bit-reversed) order
        let mut host_leaves: Vec<Frac<FK::ValExt>> = input_leaves
            .to_host()
            .map_err(FractionalSumcheckError::Copy)?;
        // MLE_DEBUG_GKR_FRACS: dump the first few leaves (raw limb 0 of p and q) before alpha
        if std::env::var("MLE_DEBUG_GKR_FRACS").is_ok() {
            tracing::warn!(
                "GPU fracs (before alpha, first 8 of {}):",
                host_leaves.len()
            );
            for (i, f) in host_leaves.iter().take(8).enumerate() {
                // reinterpret as raw u32 limbs
                let p_limbs: [u32; 4] = unsafe { std::mem::transmute_copy(&f.p) };
                let q_limbs: [u32; 4] = unsafe { std::mem::transmute_copy(&f.q) };
                tracing::warn!("  fracs[{i}]: p[0]={} q[0]={}", p_limbs[0], q_limbs[0]);
            }
        }
        // Shift every denominator by alpha, exactly like the CPU logup prover
        //   (evals.par_iter_mut().for_each(|frac| frac.q += alpha_logup)).
        // Same effect as the GPU frac_add_alpha; keeps denominators away from zero.
        for f in &mut host_leaves {
            f.q = f.q + alpha;
        }
        // No bit-reversal here: the GPU leaves already follow the stacked layout that the batch
        // MLE's eq factorization (eq_cube * eq_3b) assumes; reversing them would desync xi.
        // The CPU GKR below is the reference implementation.
        let (fallback_proof, fallback_xi) =
            fractional_sumcheck::<SC, TS>(challenger, &host_leaves, assert_zero).map_err(|_| {
                FractionalSumcheckError::NonzeroRootSum {
                    p: String::from("cpu-gkr-error"),
                    q: String::from("cpu-gkr-error"),
                }
            })?;
        return Ok((fallback_proof, fallback_xi));
    }

    let profile_rounds = std::env::var("FRAC_PROF").is_ok();
    let fn_start = std::time::Instant::now();

    let mut seg_tree = input_leaves;
    if seg_tree.is_empty() {
        return Ok((
            FracSumcheckProof {
                fractional_sum: (FK::ValExt::ZERO, FK::ValExt::ONE),
                claims_per_layer: vec![],
                sumcheck_polys: vec![],
            },
            vec![],
        ));
    };
    let leaf_count = seg_tree.len();
    // depth = l_skip + n_logup
    let tree_depth = log2_strict_usize(leaf_count);
    assert!(tree_depth > 0, "n_logup > 0 when there are interactions");
    // Segment tree construction (only the current layer is kept in memory; the first
    // combine turns the leaf pairs into extension-field fractions).
    //
    // Layout is bit-reversed so that tree combines read contiguous memory.
    // Above 1024 leaves a single kernel does the bit reversal plus the first two combines,
    // avoiding roughly 1.5N extra global reads; smaller inputs use the separate kernels.
    // On KB the fused k2 kernel is suspected to corrupt the tree for large inputs
    // (LayerConsistencyCheckFailed), so whenever use_cpu_zerocheck_mle() holds the separate,
    // verified bit_rev + frac_build_tree_layer path is used for every size.
    let layers_built = if leaf_count > 1024
        && (!FK::use_cpu_zerocheck_mle() || super::force_gpu_zc_site("treebuild"))
    {
        unsafe {
            // SAFETY: Frac<ValExt> and (ValExt, ValExt) share size, alignment and field layout.
            let pair_view = transmute::<
                &DeviceBuffer<Frac<FK::ValExt>>,
                &DeviceBuffer<(FK::ValExt, FK::ValExt)>,
            >(&seg_tree);
            FK::bit_rev_frac_ext_build_k2(pair_view, tree_depth as u32, alpha)
                .map_err(FractionalSumcheckError::BitReversal)?;
        }
        // The vectorised k2 kernel (on unless FRAC_K2_VEC starts with '0') additionally folds
        // the third tree layer.
        if std::env::var("FRAC_K2_VEC")
            .map(|v| v.starts_with('0'))
            .unwrap_or(false)
        {
            2 // first two combines done
        } else {
            3 // first three combines done
        }
    } else {
        // small input (or KB): bit reversal and first combine as separate kernels
        unsafe {
            let pair_view = transmute::<
                &DeviceBuffer<Frac<FK::ValExt>>,
                &DeviceBuffer<(FK::ValExt, FK::ValExt)>,
            >(&seg_tree);
            FK::bit_rev_frac_ext(
                pair_view,
                pair_view,
                tree_depth as u32,
                leaf_count.try_into().unwrap(),
                1,
            )
            .map_err(FractionalSumcheckError::BitReversal)?;
            FK::frac_build_tree_layer(&mut seg_tree, leaf_count, false, alpha, true)
                .map_err(FractionalSumcheckError::SegmentTree)?;
            let half_len = leaf_count / 2;
            let leaves_ptr = seg_tree.as_mut_raw_ptr() as *mut Frac<FK::ValExt>;
            let upper_half = DeviceBuffer::<Frac<FK::ValExt>>::from_raw_parts(
                leaves_ptr.add(half_len),
                half_len,
            );
            FK::frac_add_alpha(&upper_half, alpha).map_err(FractionalSumcheckError::SegmentTree)?;
            std::mem::forget(upper_half);
        }
        1 // first combine done
    };

    // Two combines per launch for the remaining layers (about a third less traffic).
    let mut i = layers_built;
    while i + 1 < tree_depth {
        let pair_half_len = leaf_count >> (i + 2);
        unsafe {
            FK::frac_build_tree_two_layers(&mut seg_tree, pair_half_len)
                .map_err(FractionalSumcheckError::SegmentTree)?;
        }
        i += 2;
    }
    // odd leftover layer
    if i < tree_depth {
        unsafe {
            FK::frac_build_tree_layer(
                &mut seg_tree,
                leaf_count >> i,
                false,
                FK::ValExt::ZERO,
                false,
            )
            .map_err(FractionalSumcheckError::SegmentTree)?;
        }
    }
    mem.emit_metrics_with_label("frac_sumcheck.segment_tree");
    mem.tracing_info("fractional_sumcheck_gkr: after building segment tree");
    let mut one_elem_scratch = DeviceBuffer::<Frac<FK::ValExt>>::with_capacity(1);
    let root_frac = read_device_element(&seg_tree, 0, &mut one_elem_scratch)?;
    if profile_rounds {
        // read_device_element synchronises, so this timing includes every tree kernel.
        tracing::info!("[fracprof] tree_build={}us", fn_start.elapsed().as_micros());
    }
    unsafe {
        FK::frac_build_tree_layer(&mut seg_tree, 2, true, FK::ValExt::ZERO, false)
            .map_err(FractionalSumcheckError::SegmentTree)?;
    }
    if assert_zero {
        if root_frac.p != FK::ValExt::ZERO {
            return Err(FractionalSumcheckError::NonzeroRootSum {
                p: format!("{:?}", root_frac.p),
                q: format!("{:?}", root_frac.q),
            });
        }
    } else {
        challenger.observe_ext(root_frac.p);
    }
    challenger.observe_ext(root_frac.q);

    let mut layer_claims = Vec::with_capacity(tree_depth);
    let mut layer_round_polys = Vec::with_capacity(tree_depth);

    let claim_lo = read_device_element(&seg_tree, 0, &mut one_elem_scratch)?;
    let claim_hi = read_device_element(&seg_tree, 1, &mut one_elem_scratch)?;
    layer_claims.push(GkrLayerClaims {
        p_xi_0: claim_lo.p,
        q_xi_0: claim_lo.q,
        p_xi_1: claim_hi.p,
        q_xi_1: claim_hi.q,
    });
    for claim_val in [
        layer_claims[0].p_xi_0,
        layer_claims[0].q_xi_0,
        layer_claims[0].p_xi_1,
        layer_claims[0].q_xi_1,
    ] {
        challenger.observe_ext(claim_val);
    }
    let first_mu = challenger.sample_ext();
    let mut xi_point = vec![first_mu];
    let mut d_round_sums = DeviceBuffer::<FK::ValExt>::with_capacity(2);

    let windowed_enabled = windowed_precompute_requested();

    // Scratch buffer that lets non-last outer rounds fold without destroying the tree (the
    // last outer round folds in the tree itself). With the windowed precompute, the first
    // multifold removes window_vars+1 variables at once (the pending fold_r plus the
    // window), leaving leaf_count >> (2 + window_vars); fused-fold fallback rounds below the
    // variable threshold need at most 2^min_vars entries.
    let scratch_len = if tree_depth > 2 {
        if windowed_enabled {
            (leaf_count >> (2 + PRECOMPUTE_WINDOW_VARS)).max(1 << PRECOMPUTE_DEFAULT_MIN_VARS)
        } else {
            leaf_count >> 2
        }
    } else {
        0
    };
    let mut scratch_pq = if scratch_len > 0 {
        // kept across proofs (~1.1 GiB); allocating that fresh can hit `d_malloc`'s
        // trim-and-retry path, which forces a device sync.
        super::buf_cache_checkout::<Frac<FK::ValExt>>("gkr_work", scratch_len)
    } else {
        DeviceBuffer::new()
    };
    let block_partials_cap = if tree_depth > 1 {
        (unsafe { FK::frac_compute_round_temp_buffer_size((1 << (tree_depth - 1)) as u32) })
            as usize
    } else {
        0
    };
    let mut block_partials = if block_partials_cap > 0 {
        DeviceBuffer::<FK::ValExt>::with_capacity(block_partials_cap)
    } else {
        DeviceBuffer::new()
    };
    let min_tail_blocks = min_tail_blocks_from_env();
    let target_tail_blocks = target_tail_blocks_from_env();
    let tile_override = tail_tile_override_from_env();
    let min_vars = min_window_vars_from_env();
    let mut m_table = DeviceBuffer::<FK::ValExt>::new();
    let mut m_partials = DeviceBuffer::<FK::ValExt>::new();
    let mut d_eq_prefix = DeviceBuffer::<FK::ValExt>::new();
    let mut d_eq_suffix = DeviceBuffer::<FK::ValExt>::new();

    // FRAC_PROF=1: synced per-outer-round timing, used to compare the per-round host/GPU
    // round-trip cost with the bandwidth floor.
    if profile_rounds {
        tracing::info!("[fracprof] pre_loop={}us", fn_start.elapsed().as_micros());
    }
    let mut round_micros: Vec<u128> = Vec::new();
    for round in 1..tree_depth {
        let round_span = debug_span!("GKR", round).entered();
        let round_start = std::time::Instant::now();

        // The tree revert happens inside revert_and_first_inner_round.

        debug_assert_eq!(xi_point.len(), round);
        // eq_layers holds, for each j in 1..xi_point.len(), the table eq(xi_point[j..], x) over
        // the matching hypercube.
        let mut eq_layers = SqrtEqLayersFor::from_xi_with_kernels::<FK>(&xi_point[1..])
            .map_err(FractionalSumcheckError::EvalEqHypercube)?;

        let mut inner_round_polys = Vec::with_capacity(round);
        let mut sampled_rs = Vec::with_capacity(round);
        let mut pq_len = 2 << round;

        let batch_lambda = challenger.sample_ext();

        let round_partials_cap =
            unsafe { FK::frac_compute_round_temp_buffer_size((1 << round) as u32) } as usize;
        if round_partials_cap > block_partials.len() {
            block_partials = DeviceBuffer::<FK::ValExt>::with_capacity(round_partials_cap);
        }

        let last_outer_round = round == tree_depth - 1;
        debug_assert!(round > 0);
        let mode = pick_inner_round_mode(
            round,
            windowed_enabled,
            min_tail_blocks,
            target_tail_blocks,
            tile_override,
            min_vars,
        );

        // Claim the next inner round must sum to (s_{j-1}(r_{j-1})); begins as the layer claim.
        let (numer_at_mu, denom_at_mu) = combine_layer_claims_at::<FK, SC>(
            layer_claims.last().unwrap(),
            /* mu */ xi_point[0],
        );
        let mut running_claim = numer_at_mu + batch_lambda * denom_at_mu;
        let mut eq_prefix_product = FK::ValExt::ONE;

        // MLE_VERIFY_REVERT=<round>: snapshot the tree around the fused revert and check every
        // reverted slot against a host-side frac_unadd of the same inputs (debug only).
        let revert_check_round: Option<usize> = std::env::var("MLE_VERIFY_REVERT")
            .ok()
            .and_then(|s| s.parse().ok());
        let layer_before_revert: Option<Vec<Frac<FK::ValExt>>> =
            if revert_check_round == Some(round) {
                use crate::runtime::copy::MemCopyD2H;
                Some(seg_tree.to_host().map_err(FractionalSumcheckError::Copy)?)
            } else {
                None
            };

        // Inner round 0 reverts the tree and computes in one kernel; its fold is deferred and
        // merged into the next inner round's compute.
        let first_r = revert_and_first_inner_round::<FK, SC, TS>(
            &mut eq_layers,
            &mut seg_tree,
            pq_len,
            batch_lambda,
            challenger,
            &mut d_round_sums,
            &mut block_partials,
            &mut inner_round_polys,
            &mut sampled_rs,
            &mut running_claim,
            xi_point[0],
            &mut eq_prefix_product,
        )?;

        if let Some(tree_before) = layer_before_revert {
            use crate::runtime::copy::MemCopyD2H;
            use p3_field::Field;
            let tree_after: Vec<Frac<FK::ValExt>> =
                seg_tree.to_host().map_err(FractionalSumcheckError::Copy)?;
            let half_len = pq_len / 2;
            let quarter_len = pq_len / 4;
            let num_pairs = pq_len / 2;
            let mut even_mismatch = 0usize;
            let mut odd_mismatch = 0usize;
            let mut first_diff = None;
            // host frac_unadd(sum, rhs): q0 = sum.q / rhs.q; p0 = (sum.p - q0 * rhs.p) / rhs.q
            let cpu_unadd = |sum: &Frac<FK::ValExt>, rhs: &Frac<FK::ValExt>| {
                let rhs_q_inv = rhs.q.inverse();
                let q0 = sum.q * rhs_q_inv;
                let p0 = (sum.p - q0 * rhs.p) * rhs_q_inv;
                (p0, q0)
            };
            let mut bad_pair: Option<(usize, usize)> = None;
            for idx in 0..(num_pairs / 2) {
                // even: unadd(tree_before[idx], tree_before[idx + half_len]) vs tree_after[idx]
                let (ep, eq) = cpu_unadd(&tree_before[idx], &tree_before[idx + half_len]);
                if ep != tree_after[idx].p || eq != tree_after[idx].q {
                    even_mismatch += 1;
                    if first_diff.is_none() {
                        first_diff =
                            Some(("even", idx, ep, eq, tree_after[idx].p, tree_after[idx].q));
                        bad_pair = Some((idx, idx + half_len));
                    }
                }
                // odd slot: same with both inputs and the output shifted by quarter_len
                let (op, oq) = cpu_unadd(
                    &tree_before[idx + quarter_len],
                    &tree_before[idx + half_len + quarter_len],
                );
                if op != tree_after[idx + quarter_len].p || oq != tree_after[idx + quarter_len].q {
                    odd_mismatch += 1;
                    if first_diff.is_none() {
                        first_diff = Some((
                            "odd",
                            idx + quarter_len,
                            op,
                            oq,
                            tree_after[idx + quarter_len].p,
                            tree_after[idx + quarter_len].q,
                        ));
                    }
                }
            }
            tracing::warn!(
                "REVERT_VERIFY round={round} pq_size={pq_len}: even_mismatch={even_mismatch} odd_mismatch={odd_mismatch} (of {})",
                num_pairs / 2
            );
            if let Some((kind, pos, cp, cq, gp, gq)) = first_diff {
                tracing::warn!(
                    "REVERT_VERIFY first bad {kind} pos={pos}: CPU=({cp:?},{cq:?}) GPU=({gp:?},{gq:?})"
                );
            }
            // Print the raw limbs of the first mismatching input pair so the case can be replayed
            // in an isolated frac_build_tree_layer test.
            // SAFETY: assumes ValExt is [u32; 4] (KB); debug-only path.
            if let Some((lhs_idx, rhs_idx)) = bad_pair {
                let lhs_raw: [u32; 8] = unsafe { std::mem::transmute_copy(&tree_before[lhs_idx]) };
                let rhs_raw: [u32; 8] = unsafe { std::mem::transmute_copy(&tree_before[rhs_idx]) };
                tracing::warn!(
                    "REVERT_VERIFY bad inputs (raw [p0..3,q0..3]): lhs={lhs_raw:?} rhs={rhs_raw:?}"
                );
            }
        }

        // Remaining inner rounds: each one folds with last_r and computes the next poly.
        let mut last_r = first_r;
        let folded_pq: &mut DeviceBuffer<Frac<FK::ValExt>>;

        match mode {
            InnerRoundMode::FusedFold => {
                // one fused compute+fold kernel per inner round
                let mut planner = PingPongPlanner::new(scratch_len);
                for &xi_coord in xi_point.iter().skip(1) {
                    let pq_len_before_fold = pq_len;
                    let folded_len = pq_len >> 1;

                    let challenge = match planner.plan_fused_round(folded_len, last_outer_round) {
                        FoldDestination::TreeIntoScratch => fused_round_out_of_place::<FK, SC, TS>(
                            &mut eq_layers,
                            &seg_tree,
                            &mut scratch_pq,
                            pq_len_before_fold,
                            batch_lambda,
                            last_r,
                            challenger,
                            &mut d_round_sums,
                            &mut block_partials,
                            &mut inner_round_polys,
                            &mut sampled_rs,
                            &mut running_claim,
                            xi_coord,
                            &mut eq_prefix_product,
                        )?,
                        FoldDestination::ScratchIntoTree => fused_round_out_of_place::<FK, SC, TS>(
                            &mut eq_layers,
                            &scratch_pq,
                            &mut seg_tree,
                            pq_len_before_fold,
                            batch_lambda,
                            last_r,
                            challenger,
                            &mut d_round_sums,
                            &mut block_partials,
                            &mut inner_round_polys,
                            &mut sampled_rs,
                            &mut running_claim,
                            xi_coord,
                            &mut eq_prefix_product,
                        )?,
                        FoldDestination::TreeInPlace => fused_round_in_place::<FK, SC, TS>(
                            &mut eq_layers,
                            &mut seg_tree,
                            pq_len_before_fold,
                            batch_lambda,
                            last_r,
                            challenger,
                            &mut d_round_sums,
                            &mut block_partials,
                            &mut inner_round_polys,
                            &mut sampled_rs,
                            &mut running_claim,
                            xi_coord,
                            &mut eq_prefix_product,
                        )?,
                        FoldDestination::ScratchInPlace => fused_round_in_place::<FK, SC, TS>(
                            &mut eq_layers,
                            &mut scratch_pq,
                            pq_len_before_fold,
                            batch_lambda,
                            last_r,
                            challenger,
                            &mut d_round_sums,
                            &mut block_partials,
                            &mut inner_round_polys,
                            &mut sampled_rs,
                            &mut running_claim,
                            xi_coord,
                            &mut eq_prefix_product,
                        )?,
                    };

                    pq_len >>= 1;
                    last_r = challenge;
                }

                // the final challenge still needs its own fold (nothing left to fuse it into)
                folded_pq = match planner.plan_final_fold(last_outer_round) {
                    FoldDestination::ScratchInPlace => {
                        unsafe {
                            FK::fold_ef_frac_columns_inplace(&mut scratch_pq, pq_len, last_r)
                                .map_err(FractionalSumcheckError::FoldColumns)?;
                        }
                        &mut scratch_pq
                    }
                    FoldDestination::TreeInPlace => {
                        unsafe {
                            FK::fold_ef_frac_columns_inplace(&mut seg_tree, pq_len, last_r)
                                .map_err(FractionalSumcheckError::FoldColumns)?;
                        }
                        &mut seg_tree
                    }
                    FoldDestination::TreeIntoScratch => {
                        unsafe {
                            FK::fold_ef_frac_columns(
                                &seg_tree,
                                scratch_pq.as_mut_ptr(),
                                pq_len,
                                last_r,
                            )
                            .map_err(FractionalSumcheckError::FoldColumns)?;
                        }
                        &mut scratch_pq
                    }
                    FoldDestination::ScratchIntoTree => unreachable!(),
                };
                pq_len >>= 1;
            }
            InnerRoundMode::WindowedPrecompute => {
                let window_base = 1usize;
                let window_stop = round.div_ceil(2);

                // The first window builds M straight from the tree with fold_pending set, folding
                // last_r on the fly. Multifolds write into `window_dst` (scratch on earlier outer
                // rounds, the tree on the last one); later windows read and write `window_dst` with
                // fold_pending cleared.
                let mut fold_pending = true;
                let tree_read_ptr = seg_tree.as_ptr();
                let window_dst = if last_outer_round {
                    &mut seg_tree
                } else {
                    &mut scratch_pq
                };

                // One extra variable of room: on the first window the pending fold_r is
                // prepended to the window challenges.
                let mut host_eq_window = vec![FK::ValExt::ZERO; 1 << (PRECOMPUTE_WINDOW_VARS + 1)];
                let mut host_eq_prefix = vec![FK::ValExt::ZERO; 1 << PRECOMPUTE_WINDOW_VARS];
                let mut host_eq_suffix = vec![FK::ValExt::ZERO; 1 << PRECOMPUTE_WINDOW_VARS];

                if d_eq_prefix.is_empty() {
                    d_eq_prefix =
                        DeviceBuffer::<FK::ValExt>::with_capacity(1usize << PRECOMPUTE_WINDOW_VARS);
                }
                if d_eq_suffix.is_empty() {
                    d_eq_suffix =
                        DeviceBuffer::<FK::ValExt>::with_capacity(1usize << PRECOMPUTE_WINDOW_VARS);
                }

                let mut window_base = window_base;
                while window_base < window_stop {
                    let vars_left = round - window_base;
                    let rounds_avail = window_stop - window_base;
                    let Some(window_vars) = pick_window_width(
                        vars_left,
                        rounds_avail,
                        min_tail_blocks,
                        target_tail_blocks,
                        tile_override,
                        min_vars,
                    ) else {
                        break;
                    };
                    if m_table.is_empty() {
                        let m_capacity = 1usize << (2 * PRECOMPUTE_WINDOW_VARS);
                        m_table = DeviceBuffer::<FK::ValExt>::with_capacity(m_capacity);
                    }
                    let d_m = m_table.as_mut_ptr();
                    // The eq window table borrows block_partials' storage: the M eval rounds
                    // are done before the multifold reads it, and block_partials is not used
                    // again until the next fused-fold round.
                    let eq_window_cap = 1usize << (PRECOMPUTE_WINDOW_VARS + 1);
                    debug_assert!(
                        block_partials.len() >= eq_window_cap,
                        "tmp_block_sums too small for eq_r_window: {} < {}",
                        block_partials.len(),
                        eq_window_cap,
                    );
                    let d_eq_window = block_partials.as_mut_ptr();

                    // With fold_pending the source still has vars_left+1 variables and is
                    // folded inside the kernel; tiling depends only on vars_left - window_vars
                    // in both cases.
                    let tile_len = pick_tail_tile(
                        vars_left,
                        window_vars,
                        min_tail_blocks,
                        target_tail_blocks,
                        tile_override,
                    );
                    let tail_blocks = count_tail_blocks(vars_left, window_vars, tile_len);
                    let m_entries = (1usize << window_vars) * (1usize << window_vars);
                    let partials_len = tail_blocks * m_entries;
                    if partials_len > m_partials.len() {
                        m_partials = DeviceBuffer::<FK::ValExt>::with_capacity(partials_len);
                    }

                    let (eq_low_ptr, eq_high_ptr, low_stride, _) =
                        eq_suffix_pointers(&eq_layers, window_vars - 1);

                    let pending_r = last_r; // keep: the window loop below reassigns last_r
                    let m_src = if fold_pending {
                        tree_read_ptr
                    } else {
                        window_dst.as_ptr()
                    };
                    unsafe {
                        FK::frac_precompute_m_build_raw(
                            m_src,
                            vars_left,
                            window_vars,
                            batch_lambda,
                            pending_r,
                            fold_pending, // fold last_r inline on the first window only
                            eq_low_ptr,
                            eq_high_ptr,
                            low_stride,
                            tile_len,
                            m_partials.as_mut_ptr(),
                            partials_len,
                            d_m,
                        )
                        .map_err(FractionalSumcheckError::ComputeRound)?;
                    }

                    let mut window_challenges = Vec::with_capacity(window_vars);
                    for step in 0..window_vars {
                        let prefix_vars = step;
                        let suffix_vars = window_vars - step - 1;
                        fill_eq_table_host(&window_challenges, &mut host_eq_prefix);
                        fill_eq_table_host(
                            &xi_point[window_base + step + 1..window_base + window_vars],
                            &mut host_eq_suffix,
                        );

                        upload_to_device_ptr(
                            d_eq_prefix.as_mut_ptr(),
                            &host_eq_prefix[..(1usize << prefix_vars)],
                        )?;
                        upload_to_device_ptr(
                            d_eq_suffix.as_mut_ptr(),
                            &host_eq_suffix[..(1usize << suffix_vars)],
                        )?;
                        unsafe {
                            FK::frac_precompute_m_eval_round_raw(
                                d_m,
                                window_vars,
                                step,
                                d_eq_prefix.as_ptr(),
                                d_eq_suffix.as_ptr(),
                                d_round_sums.as_mut_ptr(),
                            )
                            .map_err(FractionalSumcheckError::ComputeRound)?;
                        }
                        eq_layers.drop_layer();
                        let challenge = absorb_round_and_sample::<FK, SC, TS>(
                            &d_round_sums,
                            challenger,
                            &mut inner_round_polys,
                            &mut sampled_rs,
                            &mut running_claim,
                            xi_point[window_base + step],
                            &mut eq_prefix_product,
                        )?;
                        last_r = challenge;
                        window_challenges.push(challenge);
                    }

                    // eq table over the window challenges, consumed by the multifold.
                    let (src_vars, fold_vars) = if fold_pending {
                        let mut fold_rs = Vec::with_capacity(window_vars + 1);
                        fold_rs.push(pending_r);
                        fold_rs.extend_from_slice(&window_challenges);
                        fill_eq_table_host(&fold_rs, &mut host_eq_window);
                        upload_to_device_ptr(
                            d_eq_window,
                            &host_eq_window[..(1 << (window_vars + 1))],
                        )?;
                        (vars_left + 1, window_vars + 1)
                    } else {
                        fill_eq_table_host(&window_challenges, &mut host_eq_window);
                        upload_to_device_ptr(d_eq_window, &host_eq_window[..(1 << window_vars)])?;
                        (vars_left, window_vars)
                    };

                    let fold_src = if fold_pending {
                        tree_read_ptr
                    } else {
                        window_dst.as_ptr()
                    };
                    unsafe {
                        FK::frac_multifold_raw(
                            fold_src,
                            window_dst.as_mut_ptr(),
                            src_vars,
                            fold_vars,
                            d_eq_window,
                        )
                        .map_err(FractionalSumcheckError::FoldColumns)?;
                    }
                    pq_len >>= fold_vars;
                    fold_pending = false;
                    window_base += window_vars;
                }

                if window_base < round {
                    // Leftover rounds: the first one only computes (data is already folded), the
                    // rest are fused fold+compute.
                    unsafe {
                        FK::frac_compute_round(
                            &eq_layers,
                            window_dst,
                            pq_len / 2,
                            batch_lambda,
                            &mut d_round_sums,
                            &mut block_partials,
                        )
                        .map_err(FractionalSumcheckError::ComputeRound)?;
                    }
                    eq_layers.drop_layer();
                    last_r = absorb_round_and_sample::<FK, SC, TS>(
                        &d_round_sums,
                        challenger,
                        &mut inner_round_polys,
                        &mut sampled_rs,
                        &mut running_claim,
                        xi_point[window_base],
                        &mut eq_prefix_product,
                    )?;

                    for &xi_coord in xi_point.iter().skip(window_base + 1) {
                        let pq_len_before_fold = pq_len;
                        last_r = fused_round_in_place::<FK, SC, TS>(
                            &mut eq_layers,
                            window_dst,
                            pq_len_before_fold,
                            batch_lambda,
                            last_r,
                            challenger,
                            &mut d_round_sums,
                            &mut block_partials,
                            &mut inner_round_polys,
                            &mut sampled_rs,
                            &mut running_claim,
                            xi_coord,
                            &mut eq_prefix_product,
                        )?;
                        pq_len >>= 1;
                    }
                }

                unsafe {
                    FK::fold_ef_frac_columns_inplace(window_dst, pq_len, last_r)
                        .map_err(FractionalSumcheckError::FoldColumns)?;
                }
                folded_pq = window_dst;
                pq_len >>= 1;
            }
        }

        let next_claims = [
            read_device_element(folded_pq, 0, &mut one_elem_scratch)?,
            read_device_element(folded_pq, pq_len / 2, &mut one_elem_scratch)?,
        ];

        layer_claims.push(GkrLayerClaims {
            p_xi_0: next_claims[0].p,
            q_xi_0: next_claims[0].q,
            p_xi_1: next_claims[1].p,
            q_xi_1: next_claims[1].q,
        });

        challenger.observe_ext(layer_claims[round].p_xi_0);
        challenger.observe_ext(layer_claims[round].q_xi_0);
        challenger.observe_ext(layer_claims[round].p_xi_1);
        challenger.observe_ext(layer_claims[round].q_xi_1);

        let layer_mu = challenger.sample_ext();
        xi_point = [vec![layer_mu], sampled_rs].concat();

        layer_round_polys.push(inner_round_polys);
        if profile_rounds {
            let _ = crate::runtime::stream::current_stream_sync();
            round_micros.push(round_start.elapsed().as_micros());
        }
        round_span.exit();
    }
    if profile_rounds {
        let total: u128 = round_micros.iter().sum();
        tracing::info!(
            target: "bench",
            "[fracprof] total={total}us rounds={} per_round={round_micros:?}",
            round_micros.len()
        );
        tracing::info!("[fracprof] fn_total={}us", fn_start.elapsed().as_micros());
    }
    mem.emit_metrics_with_label("frac_sumcheck.gkr_rounds");
    mem.tracing_info("after_fractional_sumcheck_gkr");

    // Hand the large buffers back to the cross-proof cache. Each inner round ended with a
    // D2H of its block sums, so the GPU is no longer touching them.
    super::buf_cache_checkin("gkr_leaves", seg_tree);
    super::buf_cache_checkin("gkr_work", scratch_pq);

    Ok((
        FracSumcheckProof {
            fractional_sum: (root_frac.p, root_frac.q),
            claims_per_layer: layer_claims,
            sumcheck_polys: layer_round_polys,
        },
        xi_point,
    ))
}

fn read_device_element<T: Copy>(
    src_buf: &DeviceBuffer<T>,
    elem_idx: usize,
    staging: &mut DeviceBuffer<T>,
) -> Result<T, FractionalSumcheckError> {
    debug_assert!(!staging.is_empty());
    unsafe {
        cuda_memcpy::<true, true>(
            staging.as_mut_raw_ptr(),
            src_buf.as_ptr().add(elem_idx) as *const std::ffi::c_void,
            std::mem::size_of::<T>(),
        )?;
    }
    let host_vals = staging.to_host()?;
    Ok(host_vals[0])
}

/// Collapses the two halves of a layer claim at `layer_mu` by linear interpolation.
fn combine_layer_claims_at<FK, SC>(
    claim_pair: &GkrLayerClaims<SC>,
    layer_mu: FK::ValExt,
) -> (FK::ValExt, FK::ValExt)
where
    FK: FieldKernels,
    SC: StarkProtocolConfig<EF = FK::ValExt>,
{
    let p_interp = interpolate_linear_at_01(&[claim_pair.p_xi_0, claim_pair.p_xi_1], layer_mu);
    let q_interp = interpolate_linear_at_01(&[claim_pair.q_xi_0, claim_pair.q_xi_1], layer_mu);
    (p_interp, q_interp)
}

/// Turns the GPU's s'(1), s'(2) into the round polynomial's values s(1), s(2), s(3), where
/// s(X) = eq(xi_coord, X) * s'(X); also returns s' at {0, 1, 2}.
fn expand_round_poly_evals<FK: FieldKernels>(
    d_round_sums: &DeviceBuffer<FK::ValExt>,
    running_claim: FK::ValExt,
    xi_coord: FK::ValExt,
    eq_prefix_product: FK::ValExt,
) -> Result<([FK::ValExt; ROUND_POLY_DEG], [FK::ValExt; ROUND_POLY_DEG]), FractionalSumcheckError> {
    let gpu_partials = d_round_sums.to_host()?;
    debug_assert_eq!(gpu_partials.len(), ROUND_POLY_DEG - 1);

    // reduced_evals: s'(X) scaled by eq(xi_{j+1..}, r_{j+1..}), sampled at X = 0, 1, 2
    let mut reduced_evals = [FK::ValExt::ZERO; ROUND_POLY_DEG];
    reduced_evals[1] = gpu_partials[0] * eq_prefix_product;
    reduced_evals[2] = gpu_partials[1] * eq_prefix_product;

    // s'(0) follows from the running claim: s_j(0) + s_j(1) = s_{j-1}(r_{j-1}), with
    // s_j(0) = (1 - xi_j) s'_j(0) and s_j(1) = xi_j s'_j(1). Hence
    // (1 - xi_j) s'_j(0) = running_claim - xi_j s'_j(1); 1 - xi_j is nonzero with
    // overwhelming probability since xi_j is random.
    let weight_at_0 = FK::ValExt::ONE - xi_coord;
    debug_assert_ne!(weight_at_0, FK::ValExt::ZERO);
    let weight_at_1 = xi_coord;
    reduced_evals[0] = (running_claim - weight_at_1 * reduced_evals[1]) * weight_at_0.inverse();

    let round_evals: [FK::ValExt; ROUND_POLY_DEG] = from_fn(|i| {
        // value at X = i + 1 (s(0) is not sent)
        let x = FK::ValExt::from_usize(i + 1);
        let reduced_at_x = if i < ROUND_POLY_DEG - 1 {
            reduced_evals[i + 1]
        } else {
            interpolate_quadratic_at_012(&reduced_evals, x)
        };
        eval_eq_mle(&[xi_coord], &[x]) * reduced_at_x
    });

    Ok((round_evals, reduced_evals))
}

/// Builds a device buffer of `2^n` pseudo-random fractional leaves (fixed seed) for benchmarks.
pub fn make_synthetic_leaves<FK: FieldKernels>(
    n: usize,
) -> Result<DeviceBuffer<Frac<FK::ValExt>>, FractionalSumcheckError>
where
    FK::Val: p3_field::PrimeField32,
    FK::ValExt: p3_field::BasedVectorSpace<FK::Val>,
{
    use crate::runtime::copy::cuda_memcpy;
    use rand::{rngs::StdRng, Rng, RngExt, SeedableRng};

    let table_len = 1usize << n;
    let mut rng = StdRng::seed_from_u64(42);
    // Generate random field elements using raw u32 values (all field types are u32-backed).
    // SAFETY: ValExt is [u32; 4] (degree-4 extension) = Frac numerator/denominator.
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
    let host_vals: Vec<(FK::ValExt, FK::ValExt)> = (0..table_len)
        .map(|_| {
            let mut random_ext = || -> FK::ValExt {
                // Build a ValExt from 4 random u32 component values using UFCS
                <FK::ValExt as BasedVectorSpace<FK::Val>>::from_basis_coefficients_fn(|_| {
                    let v: u32 = rng.random();
                    let canonical = v % <FK::Val as PrimeField32>::ORDER_U32;
                    unsafe { std::ptr::read(&canonical as *const u32 as *const FK::Val) }
                })
            };
            (random_ext(), random_ext())
        })
        .collect();
    let device_leaves = DeviceBuffer::<Frac<FK::ValExt>>::with_capacity(table_len);
    unsafe {
        cuda_memcpy::<false, true>(
            device_leaves.as_mut_raw_ptr(),
            host_vals.as_ptr() as *const std::ffi::c_void,
            std::mem::size_of_val(host_vals.as_slice()),
        )?;
    }
    Ok(device_leaves)
}

#[cfg(test)]
mod tests {
    use crate::runtime::{memory_manager::MemTracker, stream::current_stream_sync};
    use p3_field::PrimeCharacteristicRing;

    use super::{
        fractional_sumcheck_gpu, make_synthetic_leaves, FractionalSumcheckError, InnerRoundMode,
    };
    use mle_core::config::koala_bear_poseidon2::{KoalaBearPoseidon2Config as SC, EF};

    use crate::{cuda::field_kernels::KoalaBearKernels, sponge::KoalaBearDuplexSpongeGpu};

    /// Proves a fractional sumcheck using the given inner-round strategy, returning the proof
    /// together with the final randomness.
    fn prove_with_mode(
        n: usize,
        mode_choice: InnerRoundMode,
    ) -> Result<(super::FracSumcheckProof<SC>, Vec<EF>), FractionalSumcheckError> {
        // SAFETY: this mutates the process environment, so run these tests with
        // --test-threads=1.
        let want_windowed = matches!(mode_choice, InnerRoundMode::WindowedPrecompute);
        unsafe {
            std::env::set_var(
                "MLE_CUDA_GKR_PRECOMPUTE_M",
                if want_windowed { "1" } else { "0" },
            );
        }
        let mut challenger = KoalaBearDuplexSpongeGpu::new();
        let input_leaves = make_synthetic_leaves::<KoalaBearKernels>(n)?;
        let mut mem = MemTracker::start("test.precompute_m");
        let outcome = fractional_sumcheck_gpu::<KoalaBearKernels, SC, _>(
            &mut challenger,
            input_leaves,
            EF::ZERO,
            false,
            &mut mem,
        )?;
        current_stream_sync().expect("sync");
        Ok(outcome)
    }

    fn assert_same_proof(
        first_run: &(super::FracSumcheckProof<SC>, Vec<EF>),
        second_run: &(super::FracSumcheckProof<SC>, Vec<EF>),
    ) {
        assert_eq!(
            first_run.0.fractional_sum, second_run.0.fractional_sum,
            "fractional_sum mismatch"
        );
        assert_eq!(
            first_run.0.claims_per_layer, second_run.0.claims_per_layer,
            "claims_per_layer mismatch"
        );
        assert_eq!(
            first_run.0.sumcheck_polys, second_run.0.sumcheck_polys,
            "sumcheck_polys mismatch"
        );
        assert_eq!(first_run.1, second_run.1, "final randomness mismatch");
    }

    /// Compares the windowed precompute against FusedFold at n=24,25,26.
    /// n=24: top layer vars_left=22 (one window).
    /// n=25: top layer vars_left=23 (one window, more tail).
    /// n=26: top layer vars_left=24 (one window, even more tail).
    #[test]
    fn test_precompute_m_matches_fused() -> Result<(), FractionalSumcheckError> {
        for n in [24, 25, 26] {
            eprintln!("--- testing n={n} ---");
            let fold_eval_out = prove_with_mode(n, InnerRoundMode::FusedFold)?;
            let windowed_out = prove_with_mode(n, InnerRoundMode::WindowedPrecompute)?;
            assert_same_proof(&fold_eval_out, &windowed_out);
        }
        Ok(())
    }

    /// Compares the windowed precompute against FusedFold with lowered thresholds so that
    /// several windows run at small n. At n=16, round=15: window_stop=8, first window at
    /// window_base=1 (vars_left=14), second at window_base=4 (vars_left=11), then one
    /// fused-fold tail round.
    #[test]
    fn test_precompute_m_multi_window_matches_fused() -> Result<(), FractionalSumcheckError> {
        unsafe {
            std::env::set_var("MLE_CUDA_GKR_PRECOMPUTE_M_MIN_N", "8");
            std::env::set_var("MLE_CUDA_GKR_PRECOMPUTE_M_MIN_BLOCKS", "1");
        }
        let fold_eval_out = prove_with_mode(16, InnerRoundMode::FusedFold)?;
        let windowed_out = prove_with_mode(16, InnerRoundMode::WindowedPrecompute)?;
        assert_same_proof(&fold_eval_out, &windowed_out);
        unsafe {
            std::env::remove_var("MLE_CUDA_GKR_PRECOMPUTE_M_MIN_N");
            std::env::remove_var("MLE_CUDA_GKR_PRECOMPUTE_M_MIN_BLOCKS");
        }
        Ok(())
    }

    /// KB GPU GKR vs CPU reference: compare GPU proof claims against CPU proof claims.
    /// This is the correct correctness test — just running without panic is NOT enough
    /// because the prover has no internal consistency check (only the verifier does).
    ///
    /// n=16 → 64K leaves, 16 outer rounds. If any claim diverges, reports the first
    /// round where GPU and CPU disagree.
    #[test]
    fn test_kb_gkr_gpu_vs_cpu_n16() -> Result<(), FractionalSumcheckError> {
        kb_gkr_gpu_vs_cpu(16)
    }

    /// KB GPU GKR vs CPU at n=20 (1M leaves).
    #[test]
    fn test_kb_gkr_gpu_vs_cpu_n20() -> Result<(), FractionalSumcheckError> {
        kb_gkr_gpu_vs_cpu(20)
    }

    /// KB GPU GKR vs CPU at n=24 (matches reth188 per-partition n_logup).
    #[test]
    fn test_kb_gkr_gpu_vs_cpu_n24() -> Result<(), FractionalSumcheckError> {
        kb_gkr_gpu_vs_cpu(24)
    }

    /// Helper: run GPU and CPU KB GKR on the same synthetic leaves (seed=42), compare claims.
    fn kb_gkr_gpu_vs_cpu(n: usize) -> Result<(), FractionalSumcheckError> {
        use crate::runtime::{copy::MemCopyD2H, memory_manager::MemTracker};
        use mle_core::{
            config::koala_bear_poseidon2::{
                default_duplex_sponge, KoalaBearPoseidon2Config as KbSC,
            },
            prover::fractional_sumcheck_gkr::fractional_sumcheck,
        };
        use p3_field::PrimeCharacteristicRing;

        use crate::{cuda::field_kernels::KoalaBearKernels, sponge::KoalaBearDuplexSpongeGpu};
        type KbEF = <KoalaBearKernels as super::FieldKernels>::ValExt;

        // make_synthetic_leaves uses seed=42, so calling twice gives identical leaves.
        let gpu_leaves = make_synthetic_leaves::<KoalaBearKernels>(n)?;
        let cpu_leaves: Vec<_> = make_synthetic_leaves::<KoalaBearKernels>(n)?.to_host()?;

        // GPU GKR
        let mut gpu_transcript = KoalaBearDuplexSpongeGpu::new();
        let mut mem = MemTracker::start("test.kb_gkr_gpu_vs_cpu");
        let (gpu_proof, _) = fractional_sumcheck_gpu::<KoalaBearKernels, KbSC, _>(
            &mut gpu_transcript,
            gpu_leaves,
            KbEF::ZERO,
            false,
            &mut mem,
        )?;
        current_stream_sync().expect("sync");

        // CPU GKR reference (same initial state as GPU transcript)
        let mut cpu_transcript = default_duplex_sponge();
        let (cpu_proof, _) =
            fractional_sumcheck::<KbSC, _>(&mut cpu_transcript, &cpu_leaves, false)
                .unwrap_or_else(|e| panic!("CPU KB GKR failed: {e:?}"));

        // Compare fractional_sum (root claim)
        assert_eq!(
            gpu_proof.fractional_sum, cpu_proof.fractional_sum,
            "KB GPU vs CPU fractional_sum mismatch at n={n}"
        );

        // Print CPU's s'(1) and s'(2) at the expected failing round for comparison with GPU printf
        if n == 16 || n == 12 || n == 24 {
            let failing_j = if n == 12 {
                10
            } else if n == 16 {
                12
            } else {
                13
            };
            if let Some(outer_polys) = cpu_proof.sumcheck_polys.get(failing_j - 1) {
                if let Some(inner_poly) = outer_polys.first() {
                    eprintln!(
                        "CPU_DBG n={n} outer_round={failing_j} inner_k=0 s=[{:?},{:?},{:?}]",
                        inner_poly[0], inner_poly[1], inner_poly[2]
                    );
                }
            }
            if let Some(outer_polys) = gpu_proof.sumcheck_polys.get(failing_j - 1) {
                if let Some(inner_poly) = outer_polys.first() {
                    eprintln!(
                        "GPU_DBG n={n} outer_round={failing_j} inner_k=0 s=[{:?},{:?},{:?}]",
                        inner_poly[0], inner_poly[1], inner_poly[2]
                    );
                }
            }
        }

        // Compare sumcheck_polys FIRST (inner sub-round granularity) to find root cause.
        // sumcheck_polys has tree_depth-1 entries; entry[outer_j-1] has (outer_j) inner polys.
        // On first outer-round mismatch, we also print which inner sub-round first diverges.
        for (outer_j, (g_outer, c_outer)) in gpu_proof
            .sumcheck_polys
            .iter()
            .zip(cpu_proof.sumcheck_polys.iter())
            .enumerate()
        {
            let outer_round = outer_j + 1; // 1-indexed outer round
            for (inner_k, (g_inner, c_inner)) in g_outer.iter().zip(c_outer.iter()).enumerate() {
                if g_inner != c_inner {
                    panic!(
                        "KB GPU vs CPU sumcheck_polys FIRST diverge at \
                         outer_round={outer_round}, inner_k={inner_k} (n={n}): \
                         GPU={g_inner:?}, CPU={c_inner:?}"
                    );
                }
            }
            if g_outer.len() != c_outer.len() {
                panic!(
                    "sumcheck_polys length mismatch at outer_round={outer_round}: \
                     GPU={}, CPU={}",
                    g_outer.len(),
                    c_outer.len()
                );
            }
        }

        // Now compare claims_per_layer
        assert_eq!(
            gpu_proof.claims_per_layer.len(),
            cpu_proof.claims_per_layer.len(),
            "claims_per_layer length mismatch at n={n}"
        );
        for (j, (g, c)) in gpu_proof
            .claims_per_layer
            .iter()
            .zip(cpu_proof.claims_per_layer.iter())
            .enumerate()
        {
            assert_eq!(
                g, c,
                "KB GPU vs CPU claims_per_layer mismatch at outer round j={j} (n={n}): GPU={g:?}, CPU={c:?}"
            );
        }

        eprintln!("PASS: KB GPU GKR == CPU reference at n={n}");
        Ok(())
    }
}
