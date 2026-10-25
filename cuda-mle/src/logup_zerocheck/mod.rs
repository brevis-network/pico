//! ## Peak memory with stream-ordered frees
//!
//! The logup/zerocheck GPU helpers allocate scratch device buffers and launch kernels on them.
//! Those buffers are released with cudaFreeAsync, i.e. in stream order only. Until the current
//! stream is synchronized, a fresh allocation can therefore coexist physically with buffers that
//! were already "freed", so the real peak can exceed the logical maximum MemTracker reports.
//! Where the physical peak matters, synchronize the current stream once the outputs have been
//! consumed, e.g. through `to_host()` on them or an explicit `current_stream_sync()`.

use std::{
    cmp::max,
    collections::hash_map::Entry,
    iter::{self, zip},
    marker::PhantomData,
    sync::Arc,
};

use crate::runtime::{
    copy::{MemCopyD2H, MemCopyH2D},
    d_buffer::DeviceBuffer,
    error::MemCopyError,
    memory_manager::MemTracker,
};
use itertools::{izip, Itertools};
use mle_core::{
    air::symbolic::SymbolicConstraints,
    p3_matrix::dense::RowMajorMatrix,
    poly::{
        eq_sharp_uni_poly, eq_uni_poly, eval_eq_mle, eval_eq_sharp_uni, eval_eq_uni,
        eval_eq_uni_at_one, evals_eq_hypercube_serial,
        matrix::{ColMajorMatrix, MatrixDimensions},
        ntt::SerialRadix2Dft,
        UnivariatePoly,
    },
    proof::{column_openings_by_rot, BatchConstraintProof, GkrProof},
    protocol::stacking::{calculate_n_logup, StackedLayout},
    prover::{
        evaluator::InteractionEvalPlan, fractional_sumcheck_gkr::Frac,
        sumcheck::sumcheck_round0_deg, ColMajorEvalHelper, DeviceMultiStarkProvingKey,
        ProvingContext,
    },
};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_util::{log2_ceil_usize, log2_strict_usize};
use rustc_hash::FxHashMap;
use tracing::{debug, info, info_span, instrument};

use crate::{
    base::DeviceMatrix,
    cuda::{field_kernels::FieldKernels, logup_zerocheck::MainMatrixPtrs},
    data_transporter::transport_matrix_d2h_col_major,
    error::LogupZerocheckError,
    gpu_backend::GenericGpuBackend,
    hash_scheme::GpuHashScheme,
    logup_zerocheck::{
        batch_mle::evaluate_zerocheck_batched,
        fold_ple::fold_ple_evals_rotate,
        gkr_input::TraceInteractionMeta,
        round0::{evaluate_round0_interactions_cpu_fallback, evaluate_round0_interactions_gpu},
    },
    poly::EqEvalLayers,
    sponge::GpuFiatShamirTranscript,
    utils::compute_barycentric_inv_lagrange_denoms,
};

pub(crate) mod batch_mle;
pub(crate) mod batch_mle_monomial;
mod errors;
pub(crate) mod fold_ple;
/// Fraction sumcheck via GKR
mod fractional;
/// Evaluates the logup interactions that make up the GKR input layer
mod gkr_input;
pub(crate) mod jit_emit;
mod mle_round;
pub(crate) mod round0;
pub(crate) mod rules;

use batch_mle::{evaluate_logup_batched, TraceCtx};
use batch_mle_monomial::{
    compute_lambda_combinations, compute_logup_combinations, get_num_monomials,
    get_zerocheck_rules_len, trace_has_monomials, LogupCombinations, LogupMonomialBatch,
    ZerocheckMonomialBatch, ZerocheckMonomialParYBatch,
};
pub use errors::*;
pub use fractional::{fractional_sumcheck_gpu, make_synthetic_leaves};
use gkr_input::{collect_trace_interactions, log_gkr_input_evals};
use round0::evaluate_round0_constraints_gpu;

/// Share of the device's pool headroom the round-0 / MLE-round temporaries may claim
/// (`MLE_R0_BUDGET_ALPHA`, default 0.75). Below 1 on purpose: the other prover lane on the card
/// allocates from the same pool and may peak at the same time. 0.75 is the largest of
/// {0.25, 0.5, 0.75} whose dual-lane per-card peaks stayed in the base band on a 32 GiB card
/// (28 GB pool reservation), and the smallest that gives the Keccak round-0 interpreter its
/// whole 11.2 GB intermediates buffer (k = 1) on a 2^26-leaf chunk.
fn r0_budget_alpha() -> f64 {
    static V: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("MLE_R0_BUDGET_ALPHA")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .map(|a| a.clamp(0.0, 1.0))
            .unwrap_or(0.75)
    })
}

/// Bytes the current device's memory pool can hand out without growing: reserved minus used, read
/// through `cudaMemPoolGetAttribute`. This sees through the pool's up-front reservation, which the
/// driver's free count (`cudaMemGetInfo`) reports as occupied.
fn pool_headroom_bytes() -> usize {
    let dev = crate::runtime::context::get_device().unwrap_or(0).max(0) as usize;
    let pools = crate::runtime::memory_manager::pool_bytes_for(dev);
    let p = pools.external.unwrap_or(pools.default_pool);
    p.reserved.saturating_sub(p.used) as usize
}

/// The temporary budget the round-0 interpreter and the MLE-round batching work under.
///
/// `today` is the value the code derived before this function existed: the GKR leaf buffer's
/// size, less what has been folded so far. Only the riscv machine (`save_memory`) goes through
/// here; the recursion machine keeps its flat 5 GiB. That proxy has nothing to do with the memory
/// actually available: on a Keccak chunk the leaf
/// buffer (2^26 leaves, 2.1 GB) is smaller than one folded Keccak matrix (2.76 GB), the
/// subtraction saturates at 0 and MLE-round batching switches itself off (`exceeds memory limit`
/// in `batch_mle.rs`); on the round-0 side a small proxy slices the interpreter's grid by `k`.
///
/// Take the larger of `today` and a share of the real pool headroom, so no configuration gets less
/// than it has now, and the kernels keep applying their own `min(desired, budget)`.
fn r0_temp_budget(today: usize) -> usize {
    let share = (pool_headroom_bytes() as f64 * r0_budget_alpha()) as usize;
    today.max(share)
}

/// Re-derive the budget right before a round-0 allocation. The budget was fixed at round-0 entry;
/// the AIRs are processed in sequence after that, and the card's other prover lane allocates from
/// the same pool in the meantime, so the headroom the budget was sized from may have shrunk by
/// the time the large intermediates buffer (Keccak: 11.2 GB) is actually requested. Take the
/// current share when it is smaller, never less than `floor` (the value the code used before the
/// headroom formula), so a tight moment falls back to today's behaviour instead of a pool grow.
/// Two host-side pool counter reads; no device synchronisation.
fn r0_temp_budget_recheck(budget: usize, floor: usize) -> usize {
    let share = (pool_headroom_bytes() as f64 * r0_budget_alpha()) as usize;
    budget.min(share).max(floor)
}

/// Shape threshold for high-num_y traces: once `num_monomials >= DAG_FALLBACK_MONOMIAL_RATIO *
/// rules_len`, the DAG evaluator is preferred over the monomial kernel. The value is a tuning
/// knob; at its current setting the monomial kernel wins everywhere except Poseidon2Air, whose
/// DAG is far smaller than its monomial expansion.
const DAG_FALLBACK_MONOMIAL_RATIO: usize = 2;

// ---- Workload-model monomial-path dispatch --------------------------------------------
//
// Two per-round zerocheck path decisions are made from a cost model instead of shape alone:
//
//   par-y monomial cost  ≈ num_y * num_monomials / PAR_Y_MONO_EVALS_PER_US   (bandwidth bound)
//   DAG interpreter cost ≈ rules_len * DAG_FLOOR_NS_PER_RULE                 (latency floor,
//                                                                             num_y-independent)
//
// Crossover rule: a DAG-shaped trace (ratio gate above) only takes the DAG when its par-y
//     estimate exceeds the DAG latency floor. Poseidon2's DAG costs ~5ms/round regardless of
//     num_y (measured flat over ny 2^13->2^10), while par-y at low num_y is 0.8-3.6ms.
// Huge-monomial rule: AIRs with very many monomials never join the batched low-num_y monomial
//     kernel (one thread per monomial -> uncoalesced loads, measured unit cost ~2.2x par-y);
//     they run through the par-y kernel instead (y_blocks >= 1, mono-chunking supplies
//     the parallelism, so par-y is well-formed at any num_y).
//
// Both decisions only pick *which equivalent kernel* evaluates a trace; the evaluated
// polynomial values are bit-identical. Set MLE_MONO_PATH=legacy to restore the old
// (shape-only ratio gate + pure num_y threshold) dispatch for A/B comparison.

/// Measured par-y monomial throughput on the bench GPU: ~2.2-2.5e7 monomial-evals/ms
/// (near bandwidth bound at batch scale), i.e. ~24k evals/us. Used only for the
/// crossover estimate below; a conservative (low) value biases toward keeping the DAG.
const PAR_Y_MONO_EVALS_PER_US: u64 = 24_000;

/// DAG interpreter latency floor per rule (serial rule chain). Calibrated from
/// Poseidon2 (9,377 rules ~= 4.8-5.1ms/round => ~0.53us/rule) and Cpu
/// (839 rules <= ~0.3ms/round => <= ~0.36us/rule); 0.4us/rule = 400ns is a compromise
/// that captures the P2 low-num_y wins without flipping Cpu rounds where its cheap DAG
/// still wins.
const DAG_FLOOR_NS_PER_RULE: u64 = 400;

/// Crossover: keep the DAG only when
///   `num_y * num_monomials >= rules_len * DAG_CROSSOVER_EVALS_PER_RULE`.
/// Derivation: par-y time >= DAG floor
///   <=> num_y*M / PAR_Y_MONO_EVALS_PER_US >= rules_len * DAG_FLOOR_NS_PER_RULE / 1000.
/// For Poseidon2 (M = 38,841 measured, 9,377 rules) this puts the crossover at
/// num_y ~ 2^11: rounds with num_y <= 2048 leave the ~5ms DAG floor for a 0.8-3.6ms
/// par-y launch.
const DAG_CROSSOVER_EVALS_PER_RULE: u64 = DAG_FLOOR_NS_PER_RULE * PAR_Y_MONO_EVALS_PER_US / 1000;

/// Admission cap for the batched low-num_y monomial kernel. Measured monomial counts
/// (transport_pk_to_device_kb expansion): Poseidon2 M = 38,841, KeccakPermute M = 39,619;
/// every other AIR in the riscv machine is < 2k, so 10k cleanly separates the two huge-M
/// AIRs that pay the kappa~2.2 uncoalesced-load penalty in the low batch.
const LOW_BATCH_MAX_MONOMIALS: u32 = 10_000;

/// Zerocheck monomial-path dispatch policy; `MLE_MONO_PATH=legacy` restores the earlier
/// shape-only dispatch (ratio gate + pure num_y threshold) for A/B benchmarking.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MonoPathPolicy {
    /// Workload-model dispatch (crossover + huge-monomial rules above). Default.
    Workload,
    /// Earlier behavior: DAG on ratio gate alone; low batch on num_y threshold alone.
    Legacy,
}

fn mono_path_policy() -> MonoPathPolicy {
    static POLICY: std::sync::OnceLock<MonoPathPolicy> = std::sync::OnceLock::new();
    *POLICY.get_or_init(|| match std::env::var("MLE_MONO_PATH").as_deref() {
        Ok("legacy") => MonoPathPolicy::Legacy,
        _ => MonoPathPolicy::Workload,
    })
}

#[inline]
pub(crate) fn air_width_for_mat(need_rot: bool, mat_width: usize) -> u32 {
    if need_rot {
        debug_assert_eq!(mat_width % 2, 0, "rotated matrices should have even width");
        (mat_width / 2) as u32
    } else {
        mat_width as u32
    }
}

/// Debug bisection helper: returns true if a given zerocheck/logup-mle site should be FORCED
/// onto the GPU path (overriding `use_cpu_zerocheck_mle()==true`). Controlled by env
/// `MLE_GPU_ZC` = comma-separated site names, e.g. `mle`, `fold`, `zc_r0`, `logup_r0`,
/// `treebuild`, or `all`. Used to isolate which GPU zerocheck/logup path is buggy.
pub(crate) fn force_gpu_zc_site(name: &str) -> bool {
    std::env::var("MLE_GPU_ZC")
        .map(|v| v.split(',').any(|s| s.trim() == name || s.trim() == "all"))
        .unwrap_or(false)
}

// cross-prove cache for the two multi-GiB GKR buffers (leaves ~4.3 GiB, fold work
// buffer ~1.1 GiB). Fresh `with_capacity` for these sizes risks allocator defragmentation
// (re-mapping ~70 pages) on every prove, ~7-8 ms each. The cache keeps the regions checked
// out of the pool between proves (keyed by device + site name; capacity grows monotonically).
// GKR_BUF_CACHE=0 disables. Safety: checkin happens after the prove's stream is synced, so
// no in-flight GPU work references the region when the next prove checks it out.
mod buf_cache {
    use std::{
        collections::HashMap,
        sync::{Mutex, OnceLock},
    };

    use crate::runtime::d_buffer::DeviceBuffer;

    type Key = (i32, &'static str);
    // value: (device ptr, capacity in bytes)
    static CACHE: OnceLock<Mutex<HashMap<Key, (usize, usize)>>> = OnceLock::new();

    fn enabled() -> bool {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| std::env::var("GKR_BUF_CACHE").map_or(true, |v| v != "0"))
    }

    /// Minimum free VRAM (bytes) required *after* keeping a region cached. On memory-tight
    /// configurations (e.g. single-node E2E: ~18.6 GiB prover peak + 8 GiB pico pool on a
    /// 32 GiB card) holding multi-GiB regions out of the pool starves later allocations
    /// (riscv trace-gen OOM), so checkin degrades to a plain free instead.
    fn min_free_bytes() -> usize {
        static V: OnceLock<usize> = OnceLock::new();
        *V.get_or_init(|| {
            std::env::var("GKR_BUF_CACHE_MIN_FREE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8 << 30)
        })
    }

    fn free_vram() -> usize {
        #[link(name = "cudart")]
        extern "C" {
            fn cudaMemGetInfo(free: *mut usize, total: *mut usize) -> i32;
        }
        let mut free = 0usize;
        let mut total = 0usize;
        unsafe { cudaMemGetInfo(&mut free, &mut total) };
        free
    }

    fn cache() -> &'static Mutex<HashMap<Key, (usize, usize)>> {
        CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Returns a buffer of exactly `len` elements, reusing the cached region for `name` on the
    /// current device when its capacity suffices.
    ///
    /// Keyed by device, not by lane: a card's riscv and recursion lanes share one slot, so whichever
    /// checks out first takes it and the other allocates its own region. That raises the card's peak
    /// by a region and costs the loser its re-alloc on every prove. `min_free_bytes` is measured
    /// against whole-device free VRAM, so one lane's residency can also switch the other's caching
    /// off. Sized deliberately per card rather than per lane; revisit with a measurement, not a
    /// guess. With one prover lane per card (the prover's lane switch off) the slot is simply that
    /// lane's, so the inter-lane half of this goes away; `min_free_bytes` still sees a co-tenant
    /// process on the card.
    pub(crate) fn checkout<T>(name: &'static str, len: usize) -> DeviceBuffer<T> {
        if enabled() {
            let bytes = len * std::mem::size_of::<T>();
            let dev = crate::runtime::context::get_device().unwrap_or(0);
            let mut map = cache().lock().unwrap();
            if let Some(&(ptr, cap)) = map.get(&(dev, name)) {
                if cap >= bytes {
                    map.remove(&(dev, name));
                    // SAFETY: ptr was allocated by the memory manager via with_capacity and never freed
                    // (checkin forgets the owning buffer); capacity covers `len` elements.
                    return unsafe { DeviceBuffer::from_raw_parts(ptr as *mut T, len) };
                }
                // Capacity too small: drop the cached region (frees to pool) and re-alloc.
                map.remove(&(dev, name));
                drop(map);
                drop(unsafe { DeviceBuffer::from_raw_parts(ptr as *mut u8, cap) });
                return DeviceBuffer::with_capacity(len);
            }
        }
        DeviceBuffer::with_capacity(len)
    }

    /// Bytes this device's cached regions hold. `checkin` forgets the owning buffer rather than
    /// freeing it, so these are LIVE in both the pool and the tracker — the census reports them
    /// apart so a resting-live climb can be attributed to the ratchet rather than hunted for.
    pub(crate) fn cached_bytes(device: i32) -> usize {
        cache().lock().map_or(0, |m| {
            m.iter()
                .filter(|((dev, _), _)| *dev == device)
                .map(|(_, (_, cap))| *cap)
                .sum()
        })
    }

    /// Returns `buf` to the cache for `name` (current device). The buffer's region must not be
    /// referenced by in-flight GPU work (call after the prove's final sync).
    pub(crate) fn checkin<T>(name: &'static str, buf: DeviceBuffer<T>) {
        if !enabled() || buf.is_empty() {
            return;
        }
        // Memory-pressure guard: keeping the region must leave at least `min_free_bytes()`
        // of free VRAM (the region itself is already allocated, so `free_vram()` reflects
        // the post-keep state). Otherwise return it to the pool.
        if free_vram() < min_free_bytes() {
            drop(buf);
            return;
        }
        let bytes = buf.len() * std::mem::size_of::<T>();
        let dev = crate::runtime::context::get_device().unwrap_or(0);
        let mut map = cache().lock().unwrap();
        // Keep the larger of the cached and incoming regions.
        if let Some((old_ptr, old_cap)) = map.remove(&(dev, name)) {
            if old_cap >= bytes {
                map.insert((dev, name), (old_ptr, old_cap));
                drop(buf);
                return;
            }
            drop(unsafe { DeviceBuffer::from_raw_parts(old_ptr as *mut u8, old_cap) });
        }
        map.insert((dev, name), (buf.as_mut_ptr() as usize, bytes));
        std::mem::forget(buf);
    }
}
pub(crate) use buf_cache::{checkin as buf_cache_checkin, checkout as buf_cache_checkout};

/// Bytes the GKR buffer cache holds on `device`. See [`buf_cache::cached_bytes`].
pub fn gkr_buf_cache_bytes(device: i32) -> usize {
    buf_cache::cached_bytes(device)
}

#[allow(clippy::type_complexity)]
#[instrument(level = "info", skip_all)]
pub fn prove_zerocheck_and_logup_gpu<FK, HS, TS>(
    transcript: &mut TS,
    mpk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
    ctx: &ProvingContext<GenericGpuBackend<HS>>,
    save_memory: bool,
    monomial_num_y_threshold: u32,
    sm_count: u32,
) -> Result<
    (
        GkrProof<HS::SC>,
        BatchConstraintProof<HS::SC>,
        Vec<FK::ValExt>,
    ),
    LogupZerocheckError,
>
where
    FK: FieldKernels,
    HS: GpuHashScheme<BaseField = FK::Val, ExtField = FK::ValExt>,
    TS: GpuFiatShamirTranscript<HS::SC>,
{
    let logup_gkr_span = info_span!("prover.rap_constraints.logup_gkr", phase = "prover").entered();
    let log_skip = mpk.params.l_skip;
    let max_deg = mpk.max_constraint_degree;
    let trace_count = ctx.per_trace.len();

    // ctx.per_trace is ordered tallest first, so trace 0 fixes the number of MLE rounds.
    let n_max = log2_strict_usize(ctx.per_trace[0].1.common_main.height()).saturating_sub(log_skip);
    // Per trace: (interaction count, lifted log-height). These feed the stacked layout of the
    // GKR input, whose shape therefore depends on the trace heights.
    let mut total_interactions = 0u64;
    let stacking_dims: Vec<_> = ctx
        .per_trace
        .iter()
        .map(|(aid, actx)| {
            let air_pk = &mpk.per_air[*aid];

            let n_int = air_pk.vk.symbolic_constraints.interactions.len();
            let rows = actx.common_main.height();
            let log_rows = log2_strict_usize(rows);
            let log_lifted = log_rows.max(log_skip);
            total_interactions += (n_int as u64) << log_lifted;
            (n_int, log_lifted)
        })
        .collect();
    // The GKR input stacking is a single column wide.
    let n_logup = calculate_n_logup(log_skip, total_interactions);
    // [g3] GKR size diagnostics: per-AIR interaction contributions
    // and the pow2 padding slack of the GKR leaf count.
    if std::env::var("G3_MEASURE").is_ok() {
        for (air_idx, air_ctx) in ctx.per_trace.iter() {
            let pk = &mpk.per_air[*air_idx];
            let ni = pk.vk.symbolic_constraints.interactions.len();
            let h = air_ctx.common_main.height();
            tracing::info!(
                target: "bench",
                "[g3] air_id={air_idx} num_interactions={ni} height={h} contrib={}",
                (ni as u64) << log2_strict_usize(h).max(log_skip)
            );
        }
        let padded = 1u64 << (log_skip + n_logup);
        tracing::info!(
            target: "bench",
            "[g3] total_interactions={total_interactions} n_logup={n_logup} gkr_leaves={padded} \
             pow2_slack={:.1}%",
            100.0 * (padded - total_interactions) as f64 / padded as f64
        );
    }
    // GKR has no univariate skip, hence a zero stride threshold for this layout.
    let interactions_layout = StackedLayout::new(0, log_skip + n_logup, stacking_dims).unwrap();

    // Proof-of-work before the LogUp challenges are drawn (soundness boost for their sampling).
    let step_prof2 = std::env::var("STEP_PROF").is_ok();
    let t_grind = std::time::Instant::now();
    let pow_witness = transcript
        .grind_gpu(mpk.params.logup.pow_bits)
        .map_err(LogupZerocheckError::Grind)?;
    if step_prof2 {
        let _ = crate::runtime::stream::current_stream_sync();
        tracing::info!(target: "bench", "[stepprof] logup_grind={}us", t_grind.elapsed().as_micros());
    }
    let alpha_logup = transcript.sample_ext();
    let beta_logup = transcript.sample_ext();
    debug!(%alpha_logup, %beta_logup);

    let has_interactions = !interactions_layout.sorted_cols.is_empty();
    let t_pn = std::time::Instant::now();
    let mut zc_prover = LogupZerocheckGpu::<FK, HS>::new(
        mpk,
        ctx,
        n_logup,
        interactions_layout,
        alpha_logup,
        beta_logup,
        save_memory,
        monomial_num_y_threshold,
        sm_count,
    )?;
    if step_prof2 {
        let _ = crate::runtime::stream::current_stream_sync();
        tracing::info!(target: "bench", "[stepprof] prover_new={}us", t_pn.elapsed().as_micros());
    }
    let n_global = zc_prover.n_global;

    let total_leaves = 1 << (log_skip + n_logup);
    zc_prover
        .mem
        .emit_metrics_with_label("prover.before_gkr_input_evals");
    zc_prover.mem.reset_peak();
    // [stepprof] synced timing of input_evals (the tracing span is async-skewed; the kernels
    // may still be in flight when the span closes). STEP_PROF=1 to enable.
    let step_prof = std::env::var("STEP_PROF").is_ok();
    let t_ie = std::time::Instant::now();
    let (inputs, alpha) = if has_interactions {
        log_gkr_input_evals::<FK, HS>(
            &zc_prover.trace_interactions,
            mpk,
            ctx,
            log_skip,
            alpha_logup,
            &zc_prover.d_challenges,
            total_leaves,
            total_interactions as usize,
        )?
    } else {
        (DeviceBuffer::new(), FK::ValExt::ZERO)
    };
    if step_prof {
        let _ = crate::runtime::stream::current_stream_sync();
        tracing::info!(target: "bench", "[stepprof][{}] input_evals_synced={}us", crate::prove_phase(), t_ie.elapsed().as_micros());
    }
    // The batch-MLE memory budget starts from the size of the GKR input buffer.
    zc_prover.gkr_mem_contribution = inputs.len() * std::mem::size_of::<Frac<FK::ValExt>>();
    zc_prover.memory_limit_bytes = zc_prover.gkr_mem_contribution;
    if !zc_prover.save_memory {
        const DEFAULT_MEMORY_LIMIT: usize = 5 << 30; // 5GiB
        if zc_prover.memory_limit_bytes > DEFAULT_MEMORY_LIMIT {
            tracing::warn!(
                "prover.memory_limit_bytes {} already exceeds 5GiB",
                zc_prover.memory_limit_bytes
            );
        }
        zc_prover.memory_limit_bytes = DEFAULT_MEMORY_LIMIT;
        zc_prover.memory_limit_floor = DEFAULT_MEMORY_LIMIT;
    } else {
        // riscv machine only: the recursion machine keeps its flat constant. Its round-0 buffers
        // are tiny (RecursionPrepAir asks for ≤ 2 MB), so the headroom formula could only move
        // its MLE-round batching, and the interleaved dual-lane A/B (night-0915, Q8) showed no
        // gain there worth the exposure.
        zc_prover.memory_limit_floor = zc_prover.memory_limit_bytes;
        zc_prover.memory_limit_bytes = r0_temp_budget(zc_prover.memory_limit_bytes);
    }
    zc_prover
        .mem
        .emit_metrics_with_label("prover.gkr_input_evals");

    let t_fr = std::time::Instant::now();
    let (frac_out, mut xi) = fractional_sumcheck_gpu::<FK, HS::SC, _>(
        transcript,
        inputs,
        alpha,
        true,
        &mut zc_prover.mem,
    )?;
    if step_prof {
        let _ = crate::runtime::stream::current_stream_sync();
        tracing::info!(target: "bench", "[stepprof][{}] fractional_sumcheck_synced={}us", crate::prove_phase(), t_fr.elapsed().as_micros());
    }
    while xi.len() != log_skip + n_global {
        xi.push(transcript.sample_ext());
    }
    debug!(?xi);
    zc_prover.xi = xi;

    logup_gkr_span.exit();

    // ple_fold falls inside this span, but it never synchronizes the stream, so the span does not
    // capture the GPU time of the folding kernels themselves.
    let round0_span = info_span!("prover.rap_constraints.round0", phase = "prover").entered();
    // Batched sumcheck starts here.
    let mut round_evals = Vec::with_capacity(n_max);
    let mut sampled_r = Vec::with_capacity(n_max + 1);
    // Randomness that batches all constraints together.
    let lambda = transcript.sample_ext();
    debug!(%lambda);

    let round0_sp_polys = zc_prover.sumcheck_uni_round0_polys(ctx, lambda)?;
    let s_0_cpu_span = info_span!("s'_0 -> s_0 cpu interpolations").entered();
    let sp0_degree = sumcheck_round0_deg(log_skip, max_deg);
    let s_deg = max_deg + 1;
    let s0_degree = sumcheck_round0_deg(log_skip, s_deg);
    let dft_len = (s0_degree + 1).next_power_of_two();
    // Serial Bowers: at the typical `dft_len = 128` of this path, p3's rayon-backed
    // `Radix2Bowers` spends more on thread-pool overhead than on the transform (~0.6s/run).
    // Matches the serial `Radix2BowersSerial` choice of the GPU riscv path.
    let dft = SerialRadix2Dft;
    let logup_s0_mat = {
        let eq_sharp = eq_sharp_uni_poly(&zc_prover.xi[..log_skip]);
        let mut eq_c = eq_sharp.into_coeffs();
        eq_c.resize(dft_len, FK::ValExt::ZERO);
        let eq_on_dom = dft.dft(eq_c);

        let mat_cols = 2 * trace_count;
        let mut coeff_mat = FK::ValExt::zero_vec(mat_cols * dft_len);
        for (col, poly) in round0_sp_polys[..2 * trace_count].iter().enumerate() {
            for (deg, &c) in poly.coeffs().iter().enumerate().take(sp0_degree + 1) {
                // SAFETY: `deg <= sp0_degree < s0_degree + 1 <= dft_len` rows and `col < mat_cols`
                // columns, both inside the `mat_cols * dft_len` allocation.
                unsafe {
                    *coeff_mat.get_unchecked_mut(deg * mat_cols + col) = c;
                }
            }
        }
        let mut evals_dom = dft.dft_batch(RowMajorMatrix::new(coeff_mat, mat_cols));
        for (eq_v, dom_row) in zip(eq_on_dom, evals_dom.values.chunks_mut(mat_cols)) {
            for cell in dom_row {
                *cell *= eq_v;
            }
        }
        dft.idft_batch(evals_dom)
    };
    let skip_size_f = FK::Val::from_usize(1 << log_skip);
    // For every present AIR, the LogUp claims sum over D of the numerator and denominator s_0.
    let (p_claims, q_claims): (Vec<_>, Vec<_>) = (0..trace_count)
        .map(|t| {
            let [claim_num, claim_den] = [0, 1].map(|which| {
                // Summing s_0 over D only needs its coefficients at multiples of |D|.
                (0..=s0_degree)
                    .step_by(1 << log_skip)
                    .map(|k| unsafe {
                        // SAFETY: the matrix is dft_len rows by 2 * trace_count columns and
                        // k <= s0_degree < dft_len.
                        *logup_s0_mat
                            .values
                            .get_unchecked(k * 2 * trace_count + 2 * t + which)
                    })
                    .sum::<FK::ValExt>()
                    * skip_size_f
            });
            transcript.observe_ext(claim_num);
            transcript.observe_ext(claim_den);

            (claim_num, claim_den)
        })
        .unzip();

    let mu = transcript.sample_ext();
    debug!(%mu);
    let mu_powers = mu.powers().take(3 * trace_count).collect_vec();

    let zc_s0 = {
        let eq_r0 = eq_uni_poly::<FK::Val, _>(log_skip, zc_prover.xi[0]);
        let mut eq_c = eq_r0.into_coeffs();
        eq_c.resize(dft_len, FK::ValExt::ZERO);
        let eq_on_dom = dft.dft(eq_c);

        // Fold the zerocheck polynomials into one, weighted by the trailing powers of mu.
        let mut zc_coeffs = FK::ValExt::zero_vec(dft_len);
        let zc_mus = &mu_powers[2 * trace_count..];
        let zc_polys = &round0_sp_polys[2 * trace_count..];
        for (deg, acc) in zc_coeffs.iter_mut().enumerate().take(sp0_degree + 1) {
            for (&m, zc_p) in zip(zc_mus, zc_polys) {
                *acc += m * *zc_p.coeffs().get(deg).unwrap_or(&FK::ValExt::ZERO);
            }
        }
        let mut evals_dom = dft.dft(zc_coeffs);
        for (eq_v, cell) in zip(eq_on_dom, &mut evals_dom) {
            *cell *= eq_v;
        }
        dft.idft(evals_dom)
    };

    // Combine logup and zerocheck parts coefficient by coefficient into the batched s_0.
    let s0_poly = UnivariatePoly::new(
        zip(logup_s0_mat.values.chunks_exact(2 * trace_count), zc_s0)
            .take(s0_degree + 1)
            .map(|(lrow, zc_c)| {
                let merged = zc_c
                    + zip(&mu_powers, lrow)
                        .map(|(&w, &v)| w * v)
                        .sum::<FK::ValExt>();
                transcript.observe_ext(merged);
                merged
            })
            .collect(),
    );
    drop(s_0_cpu_span);

    let r_0 = transcript.sample_ext();
    sampled_r.push(r_0);
    debug!(round = 0, r_round = %r_0);
    zc_prover.prev_s_eval = s0_poly.eval_at_point(r_0);
    debug!("s_0(r_0) = {}", zc_prover.prev_s_eval);

    zc_prover.fold_ple_evals(ctx, r_0)?;
    drop(round0_span);

    // Multilinear sumcheck rounds. Each round produces the univariate `s_round` (multilinear
    // pieces times eq, so degree `s_deg` = constraint degree + 1) and then draws `r_round` in
    // `FK::ValExt`. Only the points 1..=s_deg are sent: the value at 0 follows from the claim
    // `s_{round-1}(r)` left by the previous round.
    let mle_rounds_span =
        info_span!("prover.rap_constraints.mle_rounds", phase = "prover").entered();
    debug!(%s_deg);
    // [mleprof] env-gated split of eval vs fold time across the mle rounds (each synced).
    // OFF by default (no perturbation); set MLE_PROF=1 to measure.
    let mle_prof = std::env::var("MLE_PROF").is_ok();
    let mut t_eval = std::time::Duration::ZERO;
    let mut t_fold = std::time::Duration::ZERO;
    let mut prof_rows: Vec<(usize, u128, u128)> = Vec::new();
    for round in 1..=n_max {
        let te = std::time::Instant::now();
        let sp_round_evals = zc_prover.sumcheck_polys_batch_eval(round, sampled_r[round - 1])?;
        let mut ev = 0u128;
        if mle_prof {
            let _ = crate::runtime::stream::current_stream_sync();
            ev = te.elapsed().as_micros();
            t_eval += te.elapsed();
        }
        let batch_s =
            zc_prover.compute_batch_s_poly(sp_round_evals, trace_count, round, &mu_powers);
        let batch_s_evals = (1..=s_deg)
            .map(|pt| batch_s.eval_at_point(FK::ValExt::from_usize(pt)))
            .collect_vec();
        for &y in &batch_s_evals {
            transcript.observe_ext(y);
        }
        round_evals.push(batch_s_evals);

        let r_round = transcript.sample_ext();
        debug!(%round, %r_round);
        sampled_r.push(r_round);
        zc_prover.prev_s_eval = batch_s.eval_at_point(r_round);

        let tf = std::time::Instant::now();
        zc_prover.fold_mle_evals(round, r_round)?;
        if mle_prof {
            let _ = crate::runtime::stream::current_stream_sync();
            t_fold += tf.elapsed();
            prof_rows.push((round, ev, tf.elapsed().as_micros()));
        }
    }
    if mle_prof {
        for (round, ev, fo) in &prof_rows {
            tracing::info!(target: "bench", "[mleprof] round={round} eval={ev}us fold={fo}us");
        }
        tracing::info!(
            target: "bench",
            "[mleprof] TOTAL eval={}us fold={}us rounds={n_max}",
            t_eval.as_micros(), t_fold.as_micros()
        );
    }
    assert_eq!(sampled_r.len(), n_max + 1);

    let t_co = std::time::Instant::now();
    let openings_all = zc_prover.into_column_openings()?;
    if step_prof2 {
        let _ = crate::runtime::stream::current_stream_sync();
        tracing::info!(target: "bench", "[stepprof] column_openings={}us", t_co.elapsed().as_micros());
    }

    let t_obs = std::time::Instant::now();
    let rot_flags = ctx
        .per_trace
        .iter()
        .map(|(a, _)| mpk.per_air[*a].vk.params.need_rot)
        .collect::<Vec<_>>();
    // Transcript order: every trace's common-main openings, then the remaining parts
    // (preprocessed / cached) of every trace.
    for (rot, per_part) in rot_flags.iter().zip(openings_all.iter()) {
        for (at_x, at_rot) in column_openings_by_rot(&per_part[0], *rot) {
            transcript.observe_ext(at_x);
            transcript.observe_ext(at_rot);
        }
    }
    for (rot, per_part) in rot_flags.iter().zip(openings_all.iter()) {
        for extra in per_part.iter().skip(1) {
            for (at_x, at_rot) in column_openings_by_rot(extra, *rot) {
                transcript.observe_ext(at_x);
                transcript.observe_ext(at_rot);
            }
        }
    }
    if step_prof2 {
        let _ = crate::runtime::stream::current_stream_sync();
        tracing::info!(target: "bench", "[stepprof] opening_observes={}us", t_obs.elapsed().as_micros());
    }
    drop(mle_rounds_span);

    let bc_proof = BatchConstraintProof {
        numerator_term_per_air: p_claims,
        denominator_term_per_air: q_claims,
        univariate_round_coeffs: s0_poly.into_coeffs(),
        sumcheck_round_polys: round_evals,
        column_openings: openings_all,
    };
    let gkr_out = GkrProof {
        logup_pow_witness: pow_witness,
        q0_claim: frac_out.fractional_sum.1,
        claims_per_layer: frac_out.claims_per_layer,
        sumcheck_polys: frac_out.sumcheck_polys,
    };

    Ok((gkr_out, bc_proof, sampled_r))
}

pub struct LogupZerocheckGpu<'a, FK: FieldKernels, HS: GpuHashScheme> {
    pub alpha_logup: FK::ValExt,
    pub beta_pows: Vec<FK::ValExt>,
    // alpha_logup followed by beta^0, beta^1, ..., beta^max_msg_len, on device.
    pub d_challenges: DeviceBuffer<FK::ValExt>,

    pub l_skip: usize,
    n_logup: usize,
    n_global: usize,

    pub omega_skip: FK::Val,
    pub omega_skip_pows: Vec<FK::Val>,
    d_omega_skip_pows: DeviceBuffer<FK::Val>,

    pub interactions_layout: StackedLayout,
    pub constraint_degree: usize,
    n_per_trace: Vec<isize>,
    max_num_constraints: usize,
    pub monomial_num_y_threshold: u32,
    sm_count: u32,
    // Available after GKR:
    pub xi: Vec<FK::ValExt>,
    pub lambda_pows: Option<DeviceBuffer<FK::ValExt>>,
    /// Per-AIR lambda combinations (by `air_idx`), filled in once lambda has been drawn.
    lambda_combinations: Vec<Option<crate::scratch::Scratch<FK::ValExt>>>,
    /// Device copy of the beta powers used by the logup MLE rounds.
    d_beta_pows: DeviceBuffer<FK::ValExt>,
    /// Per-trace logup combinations (by `trace_idx`), filled in once xi has been drawn.
    logup_combinations: Vec<Option<LogupCombinations<FK>>>,

    // Keyed by n_T: a segment tree over eq(xi[j..1+n_T]) for j = 1..=n_T-round+1, stored in
    // reverse order.
    eq_xis: FxHashMap<usize, EqEvalLayers<FK::ValExt>>,
    eq_3b_per_trace: Vec<Vec<FK::ValExt>>,
    d_eq_3b_per_trace: Vec<crate::scratch::Scratch<FK::ValExt>>,
    // Selector values on the boolean hypercube alone; used by round 0.
    sels_per_trace_base: Vec<DeviceMatrix<FK::Val>>,
    /// Backing allocations for the current round's fold outputs — one per `batch_fold`
    /// call, replaced each round once every matrix pointing into the previous round's is
    /// gone. See `fold_mle_evals`.
    fold_pools: Vec<Arc<DeviceBuffer<FK::ValExt>>>,
    // After univariate round 0:
    mat_evals_per_trace: Vec<Vec<DeviceMatrix<FK::ValExt>>>,
    sels_per_trace: Vec<DeviceMatrix<FK::ValExt>>,
    // Store public_values per trace (similar to CPU's ColMajorEvalHelper)
    public_values_per_trace: Vec<DeviceBuffer<FK::Val>>,
    air_indices_per_trace: Vec<usize>,
    zerocheck_tilde_evals: Vec<FK::ValExt>,
    logup_tilde_evals: Vec<[FK::ValExt; 2]>,
    needs_next_per_trace: Vec<bool>,

    trace_interactions: Vec<Option<TraceInteractionMeta>>,
    pk: &'a DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,

    // During round `j`: the previous round polynomial at its challenge, `s_{j-1}(r_{j-1})`.
    pub(crate) prev_s_eval: FK::ValExt,
    pub(crate) eq_ns: Vec<FK::ValExt>,
    pub(crate) eq_sharp_ns: Vec<FK::ValExt>,

    mem: MemTracker,
    save_memory: bool,

    gkr_mem_contribution: usize,
    /// Byte budget for the batch-MLE scratch buffers; fixed once the GKR input is evaluated.
    memory_limit_bytes: usize,
    /// The proxy value `memory_limit_bytes` was derived from (see `r0_temp_budget`); the floor a
    /// pre-allocation re-check never goes below.
    memory_limit_floor: usize,

    _phantom: PhantomData<FK>,
}

impl<'a, FK: FieldKernels, HS: GpuHashScheme<BaseField = FK::Val, ExtField = FK::ValExt>>
    LogupZerocheckGpu<'a, FK, HS>
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        pk: &'a DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
        ctx: &ProvingContext<GenericGpuBackend<HS>>,
        n_logup: usize,
        gkr_layout: StackedLayout,
        alpha_logup: FK::ValExt,
        beta_logup: FK::ValExt,
        save_memory: bool,
        monomial_num_y_threshold: u32,
        sm_count: u32,
    ) -> Result<Self, LogupZerocheckError> {
        let mem = MemTracker::start("prover.logup_zerocheck_prover");
        let skip_bits = pk.params.l_skip;
        let w_skip = FK::Val::two_adic_generator(skip_bits);
        let w_skip_pows = w_skip.powers().take(1 << skip_bits).collect_vec();
        let w_skip_pows_dev = w_skip_pows.to_device()?;
        let present_count = ctx.per_trace.len();

        let deg_bound = pk.max_constraint_degree;

        let max_msg_len = pk
            .per_air
            .iter()
            .map(|a_pk| a_pk.other_data.interaction_rules.max_fields_len)
            .max()
            .unwrap_or(0);
        let beta_powers = beta_logup.powers().take(max_msg_len + 1).collect_vec();
        let host_challenges = [&[alpha_logup], &beta_powers[..]].concat();
        let challenges_dev = host_challenges.to_device()?;
        let beta_pows_dev = beta_powers.to_device()?;

        let log_n_per_trace: Vec<isize> = ctx
            .common_main_traces()
            .map(|(_, main_t)| log2_strict_usize(main_t.height()) as isize - skip_bits as isize)
            .collect();
        let n_max = log_n_per_trace[0].max(0) as usize;
        let n_global = max(n_max, n_logup);
        info!(%n_global, %n_logup);

        let constraint_cap = pk
            .per_air
            .iter()
            .map(|a_pk| {
                a_pk.vk
                    .symbolic_constraints
                    .constraints
                    .constraint_idx
                    .len()
            })
            .max()
            .unwrap_or(0);

        // Per-trace interaction info (stacked slices) used by the GPU GKR input evaluation.
        let interaction_meta = collect_trace_interactions::<FK, HS>(pk, ctx, &gkr_layout);

        let rot_per_trace = ctx
            .per_trace
            .iter()
            .map(|(a, _)| pk.per_air[*a].vk.params.need_rot)
            .collect::<Vec<_>>();

        Ok(Self {
            alpha_logup,
            beta_pows: beta_powers,
            d_challenges: challenges_dev,
            l_skip: skip_bits,
            n_logup,
            n_global,
            omega_skip: w_skip,
            omega_skip_pows: w_skip_pows,
            d_omega_skip_pows: w_skip_pows_dev,
            interactions_layout: gkr_layout,
            constraint_degree: deg_bound,
            n_per_trace: log_n_per_trace,
            max_num_constraints: constraint_cap,
            sm_count,
            xi: vec![],
            lambda_pows: None,
            lambda_combinations: (0..pk.per_air.len()).map(|_| None).collect(),
            d_beta_pows: beta_pows_dev,
            logup_combinations: (0..present_count).map(|_| None).collect(),
            eq_xis: FxHashMap::default(),
            eq_3b_per_trace: vec![],
            d_eq_3b_per_trace: vec![],
            sels_per_trace_base: vec![],
            fold_pools: vec![],
            mat_evals_per_trace: vec![],
            sels_per_trace: vec![],
            public_values_per_trace: ctx
                .per_trace
                .iter()
                .map(|(_, actx)| {
                    if actx.public_values.is_empty() {
                        Ok(DeviceBuffer::new())
                    } else {
                        actx.public_values.to_device()
                    }
                })
                .collect::<Result<Vec<_>, _>>()?,
            air_indices_per_trace: ctx.per_trace.iter().map(|(a, _)| *a).collect_vec(),
            zerocheck_tilde_evals: vec![FK::ValExt::ZERO; present_count],
            logup_tilde_evals: vec![[FK::ValExt::ZERO; 2]; present_count],
            needs_next_per_trace: rot_per_trace,
            trace_interactions: interaction_meta,
            pk,
            prev_s_eval: FK::ValExt::ZERO,
            eq_ns: Vec::with_capacity(n_max + 1),
            eq_sharp_ns: Vec::with_capacity(n_max + 1),
            mem,
            save_memory,
            gkr_mem_contribution: 0,
            memory_limit_bytes: 0, // filled in once the GKR input has been evaluated

            memory_limit_floor: 0,
            monomial_num_y_threshold,
            _phantom: PhantomData,
        })
    }

    // PERF: zerocheck could hand back evaluations and batch its polynomials by degree before
    // interpolating. LogUp cannot, because its sum claims are computed from the interpolants here.
    #[instrument(name = "prover.rap_constraints.ple_round0", level = "info", skip_all)]
    fn sumcheck_uni_round0_polys(
        &mut self,
        ctx: &ProvingContext<GenericGpuBackend<HS>>,
        lambda: FK::ValExt,
    ) -> Result<Vec<UnivariatePoly<FK::ValExt>>, LogupZerocheckError> {
        self.mem
            .emit_metrics_with_label("prover.batch_constraints.before_round0");
        self.mem.reset_peak();
        let logup_vars = self.n_logup;
        let l_skip = self.l_skip;
        let xi_pt = &self.xi;
        let lambda_pows_host = lambda.powers().take(self.max_num_constraints).collect_vec();
        self.lambda_pows = Some(if !lambda_pows_host.is_empty() {
            lambda_pows_host.to_device()?
        } else {
            DeviceBuffer::new()
        });
        // Every AIR with expanded monomials gets its lambda combinations computed up front.
        let lam_dev = self.lambda_pows.as_ref().unwrap();
        for (air_idx, air_pk) in self.pk.per_air.iter().enumerate() {
            if air_pk.other_data.zerocheck_monomials.is_some() {
                self.lambda_combinations[air_idx] = Some(
                    compute_lambda_combinations::<FK, HS>(self.pk, air_idx, lam_dev)
                        .map_err(LogupZerocheckError::LambdaCombinations)?,
                );
            }
        }
        let present_n = ctx.per_trace.len();
        debug_assert_eq!(present_n, self.n_per_trace.len());

        self.eq_3b_per_trace = ctx
            .per_trace
            .iter()
            .enumerate()
            .map(|(t_i, (a_i, _))| {
                let air_vk = &self.pk.per_air[*a_i].vk;
                let int_count = air_vk.num_interactions();
                if int_count > 0 {
                    let log_n = self.n_per_trace[t_i];
                    let lift = log_n.max(0) as usize;
                    let mut bits = vec![FK::Val::ZERO; logup_vars - lift];
                    let mut eq_weights = Vec::with_capacity(int_count);
                    for k_int in 0..int_count {
                        let row_in_stack =
                            self.interactions_layout.get(t_i, k_int).unwrap().row_idx;
                        let mut rest = row_in_stack >> (l_skip + lift);
                        for slot in &mut bits {
                            *slot = FK::Val::from_bool(rest & 1 == 1);
                            rest >>= 1;
                        }
                        let w_eq = eval_eq_mle(&self.xi[l_skip + lift..l_skip + logup_vars], &bits);
                        eq_weights.push(w_eq);
                    }
                    eq_weights
                } else {
                    vec![]
                }
            })
            .collect_vec();
        self.d_eq_3b_per_trace = self
            .eq_3b_per_trace
            .iter()
            .map(|w3| {
                if w3.is_empty() {
                    Ok(crate::scratch::Scratch::owned(DeviceBuffer::new()))
                } else {
                    crate::scratch::upload(w3)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Likewise build, ahead of time, the logup combinations of each trace that has
        // interaction monomials.
        for (tix, (aix, _)) in ctx.per_trace.iter().enumerate() {
            let apk = &self.pk.per_air[*aix];
            if apk.other_data.interaction_monomials.is_some()
                && !self.eq_3b_per_trace[tix].is_empty()
            {
                self.logup_combinations[tix] = Some(
                    compute_logup_combinations(
                        self.pk,
                        *aix,
                        &self.d_beta_pows,
                        &self.d_eq_3b_per_trace[tix],
                        &self.eq_3b_per_trace[tix],
                        &self.beta_pows,
                    )
                    .map_err(LogupZerocheckError::LogupCombinations)?,
                );
            }
        }

        // PERF: building the layers for all n together in transposed order with
        // eq_nonoverlapping_stage_ext would need less memory.
        for &log_n in &self.n_per_trace {
            let nl = log_n.max(0) as usize;
            if let Entry::Vacant(vacant) = self.eq_xis.entry(nl) {
                let eq_layers = EqEvalLayers::new_rev_with_kernels::<FK>(
                    nl,
                    xi_pt[l_skip..l_skip + nl].iter().rev(),
                )
                .map_err(LogupZerocheckError::EqEvalLayers)?;
                vacant.insert(eq_layers);
            }
        }

        self.sels_per_trace_base = self
            .n_per_trace
            .iter()
            .map(|&log_n| {
                let nl = log_n.max(0) as usize;
                let rows = 1 << nl;
                let mut sel_cols = FK::Val::zero_vec(3 * rows);
                sel_cols[rows..2 * rows - 1].fill(FK::Val::ONE); // is_transition
                sel_cols[0] = FK::Val::ONE; // is_first
                sel_cols[2 * rows + rows - 1] = FK::Val::ONE; // is_last
                let cols_dev = sel_cols.to_device()?;
                Ok(DeviceMatrix::new(Arc::new(cols_dev), rows, 3))
            })
            .collect::<Result<Vec<_>, MemCopyError>>()?;

        let base_sels = self.sels_per_trace_base.clone();

        // Slots 0..2*present_n: a logup (numer, denom) pair per present AIR; the last present_n
        // slots: one zerocheck polynomial per present AIR.
        let mut sp_polys_out = vec![UnivariatePoly::new(vec![]); 3 * present_n];
        let lam_pows_dev = self
            .lambda_pows
            .as_ref()
            .expect("lambda powers must be set before round-0 evaluation");

        // [stepprof] round0 split: accumulate synced zerocheck-vs-logup eval time across AIRs.
        let r0_prof = std::env::var("STEP_PROF").is_ok();
        let mut r0_zc_us: u128 = 0;
        let mut r0_lg_us: u128 = 0;
        if r0_prof {
            // Real headroom next to the proxy the budget is derived from: the pool counters see
            // through the pool's reservation, the driver's free count does not.
            let dev = crate::runtime::context::get_device().unwrap_or(-1);
            let pools = crate::runtime::memory_manager::pool_bytes_for(dev.max(0) as usize);
            let ext = pools.external.unwrap_or_default();
            let (driver_free, driver_total) = crate::runtime::memory_manager::device_mem_info();
            tracing::info!(
                target: "bench",
                "[stepprof][{}] r0headroom dev={dev} pool_reserved={} pool_used={} default_reserved={} \
                 default_used={} tracked={} driver_free={driver_free} driver_total={driver_total} \
                 budget={} gkr_leaves_bytes={}",
                crate::prove_phase(),
                ext.reserved,
                ext.used,
                pools.default_pool.reserved,
                pools.default_pool.used,
                crate::runtime::memory_manager::tracked_current_bytes(),
                self.memory_limit_bytes,
                self.gkr_mem_contribution
            );
        }

        // Handle one AIR's trace at a time and finish all of its work before moving on; keeping
        // an AIR's work together is cheaper than interleaving.
        for (trace_idx, ((air_idx, actx), &log_n, sel_cube, pv_dev, eq3)) in izip!(
            &ctx.per_trace,
            &self.n_per_trace,
            &base_sels,
            &self.public_values_per_trace,
            &self.eq_3b_per_trace,
        )
        .enumerate()
        {
            debug!("starting batch constraints for air_idx={air_idx} (trace_idx={trace_idx})");
            let this_pk = &self.pk.per_air[*air_idx];
            // Includes both plain AIR constraints and symbolic interactions (1c: tree form
            // is cached in the key — the DAG→tree clone-out used to run per AIR × chunk).
            let air_rules = this_pk.symbolic_constraints();
            let local_constraint_deg = this_pk.vk.max_constraint_degree as usize;
            debug_assert_eq!(air_rules.max_constraint_degree(), local_constraint_deg);
            assert!(
                local_constraint_deg <= self.constraint_degree,
                "Max constraint degree ({local_constraint_deg}) of AIR {air_idx} exceeds the global maximum {}",
                self.constraint_degree
            );

            let log_big_dom = log2_ceil_usize(local_constraint_deg << l_skip);
            let omega_root = FK::Val::two_adic_generator(log_big_dom);

            assert!(!xi_pt.is_empty(), "xi vector must not be empty");

            let trace_h = actx.common_main.height();
            let mut part_ptrs = Vec::with_capacity(actx.cached_mains.len() + 1);
            for cm in &actx.cached_mains {
                part_ptrs.push(cm.trace.buffer().as_ptr());
            }
            part_ptrs.push(actx.common_main.buffer().as_ptr());
            let part_ptrs_dev = crate::scratch::upload(&part_ptrs)?;

            let n_lift = log_n.max(0) as usize;
            let eq_tree = &self.eq_xis[&n_lift];
            let temp_budget = if self.save_memory {
                let now = r0_temp_budget_recheck(self.memory_limit_bytes, self.memory_limit_floor);
                if r0_prof && now < self.memory_limit_bytes {
                    tracing::info!(
                        target: "bench",
                        "[stepprof][{}] r0recheck air={} budget_entry={} budget_now={} floor={}",
                        crate::prove_phase(),
                        this_pk.air_name,
                        self.memory_limit_bytes,
                        now,
                        self.memory_limit_floor
                    );
                }
                now
            } else {
                self.memory_limit_bytes
            };
            // A local_constraint_deg of 0 means the AIR has no constraints. At degree 1, a
            // constraint can only vanish on all 2^l_skip points by being the zero polynomial. In
            // both cases `s'_0 = 0`, so no coset needs evaluating.
            let num_cosets_zc = local_constraint_deg.saturating_sub(1);
            let zc_on_cpu = FK::use_cpu_zerocheck_mle() && !force_gpu_zc_site("zc_r0");
            // Off unless explicitly on; see the `Z1_JIT_VERIFY` note in `round0.rs`.
            let zc_cross_check = crate::cuda::jit::env_flag("MLE_VERIFY_ZC_R0", false);

            // CPU zerocheck round0 sp_0 (computed if used for proof, or for verification).
            let zc_cpu_poly: Option<UnivariatePoly<FK::ValExt>> = if zc_on_cpu || zc_cross_check {
                use round0::evaluate_round0_constraints_cpu_fallback;
                let cached_mats: Vec<&DeviceMatrix<FK::Val>> =
                    actx.cached_mains.iter().map(|cd| &cd.trace).collect();
                let lam_host: Vec<FK::ValExt> = match self.lambda_pows.as_ref() {
                    Some(d) if !d.is_empty() => d.to_host()?,
                    _ => vec![],
                };
                evaluate_round0_constraints_cpu_fallback::<FK>(
                    &this_pk.vk.symbolic_constraints.constraints,
                    &InteractionEvalPlan::from_dag(&this_pk.vk.symbolic_constraints),
                    &cached_mats,
                    &actx.common_main,
                    &xi_pt[l_skip..l_skip + n_lift],
                    this_pk.vk.params.need_rot,
                    &lam_host,
                    l_skip,
                    trace_h,
                    local_constraint_deg,
                    &actx.public_values,
                )?
            } else {
                None
            };

            // GPU zerocheck round0 sp_0.
            let t_r0zc = std::time::Instant::now();
            let zc_gpu_poly: Option<UnivariatePoly<FK::ValExt>> = if !zc_on_cpu || zc_cross_check {
                let zc_sums = evaluate_round0_constraints_gpu::<FK, HS>(
                    this_pk,
                    sel_cube.buffer(),
                    &part_ptrs_dev,
                    pv_dev,
                    eq_tree.get_ptr(n_lift),
                    lam_pows_dev,
                    1 << l_skip,
                    1 << n_lift,
                    trace_h as u32,
                    num_cosets_zc as u32,
                    omega_root,
                    temp_budget,
                )?;
                if !zc_sums.is_empty() {
                    let q_evals = zc_sums.to_host()?;
                    if crate::cuda::jit::env_flag("MLE_DUMP_ZCR0", false) {
                        tracing::warn!(
                            "ZCR0_DUMP trace={trace_idx} l_skip={l_skip} num_cosets={num_cosets_zc} \
                             skip_domain={} omega_root={omega_root:?} q_evals={q_evals:?}",
                            1usize << l_skip
                        );
                    }
                    let q_poly = {
                        // Transpose q_evals into row-major order, one column per coset.
                        let mut q_rows = FK::ValExt::zero_vec(num_cosets_zc << l_skip);
                        for coset_idx in 0..num_cosets_zc {
                            for i in 0..1usize << l_skip {
                                q_rows[i * num_cosets_zc + coset_idx] =
                                    q_evals[(coset_idx << l_skip) + i];
                            }
                        }
                        UnivariatePoly::from_geometric_cosets_evals_idft(
                            RowMajorMatrix::new(q_rows, num_cosets_zc),
                            omega_root,
                            omega_root,
                        )
                    };
                    // sp_0 = (Z^{2^l_skip} - 1) * q
                    let sp_deg = sumcheck_round0_deg(l_skip, local_constraint_deg);
                    let sp_coeffs = (0..=sp_deg)
                        .map(|i| {
                            let mut c = -*q_poly.coeffs().get(i).unwrap_or(&FK::ValExt::ZERO);
                            if i >= 1 << l_skip {
                                c += q_poly.coeffs()[i - (1 << l_skip)];
                            }
                            c
                        })
                        .collect_vec();
                    Some(UnivariatePoly::new(sp_coeffs))
                } else {
                    None
                }
            } else {
                None
            };
            if r0_prof {
                let _ = crate::runtime::stream::current_stream_sync();
                let us = t_r0zc.elapsed().as_micros();
                r0_zc_us += us;
                // Per-AIR attribution of the synced round-0 zerocheck time (STEP_PROF only).
                tracing::info!(
                    target: "bench",
                    "[stepprof][{}] r0zc_air air={} us={us}", crate::prove_phase(), this_pk.air_name
                );
            }

            if zc_cross_check {
                match (&zc_cpu_poly, &zc_gpu_poly) {
                    (Some(c), Some(g)) => {
                        let cpu_c = c.coeffs();
                        let gpu_c = g.coeffs();
                        let mut mism = 0usize;
                        let mut first_bad = None;
                        for i in 0..cpu_c.len().max(gpu_c.len()) {
                            let cv = cpu_c.get(i).copied().unwrap_or(FK::ValExt::ZERO);
                            let gv = gpu_c.get(i).copied().unwrap_or(FK::ValExt::ZERO);
                            if cv != gv {
                                mism += 1;
                                if first_bad.is_none() { first_bad = Some((i, cv, gv)); }
                            }
                        }
                        if mism > 0 {
                            let (i, cv, gv) = first_bad.unwrap();
                            tracing::warn!(
                                "ZC_R0_VERIFY trace={trace_idx} l_skip={l_skip} n_lift={n_lift} \
                                 deg={local_constraint_deg}: {mism} coeff mismatch (cpu_len={} gpu_len={}); \
                                 first coeff={i} CPU={cv:?} GPU={gv:?}",
                                cpu_c.len(), gpu_c.len()
                            );
                        } else {
                            tracing::warn!(
                                "ZC_R0_VERIFY trace={trace_idx} l_skip={l_skip}: OK ({} coeffs)",
                                cpu_c.len()
                            );
                        }
                    }
                    (None, None) => {
                        tracing::warn!("ZC_R0_VERIFY trace={trace_idx} l_skip={l_skip}: OK (both None)");
                    }
                    _ => tracing::warn!(
                        "ZC_R0_VERIFY trace={trace_idx} l_skip={l_skip}: SHAPE mismatch cpu_some={} gpu_some={}",
                        zc_cpu_poly.is_some(), zc_gpu_poly.is_some()
                    ),
                }
            }

            let zc_pick = if zc_on_cpu { zc_cpu_poly } else { zc_gpu_poly };
            if let Some(sp_0) = zc_pick {
                sp_polys_out[2 * present_n + trace_idx] = sp_0;
            }

            // PERF: use the interaction-specific degree (D_int = max(field,count)) instead of D_air
            let (fdeg, cdeg) = air_rules.max_interaction_degrees();
            let num_cosets_logup = fdeg.max(cdeg);
            let t_r0lg = std::time::Instant::now();
            if FK::use_cpu_zerocheck_mle() && !force_gpu_zc_site("logup_r0") {
                // CPU fallback for fields where the GPU batch-MLE kernel is wrong (e.g. KB)
                let cached_mats: Vec<&DeviceMatrix<FK::Val>> =
                    actx.cached_mains.iter().map(|cd| &cd.trace).collect();
                if let Some([num_poly, den_poly]) = evaluate_round0_interactions_cpu_fallback::<FK>(
                    &this_pk.vk.symbolic_constraints.constraints,
                    &InteractionEvalPlan::from_dag(&this_pk.vk.symbolic_constraints),
                    &cached_mats,
                    &actx.common_main,
                    &xi_pt[l_skip..l_skip + n_lift],
                    this_pk.vk.params.need_rot,
                    &self.beta_pows,
                    eq3,
                    l_skip,
                    log_n,
                    trace_h,
                    num_cosets_logup,
                    omega_root,
                    &actx.public_values,
                )? {
                    sp_polys_out[2 * trace_idx] = num_poly;
                    sp_polys_out[2 * trace_idx + 1] = den_poly;
                }
            } else {
                let lg_sums = evaluate_round0_interactions_gpu::<FK, HS>(
                    this_pk,
                    air_rules,
                    sel_cube.buffer(),
                    &part_ptrs_dev,
                    pv_dev,
                    eq_tree.get_ptr(n_lift),
                    &self.beta_pows,
                    eq3,
                    1 << l_skip,
                    1 << n_lift,
                    trace_h as u32,
                    num_cosets_logup as u32,
                    omega_root,
                    temp_budget,
                )?;
                if !lg_sums.is_empty() {
                    let lg_host = lg_sums.to_host()?;
                    let (mut nums, dens): (Vec<FK::ValExt>, Vec<FK::ValExt>) =
                        lg_host.into_iter().map(|frac| (frac.p, frac.q)).unzip();
                    if log_n.is_negative() {
                        // normalize for lifting
                        let inv_scale = FK::Val::from_u32(1 << log_n.unsigned_abs()).inverse();
                        for s in &mut nums {
                            *s *= inv_scale;
                        }
                    }
                    let mut num_rows = FK::ValExt::zero_vec(num_cosets_logup << l_skip);
                    let mut den_rows = FK::ValExt::zero_vec(num_cosets_logup << l_skip);
                    for coset_idx in 0..num_cosets_logup {
                        for i in 0..1 << l_skip {
                            let from_ix = (coset_idx << l_skip) + i;
                            let to_ix = i * num_cosets_logup + coset_idx;
                            num_rows[to_ix] = nums[from_ix];
                            den_rows[to_ix] = dens[from_ix];
                        }
                    }
                    // Logup cosets begin at the identity and step by omega_root: 1, g, g^2, ...
                    sp_polys_out[2 * trace_idx] = UnivariatePoly::from_geometric_cosets_evals_idft(
                        RowMajorMatrix::new(num_rows, num_cosets_logup),
                        omega_root,
                        FK::Val::ONE, // init = 1 for identity coset
                    );
                    sp_polys_out[2 * trace_idx + 1] =
                        UnivariatePoly::from_geometric_cosets_evals_idft(
                            RowMajorMatrix::new(den_rows, num_cosets_logup),
                            omega_root,
                            FK::Val::ONE, // init = 1 for identity coset
                        );
                }
            }
            if r0_prof {
                let _ = crate::runtime::stream::current_stream_sync();
                let us = t_r0lg.elapsed().as_micros();
                r0_lg_us += us;
                tracing::info!(
                    target: "bench",
                    "[stepprof][{}] r0lg_air air={} us={us}", crate::prove_phase(), this_pk.air_name
                );
            }
        }
        if r0_prof {
            tracing::info!(
                target: "bench",
                "[stepprof][{}] round0_zerocheck={r0_zc_us}us round0_logup={r0_lg_us}us", crate::prove_phase()
            );
        }
        self.mem
            .emit_metrics_with_label("prover.batch_constraints.round0");
        Ok(sp_polys_out)
    }

    /// CPU barycentric fold for one trace matrix (column-major base field → col-major ext field).
    fn fold_ple_cpu(
        l_skip: usize,
        trace: &DeviceMatrix<FK::Val>,
        r_0: FK::ValExt,
        is_rot: bool,
    ) -> Result<DeviceMatrix<FK::ValExt>, LogupZerocheckError> {
        use crate::runtime::copy::MemCopyH2D;
        use p3_field::batch_multiplicative_inverse;
        let cpu_mat =
            transport_matrix_d2h_col_major(trace).map_err(LogupZerocheckError::MemCopy)?;
        let height = cpu_mat.height();
        let width = cpu_mat.width();
        let skip_sz = 1usize << l_skip;
        let lifted_height = height.max(skip_sz);
        let num_x = lifted_height / skip_sz;
        let offset = usize::from(is_rot);
        let omega = FK::Val::two_adic_generator(l_skip);
        let omega_pows: Vec<FK::Val> = omega.powers().take(skip_sz).collect_vec();
        let denoms: Vec<FK::ValExt> = omega_pows
            .iter()
            .map(|&x_i| r_0 - FK::ValExt::from(x_i))
            .collect_vec();
        let inv_denoms = batch_multiplicative_inverse(&denoms);
        let col_scale: Vec<FK::ValExt> = omega_pows
            .iter()
            .zip(&inv_denoms)
            .map(|(&sg, &d_inv)| d_inv * FK::ValExt::from(sg))
            .collect_vec();
        let r_pow_n = r_0.exp_power_of_2(l_skip);
        let scaling_factor =
            (r_pow_n - FK::ValExt::ONE) * FK::ValExt::from_usize(skip_sz).inverse();
        // Col-major output: values[col * num_x + x]
        let mut out_vals = FK::ValExt::zero_vec(width * num_x);
        for x in 0..num_x {
            for z in 0..skip_sz {
                let row_idx = ((x << l_skip) + z + offset) % height;
                let w = col_scale[z];
                for j in 0..width {
                    out_vals[j * num_x + x] +=
                        w * FK::ValExt::from(cpu_mat.values[j * height + row_idx]);
                }
            }
        }
        for v in &mut out_vals {
            *v *= scaling_factor;
        }
        let d_out = out_vals.to_device().map_err(LogupZerocheckError::MemCopy)?;
        Ok(DeviceMatrix::new(Arc::new(d_out), num_x, width))
    }

    // This function never waits on the GPU, so its span measures launch time, not kernel time.
    #[instrument(name = "LogupZerocheck::fold_ple_evals", level = "debug", skip_all)]
    fn fold_ple_evals(
        &mut self,
        ctx: &ProvingContext<GenericGpuBackend<HS>>,
        r_0: FK::ValExt,
    ) -> Result<(), LogupZerocheckError> {
        let l_skip = self.l_skip;
        let inv_lagrange_denoms_r0 =
            compute_barycentric_inv_lagrange_denoms(l_skip, &self.omega_skip_pows, r_0);
        let d_inv_lagrange_denoms_r0 = inv_lagrange_denoms_r0.to_device()?;

        let mut mem_limit = self.gkr_mem_contribution;
        let use_cpu = FK::use_cpu_zerocheck_mle() && !force_gpu_zc_site("fold");
        // GPU (or CPU fallback) folding for mat_evals_per_trace
        self.mat_evals_per_trace = ctx
            .per_trace
            .iter()
            .map(|(air_idx, air_ctx)| {
                let air_pk = &self.pk.per_air[*air_idx];
                let need_rot = air_pk.vk.params.need_rot;
                let mut results: Vec<DeviceMatrix<FK::ValExt>> = Vec::new();

                // Helper: fold a trace matrix using CPU, creating doubled-width matrix when
                // need_rot=true to match the GPU convention expected by
                // into_column_openings.
                let fold_cpu_with_rot = |trace: &DeviceMatrix<FK::Val>| -> Result<
                    DeviceMatrix<FK::ValExt>,
                    LogupZerocheckError,
                > {
                    use crate::runtime::copy::MemCopyH2D;
                    let local = Self::fold_ple_cpu(l_skip, trace, r_0, false)?;
                    if !need_rot {
                        return Ok(local);
                    }
                    // Combine local + rotated into one doubled-width column-major matrix.
                    let rotated = Self::fold_ple_cpu(l_skip, trace, r_0, true)?;
                    let h = local.height();
                    let w = local.width();
                    debug_assert_eq!(rotated.height(), h);
                    debug_assert_eq!(rotated.width(), w);
                    let local_h = local
                        .buffer()
                        .to_host()
                        .map_err(LogupZerocheckError::MemCopy)?;
                    let rot_h = rotated
                        .buffer()
                        .to_host()
                        .map_err(LogupZerocheckError::MemCopy)?;
                    // Build column-major: cols 0..w-1 = local, cols w..2w-1 = rotated
                    let mut combined = FK::ValExt::zero_vec(2 * w * h);
                    for col in 0..w {
                        for row in 0..h {
                            combined[col * h + row] = local_h[col * h + row];
                            combined[(col + w) * h + row] = rot_h[col * h + row];
                        }
                    }
                    let d_combined = combined.to_device().map_err(LogupZerocheckError::MemCopy)?;
                    Ok(DeviceMatrix::new(Arc::new(d_combined), h, 2 * w))
                };

                // Preprocessed (if exists)
                if let Some(committed) = &air_pk.preprocessed_data {
                    let trace = &committed.trace;
                    let folded = if use_cpu {
                        fold_cpu_with_rot(trace)?
                    } else {
                        fold_ple_evals_rotate::<FK>(
                            l_skip,
                            &self.d_omega_skip_pows,
                            trace,
                            &d_inv_lagrange_denoms_r0,
                            need_rot,
                        )?
                    };
                    results.push(folded);
                }

                // Cached mains
                for committed in &air_ctx.cached_mains {
                    let trace = &committed.trace;
                    let folded = if use_cpu {
                        fold_cpu_with_rot(trace)?
                    } else {
                        fold_ple_evals_rotate::<FK>(
                            l_skip,
                            &self.d_omega_skip_pows,
                            trace,
                            &d_inv_lagrange_denoms_r0,
                            need_rot,
                        )?
                    };
                    results.push(folded);
                }

                // Common main
                let trace = &air_ctx.common_main;
                let folded = if use_cpu {
                    fold_cpu_with_rot(trace)?
                } else {
                    fold_ple_evals_rotate::<FK>(
                        l_skip,
                        &self.d_omega_skip_pows,
                        trace,
                        &d_inv_lagrange_denoms_r0,
                        need_rot,
                    )?
                };
                mem_limit =
                    mem_limit.saturating_sub(folded.buffer().len() * size_of::<FK::ValExt>());
                results.push(folded);

                Ok(results)
            })
            .collect::<Result<Vec<_>, LogupZerocheckError>>()?;
        if self.save_memory {
            self.memory_limit_floor = mem_limit;
            self.memory_limit_bytes = r0_temp_budget(mem_limit);
        }

        // Fold the three selector columns on the GPU; they never need the rotated copy.
        self.sels_per_trace = std::mem::take(&mut self.sels_per_trace_base)
            .into_iter()
            .enumerate()
            .map(|(ti, sel_mat)| {
                let log_n = self.n_per_trace[ti];
                let x_rows = sel_mat.height();
                debug_assert_eq!(x_rows, 1 << log_n.max(0));
                debug_assert_eq!(sel_mat.width(), 3);
                let (log_dom, pt) = if log_n.is_negative() {
                    (
                        l_skip.wrapping_add_signed(log_n),
                        r_0.exp_power_of_2(-log_n as usize),
                    )
                } else {
                    (l_skip, r_0)
                };
                let dom_gen = FK::Val::two_adic_generator(log_dom);
                let first_w = eval_eq_uni_at_one(log_dom, pt);
                let last_w = eval_eq_uni_at_one(log_dom, pt * dom_gen);
                let sel_out = DeviceBuffer::<FK::ValExt>::with_capacity(x_rows * 3);
                unsafe {
                    FK::fold_selectors_round0(
                        sel_out.as_mut_ptr(),
                        sel_mat.buffer().as_ptr(),
                        first_w,
                        last_w,
                        x_rows,
                    )
                    .map_err(LogupZerocheckError::FoldSelectorsRound0)?;
                }
                Ok(DeviceMatrix::new(Arc::new(sel_out), x_rows, 3))
            })
            .collect::<Result<Vec<_>, LogupZerocheckError>>()?;

        // The eq / eq-sharp factors at r_0 are plain scalars, so evaluate them on the host.
        let eq_at_r0 = eval_eq_uni(l_skip, self.xi[0], r_0);
        let eq_sharp_at_r0 = eval_eq_sharp_uni(&self.omega_skip_pows, &self.xi[..l_skip], r_0);
        self.eq_ns.push(eq_at_r0);
        self.eq_sharp_ns.push(eq_sharp_at_r0);
        for eq_layers in self.eq_xis.values_mut() {
            // The last layer belonged to the variable just bound; drop it.
            eq_layers.pop_layer();
        }

        self.mem
            .emit_metrics_with_label("prover.batch_constraints.fold_ple_evals");
        Ok(())
    }

    #[instrument(
        name = "LogupZerocheck::sumcheck_polys_batch_eval",
        level = "info",
        skip_all,
        fields(round = round)
    )]
    /// CPU fallback for KB: computes batch sumcheck polynomial evaluations on CPU for round k.
    /// Downloads the GPU folded trace matrices, evaluates interactions using natural-order eq.
    fn sumcheck_polys_batch_eval_cpu(
        &mut self,
        round: usize,
        r_prev: FK::ValExt,
    ) -> Result<Vec<Vec<FK::ValExt>>, LogupZerocheckError> {
        let sp_deg = self.constraint_degree;
        let l_skip = self.l_skip;
        let num_traces = self.n_per_trace.len();

        let mut zc_out = vec![vec![FK::ValExt::ZERO; sp_deg]; num_traces];
        let mut logup_out: Vec<[Vec<FK::ValExt>; 2]> = vec![
            [
                vec![FK::ValExt::ZERO; sp_deg],
                vec![FK::ValExt::ZERO; sp_deg]
            ];
            num_traces
        ];

        for (trace_idx, (&n, mats, sels, &air_idx)) in izip!(
            self.n_per_trace.iter(),
            self.mat_evals_per_trace.iter(),
            self.sels_per_trace.iter(),
            self.air_indices_per_trace.iter(),
        )
        .enumerate()
        {
            let pk = &self.pk.per_air[air_idx];
            let local_deg = pk.vk.max_constraint_degree as usize;
            let has_constraints = local_deg > 0;
            let has_interactions = !pk.vk.symbolic_constraints.interactions.is_empty();
            if !has_interactions && !has_constraints {
                continue;
            }
            let n_lift = n.max(0) as usize;
            let norm_factor_denom: usize = 1 << ((-n).max(0) as usize);
            let norm_factor = FK::Val::from_usize(norm_factor_denom).inverse();
            let symbolic = SymbolicConstraints::from(&pk.vk.symbolic_constraints);
            let need_rot = self.needs_next_per_trace[trace_idx];
            let pvs_host: Vec<FK::Val> = if self.public_values_per_trace[trace_idx].is_empty() {
                vec![]
            } else {
                self.public_values_per_trace[trace_idx]
                    .to_host()
                    .map_err(LogupZerocheckError::MemCopy)?
            };
            let lambda_host: Vec<FK::ValExt> = match self.lambda_pows.as_ref() {
                Some(d) if !d.is_empty() => d.to_host().map_err(LogupZerocheckError::MemCopy)?,
                _ => vec![],
            };
            let eq_3bs = &self.eq_3b_per_trace[trace_idx];
            let beta_pows = &self.beta_pows;

            // Build ColMajorEvalHelper for interactions.
            // preprocessed_trace: None because GPU committed preprocessed data can't be
            // used as CPU StridedColMajorMatrixView; if mats[0] is preprocessed (from
            // air_pk.preprocessed_data), it becomes partitioned_main[0] harmlessly for
            // interactions that only reference Main entries (not Preprocessed entries).
            let interaction_plan = InteractionEvalPlan::from_dag(&pk.vk.symbolic_constraints);
            let eval_helper = ColMajorEvalHelper {
                constraints_dag: &pk.vk.symbolic_constraints.constraints,
                interactions: &interaction_plan,
                public_values: pvs_host,
                preprocessed_trace: None,
                needs_next: need_rot,
                constraint_degree: local_deg as u8,
            };

            if round <= n_lift {
                // Case B: trace has height 2*num_y, evaluate sumcheck poly at x=1..s_deg
                let log_num_y = n_lift - round;
                let num_y = 1usize << log_num_y;

                // Download ALL folded matrices (preprocessed, cached_mains, common_main)
                // and selectors.
                let all_mats_cpu: Vec<_> = mats
                    .iter()
                    .map(|m| {
                        transport_matrix_d2h_col_major(m).map_err(LogupZerocheckError::MemCopy)
                    })
                    .collect::<Result<_, _>>()?;
                let sel_cpu =
                    transport_matrix_d2h_col_major(sels).map_err(LogupZerocheckError::MemCopy)?;

                let height = all_mats_cpu[0].height();
                debug_assert_eq!(height, 2 * num_y);
                // Natural-order eq for remaining xi[round..n_lift]
                let eq_cpu = evals_eq_hypercube_serial(&self.xi[l_skip + round..l_skip + n_lift]);

                let sel_vals: &[FK::ValExt] = &sel_cpu.values;

                for xi_idx in 1..=sp_deg {
                    let x_ef = FK::ValExt::from_usize(xi_idx);
                    let mut numer_x = FK::ValExt::ZERO;
                    let mut denom_x = FK::ValExt::ZERO;
                    let mut zc_x = FK::ValExt::ZERO;

                    for y in 0..num_y {
                        // Interpolate selectors (col-major: values[col * height + row])
                        let sel_y_x: Vec<FK::ValExt> = (0..3)
                            .map(|k| {
                                let t0 = sel_vals[k * height + 2 * y];
                                let t1 = sel_vals[k * height + 2 * y + 1];
                                t0 + (t1 - t0) * x_ef
                            })
                            .collect();
                        // Build row_parts matching ColMajorEvalHelper.view_mats order: selectors, then
                        // each matrix split into (local, rotated) when need_rot (matrices are
                        // doubled-width [local_cols | rotated_cols] in that case).
                        let mut row_parts = vec![sel_y_x];
                        for mat_cpu in &all_mats_cpu {
                            let mat_vals = &mat_cpu.values;
                            let w = mat_cpu.width();
                            let aw = if need_rot { w / 2 } else { w };
                            let interp = |c0: usize, c1: usize| -> Vec<FK::ValExt> {
                                (c0..c1)
                                    .map(|j| {
                                        let t0 = mat_vals[j * height + 2 * y];
                                        let t1 = mat_vals[j * height + 2 * y + 1];
                                        t0 + (t1 - t0) * x_ef
                                    })
                                    .collect()
                            };
                            row_parts.push(interp(0, aw));
                            if need_rot {
                                row_parts.push(interp(aw, w));
                            }
                        }

                        let eq_w = eq_cpu[y];
                        if has_interactions {
                            let [n_val, d_val] =
                                eval_helper.acc_interactions(&row_parts, beta_pows, eq_3bs);
                            numer_x = numer_x + eq_w * n_val * norm_factor;
                            denom_x = denom_x + eq_w * d_val;
                        }
                        if has_constraints {
                            // Zerocheck: sum_y eq(xi, y) * batched_constraints(row).
                            // No norm_factor for zerocheck (matches CPU reference).
                            let c_val = eval_helper.acc_constraints(&row_parts, &lambda_host);
                            zc_x = zc_x + eq_w * c_val;
                        }
                    }
                    logup_out[trace_idx][0][xi_idx - 1] = numer_x;
                    logup_out[trace_idx][1][xi_idx - 1] = denom_x;
                    zc_out[trace_idx][xi_idx - 1] = zc_x;
                }
            } else if round == n_lift + 1 {
                // Case A.1: single-row evaluation, sets logup_tilde_evals
                // Download ALL matrices for multi-partition chips.
                let all_mats_cpu: Vec<_> = mats
                    .iter()
                    .map(|m| {
                        transport_matrix_d2h_col_major(m).map_err(LogupZerocheckError::MemCopy)
                    })
                    .collect::<Result<_, _>>()?;
                let sel_cpu =
                    transport_matrix_d2h_col_major(sels).map_err(LogupZerocheckError::MemCopy)?;

                debug_assert_eq!(all_mats_cpu[0].height(), 1);
                // height=1: column j value is values[j]. Split doubled-width into local/rot.
                let sel_vals: Vec<FK::ValExt> = sel_cpu.values.clone();
                let mut row_parts = vec![sel_vals];
                for mat_cpu in &all_mats_cpu {
                    let mv = &mat_cpu.values;
                    let w = mat_cpu.width();
                    let aw = if need_rot { w / 2 } else { w };
                    row_parts.push((0..aw).map(|j| mv[j]).collect());
                    if need_rot {
                        row_parts.push((aw..w).map(|j| mv[j]).collect());
                    }
                }

                if has_interactions {
                    let [n_val, d_val] =
                        eval_helper.acc_interactions(&row_parts, beta_pows, eq_3bs);
                    self.logup_tilde_evals[trace_idx][0] = n_val * norm_factor;
                    self.logup_tilde_evals[trace_idx][1] = d_val;
                }
                if has_constraints {
                    let c_val = eval_helper.acc_constraints(&row_parts, &lambda_host);
                    self.zerocheck_tilde_evals[trace_idx] = c_val;
                }
            }
            // Case A.2 (round > n_lift + 1): accumulate tilde evals by r_prev — handled below
        }

        // Case A.2: scale tilde evals by r_prev for all traces with round > n_lift + 1
        for (trace_idx, &n) in self.n_per_trace.iter().enumerate() {
            let n_lift = n.max(0) as usize;
            if round > n_lift + 1 {
                let pk = &self.pk.per_air[self.air_indices_per_trace[trace_idx]];
                if !pk.vk.symbolic_constraints.interactions.is_empty() {
                    for x in self.logup_tilde_evals[trace_idx].iter_mut() {
                        *x = *x * r_prev;
                    }
                }
                if pk.vk.max_constraint_degree > 0 {
                    self.zerocheck_tilde_evals[trace_idx] =
                        self.zerocheck_tilde_evals[trace_idx] * r_prev;
                }
            }
        }

        Ok(logup_out.into_iter().flatten().chain(zc_out).collect())
    }

    fn sumcheck_polys_batch_eval(
        &mut self,
        round: usize,
        r_prev: FK::ValExt,
    ) -> Result<Vec<Vec<FK::ValExt>>, LogupZerocheckError> {
        if FK::use_cpu_zerocheck_mle() && !force_gpu_zc_site("mle") {
            let cpu = self.sumcheck_polys_batch_eval_cpu(round, r_prev)?;
            // Optional GPU-vs-CPU verification of the MLE sumcheck polys (proof uses CPU).
            // Both paths read the same (CPU-folded) device state read-only.
            if std::env::var("MLE_VERIFY_MLE").is_ok() {
                let gpu = self.sumcheck_polys_batch_eval_gpu(round, r_prev)?;
                let n = cpu.len().min(gpu.len());
                let mut mism = 0usize;
                let mut first = None;
                for i in 0..n {
                    for j in 0..cpu[i].len().min(gpu[i].len()) {
                        if cpu[i][j] != gpu[i][j] {
                            mism += 1;
                            if first.is_none() {
                                first = Some((i, j, cpu[i][j], gpu[i][j]));
                            }
                        }
                    }
                }
                if mism > 0 {
                    let (i, j, c, g) = first.unwrap();
                    tracing::warn!(
                        "MLE_VERIFY round={round}: {mism} poly-coeff mismatch; first at \
                         vec_idx={i} coeff={j} CPU={c:?} GPU={g:?} (n_vecs cpu={} gpu={})",
                        cpu.len(),
                        gpu.len()
                    );
                } else {
                    tracing::warn!("MLE_VERIFY round={round}: OK ({} vecs match)", cpu.len());
                }
            }
            return Ok(cpu);
        }
        self.sumcheck_polys_batch_eval_gpu(round, r_prev)
    }

    fn sumcheck_polys_batch_eval_gpu(
        &mut self,
        round: usize,
        r_prev: FK::ValExt,
    ) -> Result<Vec<Vec<FK::ValExt>>, LogupZerocheckError> {
        let eval_pts = self.constraint_degree;
        // [mleprof2] per-path split of the round eval: column interpolation vs
        // the late/monomial/DAG kernel buckets, each synced. OFF by default.
        let prof2 = std::env::var("MLE_PROF2").is_ok();
        let mut us_interp = 0u128;
        let mut us_interp_alloc = 0u128;
        let mut us_late = 0u128;
        let mut us_logup = 0u128;
        let mut us_zc_dag = 0u128;
        let mut us_zc_mono = 0u128;

        // Per-trace result rows, populated as the traces are processed.
        let mut zc_rows: Vec<Vec<FK::ValExt>> =
            vec![vec![FK::ValExt::ZERO; eval_pts]; self.n_per_trace.len()];
        let mut lg_rows: Vec<[Vec<FK::ValExt>; 2]> = vec![
            [
                vec![FK::ValExt::ZERO; eval_pts],
                vec![FK::ValExt::ZERO; eval_pts]
            ];
            self.n_per_trace.len()
        ];

        // Holds the early-trace interpolations so they outlive the kernels that read them.
        let mut _keepalive_interpolated: Vec<DeviceMatrix<FK::ValExt>> = Vec::new();

        // One column-pointer upload buffer for the whole round, instead of a fresh device
        // allocation per trace: the per-trace `to_device()` of the column pointers was 27 001 of
        // this crate's 401 108 `d_malloc`s per run, for a vector of ~90 pointers. Sized once at the
        // widest trace; each trace then gets a `ManuallyDrop` view of exactly its own length,
        // because `interpolate_columns_gpu` reads the column count off the buffer's `len()`. Reuse
        // needs no sync: everything runs on the per-thread default stream, so the next trace's H2D
        // into this buffer is ordered after the previous trace's kernel has read it.
        let max_columns = self
            .sels_per_trace
            .iter()
            .zip(&self.mat_evals_per_trace)
            .map(|(sel_m, parts)| {
                sel_m.width() + parts.iter().map(|mat| mat.width()).sum::<usize>()
            })
            .max()
            .unwrap_or(0);
        let columns_scratch: DeviceBuffer<*const FK::ValExt> = if max_columns == 0 {
            DeviceBuffer::new()
        } else {
            DeviceBuffer::with_capacity(max_columns)
        };

        let mut direct_traces: Vec<TraceCtx<FK>> = Vec::new(); // round == n_lift + 1
        let mut interp_traces: Vec<TraceCtx<FK>> = Vec::new(); // round <= n_lift

        // Walk the traces in their original order, sorting each into one of the cases below.
        for (tix, (&log_n, parts, sel_m, eq3_dev, pv_dev, &aix)) in izip!(
            self.n_per_trace.iter(),
            self.mat_evals_per_trace.iter(),
            self.sels_per_trace.iter(),
            self.d_eq_3b_per_trace.iter(),
            self.public_values_per_trace.iter(),
            self.air_indices_per_trace.iter()
        )
        .enumerate()
        {
            let air_pk = &self.pk.per_air[aix];
            let rules_dag = &air_pk.vk.symbolic_constraints;
            let any_constraints = rules_dag.constraints.num_constraints() > 0;
            let any_interactions = !rules_dag.interactions.is_empty();
            if !any_constraints && !any_interactions {
                continue;
            }

            let lift = log_n.max(0) as usize;
            let norm_den = 1 << (-log_n).max(0);
            let norm = FK::Val::from_usize(norm_den).inverse();
            let with_prep = air_pk.preprocessed_data.is_some();
            let rot = air_pk.vk.params.need_rot;
            let main_start = usize::from(with_prep);
            let eq_tree = &self.eq_xis[&lift];

            if round > lift {
                // Case A
                if round == lift + 1 {
                    // A.1: nothing to interpolate; evaluate at num_x = 1, num_y = 1.
                    let prep_desc = if with_prep {
                        MainMatrixPtrs {
                            data: parts[0].buffer().as_ptr(),
                            air_width: air_width_for_mat(rot, parts[0].width()),
                        }
                    } else {
                        MainMatrixPtrs {
                            data: std::ptr::null(),
                            air_width: 0,
                        }
                    };
                    let main_descs: Vec<MainMatrixPtrs<FK::ValExt>> = parts[main_start..]
                        .iter()
                        .map(|mat| MainMatrixPtrs {
                            data: mat.buffer().as_ptr(),
                            air_width: air_width_for_mat(rot, mat.width()),
                        })
                        .collect_vec();
                    let main_descs_dev = crate::scratch::upload(&main_descs)?;

                    direct_traces.push(TraceCtx {
                        trace_idx: tix,
                        air_idx: aix,
                        n_lift: lift,
                        num_y: 1,
                        has_constraints: any_constraints,
                        has_interactions: any_interactions,
                        norm_factor: norm,
                        eq_xi_ptr: eq_tree.get_ptr(0),
                        sels_ptr: sel_m.buffer().as_ptr(),
                        prep_ptr: prep_desc,
                        main_ptrs_dev: main_descs_dev,
                        public_ptr: pv_dev.as_ptr(),
                        eq_3bs_ptr: eq3_dev.as_ptr(),
                    });
                } else {
                    // A.2: nothing to evaluate, only rescale the stored tilde values by r_prev.
                    if any_constraints {
                        let zc_tilde = &mut self.zerocheck_tilde_evals[tix];
                        *zc_tilde *= r_prev;
                        // zc_rows stays zero here; compute_batch_s_poly reads the tilde value.
                    }
                    if any_interactions {
                        for v in self.logup_tilde_evals[tix].iter_mut() {
                            *v *= r_prev;
                        }
                        // Likewise lg_rows: compute_batch_s_poly uses the tilde values.
                    }
                }
            } else {
                // Case B: interpolate the columns, then evaluate with num_x = eval_pts points and
                // num_y = half the current height.
                let log_y = lift - round;
                let y_len = 1 << log_y;
                let rows_h = 2 * y_len;
                debug_assert_eq!(rows_h, parts[0].height());

                let mut col_ptrs: Vec<*const FK::ValExt> = Vec::new();
                col_ptrs.extend(
                    iter::once(sel_m)
                        .chain(parts.iter())
                        .flat_map(|mat| {
                            assert_eq!(mat.height(), rows_h);
                            (0..mat.width())
                                .map(|c_i| mat.buffer().as_ptr().wrapping_add(c_i * mat.height()))
                        })
                        .collect_vec(),
                );
                let t_ip = std::time::Instant::now();
                let interp_mat =
                    DeviceMatrix::<FK::ValExt>::with_capacity(eval_pts * y_len, col_ptrs.len());
                // SAFETY: `columns_scratch` holds at least `col_ptrs.len()` elements (it was sized
                // at the widest trace above) and outlives this view; `ManuallyDrop` keeps the view
                // from freeing the scratch's allocation. See `columns_scratch`.
                let mut col_ptrs_view = std::mem::ManuallyDrop::new(unsafe {
                    DeviceBuffer::from_raw_parts(columns_scratch.as_mut_ptr(), col_ptrs.len())
                });
                col_ptrs.copy_to(&mut col_ptrs_view)?;
                if prof2 {
                    let _ = crate::runtime::stream::current_stream_sync();
                    us_interp_alloc += t_ip.elapsed().as_micros();
                }
                let t_ik = std::time::Instant::now();
                unsafe {
                    FK::interpolate_columns_gpu(
                        interp_mat.buffer(),
                        &col_ptrs_view,
                        eval_pts,
                        y_len,
                    )
                    .map_err(|err| LogupZerocheckError::InterpolateColumns(err.into()))?;
                }
                if prof2 {
                    let _ = crate::runtime::stream::current_stream_sync();
                    us_interp += t_ik.elapsed().as_micros();
                }

                let interp_rows = interp_mat.height();
                let mut col_cursor = 0usize;
                let sel_base = interp_mat
                    .buffer()
                    .as_ptr()
                    .wrapping_add(col_cursor * interp_rows);
                col_cursor += 3;
                let prep_desc = if with_prep {
                    MainMatrixPtrs {
                        data: interp_mat
                            .buffer()
                            .as_ptr()
                            .wrapping_add(col_cursor * interp_rows),
                        air_width: air_width_for_mat(rot, parts[0].width()),
                    }
                } else {
                    MainMatrixPtrs {
                        data: std::ptr::null(),
                        air_width: 0,
                    }
                };
                if with_prep {
                    col_cursor += parts[0].width();
                }
                let main_descs: Vec<MainMatrixPtrs<FK::ValExt>> = parts[main_start..]
                    .iter()
                    .map(|mat| {
                        let desc = MainMatrixPtrs {
                            data: interp_mat
                                .buffer()
                                .as_ptr()
                                .wrapping_add(col_cursor * interp_rows),
                            air_width: air_width_for_mat(rot, mat.width()),
                        };
                        col_cursor += mat.width();
                        desc
                    })
                    .collect_vec();
                debug_assert_eq!(col_cursor, interp_mat.width());
                let main_descs_dev = crate::scratch::upload(&main_descs)?;

                _keepalive_interpolated.push(interp_mat);
                let eq_ptr = eq_tree.get_ptr(log_y);

                interp_traces.push(TraceCtx {
                    trace_idx: tix,
                    air_idx: aix,
                    n_lift: lift,
                    num_y: y_len as u32,
                    has_constraints: any_constraints,
                    has_interactions: any_interactions,
                    norm_factor: norm,
                    eq_xi_ptr: eq_ptr,
                    sels_ptr: sel_base,
                    prep_ptr: prep_desc,
                    main_ptrs_dev: main_descs_dev,

                    public_ptr: pv_dev.as_ptr(),
                    eq_3bs_ptr: eq3_dev.as_ptr(),
                });
            }
        }

        let chall_ptr = self.d_challenges.as_ptr();

        // Late traces (num_y = 1) always go through the monomial path.
        let t_late = std::time::Instant::now();
        let direct_lg: Vec<_> = direct_traces
            .iter()
            .filter(|tc| tc.has_interactions)
            .collect();
        if !direct_lg.is_empty() {
            let lg_combs: Vec<_> = direct_lg
                .iter()
                .map(|tc| {
                    self.logup_combinations[tc.trace_idx]
                        .as_ref()
                        .expect("missing logup monomial combinations for late trace")
                })
                .collect();
            let mono_batch =
                LogupMonomialBatch::new(direct_lg.iter().copied(), self.pk, &lg_combs)?;
            let dev_out = mono_batch
                .evaluate(1)
                .map_err(LogupZerocheckError::MleInteractionEval)?;
            let host_out = dev_out.to_host()?;
            for (k, tix) in mono_batch.trace_indices().enumerate() {
                self.logup_tilde_evals[tix][0] = host_out[k].p * direct_lg[k].norm_factor;
                self.logup_tilde_evals[tix][1] = host_out[k].q;
            }
        }
        let direct_zc: Vec<_> = direct_traces
            .iter()
            .filter(|tc| trace_has_monomials(tc, self.pk))
            .collect();
        if !direct_zc.is_empty() {
            let lam_combs: Vec<_> = direct_zc
                .iter()
                .map(|tc| self.lambda_combinations[tc.air_idx].as_ref().unwrap())
                .collect();
            let mono_batch = ZerocheckMonomialBatch::new(direct_zc, self.pk, &lam_combs)?;
            let dev_out = mono_batch
                .evaluate(1)
                .map_err(LogupZerocheckError::MleConstraintEval)?;
            let host_out = dev_out.to_host()?;
            for (k, tix) in mono_batch.trace_indices().enumerate() {
                self.zerocheck_tilde_evals[tix] = host_out[k];
                // zc_rows untouched when num_x = 1; compute_batch_s_poly uses the tilde value.
            }
        }

        if prof2 {
            let _ = crate::runtime::stream::current_stream_sync();
            us_late += t_late.elapsed().as_micros();
        }

        // Logup for the early traces; the num_y threshold picks the kernel for each one.
        let t_lg = std::time::Instant::now();
        if !interp_traces.is_empty() {
            evaluate_logup_batched(
                &interp_traces,
                self.pk,
                chall_ptr,
                eval_pts as u32,
                self.monomial_num_y_threshold,
                &self.logup_combinations,
                &mut lg_rows,
                &mut self.logup_tilde_evals,
                self.memory_limit_bytes,
            )
            .map_err(LogupZerocheckError::MleInteractionEval)?;
        }
        if prof2 {
            let _ = crate::runtime::stream::current_stream_sync();
            us_logup += t_lg.elapsed().as_micros();
        }

        // Early traces (num_y>1): partition by threshold for zerocheck path.
        // Huge-monomial rule: AIRs with very many monomials (Poseidon2/Keccak) are kept out of
        // the batched low-num_y kernel (kappa~2.2 uncoalesced-load penalty) and fall through to
        // the par-y path.
        let path_policy = mono_path_policy();
        let (small_y, big_y): (Vec<&TraceCtx<FK>>, Vec<&TraceCtx<FK>>) = interp_traces
            .iter()
            .filter(|tc| tc.has_constraints)
            .partition(|tc| {
                tc.num_y <= self.monomial_num_y_threshold
                    && (path_policy == MonoPathPolicy::Legacy
                        || get_num_monomials(tc, self.pk) < LOW_BATCH_MAX_MONOMIALS)
            });

        // Split the high-num_y traces by how far monomial expansion inflated them relative to
        // their rule count. A trace with no monomials contributes nothing.
        let (via_dag, via_par_y): (Vec<&TraceCtx<FK>>, Vec<&TraceCtx<FK>>) =
            big_y.iter().partition(|tc| {
                let mono_n = get_num_monomials(tc, self.pk);
                let rule_n = get_zerocheck_rules_len(tc, self.pk);
                // Shape test: the DAG wins once expansion pushed the term count well past the
                // rule count.
                let dag_by_shape = mono_n as usize >= DAG_FALLBACK_MONOMIAL_RATIO * rule_n;
                if path_policy == MonoPathPolicy::Legacy {
                    return dag_by_shape;
                }
                // Crossover rule: even then, only take the DAG when the par-y workload estimate
                // exceeds the DAG latency floor (see DAG_CROSSOVER_EVALS_PER_RULE).
                dag_by_shape
                    && tc.num_y as u64 * mono_n as u64
                        >= rule_n as u64 * DAG_CROSSOVER_EVALS_PER_RULE
            });

        if std::env::var("MLE_LOG_PATH_CHOICE").is_ok() {
            tracing::warn!(
                "MLE_PATH round={round}: high_dag={:?} high_mono={:?} low_early={:?}",
                via_dag.iter().map(|tc| tc.trace_idx).collect::<Vec<_>>(),
                via_par_y.iter().map(|tc| tc.trace_idx).collect::<Vec<_>>(),
                small_y.iter().map(|tc| tc.trace_idx).collect::<Vec<_>>(),
            );
        }

        // High-num_y traces whose monomial count dwarfs their rule count: evaluate the DAG.
        let t_zd = std::time::Instant::now();
        if !via_dag.is_empty() {
            let lam_dev = self.lambda_pows.as_ref().unwrap();
            evaluate_zerocheck_batched(
                via_dag,
                self.pk,
                lam_dev,
                eval_pts as u32,
                &mut zc_rows,
                self.memory_limit_bytes,
            )
            .map_err(LogupZerocheckError::MleConstraintEval)?;
        }
        if prof2 {
            let _ = crate::runtime::stream::current_stream_sync();
            us_zc_dag += t_zd.elapsed().as_micros();
        }

        // Remaining high-num_y traces: monomial kernel parallelised over y.
        let t_zm = std::time::Instant::now();
        if !via_par_y.is_empty() {
            let lam_combs: Vec<_> = via_par_y
                .iter()
                .map(|tc| self.lambda_combinations[tc.air_idx].as_ref().unwrap())
                .collect();
            let mono_batch = ZerocheckMonomialParYBatch::new(
                via_par_y,
                self.pk,
                &lam_combs,
                self.sm_count,
                eval_pts as u32,
                None,
            )?;
            let dev_out = mono_batch
                .evaluate(eval_pts as u32)
                .map_err(LogupZerocheckError::MleConstraintEval)?;
            let host_out = dev_out.to_host()?;
            for (k, tix) in mono_batch.trace_indices().enumerate() {
                zc_rows[tix].copy_from_slice(&host_out[(k * eval_pts)..((k + 1) * eval_pts)]);
            }
        }

        // Low-num_y traces: batched monomial zerocheck.
        let small_mono = small_y;
        if !small_mono.is_empty() {
            let lam_combs: Vec<_> = small_mono
                .iter()
                .map(|tc| self.lambda_combinations[tc.air_idx].as_ref().unwrap())
                .collect();
            let mono_batch = ZerocheckMonomialBatch::new(small_mono, self.pk, &lam_combs)?;
            let dev_out = mono_batch
                .evaluate(eval_pts as u32)
                .map_err(LogupZerocheckError::MleConstraintEval)?;
            let host_out = dev_out.to_host()?;
            for (k, tix) in mono_batch.trace_indices().enumerate() {
                zc_rows[tix].copy_from_slice(&host_out[(k * eval_pts)..((k + 1) * eval_pts)]);
            }
        }
        if prof2 {
            let _ = crate::runtime::stream::current_stream_sync();
            us_zc_mono += t_zm.elapsed().as_micros();
            tracing::info!(
                target: "bench",
                "[mleprof2] round={round} interp={us_interp}us interp_alloc={us_interp_alloc}us \
                 late={us_late}us logup={us_logup}us zc_dag={us_zc_dag}us zc_mono={us_zc_mono}us"
            );
        }

        Ok(lg_rows.into_iter().flatten().chain(zc_rows).collect())
    }

    #[instrument(level = "debug", skip_all, fields(round = round))]
    fn compute_batch_s_poly(
        &mut self,
        per_poly_evals: Vec<Vec<FK::ValExt>>,
        trace_count: usize,
        round: usize,
        mu_powers: &[FK::ValExt],
    ) -> UnivariatePoly<FK::ValExt> {
        debug_assert_eq!(per_poly_evals.len(), 3 * trace_count);
        debug_assert_eq!(per_poly_evals.len(), mu_powers.len());
        let d_max = self.constraint_degree;
        let mut zc_head = vec![FK::ValExt::ZERO; d_max];
        let mut lg_head = vec![FK::ValExt::ZERO; d_max];
        let mut tail_sum = FK::ValExt::ZERO;
        for (t_i, &log_n) in self.n_per_trace.iter().enumerate() {
            let lift = log_n.max(0) as usize;
            let zc_slot = 2 * trace_count + t_i;
            let p_slot = 2 * t_i;
            let q_slot = p_slot + 1;
            if round == lift + 1 {
                let eq_acc = *self.eq_ns.last().unwrap();
                let eq_sharp_acc = *self.eq_sharp_ns.last().unwrap();
                self.zerocheck_tilde_evals[t_i] *= eq_acc;
                self.logup_tilde_evals[t_i][0] *= eq_sharp_acc;
                self.logup_tilde_evals[t_i][1] *= eq_sharp_acc;
            }
            if round <= lift {
                for pt in 0..d_max {
                    zc_head[pt] += mu_powers[zc_slot] * per_poly_evals[zc_slot][pt];
                    lg_head[pt] += mu_powers[p_slot] * per_poly_evals[p_slot][pt]
                        + mu_powers[q_slot] * per_poly_evals[q_slot][pt];
                }
            } else {
                tail_sum += mu_powers[zc_slot] * self.zerocheck_tilde_evals[t_i]
                    + mu_powers[p_slot] * self.logup_tilde_evals[t_i][0]
                    + mu_powers[q_slot] * self.logup_tilde_evals[t_i][1];
            }
        }
        let deg_s = d_max + 1;
        let skip = self.l_skip;
        // Head evaluations at 1..=d_max, now multiplied by the accumulated eq(xi, r) factors.
        let mut head_vals = vec![FK::ValExt::ZERO; deg_s];
        for pt in 0..d_max {
            head_vals[pt + 1] =
                self.eq_ns[round - 1] * zc_head[pt] + self.eq_sharp_ns[round - 1] * lg_head[pt];
        }
        // s'(0) is not computed directly: it is recovered from the sumcheck identity
        // s_j(0) + s_j(1) = s_{j-1}(r_{j-1}).
        let xi_j = self.xi[skip + round - 1];
        {
            let eq_at_0 = FK::ValExt::ONE - xi_j;
            let eq_at_1 = xi_j;
            head_vals[0] =
                (self.prev_s_eval - eq_at_1 * head_vals[1] - tail_sum) * eq_at_0.inverse();
        }
        // The head s' is of degree deg_s - 1, so deg_s points determine it.
        let head_poly = UnivariatePoly::lagrange_interpolate(
            &(0..deg_s).map(FK::Val::from_usize).collect_vec(),
            &head_vals,
        );
        // Multiply the head by eq(xi, X) = (1 - xi) + (2 * xi - 1) * X and add the tail as
        // s'_tail * X (the head already carries its eq(.., r) factors). Result has degree deg_s.
        let mut out_coeffs = head_poly.into_coeffs();
        out_coeffs.push(FK::ValExt::ZERO);
        let c0 = FK::ValExt::ONE - xi_j;
        let c1 = xi_j - c0;
        for pt in (0..deg_s).rev() {
            out_coeffs[pt + 1] = c1 * out_coeffs[pt] + c0 * out_coeffs[pt + 1];
        }
        out_coeffs[0] *= c0;
        out_coeffs[1] += tail_sum;
        UnivariatePoly::new(out_coeffs)
    }

    #[instrument(name = "LogupZerocheck::fold_mle_evals", level = "debug", skip_all, fields(round = round))]
    fn fold_mle_evals(
        &mut self,
        round: usize,
        r_round: FK::ValExt,
    ) -> Result<(), LogupZerocheckError> {
        // `input_mats` must be sorted tallest first (the `partition_point` below relies on it).
        // The four descriptor uploads below (~16 pointers/widths each) go through the prove's
        // scratch arena. The grow-only caller-lifetime buffers they used before still re-allocated
        // whenever a round was wider than every round before it — 9 116 `d_malloc`s per run.
        // `crate::scratch` makes that zero, and `batch_fold_mle` still gets a view of exactly
        // `num_matrices` elements, which is the length it asserts.
        // ONE allocation per fold round instead of one per output matrix. An allocation census put
        // this line at **70 988 `d_malloc`/`d_free` pairs per run** — 22.2% of the crate's whole
        // Rust-side inventory, and 66% of it inside the recursion proofs, which are the least
        // GPU-occupied and the most serial part of the chain. The bytes are unchanged:
        // the pool is exactly the sum of the buffers it replaces, with the same lifetime.
        //
        // Matrices whose output height is 1 keep their own allocation deliberately. They are
        // dropped from the next round's fold (`partition_point(height > 1)`) and carried forward
        // to the openings, so pooling them would pin a whole round's pool alive for a 1×w matrix.
        let mut batch_fold =
            |input_mats: Vec<DeviceMatrix<FK::ValExt>>,
             pools: &mut Vec<Arc<DeviceBuffer<FK::ValExt>>>|
             -> Result<Vec<DeviceMatrix<FK::ValExt>>, LogupZerocheckError> {
                let num_matrices = input_mats.partition_point(|mat| mat.height() > 1);
                let mut max_output_cells = 0;
                let dims = input_mats
                    .iter()
                    .take(num_matrices)
                    .map(|mat| {
                        let output_height = mat.height() >> 1;
                        max_output_cells = max(max_output_cells, output_height * mat.width());
                        (output_height, mat.width())
                    })
                    .collect_vec();
                let pool_cells: usize = dims
                    .iter()
                    .filter(|(h, _)| *h > 1)
                    .map(|(h, w)| h * w)
                    .sum();
                let pool = (pool_cells > 0)
                    .then(|| Arc::new(DeviceBuffer::<FK::ValExt>::with_capacity(pool_cells)));
                let mut pool_off = 0usize;
                let mut log_output_heights = Vec::with_capacity(dims.len());
                let mut widths = Vec::with_capacity(dims.len());
                let mut output_mats = Vec::with_capacity(dims.len());
                for &(output_height, width) in &dims {
                    let output_mat = if output_height > 1 {
                        let cells = output_height * width;
                        // SAFETY: `pool` holds `pool_cells` elements and `pool_off + cells` never
                        // exceeds it (the sum above is over exactly these matrices); the view is
                        // non-owning and the pool that backs it is kept in `pools`, which outlives
                        // every matrix made from it (see `fold_pools` below).
                        let view = unsafe {
                            DeviceBuffer::borrowed(
                                pool.as_ref()
                                    .unwrap_or_else(|| unreachable!())
                                    .as_mut_ptr()
                                    .add(pool_off),
                                cells,
                            )
                        };
                        pool_off += cells;
                        DeviceMatrix::new(Arc::new(view), output_height, width)
                    } else {
                        DeviceMatrix::<FK::ValExt>::with_capacity(output_height, width)
                    };
                    log_output_heights.push(output_height.ilog2() as u8);
                    widths.push(width as u32);
                    output_mats.push(output_mat);
                }
                if let Some(pool) = pool {
                    pools.push(pool);
                }

                let input_ptrs = input_mats
                    .iter()
                    .take(num_matrices)
                    .map(|mat| mat.buffer().as_ptr())
                    .collect_vec();
                let output_ptrs = output_mats
                    .iter()
                    .map(|mat| mat.buffer().as_mut_ptr())
                    .collect_vec();

                let d_input_ptrs = crate::scratch::upload(&input_ptrs)?;
                let d_output_ptrs = crate::scratch::upload(&output_ptrs)?;
                let d_log_output_heights = crate::scratch::upload(&log_output_heights)?;
                let d_widths = crate::scratch::upload(&widths)?;

                unsafe {
                    FK::batch_fold_mle(
                        &d_input_ptrs,
                        &d_output_ptrs,
                        &d_widths,
                        num_matrices.try_into().unwrap(),
                        &d_log_output_heights,
                        max_output_cells.try_into().unwrap(),
                        r_round,
                    )
                    .map_err(LogupZerocheckError::BatchFoldMle)?;
                }
                output_mats.extend_from_slice(&input_mats[num_matrices..]);
                Ok(output_mats)
            };

        // Pools for THIS round's output matrices; installed over the previous round's only
        // after both folds below have consumed (and dropped) every matrix that pointed into them.
        let mut next_pools: Vec<Arc<DeviceBuffer<FK::ValExt>>> = Vec::new();

        // All per-trace matrices are flattened, folded in one batch, then regrouped per trace.
        self.mat_evals_per_trace = {
            let per_trace_counts = self
                .mat_evals_per_trace
                .iter()
                .map(|per| per.len())
                .collect_vec();
            let flat_in = std::mem::take(&mut self.mat_evals_per_trace)
                .into_iter()
                .flatten()
                .collect_vec();
            let mut flat_out = batch_fold(flat_in, &mut next_pools)?.into_iter();
            per_trace_counts
                .into_iter()
                .map(|cnt| flat_out.by_ref().take(cnt).collect())
                .collect()
        };
        if self.save_memory {
            let folded_bytes: usize = self
                .mat_evals_per_trace
                .iter()
                .flatten()
                .map(|fm| fm.buffer().len() * size_of::<FK::ValExt>())
                .sum();
            let remaining = self.gkr_mem_contribution.saturating_sub(folded_bytes);
            self.memory_limit_floor = remaining;
            self.memory_limit_bytes = r0_temp_budget(remaining);
        }

        // Selector matrices: one per trace, folded as a separate batch.
        self.sels_per_trace =
            batch_fold(std::mem::take(&mut self.sels_per_trace), &mut next_pools)?;
        // Every matrix that pointed into the previous round's pools is gone now.
        self.fold_pools = next_pools;

        for eq_layers in self.eq_xis.values_mut() {
            // r_{j-1} is now bound, so its (last) layer is no longer needed.
            eq_layers.pop_layer();
        }
        let xi_j = self.xi[self.l_skip + round - 1];
        let eq_step = eval_eq_mle(&[xi_j], &[r_round]);
        self.eq_ns.push(self.eq_ns[round - 1] * eq_step);
        self.eq_sharp_ns.push(self.eq_sharp_ns[round - 1] * eq_step);
        Ok(())
    }

    #[instrument(
        name = "LogupZerocheck::into_column_openings",
        level = "debug",
        skip_all
    )]
    fn into_column_openings(mut self) -> Result<Vec<Vec<Vec<FK::ValExt>>>, LogupZerocheckError> {
        let trace_total = self.mat_evals_per_trace.len();
        let mut openings_out = Vec::with_capacity(trace_total);

        // After the last round every MLE has been folded down to a single row: its value at the
        // full challenge point `\vec r`.
        for (&rot_on, folded_parts) in self
            .needs_next_per_trace
            .iter()
            .zip(std::mem::take(&mut self.mat_evals_per_trace))
        {
            // On the device a matrix with rotation stores [plain | rotated] side by side; bring
            // each one to the host and separate the two halves.
            let mut host_mats: Vec<Option<ColMajorMatrix<FK::ValExt>>> = folded_parts
                .into_iter()
                .map(|mat| {
                    let on_host = transport_matrix_d2h_col_major(&mat)?;
                    let w_full = on_host.width();
                    let h_rows = on_host.height();
                    debug_assert_eq!(h_rows, 1, "a fully folded matrix must have a single row");
                    let w_air = if rot_on {
                        debug_assert_eq!(
                            w_full % 2,
                            0,
                            "a matrix with rotation must be twice the AIR width (plain + rotated)"
                        );
                        w_full / 2
                    } else {
                        w_full
                    };

                    // First w_air columns are the plain part; the rest (if any) the rotated part.
                    let flat = &on_host.values;
                    let plain_cols: Vec<FK::ValExt> = (0..w_air)
                        .map(|c_i| flat[c_i * h_rows]) // single row: index == column
                        .collect();
                    let rot_cols: Option<Vec<FK::ValExt>> = if rot_on {
                        Some(
                            (w_air..w_full)
                                .map(|c_i| flat[c_i * h_rows]) // single row: index == column
                                .collect(),
                        )
                    } else {
                        None
                    };

                    Ok(vec![
                        Some(ColMajorMatrix::new(plain_cols, w_air)),
                        rot_cols.map(|rc| ColMajorMatrix::new(rc, w_air)),
                    ])
                })
                .collect::<Result<Vec<_>, MemCopyError>>()?
                .into_iter()
                .flatten()
                .collect();

            // host_mats now comes in (plain, rotated) pairs, in commitment order: preprocessed
            // (when present), each cached main, and common main last. The openings list wants
            // common main first, so that final pair is popped off and placed at the front.
            assert_eq!(
                host_mats.len() % 2,
                0,
                "splitting must leave an even number of matrices"
            );
            let cm_rot = host_mats.pop().unwrap();
            let cm_plain = host_mats.pop().unwrap();

            let per_air_open = iter::once(&[cm_plain, cm_rot] as &[_])
                .chain(host_mats.chunks_exact(2))
                .map(|duo| {
                    let plain_m = duo[0].as_ref().unwrap();
                    if let Some(rot_m) = duo[1].as_ref() {
                        std::iter::zip(plain_m.columns(), rot_m.columns())
                            .flat_map(|(x0, x1)| {
                                assert_eq!(x0.len(), 1);
                                assert_eq!(x1.len(), 1);
                                [x0[0], x1[0]]
                            })
                            .collect_vec()
                    } else {
                        plain_m
                            .columns()
                            .map(|x0| {
                                assert_eq!(x0.len(), 1);
                                x0[0]
                            })
                            .collect_vec()
                    }
                })
                .collect_vec();
            openings_out.push(per_air_open);
        }
        Ok(openings_out)
    }
}
