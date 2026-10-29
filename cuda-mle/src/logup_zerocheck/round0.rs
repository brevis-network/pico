use crate::runtime::{
    copy::{MemCopyD2H, MemCopyH2D},
    d_buffer::DeviceBuffer,
    error::CudaError,
    stream::current_stream_sync,
};
use itertools::Itertools;
use mle_core::{
    air::symbolic::{
        symbolic_expression::SymbolicExpression, SymbolicConstraints, SymbolicDagBuilder,
        SymbolicExpressionDag,
    },
    poly::{
        evals_eq_hypercube_serial,
        matrix::{ColMajorMatrix, StridedColMajorMatrixView},
        UnivariatePoly,
    },
    prover::{
        evaluator::InteractionEvalPlan,
        fractional_sumcheck_gkr::Frac,
        sumcheck::{sumcheck_round0_deg, sumcheck_uni_round0_poly},
        ColMajorEvalHelper, DeviceStarkProvingKey,
    },
};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use tracing::{debug, warn};

use super::errors::Round0EvalError;
use crate::{
    base::DeviceMatrix,
    cuda::field_kernels::FieldKernels,
    data_transporter::transport_matrix_d2h_col_major,
    gpu_backend::GenericGpuBackend,
    hash_scheme::GpuHashScheme,
    logup_zerocheck::rules::{codec::Codec, SymbolicRulesGpu},
};

const ROUND0_COSET_PARALLEL_THRESHOLD: u32 = 32768;
const MAX_LOCKSTEP_NUM_COSETS: u32 = 4;

fn uses_round0_coset_parallel(num_x: u32, skip_domain: u32) -> bool {
    num_x.saturating_mul(skip_domain) < ROUND0_COSET_PARALLEL_THRESHOLD
}

/// Compiled JIT kernel pair for one AIR's zerocheck round-0 evaluation, with the
/// compile-time parameters that were baked into the module.
pub(crate) struct Z1Jit {
    kernel: crate::cuda::jit::JitKernel,
    reduce: crate::cuda::jit::JitKernel,
    num_cosets: u32,
    l_skip: u32,
}

impl crate::pkey::ConstraintOnlyRules<true> {
    /// Eagerly nvrtc-compile the Z1 round-0 zerocheck JIT kernels (if `jit_source` is set),
    /// populating the `jit_kernel` OnceLock with the AIR-fixed `(num_cosets, l_skip)`
    /// (`num_cosets = max_constraint_degree - 1`). Mirrors the lazy path in
    /// `sumcheck_uni_round0_polys`; called at keygen so nvrtc runs before the prove. Concurrent
    /// compiles are held apart by `compile_kernel`'s own lock.
    pub fn warm_jit(&self, num_cosets: u32, l_skip: u32) {
        if self.jit_source.is_none() || !(1..=5).contains(&l_skip) {
            return;
        }
        self.jit_kernel.get_or_init(|| {
            let src = self.jit_source.as_ref().unwrap();
            let full = format!("#define NC {num_cosets}u\n#define LS {l_skip}u\n{src}");
            let kernel = crate::cuda::jit::compile_kernel(&full, "z1_round0");
            let reduce = crate::cuda::jit::compile_kernel(&full, "z1_reduce");
            match (kernel, reduce) {
                (Ok(kernel), Ok(reduce)) => {
                    tracing::info!(target: "bench", "[z1jit] warm-compiled ({} rules, nc={num_cosets}, ls={l_skip})", self.inner.d_rules.len());
                    Some(Z1Jit {
                        kernel,
                        reduce,
                        num_cosets,
                        l_skip,
                    })
                }
                (Err(e), _) | (_, Err(e)) => {
                    warn!("[z1jit] warm-compile failed: {e}");
                    None
                }
            }
        });
    }
}

/// Device copy of the `DEVICE_NTT_TWIDDLES` table for the JIT module (nvrtc modules cannot read
/// the main module's `__constant__` memory). KoalaBear-specific, matching the Z1_JIT gate.
/// Layout: level L at offset 2^L − 2 holds monty(gen[L]^i), gen[L] = 3^(127·2^(24−L)) mod p.
/// One slot per device: the buffer is device-resident, so a card-0 copy is unusable from card 1.
static KB_TWIDDLES: [std::sync::OnceLock<Option<DeviceBuffer<u32>>>;
    crate::runtime::memory_manager::MAX_CUDA_DEVICES] =
    [const { std::sync::OnceLock::new() }; crate::runtime::memory_manager::MAX_CUDA_DEVICES];

fn kb_device_twiddles() -> Option<&'static DeviceBuffer<u32>> {
    let dev = crate::runtime::context::get_device().unwrap_or(0) as usize;
    KB_TWIDDLES[dev]
        .get_or_init(|| {
            const P: u64 = 0x7F00_0001;
            fn pow_mod(mut b: u64, mut e: u64) -> u64 {
                let mut r = 1u64;
                b %= P;
                while e > 0 {
                    if e & 1 == 1 {
                        r = r * b % P;
                    }
                    b = b * b % P;
                    e >>= 1;
                }
                r
            }
            let mut table = vec![0u32; (1usize << 11) - 2];
            for level in 1..=10u32 {
                let g = pow_mod(3, 127u64 << (24 - level));
                let off = (1usize << level) - 2;
                let mut w = 1u64;
                for i in 0..(1usize << level) {
                    table[off + i] = ((w << 32) % P) as u32;
                    w = w * g % P;
                }
            }
            let buf = table.to_device().ok()?;
            // Sync before publishing: `to_device` is an async H2D on this thread's stream, and the
            // slot is shared by the card's lanes. A second prover lane on this card launches on its
            // own stream, which has nothing ordering it against that copy. Same reason
            // `air_data_gpu_cached` syncs before it inserts. Kept unconditional even where the
            // card runs a single lane and has no second stream to race: `KB_TWIDDLES` has a slot
            // per device, so this is one sync per card per process, and gating it would buy nothing
            // while adding a path nothing exercises.
            current_stream_sync().ok()?;
            Some(buf)
        })
        .as_ref()
}

/// Launch the generated `z1_round0` + `z1_reduce` kernels. Mirrors the interpreter's lockstep
/// launch shape (block of 128 threads, a multiple of skip_domain), with the grid capped so the
/// per-block partial buffer stays small; x_int is tiled inside the kernel.
#[allow(clippy::too_many_arguments)]
unsafe fn launch_z1_round0<FK: FieldKernels>(
    jit: &Z1Jit,
    selectors_cube: &DeviceBuffer<FK::Val>,
    preprocessed_ptr: *const FK::Val,
    main_parts: &DeviceBuffer<*const FK::Val>,
    eq_cube: *const FK::ValExt,
    lambda_pows: &DeviceBuffer<FK::ValExt>,
    public_values: &DeviceBuffer<FK::Val>,
    tw: &DeviceBuffer<u32>,
    num_x: u32,
    height: u32,
    g_shift_monty: u32,
    num_cosets: u32,
    skip_domain: u32,
) -> Result<DeviceBuffer<FK::ValExt>, String> {
    use std::ffi::c_void;
    let block: u32 = 128;
    let grid = (num_x * skip_domain).div_ceil(block).min(2048);
    let d = (num_cosets * skip_domain) as usize;
    let tmp = DeviceBuffer::<FK::ValExt>::with_capacity(grid as usize * d);
    let sp_evals = DeviceBuffer::<FK::ValExt>::with_capacity(d);

    let mut p_tmp = tmp.as_mut_ptr() as *mut c_void;
    let mut p_sel = selectors_cube.as_ptr() as *mut c_void;
    let mut p_prep = preprocessed_ptr as *mut c_void;
    let mut p_parts = main_parts.as_ptr() as *mut c_void;
    let mut p_eq = eq_cube as *mut c_void;
    let mut p_lam = lambda_pows.as_ptr() as *mut c_void;
    let mut p_pub = public_values.as_ptr() as *mut c_void;
    let mut p_tw = tw.as_ptr() as *mut c_void;
    let mut v_nx = num_x;
    let mut v_h = height;
    let mut v_g = g_shift_monty;
    let mut params = [
        &mut p_tmp as *mut _ as *mut c_void,
        &mut p_sel as *mut _ as *mut c_void,
        &mut p_prep as *mut _ as *mut c_void,
        &mut p_parts as *mut _ as *mut c_void,
        &mut p_eq as *mut _ as *mut c_void,
        &mut p_lam as *mut _ as *mut c_void,
        &mut p_pub as *mut _ as *mut c_void,
        &mut p_tw as *mut _ as *mut c_void,
        &mut v_nx as *mut u32 as *mut c_void,
        &mut v_h as *mut u32 as *mut c_void,
        &mut v_g as *mut u32 as *mut c_void,
    ];
    // Dynamic shared memory: blockDim FpExt partials for the in-block reduction.
    jit.kernel.launch(
        grid,
        block,
        block * size_of::<FK::ValExt>() as u32,
        &mut params,
    )?;

    let mut q_out = sp_evals.as_mut_ptr() as *mut c_void;
    let mut q_tmp = tmp.as_ptr() as *mut c_void;
    let mut q_nb = grid;
    let mut rparams = [
        &mut q_out as *mut _ as *mut c_void,
        &mut q_tmp as *mut _ as *mut c_void,
        &mut q_nb as *mut u32 as *mut c_void,
    ];
    jit.reduce.launch(d as u32, 256, 0, &mut rparams)?;
    Ok(sp_evals)
}

fn check_lockstep_coset_limit(
    x_count: u32,
    domain_size: u32,
    coset_count: u32,
) -> Result<(), Round0EvalError> {
    if coset_count > MAX_LOCKSTEP_NUM_COSETS && !uses_round0_coset_parallel(x_count, domain_size) {
        return Err(CudaError::new(1).into());
    }
    Ok(())
}

/// Round-0 evaluation of one AIR's ordinary constraints (interactions are handled separately),
/// from trace data that has already been prepared.
///
/// The result is the quotient polynomial, so pass `num_cosets = constraint_degree - 1`.
/// Peak-memory caveats around stream-ordered frees are covered in the [`crate::logup_zerocheck`]
/// docs.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_round0_constraints_gpu<
    FK: FieldKernels,
    HS: GpuHashScheme<BaseField = FK::Val, ExtField = FK::ValExt>,
>(
    pk: &DeviceStarkProvingKey<GenericGpuBackend<HS>>,
    selectors_cube: &DeviceBuffer<FK::Val>,
    main_parts: &DeviceBuffer<*const FK::Val>,
    public_values: &DeviceBuffer<FK::Val>,
    eq_cube: *const FK::ValExt,
    lambda_pows: &DeviceBuffer<FK::ValExt>,
    skip_domain: u32,
    num_x: u32,
    height: u32,
    num_cosets: u32,
    g_shift: FK::Val,
    max_temp_bytes: usize,
) -> Result<crate::scratch::Scratch<FK::ValExt>, Round0EvalError> {
    let constraints_dag = &pk.vk.symbolic_constraints;
    if constraints_dag.constraints.constraint_idx.is_empty() || num_cosets == 0 {
        // The AIR has no ordinary constraints: hand back an empty buffer.
        return Ok(crate::scratch::Scratch::owned(DeviceBuffer::new()));
    }
    check_lockstep_coset_limit(num_x, skip_domain, num_cosets)?;

    let rules = &pk.other_data.zerocheck_round0;

    let preprocessed_ptr_early = pk
        .preprocessed_data
        .as_ref()
        .map(|cd| cd.trace.buffer().as_ptr())
        .unwrap_or(std::ptr::null());

    // Generated straight-line kernel, lockstep / warp-shuffle regime only
    // (1 <= l_skip <= 5 so each logical NTT fits in a warp subgroup). Compile lazily with the
    // per-AIR NC (num_cosets) and LS (l_skip) baked in; any failure or shape mismatch falls back
    // to the interpreter.
    let l_skip = skip_domain.trailing_zeros();
    // Off unless explicitly on. The comparator keeps a full reference buffer on the device beside
    // the JIT result, which is enough to OOM a four-card prove on a 32 GiB card — so `=0` reading
    // as ON is not a harmless mis-parse here, it costs the run.
    let z1_verify = crate::cuda::jit::env_flag("Z1_JIT_VERIFY", false);
    let mut z1_result: Option<crate::scratch::Scratch<FK::ValExt>> = None;
    if rules.jit_source.is_some()
        && !uses_round0_coset_parallel(num_x, skip_domain)
        && (1..=5).contains(&l_skip)
    {
        let jit = rules
            .jit_kernel
            .get_or_init(|| {
                let src = rules.jit_source.as_ref().unwrap();
                let full = format!("#define NC {num_cosets}u\n#define LS {l_skip}u\n{src}");
                let kernel = crate::cuda::jit::compile_kernel(&full, "z1_round0");
                let reduce = crate::cuda::jit::compile_kernel(&full, "z1_reduce");
                match (kernel, reduce) {
                    (Ok(kernel), Ok(reduce)) => {
                        tracing::info!(
                            target: "bench",
                            "[z1jit] compiled ({} rules, nc={num_cosets}, ls={l_skip})",
                            rules.inner.d_rules.len()
                        );
                        Some(Z1Jit {
                            kernel,
                            reduce,
                            num_cosets,
                            l_skip,
                        })
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        warn!("[z1jit] compile failed: {e}");
                        None
                    }
                }
            })
            .as_ref()
            .filter(|j| {
                let ok = j.num_cosets == num_cosets && j.l_skip == l_skip;
                if !ok {
                    // The OnceLock can never be re-initialized, so a warm/lazy parameter mismatch
                    // means this AIR silently runs the interpreter forever — make it loud.
                    warn!(
                        "[z1jit] cached kernel (nc={}, ls={}) mismatches request (nc={num_cosets}, ls={l_skip}); interpreter fallback",
                        j.num_cosets, j.l_skip
                    );
                }
                ok
            });
        if let (Some(jit), Some(tw)) = (jit, kb_device_twiddles()) {
            let g_shift_monty = crate::logup_zerocheck::jit_emit::monty(g_shift.as_canonical_u32());
            match unsafe {
                launch_z1_round0::<FK>(
                    jit,
                    selectors_cube,
                    preprocessed_ptr_early,
                    main_parts,
                    eq_cube,
                    lambda_pows,
                    public_values,
                    tw,
                    num_x,
                    height,
                    g_shift_monty,
                    num_cosets,
                    skip_domain,
                )
            } {
                Ok(sp) => {
                    let sp = crate::scratch::Scratch::owned(sp);
                    if z1_verify {
                        z1_result = Some(sp); // fall through to interpreter and compare
                    } else {
                        return Ok(sp);
                    }
                }
                // Device printed for the same reason as the G1 site: a cross-card handle fails
                // here as `CUDA_ERROR_INVALID_HANDLE` and is otherwise unattributable.
                Err(e) => warn!(
                    "[z1jit] launch failed dev={:?}: {e}; falling back",
                    crate::runtime::context::get_device()
                ),
            }
        }
    }

    let buffer_size: u32 = rules.inner.buffer_size;
    let intermed_capacity = unsafe {
        FK::zerocheck_r0_intermediates_buffer_size(
            buffer_size,
            skip_domain,
            num_x,
            num_cosets,
            max_temp_bytes,
        )
    };
    if std::env::var("STEP_PROF").is_ok() {
        // Mirror of eval_config.cuh: threads ≈ skip_domain × num_x (rounded up to whole blocks
        // there), the global intermediates buffer is used only above BUFFER_THRESHOLD = 16
        // (zerocheck_round0.cu), and `k` is how many x each thread serialises to fit the budget.
        let threads = skip_domain as usize * num_x as usize;
        let desired_bytes = if buffer_size > 16 {
            threads * num_cosets as usize * buffer_size as usize * size_of::<FK::Val>()
        } else {
            0
        };
        let k = desired_bytes.div_ceil(max_temp_bytes.max(1)).max(1);
        tracing::info!(
            target: "bench",
            "[stepprof][{}] r0budget kind=zc air={} num_x={num_x} nc={num_cosets} skip={skip_domain} \
             buffer_size={buffer_size} desired_bytes={desired_bytes} capacity_bytes={} k={k} \
             budget_bytes={max_temp_bytes}",
            crate::prove_phase(),
            pk.air_name,
            intermed_capacity * size_of::<FK::Val>()
        );
    }
    let mut node_scratch = if intermed_capacity > 0 {
        debug!("zerocheck:intermediates_capacity={intermed_capacity}");
        DeviceBuffer::<FK::Val>::with_capacity(intermed_capacity)
    } else {
        DeviceBuffer::<FK::Val>::new()
    };

    let temp_sums_buffer_capacity = unsafe {
        FK::zerocheck_r0_temp_sums_buffer_size(
            buffer_size,
            skip_domain,
            num_x,
            num_cosets,
            max_temp_bytes,
        )
    };
    debug!("zerocheck:temp_sums_buffer_capacity={temp_sums_buffer_capacity}");
    let mut partial_sums = crate::scratch::alloc::<FK::ValExt>(temp_sums_buffer_capacity);
    let used_temp_bytes = intermed_capacity * size_of::<FK::Val>()
        + temp_sums_buffer_capacity * size_of::<FK::ValExt>();
    if used_temp_bytes > max_temp_bytes {
        // Going over the requested cap is tolerated (only logged), at the price of a memory peak
        // larger than the caller planned for.
        warn!("zerocheck used_temp_bytes ({used_temp_bytes}) > max_temp_bytes ({max_temp_bytes})");
    }

    let prep_dev_ptr = preprocessed_ptr_early;

    let mut sp_evals =
        crate::scratch::alloc::<FK::ValExt>(num_cosets as usize * skip_domain as usize);
    // SAFETY:
    // - The kernel performs no bounds checking; it relies on the rules being well-formed, with
    //   every node index valid.
    unsafe {
        FK::zerocheck_ntt_eval_constraints(
            &mut partial_sums,
            &mut sp_evals,
            selectors_cube,
            prep_dev_ptr,
            main_parts,
            eq_cube,
            lambda_pows,
            public_values,
            &rules.inner.d_rules,
            &rules.inner.d_used_nodes,
            buffer_size,
            &mut node_scratch,
            skip_domain,
            num_x,
            height,
            num_cosets,
            g_shift,
            max_temp_bytes,
        )?;
    }

    // Verify mode: compare the JIT result against the interpreter bit-for-bit
    // (field arithmetic is exact, so summation-order differences cannot change values).
    if let Some(jit_buf) = z1_result {
        let a: Vec<FK::ValExt> = jit_buf.to_host()?;
        let b: Vec<FK::ValExt> = sp_evals.to_host()?;
        let bytes = |v: &Vec<FK::ValExt>| unsafe {
            std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v.as_slice()))
                .to_vec()
        };
        if bytes(&a) == bytes(&b) {
            tracing::info!(target: "bench", "[z1jit] VERIFY OK ({} sp_evals)", a.len());
        } else {
            tracing::warn!("[z1jit] VERIFY MISMATCH ({} sp_evals)", a.len());
        }
    }

    Ok(sp_evals)
}

/// Round-0 evaluation of one AIR's interaction (logup) expressions, leaving out its ordinary
/// constraints, from trace data that has already been prepared.
///
/// The interaction expressions are taken from `symbolic`. Peak-memory caveats around
/// stream-ordered frees are covered in the [`crate::logup_zerocheck`] docs.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_round0_interactions_gpu<
    FK: FieldKernels,
    HS: GpuHashScheme<BaseField = FK::Val, ExtField = FK::ValExt>,
>(
    pk: &DeviceStarkProvingKey<GenericGpuBackend<HS>>,
    symbolic: &SymbolicConstraints<FK::Val>,
    selectors_cube: &DeviceBuffer<FK::Val>,
    main_parts: &DeviceBuffer<*const FK::Val>,
    public_values: &DeviceBuffer<FK::Val>,
    eq_cube: *const FK::ValExt,
    beta_pows: &[FK::ValExt],
    eq_3bs: &[FK::ValExt],
    skip_domain: u32,
    num_x: u32,
    height: u32,
    num_cosets: u32,
    g_shift: FK::Val,
    max_temp_bytes: usize,
) -> Result<crate::scratch::Scratch<Frac<FK::ValExt>>, Round0EvalError> {
    // Nothing to do when the trace carries no interactions.
    if eq_3bs.is_empty() {
        return Ok(crate::scratch::Scratch::owned(DeviceBuffer::new()));
    }
    check_lockstep_coset_limit(num_x, skip_domain, num_cosets)?;
    let large_domain = num_cosets * skip_domain;

    // The rules, their encoding and their H2D upload are fixed per AIR and come from the key; only
    // the weights below vary per chunk, through `eq_3b`.
    let cached = &pk.other_data.interaction_round0;
    assert_eq!(
        cached.plans.len(),
        symbolic.interactions.len(),
        "round-0 interaction plan built from a different constraint system than the one passed in"
    );

    let (d_numer_weights, d_denom_weights, denom_sum_init) = {
        let mut numer_weights = vec![FK::ValExt::ZERO; cached.num_rules];
        let mut denom_weights = vec![FK::ValExt::ZERO; cached.num_rules];
        let mut denom_sum_init = FK::ValExt::ZERO;
        for (interaction_idx, plan) in cached.plans.iter().enumerate() {
            // A single expression node may be shared across interactions, possibly serving as
            // the `count` of one and as a message field of another. Only its eq_3b-weighted
            // total matters, so the weights are accumulated per rule up front.
            numer_weights[plan.count_rule_idx] += eq_3bs[interaction_idx];
            denom_sum_init += eq_3bs[interaction_idx]
                * beta_pows[plan.message_rule_idx.len()]
                * FK::Val::from_u32(plan.kind_plus_one);

            for (message_idx, &message_rule_idx) in plan.message_rule_idx.iter().enumerate() {
                denom_weights[message_rule_idx] += eq_3bs[interaction_idx] * beta_pows[message_idx];
            }
        }
        let d_numer_weights = crate::scratch::upload(&numer_weights)?;
        let d_denom_weights = crate::scratch::upload(&denom_weights)?;
        (d_numer_weights, d_denom_weights, denom_sum_init)
    };

    let d_rules = &cached.d_rules;
    let buffer_size: u32 = cached.buffer_size;
    let intermed_capacity = unsafe {
        FK::logup_r0_intermediates_buffer_size(
            buffer_size,
            skip_domain,
            num_x,
            num_cosets,
            max_temp_bytes,
        )
    };
    if std::env::var("STEP_PROF").is_ok() {
        // Mirror of eval_config.cuh: threads ≈ skip_domain × num_x (rounded up to whole blocks
        // there), the global intermediates buffer is used only above BUFFER_THRESHOLD = 16
        // (zerocheck_round0.cu), and `k` is how many x each thread serialises to fit the budget.
        let threads = skip_domain as usize * num_x as usize;
        let desired_bytes = if buffer_size > 16 {
            threads * num_cosets as usize * buffer_size as usize * size_of::<FK::Val>()
        } else {
            0
        };
        let k = desired_bytes.div_ceil(max_temp_bytes.max(1)).max(1);
        tracing::info!(
            target: "bench",
            "[stepprof][{}] r0budget kind=lg air={} num_x={num_x} nc={num_cosets} skip={skip_domain} \
             buffer_size={buffer_size} desired_bytes={desired_bytes} capacity_bytes={} k={k} \
             budget_bytes={max_temp_bytes}",
            crate::prove_phase(),
            pk.air_name,
            intermed_capacity * size_of::<FK::Val>()
        );
    }
    let mut node_scratch = if intermed_capacity > 0 {
        debug!("logup_r0:intermediates_capacity={intermed_capacity}");
        DeviceBuffer::<FK::Val>::with_capacity(intermed_capacity)
    } else {
        DeviceBuffer::<FK::Val>::new()
    };

    let temp_sums_buffer_capacity = unsafe {
        FK::logup_r0_temp_sums_buffer_size(
            buffer_size,
            skip_domain,
            num_x,
            num_cosets,
            max_temp_bytes,
        )
    };
    debug!("logup_r0:tmp_sums_buffer_capacity={temp_sums_buffer_capacity}");
    let mut partial_sums = crate::scratch::alloc::<Frac<FK::ValExt>>(temp_sums_buffer_capacity);
    let used_temp_bytes = intermed_capacity * size_of::<FK::Val>()
        + temp_sums_buffer_capacity * size_of::<Frac<FK::ValExt>>();
    if used_temp_bytes > max_temp_bytes {
        warn!(
            "logup_round0 used_temp_bytes ({used_temp_bytes}) > max_temp_bytes ({max_temp_bytes})"
        );
    }

    let prep_dev_ptr = pk
        .preprocessed_data
        .as_ref()
        .map(|cd| cd.trace.buffer().as_ptr())
        .unwrap_or(std::ptr::null());

    let mut s_evals = crate::scratch::alloc::<Frac<FK::ValExt>>(large_domain as usize);

    unsafe {
        FK::logup_bary_eval_interactions_round0(
            &mut partial_sums,
            &mut s_evals,
            selectors_cube,
            prep_dev_ptr,
            main_parts,
            eq_cube,
            public_values,
            &d_numer_weights,
            &d_denom_weights,
            denom_sum_init,
            d_rules,
            buffer_size,
            &mut node_scratch,
            skip_domain,
            num_x,
            height,
            num_cosets,
            g_shift,
            max_temp_bytes,
        )?;
    }

    // ── Debug: print first few s_evals entries to compare KB GPU vs expected ──
    #[cfg(debug_assertions)]
    if std::env::var("MLE_DEBUG_ROUND0").is_ok() {
        use crate::runtime::copy::MemCopyD2H;
        let host = s_evals.to_host().unwrap_or_default();
        tracing::warn!(
            "round0 debug: denom_sum_init={:?} height={} num_cosets={} skip_domain={}",
            denom_sum_init,
            height,
            num_cosets,
            skip_domain,
        );
        let nw = d_numer_weights.to_host().unwrap_or_default();
        let dw = d_denom_weights.to_host().unwrap_or_default();
        tracing::warn!("  numer_weights[..3]={:?}", &nw[..nw.len().min(3)]);
        tracing::warn!("  denom_weights[..3]={:?}", &dw[..dw.len().min(3)]);
        for (i, f) in host.iter().take(4).enumerate() {
            tracing::warn!("  s_evals[{i}] = p={:?} q={:?}", f.p, f.q);
        }
    }

    Ok(s_evals)
}

/// CPU reference fallback for `evaluate_round0_interactions_gpu`.
///
/// Downloads the GPU trace to CPU and uses `sumcheck_uni_round0_poly` to compute the batch MLE of
/// interaction polynomials. Reached only when `FK::use_cpu_zerocheck_mle()` is `true` or under the
/// `MLE_VERIFY_ZC_R0` cross-check — both field impls now return `false`, so the GPU kernel
/// `_kb_logup_bary_eval_interactions_round0` is the correct production path.
///
/// Returns `None` if there are no interactions (`eq_3bs` is empty).
pub fn evaluate_round0_interactions_cpu_fallback<FK: FieldKernels>(
    constraints_dag: &SymbolicExpressionDag<FK::Val>,
    interaction_plan: &InteractionEvalPlan<FK::Val>,
    cached_mains: &[&DeviceMatrix<FK::Val>],
    common_main: &DeviceMatrix<FK::Val>,
    xi_chunk: &[FK::ValExt],
    needs_next: bool,
    beta_pows: &[FK::ValExt],
    eq_3bs: &[FK::ValExt],
    l_skip: usize,
    n: isize,
    height: usize,
    num_cosets: usize,
    omega_root: FK::Val,
    public_values: &[FK::Val],
) -> Result<Option<[UnivariatePoly<FK::ValExt>; 2]>, Round0EvalError> {
    let _ = omega_root; // used structurally but not needed for the CPU sumcheck path
    if eq_3bs.is_empty() || num_cosets == 0 {
        return Ok(None);
    }

    // Download ALL GPU matrices to CPU: cached_mains then common_main (matches ColMajorEvalHelper partition
    // order)
    let mut cpu_mats = Vec::with_capacity(cached_mains.len() + 1);
    for cm in cached_mains {
        cpu_mats.push(transport_matrix_d2h_col_major(*cm)?);
    }
    cpu_mats.push(transport_matrix_d2h_col_major(common_main)?);

    // Compute eq(xi, x) evaluations for the 2^n_lift hypercube in natural order.
    // NOTE: eq_xis.layers[n_lift] from new_rev_with_kernels stores eq(xi, bit_rev(x)) which
    // is the GPU's bit-reversed convention. Since the CPU GKR runs on natural-order leaves,
    // we must use natural-order eq here so the batch MLE matches the GKR claim.
    let n_lift = xi_chunk.len(); // = n.max(0)
    let eq_cube: Vec<FK::ValExt> = evals_eq_hypercube_serial(xi_chunk);

    // Build selector matrix: col0=is_first, col1=is_transition, col2=is_last
    let mut sel_vals = FK::Val::zero_vec(3 * height);
    if height > 0 {
        sel_vals[0] = FK::Val::ONE;
        for i in 0..height.saturating_sub(1) {
            sel_vals[height + i] = FK::Val::ONE;
        }
        sel_vals[3 * height - 1] = FK::Val::ONE;
    }
    let sel_mat = ColMajorMatrix::new(sel_vals, 3);

    let eval_helper = ColMajorEvalHelper {
        constraints_dag,
        interactions: interaction_plan,
        public_values: public_values.to_vec(),
        preprocessed_trace: None,
        needs_next,
        constraint_degree: 0,
    };

    // Build mats list: selector first, then all cached_mains + common_main (with rotation if
    // needed)
    let sel_view: StridedColMajorMatrixView<FK::Val> = sel_mat.as_view().into();
    let mut mats: Vec<(StridedColMajorMatrixView<FK::Val>, bool)> = vec![(sel_view, false)];
    for cpu_mat in &cpu_mats {
        let mat_view: StridedColMajorMatrixView<FK::Val> = cpu_mat.as_view().into();
        mats.push((mat_view, false));
        if needs_next {
            mats.push((mat_view, true));
        }
    }

    let [mut numer_poly, denom_poly] = sumcheck_uni_round0_poly::<FK::Val, FK::ValExt, _, 2>(
        l_skip,
        n_lift,
        num_cosets,
        &mats,
        |_z, x, row_parts| {
            let eq = eq_cube[x];
            let [numer, denom] = eval_helper.acc_interactions(row_parts, beta_pows, eq_3bs);
            [eq * numer, eq * denom]
        },
    );

    // When n < 0 the trace is shorter than the lifted domain (cyclic repeat); apply norm factor
    if n.is_negative() {
        let norm_factor = FK::Val::from_u32(1 << n.unsigned_abs()).inverse();
        for c in numer_poly.coeffs_mut() {
            *c *= norm_factor;
        }
    }

    Ok(Some([numer_poly, denom_poly]))
}

/// CPU reference fallback for the round-0 zerocheck constraint polynomial. Reached only when
/// `FK::use_cpu_zerocheck_mle()` is `true` or under `MLE_VERIFY_ZC_R0`; the GPU kernel is the
/// correct production path. Mirrors the CPU reference `sp_0_zerochecks`.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_round0_constraints_cpu_fallback<FK: FieldKernels>(
    constraints_dag: &SymbolicExpressionDag<FK::Val>,
    interaction_plan: &InteractionEvalPlan<FK::Val>,
    cached_mains: &[&DeviceMatrix<FK::Val>],
    common_main: &DeviceMatrix<FK::Val>,
    xi_chunk: &[FK::ValExt],
    needs_next: bool,
    lambda_pows: &[FK::ValExt],
    l_skip: usize,
    height: usize,
    constraint_deg: usize,
    public_values: &[FK::Val],
) -> Result<Option<UnivariatePoly<FK::ValExt>>, Round0EvalError> {
    // deg 0/1: zerocheck sp_0 must be identically zero (no constraint poly).
    if constraint_deg <= 1 {
        return Ok(None);
    }
    let num_cosets = constraint_deg - 1;

    let mut cpu_mats = Vec::with_capacity(cached_mains.len() + 1);
    for cm in cached_mains {
        cpu_mats.push(transport_matrix_d2h_col_major(*cm)?);
    }
    cpu_mats.push(transport_matrix_d2h_col_major(common_main)?);

    let n_lift = xi_chunk.len();
    let eq_cube: Vec<FK::ValExt> = evals_eq_hypercube_serial(xi_chunk);

    let mut sel_vals = FK::Val::zero_vec(3 * height);
    if height > 0 {
        sel_vals[0] = FK::Val::ONE;
        for i in 0..height.saturating_sub(1) {
            sel_vals[height + i] = FK::Val::ONE;
        }
        sel_vals[3 * height - 1] = FK::Val::ONE;
    }
    let sel_mat = ColMajorMatrix::new(sel_vals, 3);

    let eval_helper = ColMajorEvalHelper {
        constraints_dag,
        interactions: interaction_plan,
        public_values: public_values.to_vec(),
        preprocessed_trace: None,
        needs_next,
        constraint_degree: constraint_deg as u8,
    };

    let sel_view: StridedColMajorMatrixView<FK::Val> = sel_mat.as_view().into();
    let mut mats: Vec<(StridedColMajorMatrixView<FK::Val>, bool)> = vec![(sel_view, false)];
    for cpu_mat in &cpu_mats {
        let mat_view: StridedColMajorMatrixView<FK::Val> = cpu_mat.as_view().into();
        mats.push((mat_view, false));
        if needs_next {
            mats.push((mat_view, true));
        }
    }

    // q(Z) = sum_x eq(xi,x) * C(Z,x) / (Z^{2^l_skip} - 1) on (deg-1) cosets.
    let [q] = sumcheck_uni_round0_poly::<FK::Val, FK::ValExt, _, 1>(
        l_skip,
        n_lift,
        num_cosets,
        &mats,
        |z, x, row_parts| {
            let eq = eq_cube[x];
            let c = eval_helper.acc_constraints(row_parts, lambda_pows);
            let zerofier = z.exp_power_of_2(l_skip) - FK::Val::ONE;
            [eq * c * zerofier.inverse()]
        },
    );

    // sp_0 = (Z^{2^l_skip} - 1) * q
    let sp_0_deg = sumcheck_round0_deg(l_skip, constraint_deg);
    let skip = 1usize << l_skip;
    let coeffs: Vec<FK::ValExt> = (0..=sp_0_deg)
        .map(|i| {
            let mut c = -*q.coeffs().get(i).unwrap_or(&FK::ValExt::ZERO);
            if i >= skip {
                c = c + *q.coeffs().get(i - skip).unwrap_or(&FK::ValExt::ZERO);
            }
            c
        })
        .collect();

    Ok(Some(UnivariatePoly::new(coeffs)))
}
