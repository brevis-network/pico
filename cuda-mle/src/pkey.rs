//! Per-AIR symbolic rule data, precomputed once and carried in the GPU proving key.
use crate::runtime::{
    copy::MemCopyH2D, d_buffer::DeviceBuffer, error::MemCopyError, stream::current_stream_sync,
};
use itertools::Itertools;
use mle_core::{
    air::symbolic::{
        symbolic_expression::SymbolicExpression,
        symbolic_variable::{Entry, SymbolicVariable},
        SymbolicConstraints, SymbolicDagBuilder, SymbolicExpressionDag,
    },
    keygen::types::StarkProvingKey,
    StarkProtocolConfig,
};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};

use crate::{
    cuda::jit::{env_flag, env_usize_or_warn, JitKind},
    logup_zerocheck::rules::{codec::Codec, Rule, RuleWithFlag, Source, SymbolicRulesGpu},
    monomial::{
        ExpandedInteractionMonomials, ExpandedMonomials, InteractionMonomialTerm, LambdaTerm,
        MonomialHeader, PackedVar,
    },
};

/// Reserved index base for LogUp challenge (β) leaves that `InteractionEvalRules::new` smuggles
/// through the `mle_core` symbolic DAG as `Entry::Public` (since `mle_core::Entry` has no
/// `Challenge` variant). Real public-value indices are assigned densely from 0 by each
/// AIR and never approach this, so `Entry::Public { index >= CHALLENGE_SENTINEL_BASE }` uniquely
/// tags a challenge. The sentinel is confined to keygen: `retag_challenge_sentinels` rewrites it to
/// `Source::Challenge(index - CHALLENGE_SENTINEL_BASE)` before any rule is encoded or JIT-emitted,
/// so it never reaches the wire or the GPU.
const CHALLENGE_SENTINEL_BASE: usize = 1 << 20;

/// Rewrite the sentinel `Entry::Public` β leaves (see [`CHALLENGE_SENTINEL_BASE`]) into the
/// dedicated `Source::Challenge` rule-IR node. Applied to every operand of every rule; the
/// destination (`z`) slots are always intermediates, so this is a no-op there. `Source::Challenge`
/// encodes to the exact legacy `Entry::Challenge` wire byte, so the emitted `d_rules` stream is
/// byte-identical to the original symbolic-challenge design.
fn retag_challenge_sentinels<F: Field>(rules: &mut [RuleWithFlag<F>]) {
    fn retag<F: Field>(src: &mut Source<F>) {
        if let Source::Var(v) = src {
            if matches!(v.entry, Entry::Public) && v.index >= CHALLENGE_SENTINEL_BASE {
                *src = Source::Challenge(v.index - CHALLENGE_SENTINEL_BASE);
            }
        }
    }
    for rule in rules.iter_mut() {
        match &mut rule.inner {
            Rule::Add(x, y, z) | Rule::Sub(x, y, z) | Rule::Mul(x, y, z) => {
                retag(x);
                retag(y);
                retag(z);
            }
            Rule::Neg(x, z) => {
                retag(x);
                retag(z);
            }
            Rule::Variable(x) => retag(x),
            Rule::BufferVar(x, z) => {
                retag(x);
                retag(z);
            }
        }
    }
}

/// Resolve the size gate in force for `kind`, together with a rendering of where the value came
/// from. The second half matters for diagnostics: the value falls back from the per-family var to
/// the generic one to a compiled-in default, and a message that always names the per-family var
/// sends the operator grepping the launcher for something nobody set.
fn jit_gate(kind: JitKind) -> (usize, String) {
    let default = kind.default_max_rules();
    let specific = kind.max_rules_env();
    let named = match std::env::var(specific) {
        Ok(v) => Some((specific, v)),
        Err(_) => std::env::var("MLE_JIT_MAX_RULES")
            .ok()
            .map(|v| ("MLE_JIT_MAX_RULES", v)),
    };
    match named {
        None => (default, format!("built-in default {default}")),
        Some((var, v)) => match v.trim().parse::<usize>() {
            Ok(n) => (n, format!("{var}={n}")),
            Err(_) => {
                // A typo must not silently disable the gate; warn and fall back to the default.
                tracing::warn!(
                    "[{}] unparseable {var}={v:?}; using default {default}",
                    kind.label()
                );
                (default, format!("built-in default {default}"))
            }
        },
    }
}

/// Announce an AIR dropping to the rule interpreter, once per (family, AIR) per process.
///
/// Crossing the gate is the event worth a warning: the AIR is still proved correctly, just on the
/// slower path, so nothing else in the run says it happened — which is how a rule-count drift after
/// an AIR change goes unnoticed. It is deliberately NOT paired with a "close to the gate" warning:
/// a proximity band wide enough to catch the drift that has actually been observed here is wider
/// than G1's whole headroom, so it would fire on every run at the current operating point, and
/// sizing one per family would bake measured rule counts into the source where nothing can keep
/// them true.
///
/// The dedup is not cosmetic. [`AirDataGpu::new`] re-runs the gate on every `AIR_DATA_CACHE` miss,
/// and combine node shapes do not recur within a run, so an undeduped warning repeats once per
/// node per AIR from threads on the tail's critical path.
fn warn_size_gated_once(kind: JitKind, air_name: &str, len: usize, max: usize, from: &str) {
    type SeenAirs = std::sync::Mutex<std::collections::HashSet<(&'static str, String)>>;
    static SEEN: std::sync::OnceLock<SeenAirs> = std::sync::OnceLock::new();
    let mut seen = SEEN
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if seen.insert((kind.label(), air_name.to_string())) {
        tracing::warn!(
            "[{}] AIR {air_name}: {len} rules exceeds the JIT size gate ({from}) — it runs on the \
             rule interpreter, correctly but slower. Raise the gate with {} (or \
             MLE_JIT_MAX_RULES) if this AIR should be JIT-ed.",
            kind.label(),
            kind.max_rules_env(),
        );
    }
    // Undeduped and on `bench`, because a per-keygen count of gated AIRs is what the bench logs
    // are read for; the warning above is the once-per-AIR operator-facing half.
    tracing::info!(target: "bench", "[{}] size-gated ({len} rules > {max}), interpreter", kind.label());
}

/// Size gate for JIT codegen: AIRs whose rule list exceeds the gate keep `jit_source = None` and
/// stay on the buffer interpreter, because nvrtc does not compile the largest kernels in practical
/// time. The per-family defaults (G1=2000 / Z1=11000) keep every hot-path core AIR JIT-ed while
/// gating the optional-precompile giants (Weierstrass/Fp2, up to ~72k rules). Override per family
/// with `{G1,Z1}_JIT_MAX_RULES`, or globally with `MLE_JIT_MAX_RULES`. `air_name` is diagnostic only.
fn jit_rules_within_gate<F: Field + PrimeField32>(
    rules: &SymbolicRulesGpu<F>,
    kind: JitKind,
    air_name: &str,
) -> bool {
    let (max, from) = jit_gate(kind);
    let len = rules.rules.len();
    if len > max {
        warn_size_gated_once(kind, air_name, len, max, &from);
        return false;
    }
    true
}

pub struct AirDataGpu<Fv: Field + PrimeField32> {
    pub interaction_rules: InteractionEvalRules,
    pub interaction_round0: InteractionRound0Rules,
    /// `BUFFER_VARS` is a per-kernel tuning knob that depends on how the kernel accesses
    /// memory; round 0 buffers its vars, the MLE rounds do not.
    pub zerocheck_round0: ConstraintOnlyRules<true>,
    pub zerocheck_mle: ConstraintOnlyRules<false>,
    pub zerocheck_monomials: Option<ZerocheckMonomials<Fv>>,
    pub interaction_monomials: Option<InteractionMonomials<Fv>>,
}

/// Device-side rules that evaluate every interaction's numerator and denominator; consumed by
/// the GKR input layer and by the LogUp MLE sumcheck rounds.
pub struct InteractionEvalRules {
    pub(crate) inner: EvalRules,
    /// The rules emit the `(numer, denom)` expressions in topological order rather than in
    /// interaction order. Entry `k` gives, for the k-th emitted expression, its original slot:
    /// ```text
    /// slot = 2 * interaction_idx + is_denom
    /// ```
    pub(crate) d_pair_idxs: DeviceBuffer<u32>,
    pub(crate) max_fields_len: usize,
    /// Generated straight-line CUDA source for this AIR's interaction evaluation
    /// (emitted at keygen when `G1_JIT=1`; nvrtc-compiled lazily at first prove).
    pub(crate) jit_source: Option<String>,
    pub(crate) jit_kernel: std::sync::OnceLock<Option<crate::cuda::jit::JitKernel>>,
}

impl InteractionEvalRules {
    /// Eagerly nvrtc-compile the G1 interaction-eval JIT kernel (if `jit_source` is set),
    /// populating the `jit_kernel` OnceLock. Called at keygen, so the lazy prove path (which reads
    /// the same OnceLock) does not invoke nvrtc mid-proof. Concurrent compiles are safe either way
    /// — `compile_kernel` holds a process-wide lock across nvrtc, which is what keeps libnvrtc's
    /// internal threading from deadlocking.
    pub fn warm_jit(&self) {
        let Some(src) = self.jit_source.as_ref() else {
            return;
        };
        self.jit_kernel.get_or_init(
            || match crate::cuda::jit::compile_kernel(src, "jit_interactions") {
                Ok(k) => {
                    tracing::info!(target: "bench", "[g1jit] warm-compiled ({} rules)", self.inner.d_rules.len());
                    Some(k)
                }
                Err(e) => {
                    tracing::warn!("[g1jit] warm-compile failed: {e}");
                    None
                }
            },
        );
    }
}

/// Round-0 interaction evaluation rules for one AIR.
///
/// None of this varies by chunk — the DAG walk, the rule scheduling, the encode and the H2D upload
/// all belong to the key. Only the numerator/denominator weights vary, through `eq_3b`; *which*
/// rule each weight lands on is fixed, and that is [`Self::plans`].
pub struct InteractionRound0Rules {
    /// Encoded rules. Empty when the AIR has no interactions, in which case the round-0 caller
    /// returns before reading anything else here.
    pub(crate) d_rules: DeviceBuffer<u128>,
    pub(crate) buffer_size: u32,
    /// Length of the weight vectors the caller scatters into, i.e. the rule count.
    pub(crate) num_rules: usize,
    /// One entry per interaction, in `SymbolicConstraints::interactions` order.
    pub(crate) plans: Vec<InteractionWeightPlan>,
}

/// Where one interaction's `eq_3b`-scaled weights go.
pub struct InteractionWeightPlan {
    /// Rule index the interaction's `count` expression evaluates into.
    pub(crate) count_rule_idx: usize,
    /// `kind + 1`, the constant the denominator's trailing β term multiplies.
    pub(crate) kind_plus_one: u32,
    /// Rule indices of the message fields, in message order.
    pub(crate) message_rule_idx: Vec<usize>,
}

impl InteractionRound0Rules {
    pub fn new<F: Field + PrimeField32>(
        symbolic: &SymbolicConstraints<F>,
    ) -> Result<Self, MemCopyError> {
        if symbolic.interactions.is_empty() {
            return Ok(Self {
                d_rules: DeviceBuffer::new(),
                buffer_size: 0,
                num_rules: 0,
                plans: Vec::new(),
            });
        }

        // A DAG whose "constraints" are the interaction `[count, message_0, ..]` expressions
        // themselves, with no interactions of its own. Deduplicated because the logup round-0
        // kernel indexes weights by rule, not by constraint, and does not use `used_nodes`.
        let mut dag_builder = SymbolicDagBuilder::new();
        let mut sorted_used_dag_idxs = Vec::new();
        for interaction in &symbolic.interactions {
            sorted_used_dag_idxs.push(dag_builder.add_expr(&interaction.count));
            sorted_used_dag_idxs.extend(
                interaction
                    .message
                    .iter()
                    .map(|field_expr| dag_builder.add_expr(field_expr)),
            );
        }
        sorted_used_dag_idxs.sort();
        sorted_used_dag_idxs.dedup();
        let dag = SymbolicExpressionDag {
            nodes: dag_builder.nodes,
            constraint_idx: sorted_used_dag_idxs,
        };
        let rules = SymbolicRulesGpu::new(&dag, true);

        // `dag_builder.expr_to_idx` is keyed by expression *address*, so the lookups have to happen
        // here, while the expressions this DAG was walked from are still alive. What survives is
        // plain indices.
        let plans = symbolic
            .interactions
            .iter()
            .map(|interaction| {
                let count_dag_idx =
                    dag_builder.expr_to_idx[&(&interaction.count as *const SymbolicExpression<_>)];
                InteractionWeightPlan {
                    count_rule_idx: rules.dag_idx_to_rule_idx[&count_dag_idx],
                    kind_plus_one: interaction.kind as u32 + 1,
                    message_rule_idx: interaction
                        .message
                        .iter()
                        .map(|message| {
                            let dag_idx =
                                dag_builder.expr_to_idx[&(message as *const SymbolicExpression<_>)];
                            rules.dag_idx_to_rule_idx[&dag_idx]
                        })
                        .collect(),
                }
            })
            .collect();

        let encoded_rules = rules.rules.iter().map(|c| c.encode()).collect_vec();
        Ok(Self {
            d_rules: encoded_rules.to_device()?,
            buffer_size: rules.buffer_size.try_into().unwrap(),
            num_rules: rules.rules.len(),
            plans,
        })
    }
}

/// Rule set covering an AIR's constraints alone; interactions are not included.
pub struct ConstraintOnlyRules<const BUFFER_VARS: bool> {
    pub(crate) inner: EvalRules,
    /// Generated straight-line CUDA source for this AIR's zerocheck round-0
    /// constraint evaluation (emitted at keygen when `Z1_JIT=1`, BUFFER_VARS instantiation only;
    /// nvrtc-compiled lazily at first prove with `NC`/`LS` baked in).
    pub(crate) jit_source: Option<String>,
    pub(crate) jit_kernel: std::sync::OnceLock<Option<crate::logup_zerocheck::round0::Z1Jit>>,
}

pub struct EvalRules {
    /// Encoded rules
    pub d_rules: DeviceBuffer<u128>,
    pub d_used_nodes: DeviceBuffer<usize>,
    pub buffer_size: u32,
}

extern "C" {
    fn _kb_batch_mle_pred_invalidate(d_rules: *const std::ffi::c_void);
    fn _kb_round0_pred_invalidate(d_rules: *const std::ffi::c_void);
    fn _kb_mono_fused_invalidate(d_headers: *const std::ffi::c_void);
}

impl Drop for EvalRules {
    /// The CUDA-side pred caches key packed programs on the raw `d_rules` device pointer, which
    /// is only stable while this buffer lives: once freed, the pool can hand the same address to
    /// a different air's rules and a stale hit would evaluate the wrong program. Purge the
    /// pointer from every cache before the buffer is released.
    fn drop(&mut self) {
        if self.d_rules.is_empty() {
            return;
        }
        let p = self.d_rules.as_ptr() as *const std::ffi::c_void;
        unsafe {
            _kb_batch_mle_pred_invalidate(p);
            _kb_round0_pred_invalidate(p);
        }
    }
}

pub struct ZerocheckMonomials<Fv: Field + PrimeField32> {
    pub d_headers: DeviceBuffer<MonomialHeader>,
    pub d_variables: DeviceBuffer<PackedVar>,
    pub d_lambda_terms: DeviceBuffer<LambdaTerm<Fv>>,
    pub num_monomials: u32,
}

impl<Fv: Field + PrimeField32> Drop for ZerocheckMonomials<Fv> {
    /// Same pointer-keyed cache hazard as [`EvalRules`]: the fused-monomial cache keys on the
    /// raw `d_headers` device pointer, so purge it before the buffer can be recycled for a
    /// different air's monomials.
    fn drop(&mut self) {
        if self.d_headers.is_empty() {
            return;
        }
        let p = self.d_headers.as_ptr() as *const std::ffi::c_void;
        unsafe {
            _kb_mono_fused_invalidate(p);
        }
    }
}

pub struct InteractionMonomials<Fv: Field + PrimeField32> {
    pub d_numer_headers: DeviceBuffer<MonomialHeader>,
    pub d_numer_variables: DeviceBuffer<PackedVar>,
    pub d_numer_terms: DeviceBuffer<InteractionMonomialTerm<Fv>>,
    pub num_numer_monomials: u32,
    pub d_denom_headers: DeviceBuffer<MonomialHeader>,
    pub d_denom_variables: DeviceBuffer<PackedVar>,
    pub d_denom_terms: DeviceBuffer<InteractionMonomialTerm<Fv>>,
    pub num_denom_monomials: u32,
    pub max_fields_len: usize,
    pub num_interactions: u32,
}

fn to_device_or_empty<T>(data: &[T]) -> Result<DeviceBuffer<T>, MemCopyError> {
    if data.is_empty() {
        Ok(DeviceBuffer::new())
    } else {
        data.to_device()
    }
}

/// Identity of a cached [`AirDataGpu`]. The DAG bytes are the real key: `AirDataGpu::new` reads
/// nothing but `vk.symbolic_constraints` and `air_name`, so equal bytes mean an identical object.
///
/// `(device, max_constraint_degree, l_skip)` are not decoration. The Z1 `OnceLock` inside bakes
/// `num_cosets = max_constraint_degree - 1` and `l_skip` into a compiled kernel and can never be
/// re-initialized, so one entry shared across operating points would pin the interpreter fallback
/// (`round0.rs` detects the mismatch and warns, but the kernel is lost for the process). Device
/// buffers likewise belong to the device that allocated them.
type AirDataKey = (u32, u8, u32, String, Vec<u8>);

/// Process-lifetime [`AirDataGpu`] cache, scoped to the merged-preprocessed recursion path.
///
/// The recursion machines keygen a fixed 21-chip set once per convert/combine layout, and
/// `AirDataGpu::new` redoes the same rule scheduling, monomial expansion, JIT source emission and
/// H2D uploads every time — the chips' constraints do not depend on the program the layout
/// generated. Keying on the serialized DAG keeps that an observation rather than an assumption: a
/// chip whose constraints DO vary per layout misses and pays full price, instead of being served
/// another program's evaluation rules.
///
/// `Any` because the map is one static across every `Fv`; the downcast is checked.
static AIR_DATA_CACHE: std::sync::OnceLock<
    std::sync::Mutex<
        rustc_hash::FxHashMap<AirDataKey, std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    >,
> = std::sync::OnceLock::new();

/// Cumulative hits/misses, reported on every `mle_assemble_detail` line. This is the evidence for
/// the layout-invariance claim above, not a debug counter: hits ≈ 21×(layouts−1) confirms it,
/// misses growing with layouts refutes it.
pub static AIR_DATA_HITS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub static AIR_DATA_MISSES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Entry ceiling. Reached only if the DAGs are not layout-invariant after all, in which case the
/// cache would otherwise grow one 21-AIR set per layout and leak VRAM; past it we stop inserting
/// and behave exactly as before. Override with `MLE_AIR_DATA_CACHE_CAP` (0 disables the cache).
///
/// The steady state is 21 entries PER DEVICE (one recursion chip set, keyed by device), so the
/// default must cover every card of the biggest host: 8 × 21 = 168, plus margin. Per-card VRAM is
/// unchanged by a larger cap — a card only ever holds its own 21 sets — and the sentinel purpose
/// survives: a non-invariant DAG still hits the ceiling and trips the warning below. That warning
/// used to assert non-invariance as the only cause; a cap below devices × 21 fires it too, and is
/// the first thing to check.
fn air_data_cache_cap() -> usize {
    std::env::var("MLE_AIR_DATA_CACHE_CAP")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(200)
}

/// Entries `device` holds right now. Reported by the VRAM census: the steady state is one 21-AIR
/// set per card, so a count that climbs with layouts is the non-invariance the cap above exists to
/// catch, seen before it reaches the cap.
pub fn air_data_cache_len(device: u32) -> usize {
    AIR_DATA_CACHE
        .get()
        .and_then(|m| m.lock().ok())
        .map_or(0, |m| m.keys().filter(|k| k.0 == device).count())
}

/// [`AirDataGpu::new`], served from [`AIR_DATA_CACHE`] when this AIR's constraint system has been
/// built before on this device at this operating point.
///
/// Bonus over rebuilding: the `EvalRules`/`ZerocheckMonomials` `Drop` impls exist to purge the
/// CUDA pred caches keyed on raw device pointers, because a freed buffer's address can be recycled
/// for a different AIR's rules. A cached entry never drops, so for the recursion machines that
/// hazard — and the cache invalidation it forces — disappears.
pub fn air_data_gpu_cached<S, Fv>(
    pk: &StarkProvingKey<S>,
    device_id: u32,
    l_skip: u32,
) -> Result<std::sync::Arc<AirDataGpu<Fv>>, MemCopyError>
where
    S: StarkProtocolConfig<F = Fv>,
    Fv: Field + PrimeField32 + 'static,
{
    // Per-AIR, matching `warmup_jit_kernels`: the baked `num_cosets` is this AIR's
    // `max_constraint_degree - 1`, not the machine-wide maximum.
    let max_constraint_degree = pk.vk.max_constraint_degree;
    let cap = air_data_cache_cap();
    if cap == 0 {
        return Ok(std::sync::Arc::new(AirDataGpu::new(pk)?));
    }
    // Serializing the DAG costs ~0.1 ms/AIR against the ~7 ms/AIR it guards; `compute_vk_pre_hash`
    // postcard-encodes the same DAGs each keygen for a fraction of `prehash_ms`.
    let dag_bytes = postcard::to_allocvec(&pk.vk.symbolic_constraints)
        .expect("symbolic constraint DAG is postcard-serializable (the vk pre-hash encodes it)");
    let key: AirDataKey = (
        device_id,
        max_constraint_degree,
        l_skip,
        pk.air_name.clone(),
        dag_bytes,
    );

    let mut cache = AIR_DATA_CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(hit) = cache.get(&key) {
        AIR_DATA_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Ok(hit
            .clone()
            .downcast::<AirDataGpu<Fv>>()
            .expect("AirDataGpu cache key collision across field types"));
    }
    AIR_DATA_MISSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Built under the lock: two threads keygening the same layout would otherwise each pay the
    // full build, and the recursion keygen is already serialized by its caller's cache mutex.
    let built = std::sync::Arc::new(AirDataGpu::new(pk)?);
    if cache.len() < cap {
        // `AirDataGpu::new`'s ~11 H2D uploads are async on the per-thread stream and are NOT
        // synchronized there: before this cache, visibility came from the trailing
        // `current_stream_sync()` in `assemble_pk_with_device_merged_prep` — same thread, same
        // stream. A published entry outlives that scope and can be served to a thread whose own
        // sync will never wait on these copies, so make the buffers globally visible BEFORE anyone
        // else can reach them. Misses only, and only on the publish path: an entry we do not
        // insert stays private to this caller and its trailing sync still covers it.
        current_stream_sync()?;
        cache.insert(key, built.clone());
    } else {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "[air-data-cache] at capacity ({cap}); no longer caching — every further \
                 keygen rebuilds its AirData (~10x the cached cost). Either the cap is below \
                 devices x 21 (raise MLE_AIR_DATA_CACHE_CAP) or the constraint DAGs are not \
                 layout-invariant."
            );
        });
    }
    Ok(built)
}

impl<Fv: Field + PrimeField32> AirDataGpu<Fv> {
    pub fn new<S: StarkProtocolConfig<F = Fv>>(
        pk: &StarkProvingKey<S>,
    ) -> Result<Self, MemCopyError> {
        let dag = &pk.vk.symbolic_constraints;
        let symbolic_constraints = SymbolicConstraints::from(dag);
        let interaction_rules = InteractionEvalRules::new(&symbolic_constraints, &pk.air_name)?;
        let interaction_round0 = InteractionRound0Rules::new(&symbolic_constraints)?;
        let zerocheck_round0 = ConstraintOnlyRules::<true>::new(&dag.constraints, &pk.air_name)?;
        let zerocheck_mle = ConstraintOnlyRules::<false>::new(&dag.constraints, &pk.air_name)?;

        let zerocheck_monomials = if dag.constraints.num_constraints() > 0 {
            let expanded = ExpandedMonomials::from_dag(&dag.constraints);
            Some(ZerocheckMonomials::from_expanded(&expanded)?)
        } else {
            None
        };
        let interaction_monomials = if !symbolic_constraints.interactions.is_empty() {
            let expanded =
                ExpandedInteractionMonomials::from_symbolic_constraints(&symbolic_constraints);
            Some(InteractionMonomials::from_expanded(&expanded)?)
        } else {
            None
        };
        Ok(Self {
            interaction_rules,
            interaction_round0,
            zerocheck_round0,
            zerocheck_mle,
            zerocheck_monomials,
            interaction_monomials,
        })
    }
}

impl<Fv: Field + PrimeField32> ZerocheckMonomials<Fv> {
    pub fn from_expanded(em: &ExpandedMonomials<Fv>) -> Result<Self, MemCopyError> {
        // Every header must point inside the flat buffers before they go to the device.
        let vars_len = em.variables.len();
        let terms_len = em.lambda_terms.len();
        for (m, h) in em.headers.iter().enumerate() {
            let vars_stop = h.var_offset as usize + h.num_vars as usize;
            let terms_stop = h.term_offset as usize + h.num_terms as usize;
            assert!(
                vars_stop <= vars_len,
                "monomial {m}: var_offset {} + num_vars {} = {vars_stop} is past variables.len() = {vars_len}",
                h.var_offset,
                h.num_vars
            );
            assert!(
                terms_stop <= terms_len,
                "monomial {m}: term_offset {} + num_terms {} = {terms_stop} is past lambda_terms.len() = {terms_len}",
                h.term_offset,
                h.num_terms
            );
        }

        Ok(Self {
            d_headers: em.headers.to_device()?,
            d_variables: em.variables.to_device()?,
            d_lambda_terms: em.lambda_terms.to_device()?,
            num_monomials: em.headers.len() as u32,
        })
    }
}

impl<Fv: Field + PrimeField32> InteractionMonomials<Fv> {
    pub fn from_expanded(em: &ExpandedInteractionMonomials<Fv>) -> Result<Self, MemCopyError> {
        // Bounds-check the numerator headers against their flat buffers ...
        let n_vars_len = em.numer_variables.len();
        let n_terms_len = em.numer_terms.len();
        for (m, h) in em.numer_headers.iter().enumerate() {
            let vars_stop = h.var_offset as usize + h.num_vars as usize;
            let terms_stop = h.term_offset as usize + h.num_terms as usize;
            assert!(
                vars_stop <= n_vars_len,
                "numerator monomial {m}: var_offset + num_vars out of range"
            );
            assert!(
                terms_stop <= n_terms_len,
                "numerator monomial {m}: term_offset + num_terms out of range"
            );
        }

        // ... and the denominator headers likewise.
        let d_vars_len = em.denom_variables.len();
        let d_terms_len = em.denom_terms.len();
        for (m, h) in em.denom_headers.iter().enumerate() {
            let vars_stop = h.var_offset as usize + h.num_vars as usize;
            let terms_stop = h.term_offset as usize + h.num_terms as usize;
            assert!(
                vars_stop <= d_vars_len,
                "denominator monomial {m}: var_offset + num_vars out of range"
            );
            assert!(
                terms_stop <= d_terms_len,
                "denominator monomial {m}: term_offset + num_terms out of range"
            );
        }

        Ok(Self {
            d_numer_headers: to_device_or_empty(&em.numer_headers)?,
            d_numer_variables: to_device_or_empty(&em.numer_variables)?,
            d_numer_terms: to_device_or_empty(&em.numer_terms)?,
            num_numer_monomials: em.numer_headers.len() as u32,
            d_denom_headers: to_device_or_empty(&em.denom_headers)?,
            d_denom_variables: to_device_or_empty(&em.denom_variables)?,
            d_denom_terms: to_device_or_empty(&em.denom_terms)?,
            num_denom_monomials: em.denom_headers.len() as u32,
            max_fields_len: em.max_fields_len,
            num_interactions: em.num_interactions,
        })
    }
}

impl InteractionEvalRules {
    /// `air_name` is only for the size gate's near-gate warning.
    pub fn new<F: Field + PrimeField32>(
        sc: &SymbolicConstraints<F>,
        air_name: &str,
    ) -> Result<Self, MemCopyError> {
        let ints = &sc.interactions;
        let n_ints = ints.len();
        if n_ints == 0 {
            return Ok(Self {
                inner: EvalRules::dummy(),
                max_fields_len: 0,
                d_pair_idxs: DeviceBuffer::new(),
                jit_source: None,
                jit_kernel: std::sync::OnceLock::new(),
            });
        }
        let widest_msg = ints.iter().map(|it| it.message.len()).max().unwrap_or(0);
        // The LogUp denominator is `Σ_j β^{1+j}·message[j] + β^{1+len}·(kind+1)`. We build it as
        // an `mle_core` symbolic expression so we can reuse the DAG / rule-scheduling machinery,
        // but `mle_core::Entry` no longer has a `Challenge` variant (β is applied
        // numerically via GKR, not as a symbolic AIR leaf). So the β leaves are smuggled through
        // the DAG as `Entry::Public` at a reserved sentinel index base, then rewritten to the
        // dedicated `Source::Challenge` rule-IR node by `retag_challenge_sentinels` before
        // encoding/JIT. The resulting `d_rules` byte stream is identical to the original
        // (symbolic-`Entry::Challenge`) design.
        let beta_leaves: Vec<SymbolicExpression<F>> = (0..widest_msg + 2)
            .map(|k| SymbolicVariable::<F>::new(Entry::Public, CHALLENGE_SENTINEL_BASE + k).into())
            .collect();

        // Two expressions per interaction, numerator first, in interaction order.
        let mut fracs = Vec::with_capacity(n_ints * 2);
        for it in ints.iter() {
            let num_expr = it.count.clone();
            let kind_term = SymbolicExpression::from_u32(it.kind as u32 + 1);
            let beta_tail = beta_leaves[1..].to_vec();
            let mut den_expr = SymbolicExpression::from_u32(0);
            for (pos, field) in it.message.iter().enumerate() {
                den_expr += beta_tail[pos].clone() * field.clone();
            }
            den_expr += beta_tail[it.message.len()].clone() * kind_term;
            fracs.push(num_expr);
            fracs.push(den_expr);
        }
        // Share subexpressions in one DAG. Its roots must be in ascending (topological) order,
        // so sort the (root, slot) pairs and keep the slot list as the inverse permutation.
        let (graph, slot_of) = {
            let mut builder = SymbolicDagBuilder::new();
            let mut keyed: Vec<(usize, u32)> = fracs
                .iter()
                .enumerate()
                .map(|(slot, e)| {
                    let root = builder.add_expr(e);
                    (root, slot.try_into().unwrap())
                })
                .collect_vec();
            keyed.sort();
            let (roots, slots): (Vec<_>, Vec<_>) = keyed.into_iter().unzip();
            let graph = SymbolicExpressionDag {
                nodes: builder.nodes,
                constraint_idx: roots,
            };
            (graph, slots)
        };
        let mut prog = SymbolicRulesGpu::new(&graph, false);
        // Rewrite the sentinel `Entry::Public` β leaves into `Source::Challenge` before they are
        // encoded or JIT-emitted. After this, the sentinel never escapes keygen.
        retag_challenge_sentinels(&mut prog.rules);
        let outputs = graph
            .constraint_idx
            .iter()
            .map(|&root| prog.dag_idx_to_rule_idx[&root])
            .collect_vec();
        // Emit the straight-line CUDA source for this AIR's interactions (gated; nvrtc compile is
        // deferred to first prove).
        let g1_src =
            if env_flag("G1_JIT", false) && jit_rules_within_gate(&prog, JitKind::G1, air_name) {
                // The rule count is known before the (possibly slow) nvrtc compile, so one keygen
                // run logs every AIR's JIT size up front.
                tracing::info!(target: "bench", "[g1jit] emitted ({} rules)", prog.rules.len());
                Some(crate::logup_zerocheck::jit_emit::emit_interaction_kernel(
                    &prog, &outputs, &slot_of,
                ))
            } else {
                None
            };
        let packed = prog.rules.iter().map(|r| r.encode()).collect_vec();
        let dev_rules = packed.to_device()?;
        let dev_outputs = outputs.to_device()?;
        let dev_slots = slot_of.to_device()?;
        assert_eq!(
            outputs.len(),
            2 * n_ints,
            "expected exactly one numerator and one denominator rule per interaction"
        );

        let eval = EvalRules {
            d_rules: dev_rules,
            d_used_nodes: dev_outputs,
            buffer_size: prog
                .buffer_size
                .try_into()
                .expect("rule buffer_size does not fit in u32"),
        };

        Ok(Self {
            inner: eval,
            d_pair_idxs: dev_slots,
            max_fields_len: widest_msg,
            jit_source: g1_src,
            jit_kernel: std::sync::OnceLock::new(),
        })
    }
}

/// `Z1_JIT_FORCE_AIRS=<substr>[,<substr>...]`: admit the z1 JIT for AIRs whose name contains any of
/// the comma-separated substrings, bypassing the size gate (segmentation still applies). Lets a
/// single giant (e.g. `KeccakPermuteChip`) be unlocked without JIT-ing every smaller gated AIR.
fn z1_jit_forced(air_name: &str) -> bool {
    let Ok(v) = std::env::var("Z1_JIT_FORCE_AIRS") else {
        return false;
    };
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|s| air_name.contains(s))
}

impl<const BUFFER_VARS: bool> ConstraintOnlyRules<BUFFER_VARS> {
    pub fn new<F: Field + PrimeField32>(
        dag: &SymbolicExpressionDag<F>,
        air_name: &str,
    ) -> Result<Self, MemCopyError> {
        if dag.num_constraints() == 0 {
            return Ok(Self {
                inner: EvalRules::dummy(),
                jit_source: None,
                jit_kernel: std::sync::OnceLock::new(),
            });
        }

        let rules = SymbolicRulesGpu::new(dag, BUFFER_VARS);
        let used_nodes = dag
            .constraint_idx
            .iter()
            .map(|&dag_idx| rules.dag_idx_to_rule_idx[&dag_idx])
            .collect_vec();

        // Only the round-0 (BUFFER_VARS) instantiation has a JIT kernel.
        let forced = z1_jit_forced(air_name);
        let jit_source = if BUFFER_VARS
            && env_flag("Z1_JIT", false)
            && (forced || jit_rules_within_gate(&rules, JitKind::Z1, air_name))
        {
            // Logged here rather than beside `z1_jit_forced`, so that it describes what happened:
            // `Z1_JIT=0 Z1_JIT_FORCE_AIRS=<air>` admits nothing, and a force-admission line with
            // no `emitted` line after it reads as a bug in the force list.
            if forced {
                tracing::info!(
                    target: "bench",
                    "[z1jit] force-admitted {air_name} ({} rules)",
                    rules.rules.len()
                );
            }
            // `Z1_JIT_SEG_RULES=<n>`: segment size for the `__noinline__` split (see
            // emit_round0_zc_kernel). Default 400 so bare `Z1_JIT=1` segments the giants and
            // compiles in ~linear time; set 0 for the monolithic pre-segmentation emitter
            // (byte-identical source, older cubin caches stay valid but giants won't compile).
            // `Z1_JIT_SEG_MIN` (default 2000): only rule lists STRICTLY larger get segmented —
            // mid-size kernels (<=1495 rules) compile fine monolithic and run fastest with
            // register-resident slots; segmentation trades that for local-memory slots, which
            // only pays off against the interpreter fallback of the compile-infeasible giants.
            let seg_rules = env_usize_or_warn("Z1_JIT_SEG_RULES", 400);
            let seg_min = env_usize_or_warn("Z1_JIT_SEG_MIN", 2000);
            let seg_rules = if rules.rules.len() > seg_min.max(seg_rules) {
                seg_rules
            } else {
                0
            };
            tracing::info!(
                target: "bench",
                "[z1jit] emitted ({} rules, seg={seg_rules})",
                rules.rules.len()
            );
            Some(crate::logup_zerocheck::jit_emit::emit_round0_zc_kernel(
                &rules,
                &used_nodes,
                seg_rules,
            ))
        } else {
            None
        };

        let encoded_rules = rules.rules.iter().map(|c| c.encode()).collect_vec();
        let d_rules = encoded_rules.to_device()?;
        let d_used_nodes = used_nodes.to_device()?;

        let inner = EvalRules {
            d_rules,
            d_used_nodes,
            buffer_size: rules
                .buffer_size
                .try_into()
                .expect("buffer_size exceeds u32"),
        };
        Ok(Self {
            inner,
            jit_source,
            jit_kernel: std::sync::OnceLock::new(),
        })
    }
}

impl EvalRules {
    pub fn dummy() -> Self {
        Self {
            d_rules: DeviceBuffer::new(),
            d_used_nodes: DeviceBuffer::new(),
            buffer_size: 0,
        }
    }
}
