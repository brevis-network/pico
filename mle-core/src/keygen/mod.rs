use std::{
    cmp::{max, Reverse},
    collections::HashMap,
    sync::Arc,
};

use itertools::Itertools;
use p3_air::BaseAir;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::Dimensions;
use p3_util::log2_strict_usize;
use tracing::instrument;

use crate::{
    air::symbolic::{
        get_symbolic_builder,
        symbolic_variable::{Entry, SymbolicVariable},
        SymbolicConstraintsDag, SymbolicExpressionNode, SymbolicRapBuilder,
    },
    canonical_serde::CanonicalDigest,
    config::check_field_admissible,
    hasher::MerkleHasher,
    keygen::types::{
        KeygenError, LinearConstraint, MultiStarkProvingKey, MultiStarkVerifyingKeyInner,
        StarkProvingKey, StarkVerifyingKey, StarkVerifyingParams, TraceWidth,
        VerifierSinglePreprocessedData,
    },
    poly::matrix::{ColMajorMatrix, MatrixDimensions},
    proof::CODEC_VERSION,
    protocol::stacking::StackedLayout,
    prover::stacked_pcs::{stacked_commit, StackedPcsData},
    AirRef, AnyAir, StarkProtocolConfig, SystemParams,
};

pub mod types;

struct AirKeygenBuilder<SC: StarkProtocolConfig> {
    pub is_required: bool,
    air: AirRef<SC>,
    prep: PrepStage<SC>,
}

/// Preprocessed-trace handling stage for one AIR inside the keygen builder.
enum PrepStage<SC: StarkProtocolConfig> {
    /// Per-air mode: the prep trace was committed individually at `add_air` time.
    Committed(PrepKeygenData<SC>),
    /// Merged mode: the raw prep trace is held until the joint multi-matrix commit in
    /// `generate_pk` (which takes `trace` and fills `vdata`); `dims` records the geometry at
    /// construction so it survives the take. In dims-only mode `trace` is never built — `dims`
    /// comes from [`PartitionedBaseAir::preprocessed_dims`] instead.
    Deferred {
        trace: Option<ColMajorMatrix<SC::F>>,
        dims: Option<Dimensions>,
        vdata: Option<VerifierSinglePreprocessedData<SC::Digest>>,
    },
}

impl<SC: StarkProtocolConfig> PrepStage<SC> {
    fn width(&self) -> Option<usize> {
        match self {
            PrepStage::Committed(d) => d.width(),
            PrepStage::Deferred { dims, .. } => dims.map(|d| d.width),
        }
    }
}

/// Stateful builder to create multi-stark proving and verifying keys
/// for system of multiple RAPs with multiple multi-matrix commitments
pub struct MultiStarkKeygenBuilder<SC: StarkProtocolConfig> {
    pub config: SC,
    /// Information for partitioned AIRs.
    partitioned_airs: Vec<AirKeygenBuilder<SC>>,
    /// When true, all AIRs' preprocessed traces are committed together in ONE
    /// multi-matrix stacked commitment during `generate_pk` (matrix order:
    /// `(Reverse(prep log_height), air_idx)`); requires every AIR to be required.
    merge_preprocessed: bool,
    /// When true, merged-mode AIRs declare their preprocessed geometry instead of generating the
    /// trace. Only sound when the commit is deferred — a merged *committing* keygen has nothing to
    /// commit without traces — which `generate_pk_inner` asserts.
    prep_dims_only: bool,
    /// AIR ids whose preprocessed commitment is an *application identity* (e.g. the RISC-V
    /// program table): excluded from the lean vk pre-hash preimage. See
    /// [`compute_vk_pre_hash`]. Only meaningful in per-air mode (merged mode excludes every
    /// preprocessed commitment value structurally).
    app_preprocessed_air_ids: Vec<usize>,
}

impl<SC: StarkProtocolConfig> MultiStarkKeygenBuilder<SC> {
    /// Panics with the [`ParamsError`](crate::config::ParamsError) that
    /// [`check_field_admissible`] returns for the config's params over `SC::F`, before any trace is
    /// committed.
    pub fn new(config: SC) -> Self {
        Self::with_mode(config, false, false)
    }

    /// See [MultiStarkVerifyingKey0::merged_preprocessed_commit]
    /// (crate::mle::keygen::types) for the merged-preprocessed mode contract.
    pub fn new_with_merged_preprocessed(config: SC) -> Self {
        Self::with_mode(config, true, false)
    }

    /// Merged-preprocessed mode that **declares** each AIR's preprocessed geometry rather than
    /// generating its trace, via [`PartitionedBaseAir::preprocessed_dims`]. Only valid with
    /// [`Self::generate_pk_deferred_merged_commit`] — the mode where geometry is the traces' only
    /// surviving output. An AIR that does not declare still generates, so a partially converted
    /// AIR set stays correct.
    pub fn new_with_merged_preprocessed_dims_only(config: SC) -> Self {
        Self::with_mode(config, true, true)
    }

    fn with_mode(config: SC, merge_preprocessed: bool, prep_dims_only: bool) -> Self {
        // The presets check their own field; a hand-built `SystemParams` meets one only here.
        check_field_admissible::<SC::F>(config.params()).unwrap_or_else(|err| panic!("{err}"));
        Self {
            config,
            partitioned_airs: vec![],
            merge_preprocessed,
            prep_dims_only,
            app_preprocessed_air_ids: vec![],
        }
    }

    /// Mark `air_id`'s preprocessed commitment as application identity (excluded from the lean
    /// vk pre-hash preimage; see [`compute_vk_pre_hash`]). The same id list must be supplied to
    /// any later pre-hash recomputation over this vk's `inner` (e.g. `verify_riscv`).
    pub fn mark_app_preprocessed(&mut self, air_id: usize) {
        if !self.app_preprocessed_air_ids.contains(&air_id) {
            self.app_preprocessed_air_ids.push(air_id);
        }
    }

    pub fn params(&self) -> &SystemParams {
        self.config.params()
    }

    /// Default way to add a single Interactive AIR.
    /// Returns `air_id`
    pub fn add_air(&mut self, air: AirRef<SC>) -> usize {
        self.add_air_impl(air, false)
    }

    pub fn add_required_air(&mut self, air: AirRef<SC>) -> usize {
        self.add_air_impl(air, true)
    }

    #[instrument(level = "debug", skip_all, fields(name = air.name(), is_required = is_required))]
    fn add_air_impl(&mut self, air: AirRef<SC>, is_required: bool) -> usize {
        self.partitioned_airs.push(AirKeygenBuilder::new(
            &self.config,
            air,
            is_required,
            self.merge_preprocessed,
            self.prep_dims_only,
        ));
        self.partitioned_airs.len() - 1
    }

    /// Merged-preprocessed mode: take all deferred prep traces, commit them in ONE
    /// multi-matrix stacked commitment (matrix order `(Reverse(log_height), air_idx)`,
    /// mirroring the verifier's height-descending trace ordering), and fill each AIR's
    /// `vdata` with the shared commitment + its own metadata.
    fn commit_merged_preprocessed(&mut self) -> Option<Arc<StackedPcsData<SC::F, SC::Digest>>> {
        let params = self.config.params().clone();
        let prep_dims = self.deferred_prep_dims();
        let prep_traces = self.take_sorted_prep_traces();
        if prep_traces.is_empty() {
            return None;
        }

        let trace_refs: Vec<&ColMajorMatrix<SC::F>> = prep_traces.iter().map(|(_, t)| t).collect();
        let (commit, data) = stacked_commit(
            self.config.hasher(),
            params.l_skip,
            params.n_stack,
            params.log_blowup,
            params.k_whir(),
            &trace_refs,
        )
        .unwrap();

        self.fill_merged_prep_vdata(&prep_dims, commit);
        Some(Arc::new(data))
    }

    /// Take every deferred prep trace, in the pinned commit order: descending height, ties by
    /// ascending air index. All heights are powers of two, so sorting by height equals sorting by
    /// log_height. Also asserts the merged-mode precondition.
    fn take_sorted_prep_traces(&mut self) -> Vec<(usize, ColMajorMatrix<SC::F>)> {
        self.assert_all_airs_required();
        let mut prep_traces: Vec<(usize, ColMajorMatrix<SC::F>)> = self
            .partitioned_airs
            .iter_mut()
            .enumerate()
            .filter_map(|(air_idx, b)| match &mut b.prep {
                PrepStage::Deferred { trace, .. } => trace.take().map(|t| (air_idx, t)),
                PrepStage::Committed(_) => None,
            })
            .collect();
        prep_traces.sort_by_key(|(air_idx, t)| (Reverse(t.height()), *air_idx));
        prep_traces
    }

    /// Every deferred AIR's recorded geometry, keyed by air index (declared or measured at
    /// `add_air` time). Unordered: [`Self::fill_merged_prep_vdata`] writes per air index, and the
    /// commit order is pinned by [`Self::take_sorted_prep_traces`] / the device assembler alone.
    fn deferred_prep_dims(&self) -> Vec<(usize, Dimensions)> {
        self.assert_all_airs_required();
        self.partitioned_airs
            .iter()
            .enumerate()
            .filter_map(|(air_idx, b)| match &b.prep {
                PrepStage::Deferred { dims, .. } => dims.map(|d| (air_idx, d)),
                PrepStage::Committed(_) => None,
            })
            .collect()
    }

    fn assert_all_airs_required(&self) {
        assert!(
            self.partitioned_airs.iter().all(|b| b.is_required),
            "merged-preprocessed mode requires all AIRs to be registered as required"
        );
    }

    /// Fill each AIR's `vdata` from its prep trace geometry plus the shared commitment. The
    /// geometry is a pure function of the traces, so this is identical whether `commit` is the
    /// real digest or a deferred placeholder to be patched later — and whether the geometry was
    /// measured off a generated trace or declared by the AIR.
    fn fill_merged_prep_vdata(&mut self, prep_dims: &[(usize, Dimensions)], commit: SC::Digest) {
        let params = self.config.params().clone();
        for (air_idx, dims) in prep_dims {
            // `stacking_width` is informational in merged mode: the width the matrix would
            // occupy if stacked alone (no in-tree reader depends on it).
            let log_height = log2_strict_usize(dims.height);
            let solo_width = StackedLayout::new(
                params.l_skip,
                params.n_stack + params.l_skip,
                vec![(dims.width, log_height)],
            )
            .unwrap()
            .width();
            let vdata = VerifierSinglePreprocessedData {
                commit,
                hypercube_dim: log_height as isize - params.l_skip as isize,
                stacking_width: solo_width,
            };
            match &mut self.partitioned_airs[*air_idx].prep {
                PrepStage::Deferred { vdata: slot, .. } => *slot = Some(vdata),
                PrepStage::Committed(_) => unreachable!(),
            }
        }
    }

    /// Merged mode WITHOUT the host stacked commit: fill the per-AIR geometry against a
    /// placeholder digest, leaving the real one to an external committer (the GPU commits the
    /// same traces on-device anyway). The caller completes the key with
    /// [`MultiStarkProvingKey::patch_merged_preprocessed_commit`].
    ///
    /// Skips an RS-encode at `log_blowup` plus a full Poseidon2 Merkle tree over the stacked
    /// preprocessed matrix. Returns whether any AIR had a preprocessed trace — i.e. whether the
    /// key is in merged mode at all.
    ///
    /// The geometry a committer must reproduce is not returned separately: it is already in each
    /// AIR's `vdata` (`hypercube_dim`) and `params.width.preprocessed`, which is what the device
    /// assembler checks against.
    fn defer_merged_preprocessed(&mut self) -> bool {
        let prep_dims = self.deferred_prep_dims();
        // Any generated traces are dropped unread — deferred mode's commit happens on the device.
        for b in &mut self.partitioned_airs {
            if let PrepStage::Deferred { trace, .. } = &mut b.prep {
                *trace = None;
            }
        }
        if prep_dims.is_empty() {
            return false;
        }
        self.fill_merged_prep_vdata(&prep_dims, SC::Digest::default());
        true
    }

    /// Consume the builder and generate proving key.
    /// The verifying key can be obtained from the proving key.
    pub fn generate_pk(self) -> Result<MultiStarkProvingKey<SC>, KeygenError> {
        self.generate_pk_inner(false)
    }

    /// Merged-mode keygen that skips the host stacked commit; see
    /// [`Self::defer_merged_preprocessed`]. The returned key is complete EXCEPT for the
    /// commitment value, which is `SC::Digest::default()` until
    /// [`MultiStarkProvingKey::patch_merged_preprocessed_commit`] installs the real one. Its
    /// `vk_pre_hash` is already final, so `get_vk()` is valid only after the patch.
    pub fn generate_pk_deferred_merged_commit(
        self,
    ) -> Result<MultiStarkProvingKey<SC>, KeygenError> {
        assert!(
            self.merge_preprocessed,
            "deferred merged commit requires merged-preprocessed mode"
        );
        self.generate_pk_inner(true)
    }

    fn generate_pk_inner(
        mut self,
        defer_merged_commit: bool,
    ) -> Result<MultiStarkProvingKey<SC>, KeygenError> {
        // Stage-0 attribution. The engine's `generate_pk_ms` bundles four unrelated costs, and its
        // "(DAG+checks)" label is wrong: the joint stacked commit runs in here too. Split them so
        // the convert-keygen budget can be attributed. `other_ms` closes the partition.
        //
        // A dims-only builder has no traces, so a merged *committing* keygen would commit nothing
        // and emit a key whose merged commitment disagrees with its vk — refuse at keygen instead.
        assert!(
            !self.prep_dims_only || defer_merged_commit,
            "dims-only merged preprocessed requires the deferred-commit path — there are no host \
             traces to commit"
        );
        let t_total = std::time::Instant::now();
        let params = self.params().clone();
        let app_prep_air_ids = std::mem::take(&mut self.app_preprocessed_air_ids);
        let max_constraint_degree = params.max_constraint_degree;
        let t_commit = std::time::Instant::now();
        let (merged_preprocessed_data, merged_preprocessed_commit) =
            match (self.merge_preprocessed, defer_merged_commit) {
                (true, false) => {
                    let data = self.commit_merged_preprocessed();
                    let commit = data.as_ref().map(|d| d.commit().unwrap());
                    (data, commit)
                }
                // Placeholder value, but `Some` — merged mode is carried by this being `Some`,
                // and the pre-hash preimage excludes the value, so the digest below is final.
                (true, true) => (
                    None,
                    self.defer_merged_preprocessed().then(SC::Digest::default),
                ),
                (false, _) => (None, None),
            };
        let commit_ms = t_commit.elapsed().as_millis();
        let t_symbolic = std::time::Instant::now();
        let pk_per_air: Vec<_> = self
            .partitioned_airs
            .into_iter()
            .map(|keygen_builder| {
                // Second pass: get final constraints, where RAP phase constraints may have changed
                keygen_builder.generate_pk(max_constraint_degree)
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;
        let symbolic_ms = t_symbolic.elapsed().as_millis();
        #[cfg(debug_assertions)]
        {
            // The derived per-air matrix indices must match the commit's layout order.
            if let Some(data) = &merged_preprocessed_data {
                let mat_indices = crate::keygen::types::merged_preprocessed_mat_indices(
                    pk_per_air
                        .iter()
                        .map(|pk| pk.vk.preprocessed_data.as_ref().map(|pd| pd.hypercube_dim)),
                );
                let num_mats = mat_indices.iter().flatten().count();
                debug_assert_eq!(num_mats, data.layout.mat_starts.len());
            }
        }

        let mut air_max_constraint_degree = 0;
        for pk in pk_per_air.iter() {
            let width = &pk.vk.params.width;
            tracing::info!("{:<20} | Constraint Deg = {:<2} | Prep Cols = {:<2} | Main Cols = {:<8} | {:4} Constraints | {:3} Interactions | Rot = {}",
                pk.air_name,
                pk.vk.max_constraint_degree,
                width.preprocessed.unwrap_or(0),
                format!("{:?}",width.main_widths()),
                pk.vk.symbolic_constraints.constraints.constraint_idx.len(),
                pk.vk.symbolic_constraints.interactions.len(),
                u8::from(pk.vk.params.need_rot),
            );
            air_max_constraint_degree = max(air_max_constraint_degree, pk.vk.max_constraint_degree);
            tracing::debug!(
                "On Buses {:?}",
                pk.vk
                    .symbolic_constraints
                    .interactions
                    .iter()
                    .map(|i| i.kind)
                    .collect_vec()
            );
            #[cfg(feature = "metrics")]
            {
                let labels = [("air_name", pk.air_name.clone())];
                metrics::counter!("constraint_deg", &labels)
                    .absolute(pk.vk.max_constraint_degree as u64);
                // column info will be logged by prover later
                metrics::counter!("constraints", &labels)
                    .absolute(pk.vk.symbolic_constraints.constraints.constraint_idx.len() as u64);
                metrics::counter!("interactions", &labels)
                    .absolute(pk.vk.symbolic_constraints.interactions.len() as u64);
            }
        }
        if max_constraint_degree != air_max_constraint_degree as usize {
            tracing::info!(
            "Actual max constraint degree across all AIRs ({air_max_constraint_degree}) does not match configured max constraint degree ({max_constraint_degree})",
        );
        }

        let t_thc = std::time::Instant::now();
        let num_airs = pk_per_air.len();
        let base_order = SC::F::order().to_u32_digits()[0];
        let mut count_weight_per_air_per_bus = HashMap::new();

        let mut num_interactions_per_air: Vec<u32> = Vec::with_capacity(num_airs);
        // We compute the a_i's for the constraints of the form a_0 n_0 + ... + a_{k-1} n_{k-1} <
        // a_k, First the constraints that the total number of interactions on each bus is
        // at most the base field order.
        for (air_idx, pk) in pk_per_air.iter().enumerate() {
            let constraints = &pk.vk.symbolic_constraints;
            num_interactions_per_air.push(constraints.interactions.len().try_into().unwrap());
            for interaction in &constraints.interactions {
                // Also make sure that this of interaction is valid given the security params.
                // +1 because of the bus
                let max_msg_len = params.logup.max_message_length();
                // plus one because of the bus
                let total_message_length = interaction.message.len() + 1;
                assert!(
                    total_message_length <= max_msg_len,
                    "interaction message with bus has length {}, which is more than max {max_msg_len}",
                    total_message_length,
                );

                let b = interaction.kind;
                let constraint =
                    count_weight_per_air_per_bus
                        .entry(b)
                        .or_insert_with(|| LinearConstraint {
                            coefficients: vec![0; num_airs],
                            threshold: base_order,
                        });
                constraint.coefficients[air_idx] += interaction.count_weight;
            }
        }

        let log_up_security_params = params.logup;

        // Collect all constraints: per-bus sorted by the LookupType discriminant
        // (explicitly via `as u16`, NOT the derived declaration-order `Ord`, so the
        // vk constraint order stays pinned to the wire-level bus values), then global.
        let mut all_constraints: Vec<LinearConstraint> = count_weight_per_air_per_bus
            .into_iter()
            .sorted_by_key(|(kind, _)| *kind as u16)
            .map(|(_, constraint)| constraint)
            .collect_vec();

        all_constraints.push(LinearConstraint {
            coefficients: num_interactions_per_air,
            threshold: log_up_security_params.max_interaction_count,
        });

        // Minimize: keep only constraints not implied by any other.
        let mut trace_height_constraints: Vec<LinearConstraint> = Vec::new();
        for constraint in all_constraints {
            if trace_height_constraints
                .iter()
                .any(|c| constraint.is_implied_by(c))
            {
                continue;
            }
            trace_height_constraints.retain(|c| !c.is_implied_by(&constraint));
            trace_height_constraints.push(constraint);
        }

        let thc_ms = t_thc.elapsed().as_millis();

        // `prehash_ms` deliberately spans the `pre_vk` construction as well as the hash: that
        // construction deep-clones every AIR's constraint DAG purely to hand
        // `compute_vk_pre_hash` something it only ever borrows from, so the clone is part of the
        // cost being attributed here. It is not the part worth attacking: measured on reth-188
        // convert keygen the clone is 0.04 ms/chunk against the hash's 4.74, so a borrowing
        // variant would buy ~1% of this stage.
        let t_prehash = std::time::Instant::now();
        let pre_vk: MultiStarkVerifyingKeyInner<SC> = MultiStarkVerifyingKeyInner {
            params: params.clone(),
            per_air: pk_per_air.iter().map(|pk| pk.vk.clone()).collect(),
            trace_height_constraints: trace_height_constraints.clone(),
            merged_preprocessed_commit,
        };
        // To protect against weak Fiat-Shamir, we hash the "pre"-verifying key (lean preimage:
        // machine + shape, identity commitments excluded — see `compute_vk_pre_hash`) and include
        // it in the final verifying key. A consumer that needs to bind an *untrusted* vk to a
        // trusted reference must recompute it from `inner` via [`compute_vk_pre_hash`] with the
        // SAME app-marked air ids (the SSOT used here), never trust the bundle's `pre_hash`
        // field — and must pin the excluded identity commitments separately.
        let vk_pre_hash = compute_vk_pre_hash(&self.config, &pre_vk, &app_prep_air_ids);
        let prehash_ms = t_prehash.elapsed().as_millis();

        tracing::info!(
            "mle_keygen_stages: commit_ms = {commit_ms}, symbolic_ms = {symbolic_ms}, \
             thc_ms = {thc_ms}, prehash_ms = {prehash_ms}, other_ms = {}",
            t_total
                .elapsed()
                .as_millis()
                .saturating_sub(commit_ms + symbolic_ms + thc_ms + prehash_ms)
        );

        Ok(MultiStarkProvingKey {
            params,
            per_air: pk_per_air,
            trace_height_constraints,
            max_constraint_degree,
            vk_pre_hash,
            merged_preprocessed_data,
            merged_preprocessed_commit,
            // Only a key that actually landed in merged mode has a placeholder to patch: with no
            // preprocessed traces at all, `defer_merged_commit` produced a plain per-air key.
            commit_deferred: defer_merged_commit && merged_preprocessed_commit.is_some(),
        })
    }
}

impl<SC: StarkProtocolConfig> AirKeygenBuilder<SC> {
    pub fn new(
        config: &SC,
        air: AirRef<SC>,
        is_required: bool,
        merge_preprocessed: bool,
        prep_dims_only: bool,
    ) -> Self {
        let prep = if merge_preprocessed {
            // Dims-only: the caller has committed to deferring, so geometry is all that survives.
            // `preprocessed_dims` itself generates the trace for any AIR that does not declare.
            let (trace, dims) = if prep_dims_only {
                (None, air.preprocessed_dims())
            } else {
                let trace = BaseAir::<SC::F>::preprocessed_trace(air.as_ref())
                    .map(|t| ColMajorMatrix::from_row_major(&t));
                let dims = trace.as_ref().map(|t| Dimensions {
                    width: MatrixDimensions::width(t),
                    height: MatrixDimensions::height(t),
                });
                (trace, dims)
            };
            PrepStage::Deferred {
                trace,
                dims,
                vdata: None,
            }
        } else {
            PrepStage::Committed(PrepKeygenData::new(
                config.hasher(),
                config.params(),
                air.as_ref(),
            ))
        };
        Self {
            is_required,
            air,
            prep,
        }
    }

    /// `max_constraint_degree` is the global max constraint degree. If this AIR's constraint degree
    /// exceeds it, an error will be returned.
    pub fn generate_pk(
        self,
        max_constraint_degree: usize,
    ) -> Result<StarkProvingKey<SC>, KeygenError> {
        let air_name = self.air.name();

        let symbolic_builder = self.get_symbolic_builder();
        let width = symbolic_builder.width();
        let num_public_values = symbolic_builder.num_public_values();

        let symbolic_constraints = symbolic_builder.constraints();
        let constraint_degree = symbolic_constraints.max_constraint_degree();
        if constraint_degree > max_constraint_degree {
            return Err(KeygenError::MaxConstraintDegreeExceeded {
                name: air_name.clone(),
                degree: constraint_degree,
                max_degree: max_constraint_degree,
            });
        }

        let (preprocessed_vdata, prep_prover_data) = match self.prep {
            PrepStage::Committed(PrepKeygenData {
                verifier_data,
                prover_data,
            }) => (verifier_data, prover_data),
            // Merged mode: vdata was filled by the joint commit; the prover-side data
            // lives in `MultiStarkProvingKey::merged_preprocessed_data` (per-air is None).
            PrepStage::Deferred { vdata, .. } => (vdata, None),
        };

        let dag = SymbolicConstraintsDag::from(symbolic_constraints);
        let max_rotation = dag.constraints.max_rotation();
        // `need_rot` distinguishes only rotation 0 from 1; a rotation of 2+ would be silently
        // misclassified as "no rotation" and key a wrong VK, so reject it in every build.
        assert!(
            max_rotation <= 1,
            "AIR {air_name} uses unsupported row rotation {max_rotation}; maximum supported is 1"
        );
        let need_rot = max_rotation == 1;
        let vparams = StarkVerifyingParams {
            width,
            num_public_values,
            need_rot,
        };

        let unused_variables = find_unused_vars(&dag, &vparams.width, need_rot);
        let vk = StarkVerifyingKey {
            preprocessed_data: preprocessed_vdata,
            params: vparams,
            symbolic_constraints: dag,
            max_constraint_degree: constraint_degree
                .try_into()
                .expect("constraint degree should fit in u8"),
            is_required: self.is_required,
            unused_variables,
        };
        Ok(StarkProvingKey {
            air_name,
            vk,
            preprocessed_data: prep_prover_data,
        })
    }

    pub fn get_symbolic_builder(&self) -> SymbolicRapBuilder<SC::F> {
        let width = TraceWidth {
            preprocessed: self.prep.width(),
            cached_mains: self.air.cached_main_widths(),
            common_main: self.air.common_main_width(),
        };
        get_symbolic_builder(self.air.as_ref(), &width)
    }
}

pub(super) struct PrepKeygenData<SC: StarkProtocolConfig> {
    pub verifier_data: Option<VerifierSinglePreprocessedData<SC::Digest>>,
    pub prover_data: Option<Arc<StackedPcsData<SC::F, SC::Digest>>>,
}

impl<SC: StarkProtocolConfig> PrepKeygenData<SC> {
    fn new(hasher: &SC::Hasher, params: &SystemParams, air: &dyn AnyAir<SC>) -> Self {
        let preprocessed_trace = BaseAir::<SC::F>::preprocessed_trace(air);
        let vpdata_opt = preprocessed_trace.map(|trace| {
            let trace = ColMajorMatrix::from_row_major(&trace);
            let (commit, data) = stacked_commit(
                hasher,
                params.l_skip,
                params.n_stack,
                params.log_blowup,
                params.k_whir(),
                &[&trace],
            )
            .unwrap();
            debug_assert_eq!(trace.width(), data.mat_view(0).width());
            let vdata = VerifierSinglePreprocessedData {
                commit,
                hypercube_dim: log2_strict_usize(trace.height()) as isize - params.l_skip as isize,
                stacking_width: data.matrix.width(),
            };
            let pdata = Arc::new(data);
            (vdata, pdata)
        });
        if let Some((vdata, pdata)) = vpdata_opt {
            Self {
                prover_data: Some(pdata),
                verifier_data: Some(vdata),
            }
        } else {
            Self {
                prover_data: None,
                verifier_data: None,
            }
        }
    }

    fn width(&self) -> Option<usize> {
        self.prover_data.as_ref().map(|d| d.mat_view(0).width())
    }
}

pub(crate) fn find_unused_vars<F: Field>(
    constraints: &SymbolicConstraintsDag<F>,
    width: &TraceWidth,
    need_rot: bool,
) -> Vec<SymbolicVariable<F>> {
    let preprocessed_width = width.preprocessed.unwrap_or(0);
    let mut preprocessed_present = vec![vec![false; 2]; preprocessed_width];

    let mut main_present = vec![];
    for width in width.main_widths() {
        main_present.push(vec![vec![false; 2]; width]);
    }

    for node in &constraints.constraints.nodes {
        let SymbolicExpressionNode::Variable(var) = node else {
            continue;
        };

        match var.entry {
            Entry::Preprocessed { offset } => {
                preprocessed_present[var.index][offset] = true;
            }
            Entry::Main { part_index, offset } => {
                main_present[part_index][var.index][offset] = true;
            }
            Entry::Public => {}
        }
    }

    let mut missing = vec![];
    for (index, presents) in preprocessed_present.iter().enumerate() {
        for (offset, present) in presents.iter().enumerate() {
            if !present && (offset == 0 || need_rot) {
                missing.push(SymbolicVariable::new(Entry::Preprocessed { offset }, index));
            }
        }
    }
    for (part_index, present_per_part) in main_present.iter().enumerate() {
        for (index, presents) in present_per_part.iter().enumerate() {
            for (offset, present) in presents.iter().enumerate() {
                if !present && (offset == 0 || need_rot) {
                    missing.push(SymbolicVariable::new(
                        Entry::Main { part_index, offset },
                        index,
                    ));
                }
            }
        }
    }
    missing
}

/// Domain separator for the *lean* vk pre-hash preimage. Distinct from every plain
/// `CODEC_VERSION`-prefixed postcard encoding, so a lean digest can never collide with a
/// digest of the pre-lean full-`inner` encoding.
pub const LEAN_VK_PRE_HASH_DOMAIN: u32 = u32::from_le_bytes(*b"LNvk");

/// Machine-and-shape view of one AIR's preprocessed metadata: geometry is kept, and the
/// commitment **value** is kept only for machine-fixed tables (see [`compute_vk_pre_hash`]).
/// A digest as it enters a hashed preimage: canonical field values when the config's digest is
/// made of its own field elements, otherwise the digest's own serde. See
/// [`StarkProtocolConfig::digest_as_base`].
struct PreimageDigest<'a, SC: StarkProtocolConfig>(&'a SC::Digest);

impl<SC: StarkProtocolConfig> serde::Serialize for PreimageDigest<'_, SC> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match SC::digest_as_base(self.0) {
            Some(base) => CanonicalDigest(base).serialize(s),
            None => self.0.serialize(s),
        }
    }
}

#[derive(serde::Serialize)]
#[serde(bound = "")]
struct LeanPrepData<'a, SC: StarkProtocolConfig> {
    hypercube_dim: isize,
    stacking_width: usize,
    /// Canonical values (see `canonical_serde`), byte-identical to the plain digest serde the
    /// preimage used before Plonky3 switched field serde to Montgomery form.
    commit: Option<PreimageDigest<'a, SC>>,
}

#[derive(serde::Serialize)]
#[serde(bound = "")]
struct LeanAirVk<'a, SC: StarkProtocolConfig> {
    preprocessed_data: Option<LeanPrepData<'a, SC>>,
    params: &'a StarkVerifyingParams,
    symbolic_constraints: &'a SymbolicConstraintsDag<SC::F>,
    max_constraint_degree: u8,
    is_required: bool,
    unused_variables: &'a [SymbolicVariable<SC::F>],
}

/// The lean pre-hash preimage: everything in [`MultiStarkVerifyingKeyInner`] **except identity
/// commitment values** (see [`compute_vk_pre_hash`] for the exclusion rule and its soundness
/// argument). Per-air field order mirrors the inner struct; `merged_mode` leads.
///
/// `merged_mode` (the presence bit of `merged_preprocessed_commit`, sans its value) keeps the
/// preimage injective across keygen modes: a merged-mode vk and a per-air vk with every AIR
/// app-marked would otherwise serialize identically (all commits `None`) despite driving
/// different verifier flows.
#[derive(serde::Serialize)]
#[serde(bound = "")]
struct LeanVkPreimage<'a, SC: StarkProtocolConfig> {
    merged_mode: bool,
    params: &'a SystemParams,
    per_air: Vec<LeanAirVk<'a, SC>>,
    trace_height_constraints: &'a [LinearConstraint],
}

/// Compute the vk pre-hash over the **lean** preimage: machine + shape data only.
///
/// Exclusion rule (identity commitments are NOT part of the preimage):
/// - in merged-preprocessed mode, the top-level `merged_preprocessed_commit` and every per-air
///   copy of it (each `preprocessed_data.commit` duplicates the merged digest) — the merged
///   commitment is the recursion *program's* identity;
/// - in per-air mode, the `preprocessed_data.commit` of every AIR listed in
///   `app_prep_air_indices` (e.g. the RISC-V program table) — an *application's* identity.
///
/// Geometry (`hypercube_dim`, `stacking_width`) is always kept; machine-fixed table commitments
/// (e.g. the byte lookup table) are always kept.
///
/// Soundness: the pre-hash seeds the Fiat-Shamir transcript to protect against weak
/// Fiat-Shamir. Every excluded commitment has its own independent transcript observation
/// (per-air observes in per-air mode; the explicit merged-commit observe in merged mode), so
/// its FS binding never depended on the pre-hash. Data with **no** independent observation
/// (constraint DAGs, params, widths, trace-height constraints) stays in the preimage. Identity
/// binding of the excluded commitments is the caller's contract: they are consumed as Merkle
/// opening roots in-circuit and pinned against trusted values by the apex / [`verify_riscv`].
///
/// This is the single source of truth for the value keygen stores in
/// [`MultiStarkProvingKey::vk_pre_hash`]. A consumer that must bind an *untrusted* vk to a
/// trusted reference (e.g. `verify_riscv` on a deserialized bundle) has to recompute this from
/// `inner` (with the same app-marked air ids); comparing the bundle's self-reported `pre_hash`
/// field is not enough, since that field is attacker-settable and nothing else on the verify
/// path re-derives it. The KoalaBear hasher is param-independent, so the recomputation is
/// canonical even when `inner.params` is untrusted.
pub fn compute_vk_pre_hash<SC: StarkProtocolConfig>(
    config: &SC,
    inner: &MultiStarkVerifyingKeyInner<SC>,
    app_prep_air_indices: &[usize],
) -> SC::Digest {
    let merged = inner.merged_preprocessed_commit.is_some();
    let preimage = LeanVkPreimage::<SC> {
        merged_mode: merged,
        params: &inner.params,
        per_air: inner
            .per_air
            .iter()
            .enumerate()
            .map(|(air_idx, avk)| LeanAirVk::<SC> {
                preprocessed_data: avk.preprocessed_data.as_ref().map(|p| LeanPrepData::<SC> {
                    hypercube_dim: p.hypercube_dim,
                    stacking_width: p.stacking_width,
                    commit: (!merged && !app_prep_air_indices.contains(&air_idx))
                        .then_some(PreimageDigest::<SC>(&p.commit)),
                }),
                params: &avk.params,
                symbolic_constraints: &avk.symbolic_constraints,
                max_constraint_degree: avk.max_constraint_degree,
                is_required: avk.is_required,
                unused_variables: &avk.unused_variables,
            })
            .collect(),
        trace_height_constraints: &inner.trace_height_constraints,
    };
    // Postcard is not self-describing, so we domain-separate with the lean-domain tag, the codec
    // version, and the byte length.
    let vk_bytes = postcard::to_allocvec(&preimage).unwrap();
    tracing::debug!("lean pre-vkey: {} bytes", vk_bytes.len());
    let versioned_vk_bytes = LEAN_VK_PRE_HASH_DOMAIN
        .to_le_bytes()
        .into_iter()
        .chain(CODEC_VERSION.to_le_bytes())
        .chain((vk_bytes.len() as u64).to_le_bytes())
        .chain(vk_bytes);
    // The preimage is absorbed one field element PER BYTE, so the permutation count — not the
    // widening below, and not the postcard encoding — is essentially all of this function's cost
    // (measured 96% of it on a 53 670-byte convert preimage). Packing several bytes per element
    // would cut it, but it changes the digest: a VK/wire-format change, not an optimization.
    config.hasher().hash_slice(
        &versioned_vk_bytes
            .into_iter()
            .map(SC::F::from_u8)
            .collect_vec(),
    )
}

/// Domain separator for the **params-free constraint digest**. Distinct from
/// [`LEAN_VK_PRE_HASH_DOMAIN`] and from every plain `CODEC_VERSION`-prefixed postcard encoding, so
/// a constraint digest can never collide with a vk pre-hash.
pub const CONSTRAINT_DIGEST_DOMAIN: u32 = u32::from_le_bytes(*b"CSdg");

/// One AIR's constraint-digest preimage: the constraint surface and the verifier-visible shape,
/// and deliberately **nothing that depends on the operating point**.
///
/// Contrast [`LeanAirVk`], whose preimage leads with `params: &StarkVerifyingParams` *and* whose
/// enclosing [`LeanVkPreimage`] carries `&SystemParams`. `SystemParams` holds `n_stack`, a
/// function of `CHUNK_SIZE`, and `preprocessed_data.hypercube_dim` is `log_height - l_skip` — so
/// two builds at different chunk sizes get different pre-hashes even with byte-identical
/// constraints. That is exactly why the constraint comparator cannot be `compute_vk_pre_hash`.
#[derive(serde::Serialize)]
#[serde(bound = "")]
struct AirConstraintPreimage<'a, SC: StarkProtocolConfig> {
    /// The DAG is `{ constraints, interactions }`, so this covers plain AIR constraints and
    /// lookup/interaction expressions alike — a new bus cannot slip through.
    symbolic_constraints: &'a SymbolicConstraintsDag<SC::F>,
    /// Column layout: a slimming that drops a column shows up here.
    width: &'a TraceWidth,
    num_public_values: usize,
    need_rot: bool,
    max_constraint_degree: u8,
    is_required: bool,
    /// Catches a column that stopped being read.
    unused_variables: &'a [SymbolicVariable<SC::F>],
}

/// Preimage of the overall digest: the per-AIR digests keyed by air name, **sorted by name**, plus
/// the machine-level trace-height constraints.
///
/// Sorting by name makes the overall digest independent of air *ordering*, so inserting an AIR
/// does not spuriously perturb it — only the set and the per-AIR content matter.
#[derive(serde::Serialize)]
#[serde(bound = "")]
struct ConstraintDumpPreimage<'a, SC: StarkProtocolConfig> {
    per_air: Vec<(&'a str, PreimageDigest<'a, SC>)>,
    trace_height_constraints: &'a [LinearConstraint],
}

/// A machine's constraint surface, reduced to one digest per AIR plus one overall digest.
///
/// The per-AIR digests localise a mismatch without a second tool: diff two dumps and the differing
/// air names are already in the diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintDump<D> {
    /// `(air name, digest)`, sorted by name.
    pub per_air: Vec<(String, D)>,
    pub overall: D,
}

/// Hash `bytes` with the domain tag, codec version and a length prefix, mirroring
/// [`compute_vk_pre_hash`]'s framing (postcard is not self-describing, so shapes must be
/// disambiguated explicitly).
fn hash_constraint_preimage<SC: StarkProtocolConfig>(config: &SC, bytes: Vec<u8>) -> SC::Digest {
    let framed = CONSTRAINT_DIGEST_DOMAIN
        .to_le_bytes()
        .into_iter()
        .chain(CODEC_VERSION.to_le_bytes())
        .chain((bytes.len() as u64).to_le_bytes())
        .chain(bytes);
    config
        .hasher()
        .hash_slice(&framed.into_iter().map(SC::F::from_u8).collect_vec())
}

/// Digest of one AIR's constraint surface + verifier-visible shape. Params-free: see
/// [`AirConstraintPreimage`].
///
/// The air *name* is deliberately **not** in this preimage — it is the key in
/// [`ConstraintDump::per_air`]. That way a pure rename shows up as a changed name against an
/// unchanged digest, which is strictly more informative than a digest change.
pub fn air_constraint_digest<SC: StarkProtocolConfig>(
    config: &SC,
    avk: &StarkVerifyingKey<SC::F, SC::Digest>,
) -> SC::Digest {
    let preimage = AirConstraintPreimage::<SC> {
        symbolic_constraints: &avk.symbolic_constraints,
        width: &avk.params.width,
        num_public_values: avk.params.num_public_values,
        need_rot: avk.params.need_rot,
        max_constraint_degree: avk.max_constraint_degree,
        is_required: avk.is_required,
        unused_variables: &avk.unused_variables,
    };
    hash_constraint_preimage(config, postcard::to_allocvec(&preimage).unwrap())
}

/// Compute the params-free constraint dump for a whole machine.
///
/// This is the **constraint** comparator: equal dumps mean constraints, interactions, column
/// widths, public-value counts and degrees all match, independent of `CHUNK_SIZE` /
/// `log_stacked_height`. `compute_vk_pre_hash` keeps its separate role as a keygen-stability
/// check within one build and must not be repurposed for this.
///
/// Because the constraint DAG is already stored in the vk (`symbolic_constraints`), no separate
/// export path and no proving is needed — keygen alone is enough. Optional AIRs (the compute
/// precompiles) have a vk entry whether or not a chunk uses them, so the dump covers the machine's
/// whole constraint surface and is workload-independent: fib and reth produce the same digest.
///
/// `air_names` must be parallel to `inner.per_air` (air names are not stored in the vk; take them
/// from the `AirRef` list that keygen consumed, via `BaseAir::name`).
///
/// # Panics
/// If `air_names.len() != inner.per_air.len()`.
pub fn compute_constraint_dump<SC: StarkProtocolConfig>(
    config: &SC,
    inner: &MultiStarkVerifyingKeyInner<SC>,
    air_names: &[String],
) -> ConstraintDump<SC::Digest> {
    assert_eq!(
        air_names.len(),
        inner.per_air.len(),
        "air_names must be parallel to vk.per_air"
    );

    let mut per_air = air_names
        .iter()
        .zip(inner.per_air.iter())
        .map(|(name, avk)| (name.clone(), air_constraint_digest(config, avk)))
        .collect_vec();
    // Sort by name so the overall digest does not depend on air ordering. Names are unique in the
    // machines this is used on; a duplicate would still be deterministic (ties keep input order,
    // `sort_by` being stable) and both entries appear in the rendered dump.
    per_air.sort_by(|a, b| a.0.cmp(&b.0));

    let preimage = ConstraintDumpPreimage::<SC> {
        per_air: per_air
            .iter()
            .map(|(n, d)| (n.as_str(), PreimageDigest::<SC>(d)))
            .collect(),
        trace_height_constraints: &inner.trace_height_constraints,
    };
    let overall = hash_constraint_preimage(config, postcard::to_allocvec(&preimage).unwrap());

    ConstraintDump { per_air, overall }
}

impl<F: p3_field::PrimeField64, const N: usize> ConstraintDump<[F; N]> {
    /// Render as a diffable text artifact: one `name<TAB>digest` line per AIR, sorted, then the
    /// overall digest. Digests are hex-encoded postcard bytes of their canonical values (see
    /// `canonical_serde`), so the format depends neither on `Debug` formatting nor on the field
    /// type's own serde.
    ///
    /// This is the exchange format between builds or revisions: dump on each, diff the files.
    pub fn render(&self) -> String {
        let hex = |d: &[F; N]| {
            postcard::to_allocvec(&CanonicalDigest(d.as_slice()))
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        // Air names are NOT unique — the RISC-V machine registers `MemoryInitializeFinalizeChip`
        // twice, `SyscallChip` twice and `PrepAir` three times. Left bare, those lines are
        // ambiguous (you cannot tell which entry moved) and a name-keyed join across two dumps
        // cross-products them. Suffix every member of a repeated name with `#1`, `#2`, … in the
        // already name-sorted order, so each line is unique and stable.
        //
        // Only the rendering is disambiguated: the overall digest is taken over the
        // `(name, digest)` pairs, where duplicates are already distinct entries, so this does not
        // change any digest.
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for (name, _) in &self.per_air {
            *counts.entry(name.as_str()).or_default() += 1;
        }
        let mut seen: HashMap<&str, usize> = HashMap::new();

        let mut out = String::new();
        out.push_str("# params-free RISC-V constraint dump\n");
        out.push_str("# <air name>\\t<per-air digest>; repeated names are suffixed #1, #2, …\n");
        for (name, digest) in &self.per_air {
            let label = if counts[name.as_str()] > 1 {
                let n = seen.entry(name.as_str()).or_default();
                *n += 1;
                format!("{name}#{n}")
            } else {
                name.clone()
            };
            out.push_str(&format!("{label}\t{}\n", hex(digest)));
        }
        out.push_str(&format!("overall\t{}\n", hex(&self.overall)));
        out
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::{compute_constraint_dump, find_unused_vars};
    use crate::{
        air::symbolic::{
            symbolic_variable::{Entry, SymbolicVariable},
            SymbolicConstraintsDag, SymbolicExpressionDag, SymbolicExpressionNode,
        },
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        keygen::types::TraceWidth,
        test_utils::{
            test_system_params_small, FibFixture, InteractionsFixture11, TestFixture,
            TwoPreprocessedFixture,
        },
        StarkEngine, SystemParams,
    };

    type F = KoalaBear;

    fn dag(nodes: Vec<SymbolicExpressionNode<F>>) -> SymbolicConstraintsDag<F> {
        SymbolicConstraintsDag {
            constraints: SymbolicExpressionDag {
                nodes,
                constraint_idx: vec![],
            },
            interactions: vec![],
        }
    }

    fn var(entry: Entry, index: usize) -> SymbolicExpressionNode<F> {
        SymbolicExpressionNode::Variable(SymbolicVariable::new(entry, index))
    }

    /// `find_unused_vars` reports every trace cell (offset 0, plus offset 1 when `need_rot`) that no
    /// constraint node references. Non-`Variable` nodes (here a `Constant`) are skipped.
    #[test]
    fn find_unused_vars_reports_unreferenced_columns() {
        // One common-main part of width 2; only column 0 at offset 0 is referenced.
        let nodes = vec![
            var(
                Entry::Main {
                    part_index: 0,
                    offset: 0,
                },
                0,
            ),
            SymbolicExpressionNode::Constant(F::from_u32(7)),
        ];
        let width = TraceWidth {
            preprocessed: None,
            cached_mains: vec![],
            common_main: 2,
        };

        // need_rot = false ⇒ only offset-0 cells count; column 1 is the sole unused cell.
        let missing = find_unused_vars(&dag(nodes.clone()), &width, false);
        assert_eq!(missing.len(), 1);
        assert_eq!(
            missing[0].entry,
            Entry::Main {
                part_index: 0,
                offset: 0
            }
        );
        assert_eq!(missing[0].index, 1);

        // need_rot = true ⇒ offset-1 cells count too: col0@1, col1@0, col1@1 are all unused.
        let missing_rot = find_unused_vars(&dag(nodes), &width, true);
        assert_eq!(missing_rot.len(), 3);
        assert!(missing_rot
            .iter()
            .all(|v| matches!(v.entry, Entry::Main { part_index: 0, .. })));
    }

    /// `find_unused_vars` walks preprocessed columns and every main partition. `main_widths` puts
    /// cached parts first and the common main last, so the referenced common column is part 1 and
    /// the unreferenced cached column (part 0) is the one reported.
    #[test]
    fn find_unused_vars_covers_preprocessed_and_partitions() {
        let nodes = vec![
            var(Entry::Preprocessed { offset: 0 }, 0),
            var(
                Entry::Main {
                    part_index: 1,
                    offset: 0,
                },
                0,
            ), // common main (last part)
        ];
        let width = TraceWidth {
            preprocessed: Some(1),
            cached_mains: vec![1],
            common_main: 1,
        };
        let missing = find_unused_vars(&dag(nodes), &width, false);
        assert_eq!(missing.len(), 1);
        assert_eq!(
            missing[0].entry,
            Entry::Main {
                part_index: 0,
                offset: 0
            }
        );
        assert_eq!(missing[0].index, 0);
    }

    /// Keygen is deterministic — running it twice over the same air set yields the same
    /// `vk_pre_hash` (the Fiat-Shamir seed) and byte-identical proving/verifying keys. Keygen is
    /// purely symbolic (no RNG), so any drift would signal a nondeterminism bug.
    #[test]
    fn keygen_is_deterministic() {
        // Keygen commits preprocessed traces through the config's hasher, so it is
        // device-independent; any engine pins the same bytes.
        let engine: KoalaBearPoseidon2RefEngine =
            StarkEngine::new(test_system_params_small(2, 5, 3));
        let fixture = FibFixture::new(0, 1, 1 << 5);

        let (pk_a, vk_a) = fixture.keygen(&engine);
        let (pk_b, vk_b) = fixture.keygen(&engine);

        assert_eq!(vk_a.pre_hash, vk_b.pre_hash, "vk_pre_hash must be stable");
        assert_eq!(
            bincode::serialize(&pk_a).unwrap(),
            bincode::serialize(&pk_b).unwrap(),
            "proving key must be byte-identical across keygen runs"
        );
        assert_eq!(
            bincode::serialize(&vk_a).unwrap(),
            bincode::serialize(&vk_b).unwrap(),
            "verifying key must be byte-identical across keygen runs"
        );
    }

    /// Deferring the merged commit to an external committer must be invisible in the key. Two
    /// separate claims, and the GPU recursion path needs both:
    ///
    /// 1. `vk_pre_hash` is final BEFORE the commitment is known — merged mode excludes commitment
    ///    values from the pre-hash preimage, which is what makes deferral possible at all.
    /// 2. Patching the real digest in reproduces the committing keygen's vk byte for byte.
    #[test]
    fn deferred_merged_commit_reproduces_the_committing_keygen() {
        let log_trace_height = 5;
        let params = SystemParams::new_for_testing(log_trace_height);
        // Mixed heights: the height-descending commit order differs from AIR-id order, so this
        // also covers the ordering the external committer has to reproduce.
        let sels_small = (0..(1 << (log_trace_height - 1)))
            .map(|index| index % 3 == 0)
            .collect_vec();
        let sels_big = (0..(1 << log_trace_height))
            .map(|index| index % 2 == 0)
            .collect_vec();
        let fixture = TwoPreprocessedFixture::new(sels_small, sels_big);
        let engine: KoalaBearPoseidon2RefEngine = StarkEngine::new(params);
        let airs = TestFixture::<_>::airs(&fixture);

        let (pk_ref, vk_ref) = engine.keygen_merged_preprocessed(&airs);
        let mut pk_def = engine.keygen_merged_preprocessed_deferred_commit(&airs);
        let real_commit = pk_ref
            .merged_preprocessed_commit
            .expect("reference keygen is in merged mode");

        assert_eq!(
            pk_def.vk_pre_hash, pk_ref.vk_pre_hash,
            "pre-hash must not depend on the commitment value"
        );
        assert_ne!(
            pk_def.merged_preprocessed_commit,
            Some(real_commit),
            "placeholder equals the real digest, so this test would pass vacuously"
        );
        // The geometry an external committer must reproduce travels in the vdata, so it has to
        // survive deferral: same per-AIR hypercube_dim, hence the same commit ordering.
        let prep_dims = |per_air: &[super::StarkProvingKey<_>]| -> Vec<Option<isize>> {
            per_air
                .iter()
                .map(|p| p.vk.preprocessed_data.as_ref().map(|d| d.hypercube_dim))
                .collect()
        };
        assert_eq!(
            prep_dims(&pk_def.per_air),
            prep_dims(&pk_ref.per_air),
            "deferred keygen must preserve the per-AIR preprocessed geometry"
        );

        pk_def.patch_merged_preprocessed_commit(real_commit);
        assert_eq!(
            bincode::serialize(&pk_def.get_vk()).unwrap(),
            bincode::serialize(&vk_ref).unwrap(),
            "deferred keygen + patch must reproduce the committing keygen's vk byte for byte"
        );
    }

    /// The placeholder must not be able to escape as a vk. Deferral leaves the key complete in
    /// every respect EXCEPT the commitment value, so an unpatched `get_vk()` would hand out a
    /// structurally valid vk whose merged commitment is a zero digest — silently the wrong key
    /// identity. `commit_deferred` turns that into a panic instead of trusting every caller to
    /// sequence the patch correctly.
    #[test]
    #[should_panic(expected = "get_vk on a deferred-commit key")]
    fn get_vk_on_an_unpatched_deferred_key_panics() {
        let log_trace_height = 5;
        let params = SystemParams::new_for_testing(log_trace_height);
        let sels_small = (0..(1 << (log_trace_height - 1)))
            .map(|index| index % 3 == 0)
            .collect_vec();
        let sels_big = (0..(1 << log_trace_height))
            .map(|index| index % 2 == 0)
            .collect_vec();
        let fixture = TwoPreprocessedFixture::new(sels_small, sels_big);
        let engine: KoalaBearPoseidon2RefEngine = StarkEngine::new(params);
        let airs = TestFixture::<_>::airs(&fixture);

        let pk = engine.keygen_merged_preprocessed_deferred_commit(&airs);
        let _ = pk.get_vk();
    }

    /// The config the test engine is built on; pins `TestFixture`'s `SC` for inference.
    type Sc = crate::config::koala_bear_poseidon2::KoalaBearPoseidon2Config;

    /// Air names parallel to `vk.per_air`, as `compute_constraint_dump` requires.
    fn air_names(airs: &[crate::AirRef<Sc>]) -> Vec<String> {
        airs.iter().map(|a| a.name()).collect()
    }

    /// The constraint dump is stable across two independent keygens — the same property
    /// `keygen_is_deterministic` pins for `pre_hash`, but for the constraint comparator. If this
    /// drifted, a dump diff could not distinguish "the constraints differ" from "keygen is flaky".
    #[test]
    fn constraint_dump_is_stable_across_keygens() {
        let engine: KoalaBearPoseidon2RefEngine =
            StarkEngine::new(test_system_params_small(2, 5, 3));
        let fixture = InteractionsFixture11;
        let airs: Vec<crate::AirRef<Sc>> = fixture.airs();
        let names = air_names(&airs);

        let (_, vk_a) = fixture.keygen(&engine);
        let (_, vk_b) = fixture.keygen(&engine);

        let dump_a = compute_constraint_dump(engine.config(), &vk_a.inner, &names);
        let dump_b = compute_constraint_dump(engine.config(), &vk_b.inner, &names);

        assert_eq!(dump_a, dump_b, "constraint dump must be stable");
        assert_eq!(
            dump_a.render(),
            dump_b.render(),
            "rendered artifact must be byte-identical"
        );
        assert_eq!(dump_a.per_air.len(), 2, "fixture has two airs");
        assert!(
            dump_a.per_air.windows(2).all(|w| w[0].0 <= w[1].0),
            "per_air must be sorted by name"
        );
    }

    /// The load-bearing gate: mutating **one** AIR's constraints changes **exactly that** AIR's
    /// per-air digest and the overall digest, leaving every other AIR's digest untouched.
    ///
    /// That localisation is the whole reason the dump emits per-air digests: a mismatch names the
    /// chip without a second tool. The mutation is applied to the vk (the digest's actual input)
    /// rather than to an AIR's `eval`, which keeps the test about the comparator and independent of
    /// the AIR framework.
    ///
    /// It also pins the digest as *sensitive*: a comparator that ignored the DAG would pass the
    /// stability test above while being useless.
    #[test]
    fn mutating_one_air_changes_exactly_one_per_air_digest() {
        let engine: KoalaBearPoseidon2RefEngine =
            StarkEngine::new(test_system_params_small(2, 5, 3));
        let fixture = InteractionsFixture11;
        let airs: Vec<crate::AirRef<Sc>> = fixture.airs();
        let names = air_names(&airs);

        let (_, vk) = fixture.keygen(&engine);
        let baseline = compute_constraint_dump(engine.config(), &vk.inner, &names);

        let mut mutated_vk = vk.clone();
        // Append a node to air 0's constraint DAG: a real change to that AIR's constraint surface,
        // and to nothing else.
        mutated_vk.inner.per_air[0]
            .symbolic_constraints
            .constraints
            .nodes
            .push(SymbolicExpressionNode::Constant(F::from_u32(42)));
        let mutated = compute_constraint_dump(engine.config(), &mutated_vk.inner, &names);

        assert_ne!(
            baseline.overall, mutated.overall,
            "overall digest must react to a constraint change"
        );

        let mutated_name = &names[0];
        let changed = baseline
            .per_air
            .iter()
            .zip(mutated.per_air.iter())
            .filter(|((na, da), (nb, db))| {
                assert_eq!(na, nb, "sorted name order must be unchanged");
                da != db
            })
            .map(|((name, _), _)| name.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            changed,
            vec![mutated_name.clone()],
            "exactly the mutated air's digest must change"
        );
    }

    /// Repeated air names are disambiguated in the render, and only in the render.
    ///
    /// The RISC-V machine really does register duplicates (`MemoryInitializeFinalizeChip` ×2,
    /// `SyscallChip` ×2, `PrepAir` ×3), so without this the pinned artifact would carry ambiguous
    /// lines and a name-keyed diff across two dumps would cross-product them.
    #[test]
    fn repeated_air_names_are_disambiguated_in_the_render() {
        let engine: KoalaBearPoseidon2RefEngine =
            StarkEngine::new(test_system_params_small(2, 5, 3));
        let fixture = InteractionsFixture11;
        let (_, vk) = fixture.keygen(&engine);

        // Force the duplicate case: give both airs the same name.
        let names = vec!["SameName".to_string(), "SameName".to_string()];
        let dump = compute_constraint_dump(engine.config(), &vk.inner, &names);
        let rendered = dump.render();

        assert!(
            rendered.contains("SameName#1\t") && rendered.contains("SameName#2\t"),
            "repeated names must be suffixed; got:\n{rendered}"
        );
        // Every non-comment line must be unique, which is the property the artifact relies on.
        let labels: Vec<&str> = rendered
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.split('\t').next().unwrap())
            .collect();
        let unique: std::collections::BTreeSet<_> = labels.iter().collect();
        assert_eq!(labels.len(), unique.len(), "rendered labels must be unique");

        // A genuinely unique name is left bare, so the common case stays readable. (Both airs in
        // this fixture are named `DummyInteractionAir`, so distinct labels have to be supplied
        // explicitly here — which is itself a reminder that duplicate names are the real-world
        // case this disambiguation exists for.)
        let distinct = vec!["Alpha".to_string(), "Beta".to_string()];
        let bare = compute_constraint_dump(engine.config(), &vk.inner, &distinct).render();
        assert!(
            bare.contains("Alpha\t") && bare.contains("Beta\t"),
            "unique names must not be suffixed; got:\n{bare}"
        );
    }

    /// The digest is params-free: two engines at different operating points (different `l_skip` /
    /// `n_stack`, i.e. different `log_stacked_height`) produce the **same** dump for the same AIRs.
    ///
    /// This is the property `compute_vk_pre_hash` does NOT have, and the reason this comparator
    /// exists: the CPU and GPU provers are not at the same `CHUNK_SIZE`, so a params-dependent
    /// digest could not compare them.
    #[test]
    fn constraint_dump_is_independent_of_the_operating_point() {
        let fixture = InteractionsFixture11;
        let airs: Vec<crate::AirRef<Sc>> = fixture.airs();
        let names = air_names(&airs);

        let engine_a: KoalaBearPoseidon2RefEngine =
            StarkEngine::new(test_system_params_small(2, 5, 3));
        let engine_b: KoalaBearPoseidon2RefEngine =
            StarkEngine::new(test_system_params_small(3, 6, 3));

        let (_, vk_a) = fixture.keygen(&engine_a);
        let (_, vk_b) = fixture.keygen(&engine_b);

        // Sanity: the operating points really differ, so the pre-hash *does* diverge — otherwise
        // this test would be vacuous.
        assert_ne!(
            vk_a.pre_hash, vk_b.pre_hash,
            "different params must move pre_hash, else this test proves nothing"
        );

        let dump_a = compute_constraint_dump(engine_a.config(), &vk_a.inner, &names);
        let dump_b = compute_constraint_dump(engine_b.config(), &vk_b.inner, &names);
        assert_eq!(
            dump_a, dump_b,
            "the constraint dump must not depend on l_skip / n_stack"
        );
    }
}
