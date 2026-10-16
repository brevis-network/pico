use std::sync::Arc;

use derivative::Derivative;
use p3_util::log2_strict_usize;

use crate::{
    keygen::types::{
        LinearConstraint, MultiStarkVerifyingKey, MultiStarkVerifyingKeyInner, StarkVerifyingKey,
    },
    poly::matrix::MatrixDimensions,
    protocol::stacking::stacking_sort_key,
    prover::ProverBackend,
    StarkProtocolConfig, SystemParams,
};

/// The committed trace data for a single trace matrix. This type is used to store prover data for
/// both preprocessed trace and cached trace.
#[derive(Derivative)]
#[derivative(Clone(bound = "PB::Matrix: Clone"))]
pub struct CommittedTraceData<PB: ProverBackend> {
    /// The polynomial commitment.
    pub commitment: PB::Commitment,
    /// The trace matrix, unstacked, in evaluation form.
    pub trace: PB::Matrix,
    /// The PCS data for a single committed trace matrix.
    pub data: Arc<PB::PcsData>,
}

/// The proving key for a circuit consisting of multiple AIRs, after prover-specific data has been
/// transferred to device. The host data (e.g., vkey) is owned by this struct.
///
/// Ordering is always by AIR ID and includes all AIRs, including ones that may have empty traces.
#[derive(derive_new::new)]
pub struct DeviceMultiStarkProvingKey<PB: ProverBackend> {
    pub per_air: Vec<DeviceStarkProvingKey<PB>>,
    pub trace_height_constraints: Vec<LinearConstraint>,
    /// Maximum degree of constraints across all AIRs
    pub max_constraint_degree: usize,
    pub params: SystemParams,
    pub vk_pre_hash: PB::Commitment,
    /// When `Some`, ALL AIRs' preprocessed traces live in this single multi-matrix stacked
    /// commitment (see `MultiStarkVerifyingKey0::merged_preprocessed_commit`). Per-air
    /// `preprocessed_data` still holds each AIR's trace view (for constraint evaluation) with
    /// `data` pointing at this shared PCS data and `commitment` equal to the merged root.
    pub merged_preprocessed: Option<(PB::Commitment, Arc<PB::PcsData>)>,
}

/// The proving key after prover-specific data has been transferred to device. The host data (e.g.,
/// vkey) is owned by this struct.
pub struct DeviceStarkProvingKey<PB: ProverBackend> {
    /// Type name of the AIR, for display purposes only
    pub air_name: String,
    pub vk: StarkVerifyingKey<PB::Val, PB::Commitment>,
    /// Prover only data for preprocessed trace
    pub preprocessed_data: Option<CommittedTraceData<PB>>,
    pub other_data: PB::OtherAirData,
    /// Lazily-built tree form of `vk.symbolic_constraints` (see
    /// [`Self::symbolic_constraints`]): the DAG→tree conversion clones out every constraint
    /// and interaction expression, and its output is identical for every chunk — build it
    /// once per key instead of once per (AIR × chunk × prove).
    pub symbolic_constraints_cache:
        std::sync::OnceLock<crate::air::symbolic::SymbolicConstraints<PB::Val>>,
}

impl<PB: ProverBackend> DeviceStarkProvingKey<PB>
where
    PB::Val: p3_field::Field,
{
    /// The tree form of this AIR's symbolic constraints, built on first use and cached for
    /// the lifetime of the key.
    pub fn symbolic_constraints(&self) -> &crate::air::symbolic::SymbolicConstraints<PB::Val> {
        self.symbolic_constraints_cache
            .get_or_init(|| (&self.vk.symbolic_constraints).into())
    }
}

#[derive(derive_new::new)]
pub struct ProvingContext<PB: ProverBackend> {
    /// For each AIR with non-empty trace, the pair of (AIR ID, [AirProvingContext]), where AIR
    /// ID is with respect to the vkey ordering.
    pub per_trace: Vec<(usize, AirProvingContext<PB>)>,
}

#[derive(derive_new::new)]
pub struct AirProvingContext<PB: ProverBackend> {
    /// Cached main trace matrices as `PcsData`. The original trace matrix should be extractable as
    /// a view from the `PcsData`. The `PcsData` should also contain the commitment value. Cached
    /// trace commitments have a single matrix per commitment.
    ///
    /// The `PcsData` is kept inside an `Arc` to emphasize that this data is cached and may be
    /// shared between multiple proving contexts. In particular, it is not typically safe to mutate
    /// the data during a proving job.
    pub cached_mains: Vec<CommittedTraceData<PB>>,
    /// Common main trace matrix
    pub common_main: PB::Matrix,
    /// Public values
    pub public_values: Vec<PB::Val>,
}

impl<PB: ProverBackend> CommittedTraceData<PB> {
    #[inline(always)]
    pub fn height(&self) -> usize {
        self.trace.height()
    }
}

impl<PB: ProverBackend> DeviceMultiStarkProvingKey<PB> {
    /// Shared `prove_openings` prologue: derive the per-commit cached PCS data and `need_rot` flags
    /// in stacking order. Both device backends compute these identically and purely from
    /// `self`/`ctx` (no HAL calls), so they live here; each `prove_openings` keeps its own tail.
    ///
    /// Returns `(pre_cached_pcs_data_per_commit, need_rot_per_commit)`. The first is every present
    /// trace's preprocessed-then-cached PCS data in trace order (the caller prepends the common-main
    /// commit). `need_rot_per_commit[0]` holds the common-main per-trace flags; each later entry is
    /// a one-element `vec![need_rot]` aligned with `pre_cached_pcs_data_per_commit`.
    pub fn opening_prologue(
        &self,
        ctx: &ProvingContext<PB>,
    ) -> (Vec<Arc<PB::PcsData>>, Vec<Vec<bool>>) {
        let need_rot_per_trace: Vec<bool> = ctx
            .per_trace
            .iter()
            .map(|(air_idx, _)| self.per_air[*air_idx].vk.params.need_rot)
            .collect();

        // Commit order: [common_main, merged_preprocessed (if merged mode), then per
        // trace: preprocessed (per-air mode only), cached...]. In merged mode ALL
        // preprocessed matrices live in ONE multi-matrix commitment (see
        // `MultiStarkVerifyingKeyInner::merged_preprocessed_commit`); its need_rot vector
        // is per matrix, in trace order restricted to preprocessed AIRs (== the merged
        // layout's matrix order, since prep height equals trace height).
        let merged_prep = self.merged_preprocessed.is_some();
        let mut pre_cached_pcs_data_per_commit: Vec<Arc<PB::PcsData>> = Vec::new();
        if let Some((_, data)) = &self.merged_preprocessed {
            pre_cached_pcs_data_per_commit.push(data.clone());
        }
        for (air_idx, trace_ctx) in &ctx.per_trace {
            if !merged_prep {
                if let Some(cd) = &self.per_air[*air_idx].preprocessed_data {
                    pre_cached_pcs_data_per_commit.push(cd.data.clone());
                }
            }
            for cd in &trace_ctx.cached_mains {
                pre_cached_pcs_data_per_commit.push(cd.data.clone());
            }
        }

        let mut need_rot_per_commit = vec![need_rot_per_trace];
        if merged_prep {
            need_rot_per_commit.push(
                ctx.per_trace
                    .iter()
                    .filter(|(air_idx, _)| self.per_air[*air_idx].vk.preprocessed_data.is_some())
                    .map(|(air_idx, _)| self.per_air[*air_idx].vk.params.need_rot)
                    .collect(),
            );
        }
        for (air_idx, trace_ctx) in &ctx.per_trace {
            let need_rot = self.per_air[*air_idx].vk.params.need_rot;
            if !merged_prep && self.per_air[*air_idx].preprocessed_data.is_some() {
                need_rot_per_commit.push(vec![need_rot]);
            }
            for _ in &trace_ctx.cached_mains {
                need_rot_per_commit.push(vec![need_rot]);
            }
        }

        (pre_cached_pcs_data_per_commit, need_rot_per_commit)
    }

    pub fn get_vk<SC>(&self) -> MultiStarkVerifyingKey<SC>
    where
        SC: StarkProtocolConfig<F = PB::Val, Digest = PB::Commitment>,
    {
        let per_air = self.per_air.iter().map(|pk| pk.vk.clone()).collect();
        let inner = MultiStarkVerifyingKeyInner {
            params: self.params.clone(),
            per_air,
            trace_height_constraints: self.trace_height_constraints.clone(),
            merged_preprocessed_commit: self.merged_preprocessed.as_ref().map(|(c, _)| c.clone()),
        };
        MultiStarkVerifyingKey {
            inner,
            pre_hash: self.vk_pre_hash.clone(),
        }
    }
}

impl<PB: ProverBackend> IntoIterator for ProvingContext<PB> {
    type Item = (usize, AirProvingContext<PB>);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.per_trace.into_iter()
    }
}

impl<PB: ProverBackend> ProvingContext<PB> {
    pub fn common_main_traces(&self) -> impl Iterator<Item = (usize, &PB::Matrix)> {
        self.per_trace
            .iter()
            .map(|(air_idx, trace_ctx)| (*air_idx, &trace_ctx.common_main))
    }

    /// Returns `self` with the trace data sorted for column stacking. See
    /// [`sort_for_stacking`](Self::sort_for_stacking) for the ordering contract.
    pub fn into_sorted(mut self) -> Self {
        self.sort_for_stacking();
        self
    }

    /// Sorts the trace data for column stacking via [`stacking_sort_key`]: tallest first, ties
    /// broken by ascending AIR index. Consensus-critical — the verifier reconstructs this layout.
    /// Keys on `log2(height)`, which orders identically to raw height since `log2` is monotone on
    /// the power-of-two trace heights.
    pub fn sort_for_stacking(&mut self) {
        self.per_trace.sort_by_key(|(air_idx, trace_ctx)| {
            stacking_sort_key(log2_strict_usize(trace_ctx.common_main.height()), *air_idx)
        });
    }
}

impl<PB: ProverBackend> AirProvingContext<PB> {
    pub fn simple(common_main_trace: PB::Matrix, public_values: Vec<PB::Val>) -> Self {
        Self::new(vec![], common_main_trace, public_values)
    }
    pub fn simple_no_pis(common_main_trace: PB::Matrix) -> Self {
        Self::simple(common_main_trace, vec![])
    }

    /// Return the height of the main trace.
    pub fn height(&self) -> usize {
        self.common_main.height()
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::{AirProvingContext, ProvingContext};
    use crate::{
        config::koala_bear_poseidon2::{KoalaBearPoseidon2Config, F},
        poly::matrix::ColMajorMatrix,
        prover::ReferenceColMajorBackend,
    };

    // `sort_for_stacking` keys only on the common-main height, so any backend will do.
    type TestBackend = ReferenceColMajorBackend<KoalaBearPoseidon2Config>;

    /// Build a `ProvingContext` whose traces have the given `(air_idx, height)`, inserted in the
    /// given order. Only the common-main height drives `sort_for_stacking`, so a width-1 zero
    /// matrix of the requested height suffices.
    fn ctx_with(traces: &[(usize, usize)]) -> ProvingContext<TestBackend> {
        let per_trace = traces
            .iter()
            .map(|&(air_idx, height)| {
                let common_main = ColMajorMatrix::new(vec![F::ZERO; height], 1);
                (air_idx, AirProvingContext::simple_no_pis(common_main))
            })
            .collect();
        ProvingContext::new(per_trace)
    }

    fn air_idx_order(ctx: &ProvingContext<TestBackend>) -> Vec<usize> {
        ctx.per_trace.iter().map(|(air_idx, _)| *air_idx).collect()
    }

    /// Pins the stacking permutation. The equal-height pairs are supplied in descending AIR-index
    /// order, so this fails loudly if the `air_idx` tie-break is ever dropped from the sort key.
    #[test]
    fn sort_for_stacking_pins_mixed_height_with_tie_break() {
        // Heights: two 8s (air 3, 0), two 4s (air 5, 2), one 2 (air 1) — equal pairs reversed.
        let mut ctx = ctx_with(&[(2, 4), (3, 8), (5, 4), (0, 8), (1, 2)]);
        ctx.sort_for_stacking();
        // 8s ascending → 0, 3 ; 4s ascending → 2, 5 ; 2 → 1.
        assert_eq!(air_idx_order(&ctx), vec![0, 3, 2, 5, 1]);
    }

    /// `into_sorted` is `sort_for_stacking` taken by value; it must produce the identical order.
    #[test]
    fn into_sorted_matches_sort_for_stacking() {
        let ctx = ctx_with(&[(2, 4), (3, 8), (5, 4), (0, 8), (1, 2)]);
        assert_eq!(air_idx_order(&ctx.into_sorted()), vec![0, 3, 2, 5, 1]);
    }
}
