// Keygen API for the MLE STARK backend.
// All AIRs can be optional, and the key types are generic over the protocol config.
use std::sync::Arc;

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    air::symbolic::{symbolic_variable::SymbolicVariable, SymbolicConstraintsDag},
    prover::stacked_pcs::StackedPcsData,
    StarkProtocolConfig, SystemParams,
};

/// Widths of different parts of trace matrix
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceWidth {
    pub preprocessed: Option<usize>,
    pub cached_mains: Vec<usize>,
    pub common_main: usize,
}

impl TraceWidth {
    /// Returns the widths of all main traces, including the common main trace if it exists.
    pub fn main_widths(&self) -> Vec<usize> {
        let mut ret = self.cached_mains.clone();
        if self.common_main != 0 {
            ret.push(self.common_main);
        }
        ret
    }

    /// Returns the width of the main trace, i.e., the sum of all cached main widths and the common
    /// main width.
    pub fn main_width(&self) -> usize {
        self.cached_mains.iter().sum::<usize>() + self.common_main
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LinearConstraint {
    pub coefficients: Vec<u32>,
    pub threshold: u32,
}

impl LinearConstraint {
    /// Returns true if `self` is logically implied by `other`, i.e.,
    /// whenever `other` is satisfied, `self` is also satisfied.
    pub fn is_implied_by(&self, other: &LinearConstraint) -> bool {
        self.threshold >= other.threshold
            && self
                .coefficients
                .iter()
                .zip(&other.coefficients)
                .all(|(a, b)| a <= b)
    }
}

#[derive(Error, Debug)]
pub enum KeygenError {
    #[error("Max constraint degree exceeded for AIR {name}: {degree} > {max_degree}")]
    MaxConstraintDegreeExceeded {
        name: String,
        degree: usize,
        max_degree: usize,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct StarkVerifyingParams {
    /// Trace sub-matrix widths
    pub width: TraceWidth,
    /// Number of public values for this STARK only
    pub num_public_values: usize,
    /// A flag indicating whether at least one rotated variable is used in any
    /// of the constraints and/or interactions across all trace parts (common,
    /// preprocessed if there is one, all cached).
    pub need_rot: bool,
}

/// Verifier data for preprocessed trace for a single AIR.
///
/// Currently assumes each AIR has it's own preprocessed commitment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierSinglePreprocessedData<Digest> {
    /// Commitment to the preprocessed trace.
    pub commit: Digest,
    /// The hypercube dimension of the preprocessed data _before stacking_ (log_height -
    /// vk.l_skip).
    pub hypercube_dim: isize,
    /// The width of the data after stacking.
    pub stacking_width: usize,
}

/// Verifying key for a single STARK (corresponding to single AIR matrix)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "F: p3_field::PrimeField64, Digest: Serialize",
    deserialize = "F: p3_field::PrimeField64, Digest: Deserialize<'de>"
))]
#[repr(C)]
pub struct StarkVerifyingKey<F, Digest> {
    /// Preprocessed trace data, if any
    pub preprocessed_data: Option<VerifierSinglePreprocessedData<Digest>>,
    /// Parameters of the STARK
    pub params: StarkVerifyingParams,
    /// Symbolic constraints of the AIR in all challenge phases. This is
    /// a serialization of the constraints in the AIR.
    pub symbolic_constraints: SymbolicConstraintsDag<F>,
    /// The maximum degree of any polynomial (constraint or interaction) for this AIR.
    pub max_constraint_degree: u8,
    /// True means this AIR must have non-empty trace.
    pub is_required: bool,
    /// Symbolic variables referenced unreferenced by the AIR.
    pub unused_variables: Vec<SymbolicVariable<F>>,
}

/// Common verifying key for multiple AIRs.
///
/// This struct contains the necessary data for the verifier to verify proofs generated for
/// multiple AIRs using a single verifying key.
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(Clone(bound = ""), Debug(bound = ""))]
#[serde(bound = "")]
pub struct MultiStarkVerifyingKey<SC: StarkProtocolConfig> {
    /// All parts of the verifying key needed by the verifier, except
    /// the `pre_hash` used to initialize the Fiat-Shamir transcript.
    pub inner: MultiStarkVerifyingKeyInner<SC>,
    /// The hash of all other parts of the verifying key. The Fiat-Shamir hasher will
    /// initialize by observing this hash.
    pub pre_hash: SC::Digest,
}

/// Everything in [MultiStarkVerifyingKey] except the `pre_hash` used to initialize the Fiat-Shamir
/// transcript.
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(Clone(bound = ""), Debug(bound = ""))]
#[serde(bound = "")]
pub struct MultiStarkVerifyingKeyInner<SC: StarkProtocolConfig> {
    pub params: SystemParams,
    pub per_air: Vec<StarkVerifyingKey<SC::F, SC::Digest>>,
    pub trace_height_constraints: Vec<LinearConstraint>,
    /// When `Some`, all AIRs' preprocessed traces are committed together in ONE multi-matrix
    /// stacked commitment (this digest), instead of one commitment per AIR. Per-air
    /// `preprocessed_data` then carries metadata (`hypercube_dim`, widths) and duplicates this
    /// digest in its `commit` field; the matrix order inside the merged commitment is
    /// `(Reverse(prep log_height), air_idx)` — identical to the verifier's trace ordering
    /// restricted to preprocessed AIRs (prep height == trace height is verifier-enforced).
    /// All AIRs must be `is_required` in this mode (enforced at keygen).
    pub merged_preprocessed_commit: Option<SC::Digest>,
}

/// Proving key for a single STARK (corresponding to single AIR matrix)
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub struct StarkProvingKey<SC: StarkProtocolConfig> {
    /// Type name of the AIR, for display purposes only
    pub air_name: String,
    /// Verifying key
    pub vk: StarkVerifyingKey<SC::F, SC::Digest>,
    /// Prover only data for preprocessed trace
    pub preprocessed_data: Option<Arc<StackedPcsData<SC::F, SC::Digest>>>,
}

/// Common proving key for multiple AIRs.
///
/// This struct contains the necessary data for the prover to generate proofs for multiple AIRs
/// using a single proving key.
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub struct MultiStarkProvingKey<SC: StarkProtocolConfig> {
    pub per_air: Vec<StarkProvingKey<SC>>,
    pub trace_height_constraints: Vec<LinearConstraint>,
    /// Maximum degree of constraints across all AIRs
    pub max_constraint_degree: usize,
    pub params: SystemParams,
    /// See [MultiStarkVerifyingKey]
    pub vk_pre_hash: SC::Digest,
    /// When `Some`, the single multi-matrix stacked commitment holding ALL AIRs' preprocessed
    /// traces (see [MultiStarkVerifyingKey0::merged_preprocessed_commit]). Per-air
    /// `preprocessed_data` is `None` in this mode; per-air matrix indices are given by
    /// [merged_preprocessed_mat_indices].
    ///
    /// `None` while the commitment is deferred to an external prover (the GPU recursion path
    /// computes it on-device); `merged_preprocessed_commit` still says whether the key is in
    /// merged mode, so read that, not this, to decide.
    pub merged_preprocessed_data: Option<Arc<StackedPcsData<SC::F, SC::Digest>>>,
    /// The merged commitment VALUE, and the single source of truth for merged mode. Kept apart
    /// from `merged_preprocessed_data` because the value can outlive (or precede) the host-side
    /// PCS data: the GPU path commits on-device and never builds the host `StackedPcsData`.
    /// Deriving this from `merged_preprocessed_data` instead would silently drop merged mode —
    /// and with it flip the `merged_mode` bit in the vk pre-hash preimage.
    pub merged_preprocessed_commit: Option<SC::Digest>,
    /// True while `merged_preprocessed_commit` still holds the placeholder left by
    /// [`MultiStarkKeygenBuilder::generate_pk_deferred_merged_commit`], i.e. the external
    /// committer has not called [`Self::patch_merged_preprocessed_commit`] yet. Such a key is
    /// complete in every respect EXCEPT the commitment value, so [`Self::get_vk`] would hand out
    /// a vk whose identity is a zero digest — structurally valid and silently wrong. `get_vk_inner`
    /// asserts on it rather than trusting callers to sequence the patch correctly.
    ///
    /// Not part of the key: `#[serde(skip)]`, so it never reaches the wire and a deserialized key
    /// is never considered deferred (a deferred key is a transient in-process state — the patch
    /// happens in the same call chain that created it).
    #[serde(skip)]
    pub commit_deferred: bool,
}

/// For merged-preprocessed keys: per-air matrix index inside the merged stacked commitment
/// (`None` for AIRs without preprocessed trace). Input: per-air `hypercube_dim` of the
/// preprocessed trace (`None` if the AIR has none), in AIR-id order. The order is
/// `(Reverse(hypercube_dim), air_idx)`, matching both the keygen commit order and the
/// verifier's height-descending trace ordering.
pub fn merged_preprocessed_mat_indices(
    prep_dims: impl Iterator<Item = Option<isize>>,
) -> Vec<Option<usize>> {
    let dims: Vec<Option<isize>> = prep_dims.collect();
    let mut prep_airs: Vec<(usize, isize)> = dims
        .iter()
        .enumerate()
        .filter_map(|(i, dim)| dim.map(|d| (i, d)))
        .collect();
    prep_airs.sort_by_key(|&(air_idx, dim)| (std::cmp::Reverse(dim), air_idx));
    let mut out = vec![None; dims.len()];
    for (mat_idx, (air_idx, _)) in prep_airs.into_iter().enumerate() {
        out[air_idx] = Some(mat_idx);
    }
    out
}

impl<Val, Com> StarkVerifyingKey<Val, Com> {
    pub fn num_cached_mains(&self) -> usize {
        self.params.width.cached_mains.len()
    }

    pub fn num_parts(&self) -> usize {
        1 + self.num_cached_mains() + (self.preprocessed_data.is_some() as usize)
    }

    pub fn has_interaction(&self) -> bool {
        !self.symbolic_constraints.interactions.is_empty()
    }

    pub fn num_interactions(&self) -> usize {
        self.symbolic_constraints.interactions.len()
    }

    /// Converts from a main part index (as used by the constraint DAG) to the
    /// commitment part indexing scheme that includes preprocessed trace.
    pub fn dag_main_part_index_to_commit_index(&self, index: usize) -> usize {
        // In the dag, common main is the final part index.
        if index == self.num_cached_mains() {
            0
        } else {
            index + 1 + self.preprocessed_data.is_some() as usize
        }
    }
}

impl<SC: StarkProtocolConfig> MultiStarkProvingKey<SC> {
    pub fn get_vk(&self) -> MultiStarkVerifyingKey<SC> {
        MultiStarkVerifyingKey {
            inner: self.get_vk_inner(),
            pre_hash: self.vk_pre_hash,
        }
    }

    /// Builds the pre-hash body of the verifying key (everything except `pre_hash` itself).
    fn get_vk_inner(&self) -> MultiStarkVerifyingKeyInner<SC> {
        assert!(
            !self.commit_deferred,
            "get_vk on a deferred-commit key: `merged_preprocessed_commit` is still the \
             placeholder, so this vk would carry a zero merged commitment. Call \
             `patch_merged_preprocessed_commit` with the external committer's root first."
        );
        debug_assert!(
            self.merged_preprocessed_data
                .as_ref()
                .is_none_or(|d| Some(d.commit().unwrap()) == self.merged_preprocessed_commit),
            "merged commitment value disagrees with the host stacked PCS data it came from"
        );
        MultiStarkVerifyingKeyInner {
            params: self.params.clone(),
            per_air: self.per_air.iter().map(|pk| pk.vk.clone()).collect(),
            trace_height_constraints: self.trace_height_constraints.clone(),
            merged_preprocessed_commit: self.merged_preprocessed_commit,
        }
    }

    /// Install the merged preprocessed commitment computed outside this builder (the GPU
    /// recursion path commits on-device), replacing the placeholder left by
    /// [`MultiStarkKeygenBuilder::generate_pk_deferred_merged_commit`].
    ///
    /// Sound because merged mode structurally excludes every commitment VALUE from the vk
    /// pre-hash preimage (see [`crate::keygen::compute_vk_pre_hash`]): the pre-hash computed
    /// against the placeholder is already the final one, so this cannot change the vk identity's
    /// hash component — only the commitment component it is paired with.
    pub fn patch_merged_preprocessed_commit(&mut self, commit: SC::Digest) {
        assert!(
            self.merged_preprocessed_commit.is_some(),
            "patch_merged_preprocessed_commit on a key that is not in merged-preprocessed mode"
        );
        self.merged_preprocessed_commit = Some(commit);
        self.commit_deferred = false;
        for pk in &mut self.per_air {
            if let Some(vdata) = pk.vk.preprocessed_data.as_mut() {
                vdata.commit = commit;
            }
        }
    }
}

impl<SC: StarkProtocolConfig> MultiStarkVerifyingKey<SC> {
    /// Global maximum constraint degree across all AIRs and Interactions.
    pub fn max_constraint_degree(&self) -> usize {
        self.inner.max_constraint_degree()
    }
}

impl<SC: StarkProtocolConfig> MultiStarkVerifyingKeyInner<SC> {
    pub fn max_constraint_degree(&self) -> usize {
        self.params.max_constraint_degree
    }
}

#[cfg(test)]
mod tests {
    use super::{LinearConstraint, TraceWidth};

    fn lc(coefficients: &[u32], threshold: u32) -> LinearConstraint {
        LinearConstraint {
            coefficients: coefficients.to_vec(),
            threshold,
        }
    }

    /// `is_implied_by` — `self` (the looser bound `Σ cᵢ·xᵢ < threshold`) is implied by `other` iff
    /// `self.threshold ≥ other.threshold` and every `self.cᵢ ≤ other.cᵢ`.
    #[test]
    fn linear_constraint_is_implied_by() {
        // A constraint implies itself.
        assert!(lc(&[1, 2], 5).is_implied_by(&lc(&[1, 2], 5)));
        // Looser threshold + pointwise-smaller coefficients ⇒ implied (other ⇒ self).
        assert!(lc(&[1, 2], 6).is_implied_by(&lc(&[2, 3], 5)));
        // A tighter threshold on `self` breaks the implication.
        assert!(!lc(&[1, 2], 4).is_implied_by(&lc(&[2, 3], 5)));
        // A coefficient of `self` exceeding `other`'s breaks the implication.
        assert!(!lc(&[3, 2], 6).is_implied_by(&lc(&[2, 3], 5)));
    }

    /// `main_width` sums cached + common unconditionally; `main_widths` lists cached widths and
    /// appends the common main only when it is nonzero.
    #[test]
    fn trace_width_main_width_and_widths() {
        let w = TraceWidth {
            preprocessed: Some(4),
            cached_mains: vec![2, 3],
            common_main: 5,
        };
        assert_eq!(w.main_width(), 2 + 3 + 5);
        assert_eq!(w.main_widths(), vec![2, 3, 5]);

        // A zero common main is omitted from `main_widths` but still counted (as 0) by `main_width`.
        let w0 = TraceWidth {
            preprocessed: None,
            cached_mains: vec![7],
            common_main: 0,
        };
        assert_eq!(w0.main_width(), 7);
        assert_eq!(w0.main_widths(), vec![7]);
    }
}
