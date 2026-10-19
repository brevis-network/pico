//! Proof-shape validation — structure only, no cryptography. Every length/degree/count in the
//! proof is checked against the verifying key up front, one helper per proof section (vdata,
//! GKR, batch constraints, stacking, WHIR), so the cryptographic passes that follow can index
//! into the proof without bounds concerns.
//!
//! [`verify_proof_shape`] also re-derives the [`StackedLayout`] of every commitment from the
//! vkey and the claimed trace heights, in commitment order (common-main first,
//! then one layout per preprocessed/cached part). The verifier never trusts a layout carried by
//! the proof, and its trace ordering — tallest first, ties broken by ascending AIR index — must
//! match the prover's stacking sort in `prover/types.rs`.
//!
//! This module must stay panic-free on adversarial input: every malformed shape maps to a
//! [`ProofShapeError`]; nothing proof-derived is unwrapped or indexed unchecked.

use itertools::{izip, Itertools};
use thiserror::Error;

use crate::{
    keygen::types::{MultiStarkVerifyingKeyInner, StarkVerifyingKey},
    proof::{BatchConstraintProof, GkrProof, Proof, StackingProof, TraceVData, WhirProof},
    protocol::stacking::{present_gkr_shape, stacking_sort_key, StackedLayout, StackedPcsError},
    StarkProtocolConfig,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofShapeError {
    #[error("Invalid VData: {0}")]
    InvalidVData(ProofShapeVDataError),
    #[error("Proof contains no traces: every AIR's trace_vdata is None")]
    NoTracesPresent,
    #[error("Invalid GkrProof shape: {0}")]
    InvalidGkrProofShape(GkrProofShapeError),
    #[error("Invalid BatchConstraintProof shape: {0}")]
    InvalidBatchConstraintProofShape(BatchProofShapeError),
    #[error("Invalid StackingProof shape: {0}")]
    InvalidStackingProofShape(StackingProofShapeError),
    #[error("Invalid WhirProof shape: {0}")]
    InvalidWhirProofShape(WhirProofShapeError),
    #[error("Layout re-derivation failed: {0}")]
    InvalidStackedLayout(#[from] StackedPcsError),
}

impl ProofShapeError {
    fn invalid_vdata<T>(err: ProofShapeVDataError) -> Result<T, Self> {
        Err(Self::InvalidVData(err))
    }

    fn invalid_gkr<T>(err: GkrProofShapeError) -> Result<T, Self> {
        Err(Self::InvalidGkrProofShape(err))
    }

    fn invalid_batch_constraint<T>(err: BatchProofShapeError) -> Result<T, Self> {
        Err(Self::InvalidBatchConstraintProofShape(err))
    }

    fn invalid_stacking<T>(err: StackingProofShapeError) -> Result<T, Self> {
        Err(Self::InvalidStackingProofShape(err))
    }

    fn invalid_whir<T>(err: WhirProofShapeError) -> Result<T, Self> {
        Err(Self::InvalidWhirProofShape(err))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofShapeVDataError {
    #[error("Proof trace_vdata length ({len}) does not match number of AIRs ({num_airs})")]
    InvalidVDataLength { len: usize, num_airs: usize },
    #[error("Proof public_values length ({len}) does not match number of AIRs ({num_airs})")]
    InvalidPublicValuesLength { len: usize, num_airs: usize },
    #[error("AIR {air_idx} is required, but trace_vdata[{air_idx}] is None")]
    RequiredAirNoVData { air_idx: usize },
    #[error("AIR {air_idx} has no TraceVData, but a non-zero amount of public values")]
    PublicValuesNoVData { air_idx: usize },
    #[error(
        "TraceVData for AIR {air_idx} should have {expected} cached commitments, but has {actual}"
    )]
    InvalidCachedCommitments {
        air_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error("AIR {air_idx} should have log_height <= {}, but has {actual} (l_skip = {l_skip}, n_stack = {n_stack})", l_skip + n_stack)]
    LogHeightOutOfBounds {
        air_idx: usize,
        l_skip: usize,
        n_stack: usize,
        actual: usize,
    },
    #[error("AIR {air_idx} should have {expected} public values, but has {actual}")]
    InvalidPublicValues {
        air_idx: usize,
        expected: usize,
        actual: usize,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GkrProofShapeError {
    #[error(
        "claims_per_layer should have num_gkr_rounds = {expected} claims, but it has {actual}"
    )]
    InvalidClaimsPerLayer { expected: usize, actual: usize },
    #[error(
        "sumcheck_polys should have num_gkr_rounds.saturating_sub(1) = {expected} polynomials, but it has {actual}"
    )]
    InvalidSumcheckPolys { expected: usize, actual: usize },
    #[error(
        "Sumcheck polynomial for round {round} should have {expected} evaluations, but it has {actual}"
    )]
    InvalidSumcheckPolyEvals {
        round: usize,
        expected: usize,
        actual: usize,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BatchProofShapeError {
    #[error("numerator_term_per_air should have num_airs = {expected} terms, but it has {actual}")]
    InvalidNumeratorTerms { expected: usize, actual: usize },
    #[error(
        "denominator_term_per_air should have num_airs = {expected} terms, but it has {actual}"
    )]
    InvalidDenominatorTerms { expected: usize, actual: usize },
    #[error(
        "univariate_round_coeffs should have (max_constraint_degree + 1) * (2^l_skip - 1) + 1 = {expected} coefficients, but it has {actual}"
    )]
    InvalidUnivariateRoundCoeffs { expected: usize, actual: usize },
    #[error(
        "sumcheck_round_polys should have n_global = {expected} polynomials, but it has {actual}"
    )]
    InvalidSumcheckRoundPolys { expected: usize, actual: usize },
    #[error(
        "column_openings should have num_airs = {expected} sets of openings, but it has {actual}"
    )]
    InvalidColumnOpeningsAirs { expected: usize, actual: usize },
    #[error(
        "sumcheck_round_polys[{round}] should have degree = {expected} evaluations, but it has {actual}"
    )]
    InvalidSumcheckRoundPolyEvals {
        round: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "AIR {air_idx} has {expected} parts, but there are {actual} sets of per-part column openings"
    )]
    InvalidColumnOpeningsPerAir {
        air_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "There should be {expected} column opening pairs for AIR {air_idx}'s main trace, but instead there are {actual}"
    )]
    InvalidColumnOpeningsPerAirMain {
        air_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "There should be {expected} column opening pairs for AIR {air_idx}'s preprocessed trace, but instead there are {actual}"
    )]
    InvalidColumnOpeningsPerAirPreprocessed {
        air_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "There should be {expected} column opening pairs for AIR {air_idx}'s cached trace {cached_idx}, but instead there are {actual}"
    )]
    InvalidColumnOpeningsPerAirCached {
        air_idx: usize,
        cached_idx: usize,
        expected: usize,
        actual: usize,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StackingProofShapeError {
    #[error(
        "univariate_round_coeffs should have 2 * ((1 << mvk.params.l_skip) - 1) + 1 = {expected} coefficients, but it has {actual}"
    )]
    InvalidUnivariateRoundCoeffs { expected: usize, actual: usize },
    #[error(
        "sumcheck_round_polys should have n_stack = {expected} polynomials, but it has {actual}"
    )]
    InvalidSumcheckRoundPolys { expected: usize, actual: usize },
    #[error(
        "There should be {expected} sets of per-commit stacking openings, but instead there are {actual}"
    )]
    InvalidStackOpenings { expected: usize, actual: usize },
    #[error(
        "Stacked matrix {commit_idx} should have {expected} stacking openings, but instead there are {actual}"
    )]
    InvalidStackOpeningsPerMatrix {
        commit_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error("Total stacked width across commits ({actual}) exceeds w_stack ({w_stack})")]
    TotalStackedWidthOutOfBounds { w_stack: usize, actual: usize },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WhirProofShapeError {
    #[error(
        "whir_sumcheck_polys should have num_whir_sumcheck_rounds = {expected} polynomials, but it has {actual}"
    )]
    InvalidSumcheckPolys { expected: usize, actual: usize },
    #[error("final_poly should have len = {expected}, but it has {actual}")]
    InvalidFinalPolyLen { expected: usize, actual: usize },
    #[error(
        "There should be num_whir_rounds = {expected} codeword commits, but there are {actual}"
    )]
    InvalidCodewordCommits { expected: usize, actual: usize },
    #[error(
        "There should be num_whir_rounds = {expected} out-of-domain values, but there are {actual}"
    )]
    InvalidOodValues { expected: usize, actual: usize },
    #[error(
        "There should be num_whir_sumcheck_rounds = {expected} folding PoW witnesses, but there are {actual}"
    )]
    InvalidFoldingPowWitnesses { expected: usize, actual: usize },
    #[error(
        "There should be num_whir_rounds = {expected} query phase PoW witnesses, but there are {actual}"
    )]
    InvalidQueryPhasePowWitnesses { expected: usize, actual: usize },
    #[error(
        "There should be num_commits = {expected} sets of initial round opened rows, but there are {actual}"
    )]
    InvalidInitialRoundOpenedRows { expected: usize, actual: usize },
    #[error(
        "There should be num_commits = {expected} sets of initial round merkle proofs, but there are {actual}"
    )]
    InvalidInitialRoundMerkleProofs { expected: usize, actual: usize },
    #[error(
        "There should be num_whir_rounds = {expected} sets of non-initial round opened rows, but there are {actual}"
    )]
    InvalidCodewordOpenedRows { expected: usize, actual: usize },
    #[error(
        "There should be num_whir_rounds = {expected} sets of non-initial round merkle proofs, but there are {actual}"
    )]
    InvalidCodewordMerkleProofs { expected: usize, actual: usize },
    #[error(
        "There should be num_whir_queries = {expected} initial round opened rows for commit {commit_idx}, but there are {actual}"
    )]
    InvalidInitialRoundOpenedRowsQueries {
        commit_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "There should be num_whir_queries = {expected} initial round merkle proofs for commit {commit_idx}, but there are {actual}"
    )]
    InvalidInitialRoundMerkleProofsQueries {
        commit_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "Initial round opened row {opened_idx} for commit {commit_idx} should have length {expected}, but it has length {actual}"
    )]
    InvalidInitialRoundOpenedRowK {
        opened_idx: usize,
        commit_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "Initial round opened row {row_idx} for commit {commit_idx} should have width {expected}, but it has width {actual}"
    )]
    InvalidInitialRoundOpenedRowWidth {
        row_idx: usize,
        commit_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "Initial round merkle proof {opened_idx} for commit {commit_idx} should have depth {expected}, but it has depth {actual}"
    )]
    InvalidInitialRoundMerkleProofDepth {
        opened_idx: usize,
        commit_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "There should be num_whir_queries = {expected} round {round} opened rows, but there are {actual}"
    )]
    InvalidCodewordOpenedRowsQueries {
        round: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "There should be num_whir_queries = {expected} round {round} merkle proofs, but there are {actual}"
    )]
    InvalidCodewordMerkleProofsQueries {
        round: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "Round {round} opened row {opened_idx} should have length {expected}, but it has length {actual}"
    )]
    InvalidCodewordOpenedValues {
        round: usize,
        opened_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "Round {round} merkle proof {opened_idx} should have depth {expected}, but it has depth {actual}"
    )]
    InvalidCodewordMerkleProofDepth {
        round: usize,
        opened_idx: usize,
        expected: usize,
        actual: usize,
    },
}

/// Sorted view of the present traces: `(air index, per-AIR vkey, claimed trace vdata)`,
/// ordered tallest-first with ties broken by ascending AIR index (matching the prover's
/// stacking sort in `prover/types.rs`).
type PerTraceEntry<'a, SC> = (
    usize,
    &'a StarkVerifyingKey<<SC as StarkProtocolConfig>::F, <SC as StarkProtocolConfig>::Digest>,
    &'a TraceVData<SC>,
);

pub fn verify_proof_shape<SC: StarkProtocolConfig>(
    mvk: &MultiStarkVerifyingKeyInner<SC>,
    proof: &Proof<SC>,
) -> Result<Vec<StackedLayout>, ProofShapeError> {
    verify_vdata_shape(mvk, proof)?;

    let per_trace: Vec<PerTraceEntry<'_, SC>> = mvk
        .per_air
        .iter()
        .zip(&proof.trace_vdata)
        .enumerate()
        .filter_map(|(air_idx, (vk, vdata))| vdata.as_ref().map(|vdata| (air_idx, vk, vdata)))
        // Must reproduce the prover's stacking order (`ProvingContext::sort_for_stacking`) exactly,
        // so key on `stacking_sort_key` rather than leaning on the stable sort's input order.
        .sorted_by_key(|(air_idx, _, vdata)| stacking_sort_key(vdata.log_height, *air_idx))
        .collect_vec();
    // The remaining checks index into the tallest trace (`per_trace[0]`); a proof where every
    // AIR is absent has nothing to verify and must not panic the verifier.
    if per_trace.is_empty() {
        return Err(ProofShapeError::NoTracesPresent);
    }

    verify_gkr_shape(mvk, &per_trace, &proof.gkr_proof)?;
    verify_batch_constraint_shape(mvk, &per_trace, &proof.batch_constraint_proof)?;
    let layouts = verify_stacking_shape(mvk, &per_trace, &proof.stacking_proof)?;
    verify_whir_shape(mvk, &layouts, &proof.stacking_proof, &proof.whir_proof)?;

    Ok(layouts)
}

/// Trace heights, public values, and cached-commitment counts against the vkey.
fn verify_vdata_shape<SC: StarkProtocolConfig>(
    mvk: &MultiStarkVerifyingKeyInner<SC>,
    proof: &Proof<SC>,
) -> Result<(), ProofShapeError> {
    let num_airs = mvk.per_air.len();
    let l_skip = mvk.params.l_skip;

    if proof.trace_vdata.len() != num_airs {
        return ProofShapeError::invalid_vdata(ProofShapeVDataError::InvalidVDataLength {
            len: proof.trace_vdata.len(),
            num_airs,
        });
    } else if proof.public_values.len() != num_airs {
        return ProofShapeError::invalid_vdata(ProofShapeVDataError::InvalidPublicValuesLength {
            len: proof.public_values.len(),
            num_airs,
        });
    }

    for (air_idx, (vk, vdata, pvs)) in
        izip!(&mvk.per_air, &proof.trace_vdata, &proof.public_values).enumerate()
    {
        if vdata.is_none() {
            if vk.is_required {
                return ProofShapeError::invalid_vdata(ProofShapeVDataError::RequiredAirNoVData {
                    air_idx,
                });
            } else if !pvs.is_empty() {
                return ProofShapeError::invalid_vdata(ProofShapeVDataError::PublicValuesNoVData {
                    air_idx,
                });
            }
        } else {
            let vdata = vdata.as_ref().unwrap();
            if vdata.cached_commitments.len() != vk.num_cached_mains() {
                return ProofShapeError::invalid_vdata(
                    ProofShapeVDataError::InvalidCachedCommitments {
                        air_idx,
                        expected: vk.num_cached_mains(),
                        actual: vdata.cached_commitments.len(),
                    },
                );
            } else if vdata.log_height > l_skip + mvk.params.n_stack {
                return ProofShapeError::invalid_vdata(
                    ProofShapeVDataError::LogHeightOutOfBounds {
                        air_idx,
                        l_skip,
                        n_stack: mvk.params.n_stack,
                        actual: vdata.log_height,
                    },
                );
            } else if vk.params.num_public_values != pvs.len() {
                return ProofShapeError::invalid_vdata(ProofShapeVDataError::InvalidPublicValues {
                    air_idx,
                    expected: vk.params.num_public_values,
                    actual: pvs.len(),
                });
            }
        }
    }

    Ok(())
}

/// GKR proof: round count derived from the total interaction count, and per-round sumcheck
/// polynomial arity.
fn verify_gkr_shape<SC: StarkProtocolConfig>(
    mvk: &MultiStarkVerifyingKeyInner<SC>,
    per_trace: &[PerTraceEntry<'_, SC>],
    gkr_proof: &GkrProof<SC>,
) -> Result<(), ProofShapeError> {
    let l_skip = mvk.params.l_skip;
    let (_, num_gkr_rounds, _) = present_gkr_shape(
        l_skip,
        per_trace
            .iter()
            .map(|(_, vk, vdata)| (vk.num_interactions(), vdata.log_height)),
    );

    if gkr_proof.claims_per_layer.len() != num_gkr_rounds {
        return ProofShapeError::invalid_gkr(GkrProofShapeError::InvalidClaimsPerLayer {
            expected: num_gkr_rounds,
            actual: gkr_proof.claims_per_layer.len(),
        });
    } else if gkr_proof.sumcheck_polys.len() != num_gkr_rounds.saturating_sub(1) {
        return ProofShapeError::invalid_gkr(GkrProofShapeError::InvalidSumcheckPolys {
            expected: num_gkr_rounds.saturating_sub(1),
            actual: gkr_proof.sumcheck_polys.len(),
        });
    }

    for (i, poly) in gkr_proof.sumcheck_polys.iter().enumerate() {
        if poly.len() != i + 1 {
            return ProofShapeError::invalid_gkr(GkrProofShapeError::InvalidSumcheckPolyEvals {
                round: i + 1,
                expected: i + 1,
                actual: poly.len(),
            });
        }
    }

    Ok(())
}

/// Batch constraint proof: per-present-AIR term counts, round-0 univariate degree, multilinear
/// round count/arity, and per-part column-opening counts.
fn verify_batch_constraint_shape<SC: StarkProtocolConfig>(
    mvk: &MultiStarkVerifyingKeyInner<SC>,
    per_trace: &[PerTraceEntry<'_, SC>],
    batch_proof: &BatchConstraintProof<SC>,
) -> Result<(), ProofShapeError> {
    let l_skip = mvk.params.l_skip;
    let num_airs_present = per_trace.len();
    let n_max = per_trace[0].2.log_height.saturating_sub(l_skip);

    let s_0_deg = (mvk.max_constraint_degree() + 1) * ((1 << l_skip) - 1);
    if batch_proof.numerator_term_per_air.len() != num_airs_present {
        return ProofShapeError::invalid_batch_constraint(
            BatchProofShapeError::InvalidNumeratorTerms {
                expected: num_airs_present,
                actual: batch_proof.numerator_term_per_air.len(),
            },
        );
    } else if batch_proof.denominator_term_per_air.len() != num_airs_present {
        return ProofShapeError::invalid_batch_constraint(
            BatchProofShapeError::InvalidDenominatorTerms {
                expected: num_airs_present,
                actual: batch_proof.denominator_term_per_air.len(),
            },
        );
    } else if batch_proof.univariate_round_coeffs.len() != s_0_deg + 1 {
        return ProofShapeError::invalid_batch_constraint(
            BatchProofShapeError::InvalidUnivariateRoundCoeffs {
                expected: s_0_deg + 1,
                actual: batch_proof.univariate_round_coeffs.len(),
            },
        );
    } else if batch_proof.sumcheck_round_polys.len() != n_max {
        return ProofShapeError::invalid_batch_constraint(
            BatchProofShapeError::InvalidSumcheckRoundPolys {
                expected: n_max,
                actual: batch_proof.sumcheck_round_polys.len(),
            },
        );
    } else if batch_proof.column_openings.len() != num_airs_present {
        return ProofShapeError::invalid_batch_constraint(
            BatchProofShapeError::InvalidColumnOpeningsAirs {
                expected: num_airs_present,
                actual: batch_proof.column_openings.len(),
            },
        );
    }

    for (i, evals) in batch_proof.sumcheck_round_polys.iter().enumerate() {
        if evals.len() != mvk.max_constraint_degree() + 1 {
            return ProofShapeError::invalid_batch_constraint(
                BatchProofShapeError::InvalidSumcheckRoundPolyEvals {
                    round: i,
                    expected: mvk.max_constraint_degree() + 1,
                    actual: evals.len(),
                },
            );
        }
    }

    for (part_openings, &(air_idx, vk, _)) in batch_proof.column_openings.iter().zip(per_trace) {
        let need_rot = mvk.per_air[air_idx].params.need_rot;
        let openings_per_col = if need_rot { 2 } else { 1 };
        if part_openings.len() != vk.num_parts() {
            return ProofShapeError::invalid_batch_constraint(
                BatchProofShapeError::InvalidColumnOpeningsPerAir {
                    air_idx,
                    expected: vk.num_parts(),
                    actual: part_openings.len(),
                },
            );
        } else if part_openings[0].len() != vk.params.width.common_main * openings_per_col {
            return ProofShapeError::invalid_batch_constraint(
                BatchProofShapeError::InvalidColumnOpeningsPerAirMain {
                    air_idx,
                    expected: vk.params.width.common_main,
                    actual: part_openings[0].len(),
                },
            );
        } else if let Some(preprocessed_width) = &vk.params.width.preprocessed {
            if part_openings[1].len() != *preprocessed_width * openings_per_col {
                return ProofShapeError::invalid_batch_constraint(
                    BatchProofShapeError::InvalidColumnOpeningsPerAirPreprocessed {
                        air_idx,
                        expected: *preprocessed_width,
                        actual: part_openings[1].len(),
                    },
                );
            }
        }

        let cached_openings = &part_openings[1 + (vk.preprocessed_data.is_some() as usize)..];
        for (cached_idx, (col_opening, &width)) in cached_openings
            .iter()
            .zip(&vk.params.width.cached_mains)
            .enumerate()
        {
            if col_opening.len() != width * openings_per_col {
                return ProofShapeError::invalid_batch_constraint(
                    BatchProofShapeError::InvalidColumnOpeningsPerAirCached {
                        air_idx,
                        cached_idx,
                        expected: width,
                        actual: col_opening.len(),
                    },
                );
            }
        }
    }

    Ok(())
}

/// Stacking proof: round-0 univariate degree, `n_stack` round polynomials, and per-commit
/// opening counts. Re-derives the `StackedLayout` of every commitment from the vkey + claimed
/// trace heights (commitment order: common-main first, then one layout per
/// preprocessed/cached part) — the layout is never trusted from the proof.
fn verify_stacking_shape<SC: StarkProtocolConfig>(
    mvk: &MultiStarkVerifyingKeyInner<SC>,
    per_trace: &[PerTraceEntry<'_, SC>],
    stacking_proof: &StackingProof<SC>,
) -> Result<Vec<StackedLayout>, ProofShapeError> {
    let l_skip = mvk.params.l_skip;

    let s_0_deg = 2 * ((1 << l_skip) - 1);
    if stacking_proof.univariate_round_coeffs.len() != s_0_deg + 1 {
        return ProofShapeError::invalid_stacking(
            StackingProofShapeError::InvalidUnivariateRoundCoeffs {
                expected: s_0_deg + 1,
                actual: stacking_proof.univariate_round_coeffs.len(),
            },
        );
    } else if stacking_proof.sumcheck_round_polys.len() != mvk.params.n_stack {
        return ProofShapeError::invalid_stacking(
            StackingProofShapeError::InvalidSumcheckRoundPolys {
                expected: mvk.params.n_stack,
                actual: stacking_proof.sumcheck_round_polys.len(),
            },
        );
    }

    // Layout re-derivation cannot fail for a proof that passed the vdata checks: every
    // `log_height` is already bounded by `l_skip + n_stack` (no `LayoutHeightExceeded`), and
    // `per_trace` is height-sorted with power-of-two lifted lengths, so `row_idx` is always a
    // multiple of the next slice length (no `LayoutRowOverflow`). The `?` is defense in depth:
    // the verifier must not unwrap on proof-derived data.
    let common_main_layout = StackedLayout::new(
        l_skip,
        mvk.params.n_stack + l_skip,
        per_trace
            .iter()
            .map(|(_, vk, vdata)| (vk.params.width.common_main, vdata.log_height))
            .collect_vec(),
    )?;

    let other_layouts = if mvk.merged_preprocessed_commit.is_some() {
        // Merged mode: ONE multi-matrix layout holding every preprocessed matrix, in trace
        // order (per_trace is height-descending, so the filtered subsequence is too — the
        // same `(Reverse(log_height), air_idx)` order the keygen commit used), followed by
        // per-trace cached single-matrix layouts.
        // Matrix membership keyed on `preprocessed_data.is_some()` — the SAME predicate
        // used for `has_prep_per_trace` and the merged need_rot vector — so the layout,
        // claims, and rot flags can never disagree on which traces are in the commitment.
        let prep_mats = per_trace
            .iter()
            .filter_map(|(_, vk, vdata)| {
                vk.preprocessed_data
                    .as_ref()
                    .and(vk.params.width.preprocessed)
                    .map(|width| (width, vdata.log_height))
            })
            .collect_vec();
        debug_assert!(!prep_mats.is_empty());
        let mut layouts = vec![StackedLayout::new(
            l_skip,
            mvk.params.n_stack + l_skip,
            prep_mats,
        )?];
        for (_, vk, vdata) in per_trace.iter() {
            for &width in &vk.params.width.cached_mains {
                layouts.push(StackedLayout::new(
                    l_skip,
                    mvk.params.n_stack + l_skip,
                    vec![(width, vdata.log_height)],
                )?);
            }
        }
        layouts
    } else {
        per_trace
            .iter()
            .flat_map(|(_, vk, vdata)| {
                vk.params
                    .width
                    .preprocessed
                    .iter()
                    .chain(&vk.params.width.cached_mains)
                    .copied()
                    .map(|width| (width, vdata.log_height))
                    .collect_vec()
            })
            .map(|sorted| StackedLayout::new(l_skip, mvk.params.n_stack + l_skip, vec![sorted]))
            .collect::<Result<Vec<_>, _>>()?
    };

    // layouts.len() is the total number of commitments, which is always >= 1. The total number is
    // NOT determined from the vkey because it depends on which traces are present.
    let layouts = [common_main_layout]
        .into_iter()
        .chain(other_layouts)
        .collect_vec();

    let total_stacked_width: usize = layouts.iter().map(StackedLayout::width).sum();
    if total_stacked_width > mvk.params.w_stack {
        return ProofShapeError::invalid_stacking(
            StackingProofShapeError::TotalStackedWidthOutOfBounds {
                w_stack: mvk.params.w_stack,
                actual: total_stacked_width,
            },
        );
    }

    if stacking_proof.stacking_openings.len() != layouts.len() {
        return ProofShapeError::invalid_stacking(StackingProofShapeError::InvalidStackOpenings {
            expected: layouts.len(),
            actual: stacking_proof.stacking_openings.len(),
        });
    }

    for (commit_idx, (openings, layout)) in stacking_proof
        .stacking_openings
        .iter()
        .zip(&layouts)
        .enumerate()
    {
        let stacked_matrix_width = layout.width();
        if openings.len() != stacked_matrix_width {
            return ProofShapeError::invalid_stacking(
                StackingProofShapeError::InvalidStackOpeningsPerMatrix {
                    commit_idx,
                    expected: stacked_matrix_width,
                    actual: openings.len(),
                },
            );
        }
    }

    Ok(layouts)
}

/// WHIR proof: round/sumcheck/query counts against the WHIR parameters, opened-row shapes
/// against the re-derived layouts, and Merkle proof depths per round.
///
/// Requires [`verify_stacking_shape`] to have passed first: the per-commit opened-row width
/// check reads `stacking_proof.stacking_openings[commit_idx]`, whose length that helper
/// validated against `layouts`.
fn verify_whir_shape<SC: StarkProtocolConfig>(
    mvk: &MultiStarkVerifyingKeyInner<SC>,
    layouts: &[StackedLayout],
    stacking_proof: &StackingProof<SC>,
    whir_proof: &WhirProof<SC>,
) -> Result<(), ProofShapeError> {
    debug_assert_eq!(stacking_proof.stacking_openings.len(), layouts.len());
    let log_stacked_height = mvk.params.log_stacked_height();
    let num_whir_rounds = mvk.params.num_whir_rounds();
    let num_whir_sumcheck_rounds = mvk.params.num_whir_sumcheck_rounds();
    let k_whir = mvk.params.k_whir();
    debug_assert_ne!(num_whir_rounds, 0);

    if whir_proof.whir_sumcheck_polys.len() != num_whir_sumcheck_rounds {
        return ProofShapeError::invalid_whir(WhirProofShapeError::InvalidSumcheckPolys {
            expected: num_whir_sumcheck_rounds,
            actual: whir_proof.whir_sumcheck_polys.len(),
        });
    } else if whir_proof.codeword_commits.len() != num_whir_rounds - 1 {
        return ProofShapeError::invalid_whir(WhirProofShapeError::InvalidCodewordCommits {
            expected: num_whir_rounds - 1,
            actual: whir_proof.codeword_commits.len(),
        });
    } else if whir_proof.ood_values.len() != num_whir_rounds - 1 {
        return ProofShapeError::invalid_whir(WhirProofShapeError::InvalidOodValues {
            expected: num_whir_rounds - 1,
            actual: whir_proof.ood_values.len(),
        });
    } else if whir_proof.folding_pow_witnesses.len() != num_whir_sumcheck_rounds {
        return ProofShapeError::invalid_whir(WhirProofShapeError::InvalidFoldingPowWitnesses {
            expected: num_whir_sumcheck_rounds,
            actual: whir_proof.folding_pow_witnesses.len(),
        });
    } else if whir_proof.query_phase_pow_witnesses.len() != num_whir_rounds {
        return ProofShapeError::invalid_whir(WhirProofShapeError::InvalidQueryPhasePowWitnesses {
            expected: num_whir_rounds,
            actual: whir_proof.query_phase_pow_witnesses.len(),
        });
    } else if whir_proof.initial_round_opened_rows.len() != layouts.len() {
        return ProofShapeError::invalid_whir(WhirProofShapeError::InvalidInitialRoundOpenedRows {
            expected: layouts.len(),
            actual: whir_proof.initial_round_opened_rows.len(),
        });
    } else if whir_proof.initial_round_merkle_proofs.len() != layouts.len() {
        return ProofShapeError::invalid_whir(
            WhirProofShapeError::InvalidInitialRoundMerkleProofs {
                expected: layouts.len(),
                actual: whir_proof.initial_round_merkle_proofs.len(),
            },
        );
    } else if whir_proof.codeword_opened_values.len() != num_whir_rounds - 1 {
        return ProofShapeError::invalid_whir(WhirProofShapeError::InvalidCodewordOpenedRows {
            expected: num_whir_rounds - 1,
            actual: whir_proof.codeword_opened_values.len(),
        });
    } else if whir_proof.codeword_merkle_proofs.len() != num_whir_rounds - 1 {
        return ProofShapeError::invalid_whir(WhirProofShapeError::InvalidCodewordMerkleProofs {
            expected: num_whir_rounds - 1,
            actual: whir_proof.codeword_merkle_proofs.len(),
        });
    } else if whir_proof.final_poly.len() != 1 << mvk.params.log_final_poly_len() {
        return ProofShapeError::invalid_whir(WhirProofShapeError::InvalidFinalPolyLen {
            expected: 1 << mvk.params.log_final_poly_len(),
            actual: whir_proof.final_poly.len(),
        });
    }

    let initial_whir_round_num_queries = mvk.params.whir.rounds[0].num_queries;
    for (commit_idx, (opened_rows, merkle_proofs)) in whir_proof
        .initial_round_opened_rows
        .iter()
        .zip(&whir_proof.initial_round_merkle_proofs)
        .enumerate()
    {
        if opened_rows.len() != initial_whir_round_num_queries {
            return ProofShapeError::invalid_whir(
                WhirProofShapeError::InvalidInitialRoundOpenedRowsQueries {
                    commit_idx,
                    expected: initial_whir_round_num_queries,
                    actual: opened_rows.len(),
                },
            );
        } else if merkle_proofs.len() != initial_whir_round_num_queries {
            return ProofShapeError::invalid_whir(
                WhirProofShapeError::InvalidInitialRoundMerkleProofsQueries {
                    commit_idx,
                    expected: initial_whir_round_num_queries,
                    actual: merkle_proofs.len(),
                },
            );
        }
        let width = stacking_proof.stacking_openings[commit_idx].len();
        for (opened_idx, rows) in opened_rows.iter().enumerate() {
            if rows.len() != 1 << k_whir {
                return ProofShapeError::invalid_whir(
                    WhirProofShapeError::InvalidInitialRoundOpenedRowK {
                        opened_idx,
                        commit_idx,
                        expected: 1 << k_whir,
                        actual: rows.len(),
                    },
                );
            }
            for (row_idx, row) in rows.iter().enumerate() {
                if row.len() != width {
                    return ProofShapeError::invalid_whir(
                        WhirProofShapeError::InvalidInitialRoundOpenedRowWidth {
                            row_idx,
                            commit_idx,
                            expected: width,
                            actual: row.len(),
                        },
                    );
                }
            }
        }

        let merkle_depth = (log_stacked_height + mvk.params.log_blowup).saturating_sub(k_whir);
        for (opened_idx, proof) in merkle_proofs.iter().enumerate() {
            if proof.len() != merkle_depth {
                return ProofShapeError::invalid_whir(
                    WhirProofShapeError::InvalidInitialRoundMerkleProofDepth {
                        opened_idx,
                        commit_idx,
                        expected: merkle_depth,
                        actual: proof.len(),
                    },
                );
            }
        }
    }

    for (round_minus_one, (opened_values_per_query, merkle_proofs)) in whir_proof
        .codeword_opened_values
        .iter()
        .zip(&whir_proof.codeword_merkle_proofs)
        .take(num_whir_rounds - 1)
        .enumerate()
    {
        let round = round_minus_one + 1;
        let num_queries = mvk.params.whir.rounds[round].num_queries;
        if opened_values_per_query.len() != num_queries {
            return ProofShapeError::invalid_whir(
                WhirProofShapeError::InvalidCodewordOpenedRowsQueries {
                    round,
                    expected: num_queries,
                    actual: opened_values_per_query.len(),
                },
            );
        } else if merkle_proofs.len() != num_queries {
            return ProofShapeError::invalid_whir(
                WhirProofShapeError::InvalidCodewordMerkleProofsQueries {
                    round,
                    expected: num_queries,
                    actual: merkle_proofs.len(),
                },
            );
        }

        for (opened_idx, opened_values) in opened_values_per_query.iter().enumerate() {
            if opened_values.len() != 1 << mvk.params.k_whir() {
                return ProofShapeError::invalid_whir(
                    WhirProofShapeError::InvalidCodewordOpenedValues {
                        round,
                        opened_idx,
                        expected: 1 << mvk.params.k_whir(),
                        actual: opened_values.len(),
                    },
                );
            }
        }

        let merkle_depth = log_stacked_height + mvk.params.log_blowup - k_whir - round;
        for (opened_idx, proof) in merkle_proofs.iter().enumerate() {
            if proof.len() != merkle_depth {
                return ProofShapeError::invalid_whir(
                    WhirProofShapeError::InvalidCodewordMerkleProofDepth {
                        round,
                        opened_idx,
                        expected: merkle_depth,
                        actual: proof.len(),
                    },
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::{
        config::koala_bear_poseidon2::{Digest, DuplexSponge, KoalaBearPoseidon2Config, EF, F},
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        keygen::MultiStarkKeygenBuilder,
        lookup::LookupType,
        test_utils::{
            dummy_airs::fib_air::air::FibonacciAir, test_system_params_small, CachedFixture11,
            FibFixture, InteractionsFixture11, SelfInteractionFixture, TestFixture,
        },
        StarkEngine, SystemParams,
    };

    type Sc = KoalaBearPoseidon2Config;
    type Engine = KoalaBearPoseidon2RefEngine<DuplexSponge>;

    fn params() -> SystemParams {
        test_system_params_small(2, 5, 3)
    }

    fn fib_setup() -> (MultiStarkVerifyingKeyInner<Sc>, Proof<Sc>) {
        let engine = Engine::new(params());
        let (vk, proof) = FibFixture::new(0, 1, 1 << 5).keygen_and_prove(&engine);
        (vk.inner, proof)
    }

    fn interactions_setup() -> (MultiStarkVerifyingKeyInner<Sc>, Proof<Sc>) {
        let engine = Engine::new(params());
        let (vk, proof) = InteractionsFixture11.keygen_and_prove(&engine);
        (vk.inner, proof)
    }

    /// An honestly generated proof passes the shape check; a single-AIR fixture with no
    /// preprocessed or cached parts stacks into exactly one commitment.
    #[test]
    fn accepts_fib_proof_single_layout() {
        let (mvk, proof) = fib_setup();
        let layouts = verify_proof_shape(&mvk, &proof).expect("honest proof must pass");
        assert_eq!(layouts.len(), 1);
        assert_eq!(
            layouts[0].width_of(0),
            mvk.per_air[0].params.width.common_main
        );
    }

    /// Cached parts get one stacked commitment each: 2 AIRs with 1 cached part
    /// apiece yield 1 common-main layout + 2 cached layouts, in that order.
    #[test]
    fn accepts_cached_proof_one_layout_per_part() {
        let engine = Engine::new(params());
        let config = KoalaBearPoseidon2Config::default_from_params(params());
        let (vk, proof) = CachedFixture11::new(config).keygen_and_prove(&engine);
        let layouts = verify_proof_shape(&vk.inner, &proof).expect("honest proof must pass");
        assert_eq!(layouts.len(), 3);
    }

    /// Equal-height traces must be ordered air-index-ascending in the re-derived layout — the
    /// same tie-break the prover uses (`prover/types.rs`). The verifier relies on its sort
    /// being stable; this pins that behavior against a future `sort_unstable` regression.
    #[test]
    fn tie_break_equal_heights_is_air_index_ascending() {
        let engine = Engine::new(params());
        let (vk, proof) =
            SelfInteractionFixture::new(vec![4, 7], 5, LookupType::Byte).keygen_and_prove(&engine);
        let mvk = vk.inner;

        let log_heights: Vec<_> = proof
            .trace_vdata
            .iter()
            .map(|v| v.as_ref().unwrap().log_height)
            .collect();
        assert_eq!(log_heights[0], log_heights[1], "fixture must tie on height");

        let w0 = mvk.per_air[0].params.width.common_main;
        let w1 = mvk.per_air[1].params.width.common_main;
        assert_ne!(w0, w1, "fixture widths must differ to observe the order");

        let layouts = verify_proof_shape(&mvk, &proof).expect("honest proof must pass");
        assert_eq!(layouts[0].width_of(0), w0);
        assert_eq!(layouts[0].width_of(1), w1);
    }

    /// vdata-section rejections: every mutation returns its dedicated error variant.
    #[test]
    fn rejects_bad_vdata_shapes() {
        let (mvk, proof) = fib_setup();

        let mut bad = proof.clone();
        bad.trace_vdata.pop();
        assert_eq!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidVData(ProofShapeVDataError::InvalidVDataLength {
                len: 0,
                num_airs: 1
            })
        );

        let mut bad = proof.clone();
        bad.public_values.push(vec![]);
        assert_eq!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidVData(ProofShapeVDataError::InvalidPublicValuesLength {
                len: 2,
                num_airs: 1
            })
        );

        let mut bad = proof.clone();
        let log_height_bound = mvk.params.l_skip + mvk.params.n_stack;
        bad.trace_vdata[0].as_mut().unwrap().log_height = log_height_bound + 1;
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidVData(ProofShapeVDataError::LogHeightOutOfBounds { .. })
        ));

        let mut bad = proof.clone();
        bad.trace_vdata[0]
            .as_mut()
            .unwrap()
            .cached_commitments
            .push(Digest::default());
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidVData(ProofShapeVDataError::InvalidCachedCommitments { .. })
        ));

        let mut bad = proof.clone();
        bad.public_values[0].push(F::ZERO);
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidVData(ProofShapeVDataError::InvalidPublicValues { .. })
        ));
    }

    /// An AIR registered with `add_required_air` must be present: a proof with `None` vdata for
    /// it is rejected. (Engine fixtures register all AIRs optional, so the key is built
    /// manually.)
    #[test]
    fn rejects_required_air_without_vdata() {
        let config = KoalaBearPoseidon2Config::default_from_params(params());
        let mut keygen_builder = MultiStarkKeygenBuilder::new(config);
        keygen_builder.add_required_air(Arc::new(FibonacciAir));
        let pk = keygen_builder.generate_pk().unwrap();
        let vk = pk.get_vk();
        assert!(vk.inner.per_air[0].is_required);

        let engine = Engine::new(params());
        let proof = FibFixture::new(0, 1, 1 << 5).prove(&engine, &pk);
        assert!(verify_proof_shape(&vk.inner, &proof).is_ok());

        let mut bad = proof;
        bad.trace_vdata[0] = None;
        assert_eq!(
            verify_proof_shape(&vk.inner, &bad).unwrap_err(),
            ProofShapeError::InvalidVData(ProofShapeVDataError::RequiredAirNoVData { air_idx: 0 })
        );
    }

    /// A proof where every AIR is absent must be rejected, not panic the verifier: production
    /// keys register all AIRs optional (`engine.keygen` uses `add_air`), so this shape is
    /// reachable from adversarial input.
    #[test]
    fn rejects_all_absent_traces_without_panicking() {
        let (mvk, proof) = fib_setup();
        let mut bad = proof;
        bad.trace_vdata[0] = None;
        bad.public_values[0] = vec![];
        assert_eq!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::NoTracesPresent
        );
    }

    /// GKR-section rejections (requires a fixture with interactions so GKR rounds exist).
    #[test]
    fn rejects_bad_gkr_shapes() {
        let (mvk, proof) = interactions_setup();
        assert!(verify_proof_shape(&mvk, &proof).is_ok());

        let mut bad = proof.clone();
        bad.gkr_proof.claims_per_layer.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidGkrProofShape(GkrProofShapeError::InvalidClaimsPerLayer { .. })
        ));

        let mut bad = proof.clone();
        bad.gkr_proof.sumcheck_polys.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidGkrProofShape(GkrProofShapeError::InvalidSumcheckPolys { .. })
        ));

        let mut bad = proof.clone();
        bad.gkr_proof.sumcheck_polys[0].push([EF::ZERO; 3]);
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidGkrProofShape(
                GkrProofShapeError::InvalidSumcheckPolyEvals { .. }
            )
        ));
    }

    /// Batch-constraint-section rejections.
    #[test]
    fn rejects_bad_batch_constraint_shapes() {
        let (mvk, proof) = fib_setup();

        let mut bad = proof.clone();
        bad.batch_constraint_proof.numerator_term_per_air.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidBatchConstraintProofShape(
                BatchProofShapeError::InvalidNumeratorTerms { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.batch_constraint_proof.denominator_term_per_air.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidBatchConstraintProofShape(
                BatchProofShapeError::InvalidDenominatorTerms { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.batch_constraint_proof.univariate_round_coeffs.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidBatchConstraintProofShape(
                BatchProofShapeError::InvalidUnivariateRoundCoeffs { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.batch_constraint_proof.sumcheck_round_polys.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidBatchConstraintProofShape(
                BatchProofShapeError::InvalidSumcheckRoundPolys { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.batch_constraint_proof.sumcheck_round_polys[0].push(EF::ZERO);
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidBatchConstraintProofShape(
                BatchProofShapeError::InvalidSumcheckRoundPolyEvals { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.batch_constraint_proof.column_openings.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidBatchConstraintProofShape(
                BatchProofShapeError::InvalidColumnOpeningsAirs { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.batch_constraint_proof.column_openings[0][0].pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidBatchConstraintProofShape(
                BatchProofShapeError::InvalidColumnOpeningsPerAirMain { .. }
            )
        ));
    }

    /// Stacking-section rejections, including the `w_stack` budget check.
    #[test]
    fn rejects_bad_stacking_shapes() {
        let (mvk, proof) = fib_setup();

        let mut bad = proof.clone();
        bad.stacking_proof.univariate_round_coeffs.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidStackingProofShape(
                StackingProofShapeError::InvalidUnivariateRoundCoeffs { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.stacking_proof.sumcheck_round_polys.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidStackingProofShape(
                StackingProofShapeError::InvalidSumcheckRoundPolys { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.stacking_proof.stacking_openings.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidStackingProofShape(
                StackingProofShapeError::InvalidStackOpenings { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.stacking_proof.stacking_openings[0].pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidStackingProofShape(
                StackingProofShapeError::InvalidStackOpeningsPerMatrix { .. }
            )
        ));

        // The stacked width budget comes from the (trusted) vkey; a proof whose layouts exceed
        // it is rejected.
        let mut small_budget_mvk = mvk.clone();
        small_budget_mvk.params.w_stack = 0;
        assert!(matches!(
            verify_proof_shape(&small_budget_mvk, &proof).unwrap_err(),
            ProofShapeError::InvalidStackingProofShape(
                StackingProofShapeError::TotalStackedWidthOutOfBounds { .. }
            )
        ));
    }

    /// WHIR-section rejections.
    #[test]
    fn rejects_bad_whir_shapes() {
        let (mvk, proof) = fib_setup();
        // The whir codeword mutations below need at least 2 WHIR rounds.
        assert!(mvk.params.num_whir_rounds() >= 2);

        let mut bad = proof.clone();
        bad.whir_proof.whir_sumcheck_polys.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidWhirProofShape(
                WhirProofShapeError::InvalidSumcheckPolys { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.whir_proof.codeword_commits.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidWhirProofShape(
                WhirProofShapeError::InvalidCodewordCommits { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.whir_proof.ood_values.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidWhirProofShape(WhirProofShapeError::InvalidOodValues { .. })
        ));

        let mut bad = proof.clone();
        bad.whir_proof.folding_pow_witnesses.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidWhirProofShape(
                WhirProofShapeError::InvalidFoldingPowWitnesses { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.whir_proof.query_phase_pow_witnesses.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidWhirProofShape(
                WhirProofShapeError::InvalidQueryPhasePowWitnesses { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.whir_proof.final_poly.pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidWhirProofShape(WhirProofShapeError::InvalidFinalPolyLen { .. })
        ));

        let mut bad = proof.clone();
        bad.whir_proof.initial_round_merkle_proofs[0][0].pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidWhirProofShape(
                WhirProofShapeError::InvalidInitialRoundMerkleProofDepth { .. }
            )
        ));

        let mut bad = proof.clone();
        bad.whir_proof.codeword_merkle_proofs[0][0].pop();
        assert!(matches!(
            verify_proof_shape(&mvk, &bad).unwrap_err(),
            ProofShapeError::InvalidWhirProofShape(
                WhirProofShapeError::InvalidCodewordMerkleProofDepth { .. }
            )
        ));
    }
}
