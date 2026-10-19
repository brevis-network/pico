use itertools::Itertools;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use thiserror::Error;

use crate::{
    keygen::types::{MultiStarkVerifyingKey, MultiStarkVerifyingKeyInner, StarkVerifyingKey},
    proof::{
        BatchConstraintProof, GkrLayerClaims, GkrProof, MerkleProof, Proof, StackingProof,
        TraceVData, WhirProof,
    },
    protocol::stacking::{present_gkr_shape, stacking_sort_key, StackedLayout, StackedPcsError},
    StarkProtocolConfig, TranscriptLog,
};

#[derive(Debug, Error)]
pub enum TranscriptExtractionError {
    #[error("transcript ended early at position {position}")]
    UnexpectedEnd { position: usize },

    #[error("expected a {expected} value at position {position}")]
    UnexpectedEntryKind {
        position: usize,
        expected: &'static str,
    },

    #[error(
        "transcript mismatch at position {position}: expected observed value {expected}, got {actual}"
    )]
    ValueMismatch {
        position: usize,
        expected: String,
        actual: String,
    },

    #[error("expected a boolean at position {position}, got {value}")]
    InvalidBool { position: usize, value: String },

    #[error("field value at position {position} does not fit into usize: {value}")]
    UsizeOverflow { position: usize, value: String },

    #[error("{message}")]
    InvalidDerivedValue { message: String },

    #[error("{label} should have {expected}, but has {actual}")]
    InvalidShape {
        label: String,
        expected: usize,
        actual: usize,
    },

    #[error("proof must contain at least one trace")]
    EmptyTraceSet,

    #[error("expected zero extension-field observation, got {actual}")]
    ExpectedZeroExtension { actual: String },

    #[error("stacked layout derivation failed: {0}")]
    InvalidLayout(#[from] StackedPcsError),

    #[error("transcript has {remaining} trailing entries starting at position {position}")]
    TrailingEntries { position: usize, remaining: usize },
}

type ExtractionResult<T> = Result<T, TranscriptExtractionError>;
type TracePreamble<SC> = (
    Vec<Option<TraceVData<SC>>>,
    Vec<Vec<<SC as StarkProtocolConfig>::F>>,
);
type MerkleProofSets<SC> = Vec<Vec<MerkleProof<<SC as StarkProtocolConfig>::Digest>>>;
type OpenedRows<F> = Vec<Vec<Vec<Vec<F>>>>;
type OpenedValueSets<EF> = Vec<Vec<Vec<EF>>>;
type ExtPair<SC> = [<SC as StarkProtocolConfig>::EF; 2];
type ExtTriple<SC> = [<SC as StarkProtocolConfig>::EF; 3];
type ExtOpenings<SC> = Vec<<SC as StarkProtocolConfig>::EF>;

fn invalid_shape(
    label: impl Into<String>,
    expected: usize,
    actual: usize,
) -> TranscriptExtractionError {
    TranscriptExtractionError::InvalidShape {
        label: label.into(),
        expected,
        actual,
    }
}

/// Out-of-band hints needed to reconstruct the full [`WhirProof`] value.
///
/// The extractor rebuilds the proof from Fiat-Shamir transcript observations plus verifier-known
/// public context. The current WHIR transcript does not explicitly observe the query openings or
/// the Merkle authentication paths, so those objects are supplied separately instead of being read
/// from the transcript.
///
/// This is acceptable because these hinted objects are Merkle-bound rather than
/// Fiat-Shamir-transcript-bound. The verifier's challenges depend on the committed Merkle roots
/// and the sampled query indices, not on the concrete authentication paths or leaf contents.
/// During verification, the opened rows / opened codeword values are hashed into Merkle leaves and
/// checked against those roots at those sampled indices. The query index fixes the left/right
/// sibling ordering along the authentication path. Therefore, once the root and index are fixed, a
/// different accepted opening or Merkle proof would imply a hash collision, second preimage, or
/// Merkle equivocation.
///
/// So these hints are acceptable for proof reconstruction, but transcript round-trip extraction
/// still does not show that WHIR query openings themselves are transcript-observed; it only shows
/// that they are externally bound by the Merkle commitment machinery.
///
/// In other words, this extractor currently proves:
/// - all transcript-bound proof data can be reconstructed from the log, and
/// - the remaining WHIR query objects are supplied under the usual Merkle binding assumption.
///
/// It does not prove that the current WHIR transcript observes those query objects. If WHIR later
/// starts observing them before challenge sampling, these hints should become unnecessary.
#[derive(Clone, Copy, Debug)]
pub struct WhirProofHints<'a, F, EF, Digest> {
    /// Initial-round opened rows, grouped by committed matrix and then by sampled query.
    pub initial_round_opened_rows: &'a [Vec<Vec<Vec<F>>>],
    /// Initial-round authentication paths for the opened-row queries.
    pub initial_round_merkle_proofs: &'a [Vec<MerkleProof<Digest>>],
    /// Later-round opened codeword values, grouped by round and then by sampled query.
    pub codeword_opened_values: &'a [Vec<Vec<EF>>],
    /// Later-round authentication paths for the opened codeword queries.
    pub codeword_merkle_proofs: &'a [Vec<MerkleProof<Digest>>],
}

impl<'a, SC: StarkProtocolConfig> From<&'a WhirProof<SC>>
    for WhirProofHints<'a, SC::F, SC::EF, SC::Digest>
{
    fn from(whir_proof: &'a WhirProof<SC>) -> Self {
        Self {
            initial_round_opened_rows: &whir_proof.initial_round_opened_rows,
            initial_round_merkle_proofs: &whir_proof.initial_round_merkle_proofs,
            codeword_opened_values: &whir_proof.codeword_opened_values,
            codeword_merkle_proofs: &whir_proof.codeword_merkle_proofs,
        }
    }
}

/// Reconstructs a [`Proof`] from a verifier transcript log plus verifier-known public context.
///
/// `whir_hints` is supplied separately because the current WHIR transcript does not fully carry the
/// query proof objects. Those hints are accepted because they are Merkle-bound for the sampled
/// query indices, not because they were observed by the transcript. See [`WhirProofHints`] for the
/// precise boundary.
///
/// This makes the extractor a strong Fiat-Shamir coverage check for every proof component except
/// the current WHIR query objects. For those, the test is weaker: it checks that the proof can be
/// reconstructed from the transcript plus Merkle-bound hints, rather than from the transcript
/// alone.
///
/// # Known limitation: merged-preprocessed vks are not supported
///
/// This extractor still expects the PER-AIR preprocessed observation schedule (one prep digest
/// per preprocessed AIR). Proofs made under a vk with `merged_preprocessed_commit: Some(_)`
/// (the recursion machines) observe ONE merged digest after the common-main commit and
/// log_heights per air instead — feeding such a transcript here fails loudly at
/// `expect_observe_digest`. Merged-mode transcripts therefore have no extract-roundtrip
/// coverage; the merged tests use prove+verify instead. Teach this function the merged
/// schedule (mirror `verifier::verify`) before relying on it for merged proofs.
pub fn extract_proof<SC, State, F, const RATE: usize>(
    mvk: &MultiStarkVerifyingKey<SC>,
    log: &TranscriptLog<F, State>,
    whir_hints: WhirProofHints<'_, F, SC::EF, SC::Digest>,
) -> ExtractionResult<Proof<SC>>
where
    SC: StarkProtocolConfig<F = F, Digest = [F; RATE]>,
    F: PrimeField64,
{
    let mut cursor = TranscriptCursor::new(log);
    cursor.expect_observe_digest::<RATE>(mvk.pre_hash)?;

    let common_main_commit = cursor.observe_digest::<RATE>()?;
    let (trace_vdata, public_values) =
        extract_trace_preamble::<SC, _, F, RATE>(&mut cursor, &mvk.inner)?;
    let shapes = ExtractionShape::new(&mvk.inner, &trace_vdata)?;
    let params = &mvk.inner.params;

    let gkr_proof = extract_gkr::<SC, _>(&mut cursor, params, &shapes)?;
    let batch_constraint_proof =
        extract_batch_constraints::<SC, _>(&mut cursor, &mvk.inner, &shapes)?;
    let stacking_proof = extract_stacking::<SC, _>(&mut cursor, params, &shapes.layouts)?;
    let whir_proof = extract_whir::<SC, _, F, RATE>(
        &mut cursor,
        params,
        &stacking_proof.stacking_openings,
        whir_hints,
    )?;

    cursor.finish()?;

    Ok(Proof {
        common_main_commit,
        trace_vdata,
        public_values,
        gkr_proof,
        batch_constraint_proof,
        stacking_proof,
        whir_proof,
    })
}

struct TranscriptCursor<'a, F, State> {
    log: &'a TranscriptLog<F, State>,
    position: usize,
}

impl<'a, F, State> TranscriptCursor<'a, F, State> {
    fn new(log: &'a TranscriptLog<F, State>) -> Self {
        Self { log, position: 0 }
    }
}

impl<F, State> TranscriptCursor<'_, F, State>
where
    F: PrimeField64,
{
    fn observe(&mut self) -> ExtractionResult<F> {
        self.next(false)
    }

    fn sample(&mut self) -> ExtractionResult<F> {
        self.next(true)
    }

    fn next(&mut self, want_sample: bool) -> ExtractionResult<F> {
        if self.position >= self.log.len() {
            return Err(TranscriptExtractionError::UnexpectedEnd {
                position: self.position,
            });
        }

        let is_sample = self.log.samples()[self.position];
        if is_sample != want_sample {
            return Err(TranscriptExtractionError::UnexpectedEntryKind {
                position: self.position,
                expected: if want_sample { "sampled" } else { "observed" },
            });
        }

        let value = self.log.values()[self.position];
        self.position += 1;
        Ok(value)
    }

    fn expect_observe(&mut self, expected: F) -> ExtractionResult<()> {
        let actual = self.next(false)?;
        if actual == expected {
            Ok(())
        } else {
            Err(TranscriptExtractionError::ValueMismatch {
                position: self.position - 1,
                expected: expected.to_string(),
                actual: actual.to_string(),
            })
        }
    }

    fn observe_bool(&mut self) -> ExtractionResult<bool> {
        let value = self.next(false)?;
        if value == F::ZERO {
            Ok(false)
        } else if value == F::ONE {
            Ok(true)
        } else {
            Err(TranscriptExtractionError::InvalidBool {
                position: self.position - 1,
                value: value.to_string(),
            })
        }
    }

    fn observe_usize(&mut self) -> ExtractionResult<usize> {
        let value = self.next(false)?;
        usize::try_from(value.as_canonical_u64()).map_err(|_| {
            TranscriptExtractionError::UsizeOverflow {
                position: self.position - 1,
                value: value.to_string(),
            }
        })
    }

    fn observe_digest<const RATE: usize>(&mut self) -> ExtractionResult<[F; RATE]> {
        let mut digest = [F::ZERO; RATE];
        for value in &mut digest {
            *value = self.next(false)?;
        }
        Ok(digest)
    }

    fn expect_observe_digest<const RATE: usize>(
        &mut self,
        expected: [F; RATE],
    ) -> ExtractionResult<()> {
        for value in expected {
            self.expect_observe(value)?;
        }
        Ok(())
    }

    fn observe_ext<SC>(&mut self) -> ExtractionResult<SC::EF>
    where
        SC: StarkProtocolConfig<F = F>,
    {
        let mut coeffs = Vec::with_capacity(SC::D_EF);
        for _ in 0..SC::D_EF {
            coeffs.push(self.next(false)?);
        }
        // `coeffs` has exactly `D_EF` entries, so the reconstruction cannot fail.
        Ok(SC::EF::from_basis_coefficients_slice(&coeffs).unwrap())
    }

    fn sample_ext<SC>(&mut self) -> ExtractionResult<SC::EF>
    where
        SC: StarkProtocolConfig<F = F>,
    {
        let mut coeffs = Vec::with_capacity(SC::D_EF);
        for _ in 0..SC::D_EF {
            coeffs.push(self.next(true)?);
        }
        // `coeffs` has exactly `D_EF` entries, so the reconstruction cannot fail.
        Ok(SC::EF::from_basis_coefficients_slice(&coeffs).unwrap())
    }

    fn observe_zero_ext<SC>(&mut self) -> ExtractionResult<()>
    where
        SC: StarkProtocolConfig<F = F>,
    {
        let value = self.observe_ext::<SC>()?;
        if value == SC::EF::ZERO {
            Ok(())
        } else {
            Err(TranscriptExtractionError::ExpectedZeroExtension {
                actual: value.to_string(),
            })
        }
    }

    fn extract_witness(&mut self, bits: usize) -> ExtractionResult<F> {
        if bits == 0 {
            Ok(F::ZERO)
        } else {
            let witness = self.next(false)?;
            let _pow_challenge = self.next(true)?;
            Ok(witness)
        }
    }

    fn finish(self) -> ExtractionResult<()> {
        if self.position == self.log.len() {
            Ok(())
        } else {
            Err(TranscriptExtractionError::TrailingEntries {
                position: self.position,
                remaining: self.log.len() - self.position,
            })
        }
    }
}

struct PresentTrace<'a, SC: StarkProtocolConfig> {
    air_id: usize,
    vk: &'a StarkVerifyingKey<SC::F, SC::Digest>,
    log_height: usize,
}

struct ExtractionShape<'a, SC: StarkProtocolConfig> {
    present_traces: Vec<PresentTrace<'a, SC>>,
    n_logup: usize,
    num_gkr_rounds: usize,
    n_max: usize,
    layouts: Vec<StackedLayout>,
}

impl<'a, SC: StarkProtocolConfig> ExtractionShape<'a, SC> {
    fn new(
        mvk: &'a MultiStarkVerifyingKeyInner<SC>,
        trace_vdata: &[Option<TraceVData<SC>>],
    ) -> ExtractionResult<Self> {
        let mut present_traces = mvk
            .per_air
            .iter()
            .zip(trace_vdata)
            .enumerate()
            .filter_map(|(air_id, (vk, vdata))| {
                vdata.as_ref().map(|vdata| PresentTrace {
                    air_id,
                    vk,
                    log_height: vdata.log_height,
                })
            })
            .collect_vec();
        present_traces.sort_by_key(|trace| stacking_sort_key(trace.log_height, trace.air_id));

        if present_traces.is_empty() {
            return Err(TranscriptExtractionError::EmptyTraceSet);
        }

        let l_skip = mvk.params.l_skip;
        let (n_logup, num_gkr_rounds, n_max) = present_gkr_shape(
            l_skip,
            present_traces
                .iter()
                .map(|trace| (trace.vk.num_interactions(), trace.log_height)),
        );
        let layouts = build_layouts(mvk, &present_traces)?;

        Ok(Self {
            present_traces,
            n_logup,
            num_gkr_rounds,
            n_max,
            layouts,
        })
    }
}

fn extract_trace_preamble<SC, State, F, const RATE: usize>(
    cursor: &mut TranscriptCursor<'_, F, State>,
    mvk: &MultiStarkVerifyingKeyInner<SC>,
) -> ExtractionResult<TracePreamble<SC>>
where
    SC: StarkProtocolConfig<F = F, Digest = [F; RATE]>,
    F: PrimeField64,
{
    let mut trace_vdata = vec![None; mvk.per_air.len()];
    let mut public_values = vec![Vec::new(); mvk.per_air.len()];

    for (air_id, avk) in mvk.per_air.iter().enumerate() {
        let is_present = if avk.is_required {
            true
        } else {
            cursor.observe_bool()?
        };

        if is_present {
            let log_height = if let Some(preprocessed) = &avk.preprocessed_data {
                cursor.expect_observe_digest::<RATE>(preprocessed.commit)?;
                mvk.params
                    .l_skip
                    .checked_add_signed(preprocessed.hypercube_dim)
                    .ok_or_else(|| TranscriptExtractionError::InvalidDerivedValue {
                        message: format!(
                            "preprocessed AIR {air_id} has invalid derived log height: l_skip={}, hypercube_dim={}",
                            mvk.params.l_skip, preprocessed.hypercube_dim
                        ),
                    })?
            } else {
                cursor.observe_usize()?
            };

            let mut cached_commitments = Vec::with_capacity(avk.params.width.cached_mains.len());
            for _ in 0..avk.params.width.cached_mains.len() {
                cached_commitments.push(cursor.observe_digest::<RATE>()?);
            }
            trace_vdata[air_id] = Some(TraceVData {
                log_height,
                cached_commitments,
            });

            let mut pvs = Vec::with_capacity(avk.params.num_public_values);
            for _ in 0..avk.params.num_public_values {
                pvs.push(cursor.observe()?);
            }
            public_values[air_id] = pvs;
        }
    }

    Ok((trace_vdata, public_values))
}

fn build_layouts<SC: StarkProtocolConfig>(
    mvk: &MultiStarkVerifyingKeyInner<SC>,
    present_traces: &[PresentTrace<'_, SC>],
) -> Result<Vec<StackedLayout>, StackedPcsError> {
    let l_skip = mvk.params.l_skip;
    let log_stacked_height = mvk.params.n_stack + l_skip;

    let common_main_layout = StackedLayout::new(
        l_skip,
        log_stacked_height,
        present_traces
            .iter()
            .map(|trace| (trace.vk.params.width.common_main, trace.log_height))
            .collect_vec(),
    )?;

    let other_layouts = present_traces
        .iter()
        .flat_map(|trace| {
            trace
                .vk
                .params
                .width
                .preprocessed
                .iter()
                .chain(&trace.vk.params.width.cached_mains)
                .copied()
                .map(|width| (width, trace.log_height))
                .collect_vec()
        })
        .map(|sorted| StackedLayout::new(l_skip, log_stacked_height, vec![sorted]))
        .collect::<Result<Vec<_>, _>>()?;

    Ok([common_main_layout]
        .into_iter()
        .chain(other_layouts)
        .collect())
}

fn extract_gkr<SC, State>(
    cursor: &mut TranscriptCursor<'_, SC::F, State>,
    params: &crate::SystemParams,
    shapes: &ExtractionShape<'_, SC>,
) -> ExtractionResult<GkrProof<SC>>
where
    SC: StarkProtocolConfig,
{
    let logup_pow_witness = cursor.extract_witness(params.logup.pow_bits)?;
    let _alpha_logup = cursor.sample_ext::<SC>()?;
    let _beta_logup = cursor.sample_ext::<SC>()?;

    if shapes.num_gkr_rounds == 0 {
        return Ok(GkrProof {
            logup_pow_witness,
            q0_claim: SC::EF::ONE,
            claims_per_layer: Vec::new(),
            sumcheck_polys: Vec::new(),
        });
    }

    let q0_claim = cursor.observe_ext::<SC>()?;
    let mut claims_per_layer = Vec::with_capacity(shapes.num_gkr_rounds);
    claims_per_layer.push(read_layer_claims::<SC, _>(cursor)?);

    let mut sumcheck_polys = Vec::with_capacity(shapes.num_gkr_rounds.saturating_sub(1));
    let _mu0 = cursor.sample_ext::<SC>()?;
    for round in 1..shapes.num_gkr_rounds {
        let _lambda = cursor.sample_ext::<SC>()?;
        let mut round_polys = Vec::with_capacity(round);
        for _ in 0..round {
            round_polys.push(read_ext_array3::<SC, _>(cursor)?);
            let _ri = cursor.sample_ext::<SC>()?;
        }
        sumcheck_polys.push(round_polys);
        claims_per_layer.push(read_layer_claims::<SC, _>(cursor)?);
        let _mu = cursor.sample_ext::<SC>()?;
    }

    Ok(GkrProof {
        logup_pow_witness,
        q0_claim,
        claims_per_layer,
        sumcheck_polys,
    })
}

fn extract_batch_constraints<SC, State>(
    cursor: &mut TranscriptCursor<'_, SC::F, State>,
    mvk: &MultiStarkVerifyingKeyInner<SC>,
    shapes: &ExtractionShape<'_, SC>,
) -> ExtractionResult<BatchConstraintProof<SC>>
where
    SC: StarkProtocolConfig,
{
    let l_skip = mvk.params.l_skip;
    let xi_len = shapes.num_gkr_rounds;
    let target_xi_len = l_skip + shapes.n_max.max(shapes.n_logup);
    for _ in xi_len..target_xi_len {
        let _pad = cursor.sample_ext::<SC>()?;
    }
    let _lambda = cursor.sample_ext::<SC>()?;

    let mut numerator_term_per_air = Vec::with_capacity(shapes.present_traces.len());
    let mut denominator_term_per_air = Vec::with_capacity(shapes.present_traces.len());
    for _ in 0..shapes.present_traces.len() {
        numerator_term_per_air.push(cursor.observe_ext::<SC>()?);
        denominator_term_per_air.push(cursor.observe_ext::<SC>()?);
    }

    let _mu = cursor.sample_ext::<SC>()?;

    let s0_len = (mvk.max_constraint_degree() + 1) * ((1 << l_skip) - 1) + 1;
    let mut univariate_round_coeffs = Vec::with_capacity(s0_len);
    for _ in 0..s0_len {
        univariate_round_coeffs.push(cursor.observe_ext::<SC>()?);
    }
    let _r0 = cursor.sample_ext::<SC>()?;

    let round_poly_len = mvk.max_constraint_degree() + 1;
    let mut sumcheck_round_polys = Vec::with_capacity(shapes.n_max);
    for _ in 0..shapes.n_max {
        let mut round = Vec::with_capacity(round_poly_len);
        for _ in 0..round_poly_len {
            round.push(cursor.observe_ext::<SC>()?);
        }
        sumcheck_round_polys.push(round);
        let _r = cursor.sample_ext::<SC>()?;
    }

    let mut column_openings = shapes
        .present_traces
        .iter()
        .map(|trace| vec![Vec::new(); trace.vk.num_parts()])
        .collect_vec();

    for (trace_idx, trace) in shapes.present_traces.iter().enumerate() {
        column_openings[trace_idx][0] = read_column_openings_part::<SC, _>(
            cursor,
            trace.vk.params.width.common_main,
            trace.vk.params.need_rot,
        )?;
    }

    for (trace_idx, trace) in shapes.present_traces.iter().enumerate() {
        let mut part_idx = 1;
        if let Some(width) = trace.vk.params.width.preprocessed {
            column_openings[trace_idx][part_idx] =
                read_column_openings_part::<SC, _>(cursor, width, trace.vk.params.need_rot)?;
            part_idx += 1;
        }
        for &width in &trace.vk.params.width.cached_mains {
            column_openings[trace_idx][part_idx] =
                read_column_openings_part::<SC, _>(cursor, width, trace.vk.params.need_rot)?;
            part_idx += 1;
        }
    }

    Ok(BatchConstraintProof {
        numerator_term_per_air,
        denominator_term_per_air,
        univariate_round_coeffs,
        sumcheck_round_polys,
        column_openings,
    })
}

fn extract_stacking<SC, State>(
    cursor: &mut TranscriptCursor<'_, SC::F, State>,
    params: &crate::SystemParams,
    layouts: &[StackedLayout],
) -> ExtractionResult<StackingProof<SC>>
where
    SC: StarkProtocolConfig,
{
    let _lambda = cursor.sample_ext::<SC>()?;

    let univariate_len = 2 * ((1 << params.l_skip) - 1) + 1;
    let mut univariate_round_coeffs = Vec::with_capacity(univariate_len);
    for _ in 0..univariate_len {
        univariate_round_coeffs.push(cursor.observe_ext::<SC>()?);
    }

    let _u0 = cursor.sample_ext::<SC>()?;
    let mut sumcheck_round_polys = Vec::with_capacity(params.n_stack);
    for _ in 0..params.n_stack {
        let mut evals = [SC::EF::ZERO; 2];
        for eval in &mut evals {
            *eval = cursor.observe_ext::<SC>()?;
        }
        sumcheck_round_polys.push(evals);
        let _u = cursor.sample_ext::<SC>()?;
    }

    let mut stacking_openings = Vec::with_capacity(layouts.len());
    for layout in layouts {
        let mut openings = Vec::with_capacity(layout.width());
        for _ in 0..layout.width() {
            openings.push(cursor.observe_ext::<SC>()?);
        }
        stacking_openings.push(openings);
    }

    Ok(StackingProof {
        univariate_round_coeffs,
        sumcheck_round_polys,
        stacking_openings,
    })
}

fn extract_whir<SC, State, F, const RATE: usize>(
    cursor: &mut TranscriptCursor<'_, F, State>,
    params: &crate::SystemParams,
    stacking_openings: &[Vec<SC::EF>],
    whir_hints: WhirProofHints<'_, F, SC::EF, SC::Digest>,
) -> ExtractionResult<WhirProof<SC>>
where
    SC: StarkProtocolConfig<F = F, Digest = [F; RATE]>,
    F: PrimeField64,
{
    let mu_pow_witness = cursor.extract_witness(params.whir.mu_pow_bits)?;
    let _mu = cursor.sample_ext::<SC>()?;

    let num_whir_rounds = params.num_whir_rounds();
    let num_whir_sumcheck_rounds = params.num_whir_sumcheck_rounds();
    let k_whir = params.k_whir();
    let widths = stacking_openings.iter().map(Vec::len).collect_vec();

    let mut whir_sumcheck_polys = Vec::with_capacity(num_whir_sumcheck_rounds);
    let mut codeword_commits = Vec::with_capacity(num_whir_rounds.saturating_sub(1));
    let mut ood_values = Vec::with_capacity(num_whir_rounds.saturating_sub(1));
    let mut folding_pow_witnesses = Vec::with_capacity(num_whir_sumcheck_rounds);
    let mut query_phase_pow_witnesses = Vec::with_capacity(num_whir_rounds);
    let mut final_poly = Vec::new();

    let initial_round_opened_rows =
        validate_initial_round_opened_rows(whir_hints.initial_round_opened_rows, &widths, params)?;
    let initial_round_merkle_proofs = validate_initial_round_merkle_proofs::<SC>(
        whir_hints.initial_round_merkle_proofs,
        &widths,
        params,
    )?;
    let codeword_opened_values =
        validate_codeword_opened_values(whir_hints.codeword_opened_values, params)?;
    let codeword_merkle_proofs =
        validate_codeword_merkle_proofs::<SC>(whir_hints.codeword_merkle_proofs, params)?;

    let mut remaining_sumcheck_rounds = num_whir_sumcheck_rounds;
    for (whir_round, round_params) in params.whir.rounds.iter().enumerate() {
        let rounds_this_whir = remaining_sumcheck_rounds.min(k_whir);
        for _ in 0..rounds_this_whir {
            whir_sumcheck_polys.push(read_ext_array2::<SC, _>(cursor)?);
            folding_pow_witnesses.push(cursor.extract_witness(params.whir.folding_pow_bits)?);
            let _alpha = cursor.sample_ext::<SC>()?;
        }
        remaining_sumcheck_rounds -= rounds_this_whir;

        let is_final_round = whir_round + 1 == num_whir_rounds;
        if is_final_round {
            final_poly = (0..(1 << params.log_final_poly_len()))
                .map(|_| cursor.observe_ext::<SC>())
                .collect::<Result<Vec<_>, _>>()?;
        } else {
            codeword_commits.push(cursor.observe_digest::<RATE>()?);
            let _z0 = cursor.sample_ext::<SC>()?;
            ood_values.push(cursor.observe_ext::<SC>()?);
        }

        query_phase_pow_witnesses.push(cursor.extract_witness(params.whir.query_phase_pow_bits)?);
        for _ in 0..round_params.num_queries {
            let _index = cursor.sample()?;
        }

        let _gamma = cursor.sample_ext::<SC>()?;
    }

    debug_assert_eq!(remaining_sumcheck_rounds, 0);

    Ok(WhirProof {
        mu_pow_witness,
        whir_sumcheck_polys,
        codeword_commits,
        ood_values,
        folding_pow_witnesses,
        query_phase_pow_witnesses,
        initial_round_opened_rows,
        initial_round_merkle_proofs,
        codeword_opened_values,
        codeword_merkle_proofs,
        final_poly,
    })
}

fn validate_initial_round_merkle_proofs<SC: StarkProtocolConfig>(
    initial_round_merkle_proofs: &[Vec<MerkleProof<SC::Digest>>],
    widths: &[usize],
    params: &crate::SystemParams,
) -> ExtractionResult<MerkleProofSets<SC>> {
    let expected_commit_count = widths.len();
    if initial_round_merkle_proofs.len() != expected_commit_count {
        return Err(invalid_shape(
            "initial-round WHIR Merkle proof hints",
            expected_commit_count,
            initial_round_merkle_proofs.len(),
        ));
    }

    let expected_queries = params.whir.rounds[0].num_queries;
    let expected_depth =
        (params.log_stacked_height() + params.log_blowup).saturating_sub(params.k_whir());
    for (commit_idx, proofs) in initial_round_merkle_proofs.iter().enumerate() {
        if proofs.len() != expected_queries {
            return Err(invalid_shape(
                format!("initial-round WHIR Merkle proof hints for commit {commit_idx}"),
                expected_queries,
                proofs.len(),
            ));
        }
        for (query_idx, proof) in proofs.iter().enumerate() {
            if proof.len() != expected_depth {
                return Err(invalid_shape(
                    format!(
                        "initial-round WHIR Merkle proof hint for commit {commit_idx}, query {query_idx}"
                    ),
                    expected_depth,
                    proof.len(),
                ));
            }
        }
    }

    Ok(initial_round_merkle_proofs.to_vec())
}

fn validate_initial_round_opened_rows<F>(
    initial_round_opened_rows: &[Vec<Vec<Vec<F>>>],
    widths: &[usize],
    params: &crate::SystemParams,
) -> ExtractionResult<OpenedRows<F>>
where
    F: PrimeField64,
{
    let expected_commit_count = widths.len();
    if initial_round_opened_rows.len() != expected_commit_count {
        return Err(invalid_shape(
            "initial-round WHIR opened-row hints",
            expected_commit_count,
            initial_round_opened_rows.len(),
        ));
    }

    let expected_queries = params.whir.rounds[0].num_queries;
    let expected_rows = 1 << params.k_whir();
    for (commit_idx, (&width, opened_rows_per_query)) in
        widths.iter().zip(initial_round_opened_rows).enumerate()
    {
        if opened_rows_per_query.len() != expected_queries {
            return Err(invalid_shape(
                format!("initial-round WHIR opened-row hints for commit {commit_idx}"),
                expected_queries,
                opened_rows_per_query.len(),
            ));
        }
        for (query_idx, opened_rows) in opened_rows_per_query.iter().enumerate() {
            if opened_rows.len() != expected_rows {
                return Err(invalid_shape(
                    format!(
                        "initial-round WHIR opened-row hint for commit {commit_idx}, query {query_idx}"
                    ),
                    expected_rows,
                    opened_rows.len(),
                ));
            }
            for (row_idx, row) in opened_rows.iter().enumerate() {
                if row.len() != width {
                    return Err(invalid_shape(
                        format!(
                            "initial-round WHIR opened-row hint for commit {commit_idx}, query {query_idx}, row {row_idx}"
                        ),
                        width,
                        row.len(),
                    ));
                }
            }
        }
    }

    Ok(initial_round_opened_rows.to_vec())
}

fn validate_codeword_merkle_proofs<SC: StarkProtocolConfig>(
    codeword_merkle_proofs: &[Vec<MerkleProof<SC::Digest>>],
    params: &crate::SystemParams,
) -> ExtractionResult<MerkleProofSets<SC>> {
    let expected_round_count = params.num_whir_rounds().saturating_sub(1);
    if codeword_merkle_proofs.len() != expected_round_count {
        return Err(invalid_shape(
            "non-initial WHIR Merkle proof hints",
            expected_round_count,
            codeword_merkle_proofs.len(),
        ));
    }

    for (round_minus_one, proofs) in codeword_merkle_proofs.iter().enumerate() {
        let round = round_minus_one + 1;
        let expected_queries = params.whir.rounds[round].num_queries;
        if proofs.len() != expected_queries {
            return Err(invalid_shape(
                format!("WHIR round {round} Merkle proof hints"),
                expected_queries,
                proofs.len(),
            ));
        }
        let expected_depth =
            params.log_stacked_height() + params.log_blowup - params.k_whir() - round;
        for (query_idx, proof) in proofs.iter().enumerate() {
            if proof.len() != expected_depth {
                return Err(invalid_shape(
                    format!("WHIR round {round} Merkle proof hint for query {query_idx}"),
                    expected_depth,
                    proof.len(),
                ));
            }
        }
    }

    Ok(codeword_merkle_proofs.to_vec())
}

fn validate_codeword_opened_values<EF>(
    codeword_opened_values: &[Vec<Vec<EF>>],
    params: &crate::SystemParams,
) -> ExtractionResult<OpenedValueSets<EF>>
where
    EF: Clone + core::fmt::Debug + core::fmt::Display + PartialEq + Eq,
{
    let expected_round_count = params.num_whir_rounds().saturating_sub(1);
    if codeword_opened_values.len() != expected_round_count {
        return Err(invalid_shape(
            "non-initial WHIR opened-value hints",
            expected_round_count,
            codeword_opened_values.len(),
        ));
    }

    let expected_values = 1 << params.k_whir();
    for (round_minus_one, opened_values_per_query) in codeword_opened_values.iter().enumerate() {
        let round = round_minus_one + 1;
        let expected_queries = params.whir.rounds[round].num_queries;
        if opened_values_per_query.len() != expected_queries {
            return Err(invalid_shape(
                format!("WHIR round {round} opened-value hints"),
                expected_queries,
                opened_values_per_query.len(),
            ));
        }
        for (query_idx, opened_values) in opened_values_per_query.iter().enumerate() {
            if opened_values.len() != expected_values {
                return Err(invalid_shape(
                    format!("WHIR round {round} opened-value hint for query {query_idx}"),
                    expected_values,
                    opened_values.len(),
                ));
            }
        }
    }

    Ok(codeword_opened_values.to_vec())
}

fn read_layer_claims<SC, State>(
    cursor: &mut TranscriptCursor<'_, SC::F, State>,
) -> ExtractionResult<GkrLayerClaims<SC>>
where
    SC: StarkProtocolConfig,
{
    let p_xi_0 = cursor.observe_ext::<SC>()?;
    let q_xi_0 = cursor.observe_ext::<SC>()?;
    let p_xi_1 = cursor.observe_ext::<SC>()?;
    let q_xi_1 = cursor.observe_ext::<SC>()?;
    Ok(GkrLayerClaims {
        p_xi_0,
        p_xi_1,
        q_xi_0,
        q_xi_1,
    })
}

fn read_ext_array2<SC, State>(
    cursor: &mut TranscriptCursor<'_, SC::F, State>,
) -> ExtractionResult<ExtPair<SC>>
where
    SC: StarkProtocolConfig,
{
    Ok([cursor.observe_ext::<SC>()?, cursor.observe_ext::<SC>()?])
}

fn read_ext_array3<SC, State>(
    cursor: &mut TranscriptCursor<'_, SC::F, State>,
) -> ExtractionResult<ExtTriple<SC>>
where
    SC: StarkProtocolConfig,
{
    Ok([
        cursor.observe_ext::<SC>()?,
        cursor.observe_ext::<SC>()?,
        cursor.observe_ext::<SC>()?,
    ])
}

fn read_column_openings_part<SC, State>(
    cursor: &mut TranscriptCursor<'_, SC::F, State>,
    width: usize,
    need_rot: bool,
) -> ExtractionResult<ExtOpenings<SC>>
where
    SC: StarkProtocolConfig,
{
    let mut openings = Vec::with_capacity(width * (1 + need_rot as usize));
    for _ in 0..width {
        openings.push(cursor.observe_ext::<SC>()?);
        if need_rot {
            openings.push(cursor.observe_ext::<SC>()?);
        } else {
            cursor.observe_zero_ext::<SC>()?;
        }
    }
    Ok(openings)
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::{extract_proof, WhirProofHints};
    use crate::{
        config::koala_bear_poseidon2::{
            default_duplex_sponge_recorder, DuplexSpongeRecorder, KoalaBearPoseidon2Config,
        },
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        test_utils::{
            test_system_params_small, CachedFixture11, InteractionsFixture11,
            PreprocessedAndCachedFixture, PreprocessedFibFixture, TestFixture,
            TwoPreprocessedFixture,
        },
        StarkEngine, SystemParams, TranscriptHistory,
    };

    type ConcreteSC = KoalaBearPoseidon2Config;
    type ConcreteEngine = KoalaBearPoseidon2RefEngine<DuplexSpongeRecorder>;

    fn test_proof_extract_roundtrip<Fx: TestFixture<ConcreteSC>>(
        fixture: Fx,
        params: SystemParams,
    ) -> eyre::Result<()> {
        let engine = ConcreteEngine::new(params);
        let (pk, vk) = fixture.keygen(&engine);
        let mut recorder = default_duplex_sponge_recorder();
        let proof = fixture.prove_from_transcript(&engine, &pk, &mut recorder);
        let log = recorder.into_log();
        let whir_hints = WhirProofHints::from(&proof.whir_proof);

        let extracted =
            extract_proof(&vk, &log, whir_hints).map_err(|error| eyre::eyre!("{error}"))?;
        assert_eq!(proof, extracted);
        Ok(())
    }

    #[test]
    fn interactions_proof_extract_roundtrip() -> eyre::Result<()> {
        let params = test_system_params_small(2, 5, 3);
        test_proof_extract_roundtrip(InteractionsFixture11, params)
    }

    #[test]
    fn cached_proof_extract_roundtrip() -> eyre::Result<()> {
        let params = test_system_params_small(2, 5, 3);
        let config = KoalaBearPoseidon2Config::default_from_params(params.clone());
        test_proof_extract_roundtrip(CachedFixture11::new(config), params)
    }

    /// Merged-preprocessed mode: keygen with ONE multi-matrix prep commitment,
    /// then prove + verify end-to-end.
    fn test_merged_prep_prove_verify<Fx: TestFixture<ConcreteSC>>(
        fixture: Fx,
        params: SystemParams,
    ) -> eyre::Result<()> {
        let engine = ConcreteEngine::new(params);
        let (pk, vk) = engine.keygen_merged_preprocessed(&fixture.airs());
        assert!(vk.inner.merged_preprocessed_commit.is_some());
        assert!(pk.per_air.iter().all(|pk| pk.preprocessed_data.is_none()));
        assert!(pk.per_air.iter().all(|pk| pk.vk.is_required));
        let proof = fixture.prove(&engine, &pk);
        engine
            .verify(&vk, &proof)
            .map_err(|error| eyre::eyre!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn merged_preprocessed_prove_verify() -> eyre::Result<()> {
        let log_trace_height = 5;
        let params = SystemParams::new_for_testing(log_trace_height);
        let selectors = (0..(1 << log_trace_height))
            .map(|index| index % 2 == 0)
            .collect_vec();
        test_merged_prep_prove_verify(PreprocessedFibFixture::new(0, 1, selectors), params)
    }

    #[test]
    fn merged_preprocessed_two_airs_different_heights_prove_verify() -> eyre::Result<()> {
        // AIR 0 is the SMALLER trace, so the height-descending trace ordering
        // ([air 1, air 0]) differs from AIR-id order — exercising the merged
        // matrix ordering, need_rot mapping, and claim-to-layout association.
        let log_trace_height = 5;
        let params = SystemParams::new_for_testing(log_trace_height);
        let sels_small = (0..(1 << (log_trace_height - 1)))
            .map(|index| index % 3 == 0)
            .collect_vec();
        let sels_big = (0..(1 << log_trace_height))
            .map(|index| index % 2 == 0)
            .collect_vec();
        test_merged_prep_prove_verify(TwoPreprocessedFixture::new(sels_small, sels_big), params)
    }

    #[test]
    fn preprocessed_proof_extract_roundtrip() -> eyre::Result<()> {
        let log_trace_height = 5;
        let params = SystemParams::new_for_testing(log_trace_height);
        let selectors = (0..(1 << log_trace_height))
            .map(|index| index % 2 == 0)
            .collect_vec();

        test_proof_extract_roundtrip(PreprocessedFibFixture::new(0, 1, selectors), params)
    }

    #[test]
    fn preprocessed_and_cached_proof_extract_roundtrip() -> eyre::Result<()> {
        let log_trace_height = 5;
        let params = SystemParams::new_for_testing(log_trace_height);
        let selectors = (0..(1 << log_trace_height))
            .map(|index| index % 2 == 0)
            .collect_vec();

        for num_cached_parts in [1, 2, 3] {
            let config = KoalaBearPoseidon2Config::default_from_params(params.clone());
            let fixture =
                PreprocessedAndCachedFixture::new(selectors.clone(), config, num_cached_parts);
            test_proof_extract_roundtrip(fixture, params.clone())?;
        }

        Ok(())
    }
}
