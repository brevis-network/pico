use itertools::{izip, Itertools};
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use thiserror::Error;

use crate::{
    keygen::types::{MultiStarkVerifyingKey, MultiStarkVerifyingKeyInner},
    poly::Squarable,
    proof::Proof,
    protocol::stacking::{lifted_log_height, stacking_sort_key},
    verifier::{
        batch_constraints::{verify_zerocheck_and_logup_inner, BatchConstraintError},
        proof_shape::{verify_proof_shape, ProofShapeError},
        stacked_reduction::{verify_stacked_reduction_inner, StackedReductionError},
        whir::{verify_whir_opening_inner, WhirVerificationError},
    },
    FiatShamirTranscript, StarkProtocolConfig,
};

/// What a verifier pass is for.
///
/// `TranscriptOnly` drives the Fiat-Shamir transcript through the same observe/sample sequence as
/// `Verify` but performs none of the algebraic checks: it produces no verdict and must never be
/// used to accept a proof. Every value the transcript observes is read straight out of the proof
/// or the verifying key, and every branch deciding *what* is observed is a function of the public
/// shape (`merged_prep`, round counts, `avk.is_required`, `preprocessed_data.is_some()`), so a
/// computation and its assertion can be skipped together without moving the transcript.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Pass {
    Verify,
    TranscriptOnly,
}

impl Pass {
    /// True iff the algebraic checks run.
    #[inline]
    pub(crate) const fn checks(self) -> bool {
        matches!(self, Pass::Verify)
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum VerifierError<EF: core::fmt::Debug + core::fmt::Display + PartialEq + Eq> {
    #[error("Protocol and VerifyingKey has mismatch in SystemParams")]
    SystemParamsMismatch,

    #[error("Trace heights are too large")]
    TraceHeightsTooLarge,

    #[error("Preprocessed trace height does not match verifier trace data")]
    PreprocessedTraceHeightMismatch,

    /// A proof without any traces is always considered invalid.
    #[error("Proof has no traces")]
    EmptyTraces,

    #[error("Stacked reduction returned an empty opening point")]
    EmptyOpeningPoint,

    #[error("Proof shape verification failed: {0}")]
    ProofShapeError(#[from] ProofShapeError),

    #[error("Batch constraint verification failed: {0}")]
    BatchConstraintError(#[from] BatchConstraintError<EF>),

    #[error("Stacked reduction verification failed: {0}")]
    StackedReductionError(#[from] StackedReductionError<EF>),

    #[error("Whir verification failed: {0}")]
    WhirError(#[from] WhirVerificationError<EF>),
}

/// Why a transcript-only walk could not be performed.
///
/// Deliberately NOT a verdict type: [`replay_transcript`] returning `Ok(())` says nothing about
/// the proof's validity. Only shapes that make the walk itself impossible appear here.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum TranscriptReplayError {
    #[error("Protocol and VerifyingKey has mismatch in SystemParams")]
    SystemParamsMismatch,

    #[error("Proof has no traces")]
    EmptyTraces,

    #[error("Stacked reduction returned an empty opening point")]
    EmptyOpeningPoint,

    #[error("Proof shape verification failed: {0}")]
    ProofShapeError(#[from] ProofShapeError),

    /// A GKR layer, sumcheck-poly or sub-round count disagreeing with the round count `n_logup`
    /// fixes (`GkrVerificationError::is_shape_error`). These run on both passes — the walk indexes
    /// the slices they size — and `verify_proof_shape` already rejects them, so reaching one means
    /// the two shape derivations disagree. Stringly typed only because the underlying error is
    /// generic over the extension field and this enum is not.
    #[error("GKR proof shape is inconsistent: {0}")]
    GkrShapeError(String),

    /// A verdict-bearing check fired on a pass that skips every check. No check known to us
    /// reaches this (the shape errors above are the ones that used to land here); surfaced as an
    /// error rather than a panic so a future edit that leaves a check on this path is visible.
    #[error("transcript replay reached a verdict-bearing check: {0}")]
    UnexpectedCheck(String),
}

/// Proof that a transcript-only walk ran to completion. Deliberately carries nothing: it exists so
/// that [`replay_transcript`]'s success value cannot be confused with [`verify`]'s acceptance at
/// the type level. There is no verdict to read out of it — the result of the walk is the final
/// transcript state, held by the caller's own transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptWalk(());

pub mod batch_constraints;
pub mod evaluator;
pub mod fractional_sumcheck_gkr;
pub mod proof_shape;
pub mod stacked_reduction;
#[cfg(test)]
mod transcript_extractor;
pub mod whir;

pub fn verify<SC: StarkProtocolConfig, TS: FiatShamirTranscript<SC>>(
    config: &SC,
    mvk: &MultiStarkVerifyingKey<SC>,
    proof: &Proof<SC>,
    transcript: &mut TS,
) -> Result<(), VerifierError<SC::EF>>
where
    SC::EF: p3_field::TwoAdicField,
{
    verify_inner(config, mvk, proof, transcript, Pass::Verify)
}

/// Drive `proof`'s Fiat-Shamir transcript through exactly the observe/sample sequence [`verify`]
/// would, performing none of the algebraic checks.
///
/// **Returns no verdict.** [`TranscriptWalk`] says the walk completed, not that the proof is valid;
/// the result is the final transcript state carried by `transcript`, from which challenges (e.g.
/// the WHIR query indices) can be read. It is a distinct type from [`verify`]'s `()` precisely so
/// the two cannot be mistaken for one another. Order-identity with [`verify`] holds by
/// construction: both share one body, selected by [`Pass`].
pub fn replay_transcript<SC: StarkProtocolConfig, TS: FiatShamirTranscript<SC>>(
    config: &SC,
    mvk: &MultiStarkVerifyingKey<SC>,
    proof: &Proof<SC>,
    transcript: &mut TS,
) -> Result<TranscriptWalk, TranscriptReplayError>
where
    SC::EF: p3_field::TwoAdicField,
{
    verify_inner(config, mvk, proof, transcript, Pass::TranscriptOnly)
        .map(|()| TranscriptWalk(()))
        .map_err(|err| match err {
            VerifierError::SystemParamsMismatch => TranscriptReplayError::SystemParamsMismatch,
            VerifierError::EmptyTraces => TranscriptReplayError::EmptyTraces,
            VerifierError::EmptyOpeningPoint => TranscriptReplayError::EmptyOpeningPoint,
            VerifierError::ProofShapeError(err) => TranscriptReplayError::ProofShapeError(err),
            VerifierError::BatchConstraintError(BatchConstraintError::GkrVerificationFailed(
                gkr,
            )) if gkr.is_shape_error() => TranscriptReplayError::GkrShapeError(gkr.to_string()),
            other => TranscriptReplayError::UnexpectedCheck(other.to_string()),
        })
}

fn verify_inner<SC: StarkProtocolConfig, TS: FiatShamirTranscript<SC>>(
    config: &SC,
    mvk: &MultiStarkVerifyingKey<SC>,
    proof: &Proof<SC>,
    transcript: &mut TS,
    pass: Pass,
) -> Result<(), VerifierError<SC::EF>>
where
    SC::EF: p3_field::TwoAdicField,
{
    if config.params() != &mvk.inner.params {
        return Err(VerifierError::SystemParamsMismatch);
    }
    let Proof {
        common_main_commit,
        trace_vdata,
        public_values,
        gkr_proof,
        batch_constraint_proof,
        stacking_proof,
        whir_proof,
    } = proof;
    let MultiStarkVerifyingKey {
        inner: mvk,
        pre_hash: mvk_pre_hash,
    } = mvk;
    let MultiStarkVerifyingKeyInner {
        params,
        per_air,
        trace_height_constraints,
        merged_preprocessed_commit,
    } = mvk;
    let merged_prep = merged_preprocessed_commit.is_some();
    let l_skip = params.l_skip;
    // Total number of AIRs is in vkey, committed to in vk_pre_hash
    let num_airs = per_air.len();
    // Number of present traces. This is implicitly hashed via the
    // transcript.observe(is_air_present) below.
    let num_traces = trace_vdata.iter().flatten().collect_vec().len();
    if num_traces == 0 {
        return Err(VerifierError::EmptyTraces);
    }
    // We verify the proof shape early to return error and prevent later panics. Runs on BOTH
    // passes: `layouts` itself is consumed only by checked code, but every index and `unwrap` on
    // the transcript path (round counts, per-round proof slices, present-trace vdata) is in
    // bounds only because this ran. It is length/count comparisons plus a layout re-derivation
    // from vk widths — no hashing, no field arithmetic over proof data.
    let layouts = verify_proof_shape::<SC>(mvk, proof)?;

    let mut trace_id_to_air_id: Vec<usize> = (0..num_airs).collect();
    // Present traces (`is_none` false) sort first via `stacking_sort_key`; absent ones sort last
    // and are truncated off.
    trace_id_to_air_id.sort_by_key(|&air_id| {
        (
            trace_vdata[air_id].is_none(),
            trace_vdata[air_id]
                .as_ref()
                .map(|vdata| stacking_sort_key(vdata.log_height, air_id)),
        )
    });
    trace_id_to_air_id.truncate(num_traces);

    // Reads only claimed log_heights and vk coefficients; observes nothing.
    if pass.checks() {
        for constraint in trace_height_constraints {
            let sum = trace_id_to_air_id
                .iter()
                .map(|&air_id| {
                    let log_height = trace_vdata[air_id].as_ref().unwrap().log_height;
                    // Shift in u64 (the helper gives only the exponent) so an oversized
                    // `log_height` can't wrap the shift and bypass the bound —
                    // defense-in-depth beyond the proof-shape `n <= n_stack` check.
                    (1u64 << lifted_log_height(log_height, l_skip))
                        * constraint.coefficients[air_id] as u64
                })
                .sum::<u64>();
            if sum >= constraint.threshold as u64 {
                return Err(VerifierError::TraceHeightsTooLarge);
            }
        }
    }

    let omega_skip = SC::F::two_adic_generator(l_skip);
    let omega_skip_pows = omega_skip.powers().take(1 << l_skip).collect_vec();

    // Preamble
    transcript.observe_commit(*mvk_pre_hash);
    transcript.observe_commit(proof.common_main_commit);
    // Merged-preprocessed mode: the single multi-matrix prep commitment is observed once;
    // per-air prep heights stay bound via the hypercube_dim check below (vk is bound via
    // pre_hash) and every present air observes its log_height uniformly.
    if let Some(mc) = merged_preprocessed_commit {
        transcript.observe_commit(*mc);
    }

    for (trace_vdata, avk, pvs) in izip!(&proof.trace_vdata, per_air, &proof.public_values) {
        let is_air_present = trace_vdata.is_some();

        // Proof shape asserts that vk.is_required => is_air_present (see
        // ProofShapeVDataError::RequiredAirNoVData)
        if !avk.is_required {
            transcript.observe(SC::F::from_bool(is_air_present));
        }
        if let Some(trace_vdata) = trace_vdata {
            if let Some(pdata) = avk.preprocessed_data.as_ref() {
                // Binds the claimed height to the vk; the observation below is unconditional
                // either way.
                if pass.checks()
                    && (pdata.hypercube_dim + l_skip as isize) as usize != trace_vdata.log_height
                {
                    return Err(VerifierError::PreprocessedTraceHeightMismatch);
                }
                if merged_prep {
                    transcript.observe(SC::F::from_usize(trace_vdata.log_height));
                } else {
                    transcript.observe_commit(pdata.commit);
                }
            } else {
                transcript.observe(SC::F::from_usize(trace_vdata.log_height));
            }
            debug_assert_eq!(
                avk.params.width.cached_mains.len(),
                trace_vdata.cached_commitments.len()
            );
            for commit in &trace_vdata.cached_commitments {
                transcript.observe_commit(*commit);
            }
            debug_assert_eq!(avk.params.num_public_values, pvs.len());
        }
        for pv in pvs {
            transcript.observe(*pv);
        }
    }

    // n_per_trace.len() = num_traces
    let n_per_trace: Vec<isize> = trace_id_to_air_id
        .iter()
        .map(|&air_id| trace_vdata[air_id].as_ref().unwrap().log_height as isize - l_skip as isize)
        .collect();
    let r = verify_zerocheck_and_logup_inner::<SC, TS>(
        transcript,
        mvk,
        public_values,
        gkr_proof,
        batch_constraint_proof,
        &trace_id_to_air_id,
        &n_per_trace,
        &omega_skip_pows,
        pass,
    )?;

    let need_rot_per_trace = trace_id_to_air_id
        .iter()
        .map(|&air_id| per_air[air_id].params.need_rot)
        .collect_vec();
    let has_prep_per_trace = trace_id_to_air_id
        .iter()
        .map(|&air_id| per_air[air_id].preprocessed_data.is_some())
        .collect_vec();
    let mut need_rot_per_commit = vec![need_rot_per_trace];
    if merged_prep {
        // One need_rot flag per matrix in the merged commitment, in trace order restricted
        // to preprocessed AIRs (== the merged layout's matrix order).
        need_rot_per_commit.push(
            trace_id_to_air_id
                .iter()
                .filter(|&&air_id| per_air[air_id].preprocessed_data.is_some())
                .map(|&air_id| per_air[air_id].params.need_rot)
                .collect_vec(),
        );
    }
    for &air_id in &trace_id_to_air_id {
        let need_rot = per_air[air_id].params.need_rot;
        if !merged_prep && per_air[air_id].preprocessed_data.is_some() {
            need_rot_per_commit.push(vec![need_rot]);
        }
        let cached_len = trace_vdata[air_id]
            .as_ref()
            .unwrap()
            .cached_commitments
            .len();
        for _ in 0..cached_len {
            need_rot_per_commit.push(vec![need_rot]);
        }
    }

    let u_prism = verify_stacked_reduction_inner::<SC, TS>(
        transcript,
        stacking_proof,
        &layouts,
        &need_rot_per_commit,
        merged_prep,
        &has_prep_per_trace,
        l_skip,
        params.n_stack,
        &proof.batch_constraint_proof.column_openings,
        &r,
        &omega_skip_pows,
        pass,
    )?;

    let (&u0, u_rest) = u_prism
        .split_first()
        .ok_or(VerifierError::EmptyOpeningPoint)?;
    let u_cube = u0
        .exp_powers_of_2()
        .take(l_skip)
        .chain(u_rest.iter().copied())
        .collect_vec();

    let mut commits = vec![*common_main_commit];
    if let Some(mc) = merged_preprocessed_commit {
        commits.push(*mc);
    }
    for &air_id in trace_id_to_air_id.iter() {
        if !merged_prep {
            if let Some(preprocessed) = &per_air[air_id].preprocessed_data {
                commits.push(preprocessed.commit);
            }
        }
        commits.extend(&trace_vdata[air_id].as_ref().unwrap().cached_commitments);
    }

    verify_whir_opening_inner::<SC, TS>(
        transcript,
        config,
        whir_proof,
        &stacking_proof.stacking_openings,
        &commits,
        &u_cube,
        pass,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use p3_field::PrimeField64;

    use itertools::izip;
    use p3_field::TwoAdicField;

    use super::{replay_transcript, verify};
    use crate::{
        config::koala_bear_poseidon2::{
            default_duplex_sponge_recorder, Digest, DuplexSpongeRecorder, KoalaBearPoseidon2Config,
            EF, F, WIDTH,
        },
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        keygen::types::MultiStarkVerifyingKey,
        proof::Proof,
        protocol::stacking::stacking_sort_key,
        test_utils::{
            test_system_params_small, CachedFixture11, InteractionsFixture11, MixtureFixture,
            PreprocessedAndCachedFixture, TestFixture, TwoPreprocessedFixture,
        },
        verifier::batch_constraints::verify_zerocheck_and_logup,
        FiatShamirTranscript, StarkEngine, SystemParams, TranscriptHistory, TranscriptLog,
    };

    type RefEngine = KoalaBearPoseidon2RefEngine<DuplexSpongeRecorder>;

    /// [`DuplexSpongeRecorder`] implements `FiatShamirTranscript<SC>` for every `SC`, so a bare
    /// `transcript.observe(..)` outside a call that already pins the config is ambiguous. These two
    /// pin it once, for the preamble mirror in
    /// [`verify_zerocheck_and_logup_wrapper_accepts_and_rejects`].
    fn obs(transcript: &mut DuplexSpongeRecorder, value: F) {
        FiatShamirTranscript::<KoalaBearPoseidon2Config>::observe(transcript, value);
    }

    fn obs_commit(transcript: &mut DuplexSpongeRecorder, digest: Digest) {
        FiatShamirTranscript::<KoalaBearPoseidon2Config>::observe_commit(transcript, digest);
    }

    /// Full-pipeline integration: prove with the real coordinator (the stacked-reduction
    /// output feeding the WHIR opening) and run the complete verifier. Also asserts the WHIR
    /// opening proof is load-bearing: corrupting it must fail full verification.
    fn assert_prove_and_verify<Fx: TestFixture<KoalaBearPoseidon2Config>>(
        fixture: Fx,
        params: SystemParams,
    ) {
        let engine = KoalaBearPoseidon2RefEngine::<DuplexSpongeRecorder>::new(params);
        let (pk, vk) = fixture.keygen(&engine);
        let mut proof = fixture.prove(&engine, &pk);
        verify(
            engine.config(),
            &vk,
            &proof,
            &mut default_duplex_sponge_recorder(),
        )
        .expect("honest proof verifies");

        // The stacking proof carries the per-commitment, per-column openings that
        // verify_whir_opening just checked against the commitments.
        assert!(!proof.stacking_proof.stacking_openings.is_empty());

        proof.whir_proof.final_poly[0] += EF::ONE;
        assert!(
            verify(
                engine.config(),
                &vk,
                &proof,
                &mut default_duplex_sponge_recorder()
            )
            .is_err(),
            "tampered WHIR proof must fail full verification"
        );
    }

    #[test]
    fn interactions_fixture_prove_and_verify() {
        assert_prove_and_verify(InteractionsFixture11, test_system_params_small(2, 5, 3));
    }

    /// The cached fixture commits extra matrices, so the WHIR opening spans multiple
    /// commitments.
    #[test]
    fn cached_fixture_prove_and_verify() {
        let params = test_system_params_small(2, 5, 3);
        assert_prove_and_verify(
            CachedFixture11::new(KoalaBearPoseidon2Config::default_from_params(
                params.clone(),
            )),
            params,
        );
    }

    /// FNV-1a fingerprint of the ordered `(canonical value, is_sample)` transcript stream — a
    /// stable, platform-independent signature of the Fiat-Shamir observation schedule.
    fn transcript_signature<F: PrimeField64, S>(log: &TranscriptLog<F, S>) -> (usize, u64) {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut hash = FNV_OFFSET;
        for (value, &is_sample) in log.values().iter().zip(log.samples()) {
            for byte in value
                .as_canonical_u64()
                .to_le_bytes()
                .into_iter()
                .chain([is_sample as u8])
            {
                hash ^= byte as u64;
                hash = hash.wrapping_mul(FNV_PRIME);
            }
        }
        (log.len(), hash)
    }

    /// Runs one prove + verify over `fixture`/`params` with recording transcripts on both sides,
    /// returning the prover's and verifier's ordered observe/sample logs.
    fn record_prover_and_verifier_logs<Fx: TestFixture<KoalaBearPoseidon2Config>>(
        fixture: Fx,
        params: SystemParams,
    ) -> (TranscriptLog<F, [F; WIDTH]>, TranscriptLog<F, [F; WIDTH]>) {
        let engine = KoalaBearPoseidon2RefEngine::<DuplexSpongeRecorder>::new(params);
        let (pk, vk) = fixture.keygen(&engine);

        // Prover's ordered observe/sample stream.
        let mut prover_recorder = default_duplex_sponge_recorder();
        let proof = fixture.prove_from_transcript(&engine, &pk, &mut prover_recorder);
        let prover_log = prover_recorder.into_log();

        // Verifier's ordered observe/sample stream over the same proof.
        let mut verifier_recorder = default_duplex_sponge_recorder();
        verify(engine.config(), &vk, &proof, &mut verifier_recorder)
            .expect("honest proof verifies");
        let verifier_log = verifier_recorder.into_log();

        (prover_log, verifier_log)
    }

    /// Pins the Fiat-Shamir observation schedule. The observe/sample order is duplicated across the
    /// prover, verifier, and transcript extractor with only a prose spec, and a silent reorder
    /// breaks Fiat-Shamir soundness while otherwise showing up only as an end-to-end verification
    /// failure.
    ///
    /// PoW grinding is disabled (`pow_bits = 0`) so `grind` is a deterministic no-op (no parallel
    /// `find_any`) and the recorded transcript is byte-stable across runs and machines. This pins
    /// every observation EXCEPT each grind's witness sub-steps (skipped at `pow = 0`), whose
    /// ordering is covered by `prover_and_verifier_transcripts_match_with_grinding` and the
    /// zero/non-zero `pow_bits` transcript tests.
    #[test]
    fn transcript_observation_order_is_pinned() {
        let mut params = test_system_params_small(2, 5, 3);
        params.logup.pow_bits = 0;
        params.whir.mu_pow_bits = 0;
        params.whir.folding_pow_bits = 0;
        params.whir.query_phase_pow_bits = 0;

        let (prover_log, verifier_log) =
            record_prover_and_verifier_logs(InteractionsFixture11, params);

        // (1) Prover and verifier must drive the transcript identically — same values, same
        // observe/sample flags, in the same order. A one-sided reorder breaks this.
        assert_eq!(
            prover_log.samples(),
            verifier_log.samples(),
            "prover vs verifier observe/sample schedule diverged"
        );
        assert_eq!(
            prover_log.values(),
            verifier_log.values(),
            "prover vs verifier observed/sampled values diverged"
        );

        // (2) Golden pin: a compact fingerprint of the ordered (value, is_sample) stream. A silent
        // reorder — even one applied symmetrically to prover AND verifier, which check (1) cannot
        // catch — changes this. Update GOLDEN only alongside an intentional protocol change.
        // The first observed value is the vk pre-hash, so the fingerprint (not the count) also
        // moves whenever the pre-hash preimage definition changes (`compute_vk_pre_hash`).
        const GOLDEN: (usize, u64) = (574, 13_775_646_401_442_936_072);
        assert_eq!(
            transcript_signature(&verifier_log),
            GOLDEN,
            "Fiat-Shamir observation order changed; if intentional, update GOLDEN"
        );
    }

    /// Companion to [`transcript_observation_order_is_pinned`]: with PoW grinding ACTIVE
    /// (`test_system_params_small` uses `pow_bits = 2 / 1 / 2 / 3`), the prover and verifier must
    /// still drive the transcript identically. This extends the observe-order symmetry check across
    /// the WHIR/LogUp grind sub-steps the `pow = 0` golden skips. It is not golden-pinned because
    /// the ground witnesses are nondeterministic under parallel search; only the prover-vs-verifier
    /// equality (deterministic within a run — the verifier reads the witness from the proof) is
    /// asserted.
    #[test]
    fn prover_and_verifier_transcripts_match_with_grinding() {
        let params = test_system_params_small(2, 5, 3);
        let (prover_log, verifier_log) =
            record_prover_and_verifier_logs(InteractionsFixture11, params);

        assert_eq!(
            prover_log.samples(),
            verifier_log.samples(),
            "prover vs verifier observe/sample schedule diverged under grinding"
        );
        assert_eq!(
            prover_log.values(),
            verifier_log.values(),
            "prover vs verifier observed/sampled values diverged under grinding"
        );
    }

    /// A [`DuplexSpongeRecorder`] that additionally captures each `sample_bits(bits) -> value`.
    /// `sample_bits` is a trait default routed through `sample`, so the inner log already holds
    /// the drawn value; what it cannot recover is the `bits` argument, which is what selects the
    /// low bits a WHIR query index is read from.
    #[derive(Clone)]
    struct BitsRecorder {
        inner: DuplexSpongeRecorder,
        bits: Vec<(usize, u64)>,
    }

    impl BitsRecorder {
        fn new() -> Self {
            Self {
                inner: default_duplex_sponge_recorder(),
                bits: Vec::new(),
            }
        }
    }

    impl FiatShamirTranscript<KoalaBearPoseidon2Config> for BitsRecorder {
        fn observe(&mut self, value: F) {
            FiatShamirTranscript::<KoalaBearPoseidon2Config>::observe(&mut self.inner, value);
        }

        fn sample(&mut self) -> F {
            FiatShamirTranscript::<KoalaBearPoseidon2Config>::sample(&mut self.inner)
        }

        fn observe_commit(&mut self, digest: Digest) {
            FiatShamirTranscript::<KoalaBearPoseidon2Config>::observe_commit(
                &mut self.inner,
                digest,
            );
        }

        fn sample_bits(&mut self, bits: usize) -> u64 {
            let value = FiatShamirTranscript::<KoalaBearPoseidon2Config>::sample_bits(
                &mut self.inner,
                bits,
            );
            self.bits.push((bits, value));
            value
        }
    }

    /// Proves `fixture` once, then drives the same proof through `verify` and
    /// `replay_transcript` on two fresh identical transcripts and asserts the two agree on the
    /// full `sample_bits` stream (bits AND values, in order) and on the full observe/sample
    /// stream underneath it.
    fn assert_replay_matches_verify<Fx: TestFixture<KoalaBearPoseidon2Config>>(
        fixture: Fx,
        params: SystemParams,
    ) {
        let engine = RefEngine::new(params);
        let (pk, vk) = fixture.keygen(&engine);
        let proof = fixture.prove(&engine, &pk);
        assert_replay_matches_verify_on(&engine, &vk, &proof);
    }

    /// [`assert_replay_matches_verify`] over a key and proof the caller already has, so the
    /// merged-preprocessed variant below can reuse the comparison.
    fn assert_replay_matches_verify_on(
        engine: &RefEngine,
        vk: &MultiStarkVerifyingKey<KoalaBearPoseidon2Config>,
        proof: &Proof<KoalaBearPoseidon2Config>,
    ) {
        let mut verified = BitsRecorder::new();
        verify(engine.config(), vk, proof, &mut verified).expect("honest proof verifies");
        let mut replayed = BitsRecorder::new();
        replay_transcript(engine.config(), vk, proof, &mut replayed).expect("replay completes");

        // Anti-vacuity: two empty streams compare equal, so a transcript that never sampled bits
        // (or a pass that returned early) would otherwise pass this test.
        assert!(
            !verified.bits.is_empty(),
            "no sample_bits calls recorded; the comparison below would be vacuous"
        );
        assert_eq!(
            verified.bits, replayed.bits,
            "transcript-only pass drew a different sample_bits stream than verify"
        );

        // The bits stream is a projection; this pins every observe and every sample.
        let verify_log = verified.inner.into_log();
        let replay_log = replayed.inner.into_log();
        assert!(!verify_log.is_empty());
        assert_eq!(
            verify_log.samples(),
            replay_log.samples(),
            "transcript-only pass diverged on the observe/sample schedule"
        );
        assert_eq!(
            verify_log.values(),
            replay_log.values(),
            "transcript-only pass diverged on the observed/sampled values"
        );
    }

    /// `params.logup.pow_bits` and all three WHIR pow_bits are non-zero here, so `check_witness`
    /// contributes `sample_bits` calls of its own alongside the query indices.
    #[test]
    fn replay_matches_verify_interactions_fixture() {
        assert_replay_matches_verify(InteractionsFixture11, test_system_params_small(2, 5, 3));
    }

    /// Several commitments, so the WHIR initial round opens more than one Merkle tree — the
    /// per-query block the transcript-only pass skips entirely.
    #[test]
    fn replay_matches_verify_cached_fixture() {
        let params = test_system_params_small(2, 5, 3);
        assert_replay_matches_verify(
            CachedFixture11::new(KoalaBearPoseidon2Config::default_from_params(
                params.clone(),
            )),
            params,
        );
    }

    /// Preprocessed, cached, interaction-carrying and constraint-only AIRs together, so the
    /// preamble takes every PER-AIR observation branch — the `is_air_present` flag, the
    /// `observe_commit(pdata.commit)` for a preprocessed AIR, the bare `observe(log_height)` for
    /// one without, and the cached commitments — and the constraint evaluator (skipped on the
    /// replay pass) has real work on the verify pass.
    ///
    /// The merged-preprocessed branches are a different shape and are covered by
    /// [`replay_matches_verify_merged_prep_two_preprocessed`] and
    /// [`replay_matches_verify_merged_prep_with_cached`].
    #[test]
    fn replay_matches_verify_mixture_fixture() {
        let params = test_system_params_small(2, 5, 3);
        assert_replay_matches_verify(
            MixtureFixture::standard(
                4,
                KoalaBearPoseidon2Config::default_from_params(params.clone()),
            ),
            params,
        );
    }

    /// [`assert_replay_matches_verify`] over a key from `keygen_merged_preprocessed`: ONE
    /// multi-matrix preprocessed commitment and every AIR marked required. That is how every
    /// recursion (convert/combine) proof is verified, and it takes three preamble/reduction
    /// branches the per-air fixtures above cannot reach:
    ///
    /// - a required AIR SKIPS the `observe(is_air_present)` flag;
    /// - a preprocessed AIR under a merged commit observes its `log_height` instead of the
    ///   per-air `observe_commit(pdata.commit)`;
    /// - `verify_stacked_reduction_inner` gathers commit 1's claims in merged-matrix order.
    fn assert_replay_matches_verify_merged_prep<Fx: TestFixture<KoalaBearPoseidon2Config>>(
        fixture: Fx,
        params: SystemParams,
    ) {
        let engine = RefEngine::new(params);
        let (pk, vk) = engine.keygen_merged_preprocessed(&fixture.airs());

        // Anti-vacuity: without these a keygen change would silently turn this into a second
        // per-air-prep run, and the branches named above would go back to being untested.
        assert!(
            vk.inner.merged_preprocessed_commit.is_some(),
            "merged-preprocessed keygen produced no merged commitment"
        );
        assert!(
            vk.inner.per_air.iter().all(|avk| avk.is_required),
            "merged-preprocessed keygen left an AIR non-required, so the skipped is_air_present \
             observation is not exercised"
        );
        assert!(
            vk.inner
                .per_air
                .iter()
                .any(|avk| avk.preprocessed_data.is_some()),
            "fixture has no preprocessed AIR, so the merged-prep branches are unreachable"
        );

        let proof = fixture.prove(&engine, &pk);
        assert_replay_matches_verify_on(&engine, &vk, &proof);
    }

    /// Two preprocessed AIRs at different heights, so the merged commitment holds two matrices and
    /// trace order differs from AIR-id order — the merged gather is then order-sensitive.
    #[test]
    fn replay_matches_verify_merged_prep_two_preprocessed() {
        let log_trace_height = 5;
        let params = SystemParams::new_for_testing(log_trace_height);
        let sels_small = (0..(1 << (log_trace_height - 1)))
            .map(|index| index % 3 == 0)
            .collect::<Vec<_>>();
        let sels_big = (0..(1 << log_trace_height))
            .map(|index| index % 2 == 0)
            .collect::<Vec<_>>();
        assert_replay_matches_verify_merged_prep(
            TwoPreprocessedFixture::new(sels_small, sels_big),
            params,
        );
    }

    /// Merged preprocessed commitment PLUS cached commitments on the same AIR, so the
    /// `commit_idx` walk past the merged commit (`skip(2)`) is exercised as well.
    #[test]
    fn replay_matches_verify_merged_prep_with_cached() {
        let log_trace_height = 5;
        let params = SystemParams::new_for_testing(log_trace_height);
        let sels = (0..(1 << log_trace_height))
            .map(|index| index % 2 == 0)
            .collect::<Vec<_>>();
        let config = KoalaBearPoseidon2Config::default_from_params(params.clone());
        assert_replay_matches_verify_merged_prep(
            PreprocessedAndCachedFixture::new(sels, config, 2),
            params,
        );
    }

    /// Drives the crate-public [`verify_zerocheck_and_logup`] — the `Pass::Verify` door its three
    /// siblings (`verify_gkr`, `verify_stacked_reduction`, `verify_whir_opening`) each get from an
    /// out-of-crate caller, and which `verify_inner` reaches through `_inner` instead.
    ///
    /// The preamble below MIRRORS `verify_inner`'s, because the wrapper's contract is "called with
    /// the transcript positioned where the STARK preamble leaves it". An intentional reorder
    /// breaks `transcript_observation_order_is_pinned` first, which is the signal that this mirror
    /// needs the same edit.
    #[test]
    fn verify_zerocheck_and_logup_wrapper_accepts_and_rejects() {
        let params = test_system_params_small(2, 5, 3);
        let engine = RefEngine::new(params);
        let (pk, vk) = InteractionsFixture11.keygen(&engine);
        let proof = InteractionsFixture11.prove(&engine, &pk);

        // Per-air prep here, so `merged_preprocessed_commit` is None and the merged observation is
        // not part of the mirror.
        assert!(vk.inner.merged_preprocessed_commit.is_none());

        let run = |proof: &Proof<KoalaBearPoseidon2Config>| {
            let mvk = &vk.inner;
            let l_skip = mvk.params.l_skip;
            let num_traces = proof.trace_vdata.iter().flatten().count();

            let mut trace_id_to_air_id: Vec<usize> = (0..mvk.per_air.len()).collect();
            trace_id_to_air_id.sort_by_key(|&air_id| {
                (
                    proof.trace_vdata[air_id].is_none(),
                    proof.trace_vdata[air_id]
                        .as_ref()
                        .map(|vdata| stacking_sort_key(vdata.log_height, air_id)),
                )
            });
            trace_id_to_air_id.truncate(num_traces);

            // `Powers::take` is inherent in Plonky3 0.5 (a `BoundedPowers`), whose `collect` is
            // not the iterator one.
            let omega_skip_pows = F::two_adic_generator(l_skip)
                .powers()
                .take(1 << l_skip)
                .collect();

            let mut transcript = default_duplex_sponge_recorder();
            obs_commit(&mut transcript, vk.pre_hash);
            obs_commit(&mut transcript, proof.common_main_commit);
            for (trace_vdata, avk, pvs) in
                izip!(&proof.trace_vdata, &mvk.per_air, &proof.public_values)
            {
                if !avk.is_required {
                    obs(&mut transcript, F::from_bool(trace_vdata.is_some()));
                }
                if let Some(trace_vdata) = trace_vdata {
                    match avk.preprocessed_data.as_ref() {
                        Some(pdata) => obs_commit(&mut transcript, pdata.commit),
                        None => obs(&mut transcript, F::from_usize(trace_vdata.log_height)),
                    }
                    for commit in &trace_vdata.cached_commitments {
                        obs_commit(&mut transcript, *commit);
                    }
                }
                for pv in pvs {
                    obs(&mut transcript, *pv);
                }
            }

            let n_per_trace = trace_id_to_air_id
                .iter()
                .map(|&air_id| {
                    proof.trace_vdata[air_id].as_ref().unwrap().log_height as isize
                        - l_skip as isize
                })
                .collect::<Vec<_>>();

            verify_zerocheck_and_logup(
                &mut transcript,
                mvk,
                &proof.public_values,
                &proof.gkr_proof,
                &proof.batch_constraint_proof,
                &trace_id_to_air_id,
                &n_per_trace,
                &omega_skip_pows,
            )
        };

        let rs = run(&proof).expect("honest proof passes zerocheck + logup");
        // Anti-vacuity: an empty `rs` would make the tampered case below prove nothing about the
        // reduction, only about an early return.
        assert!(!rs.is_empty(), "zerocheck returned no sumcheck point");

        let mut tampered = proof.clone();
        tampered.batch_constraint_proof.column_openings[0][0][0] += EF::ONE;
        assert!(
            run(&tampered).is_err(),
            "a tampered column opening must fail zerocheck + logup"
        );
    }
}
