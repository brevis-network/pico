use std::sync::Arc;

use itertools::Itertools;

use crate::{
    air::debug::{debug_constraints_and_interactions, AirProofRawInput},
    keygen::{
        types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
        MultiStarkKeygenBuilder,
    },
    poly::matrix::{ColMajorMatrix, StridedColMajorMatrixView},
    proof::*,
    prover::{
        Coordinator, DeviceDataTransporter, DeviceMultiStarkProvingKey, MultiRapProver,
        OpeningProver, Prover, ProverBackend, ProverDevice, ProvingContext,
    },
    verifier::{verify, VerifierError},
    AirRef, FiatShamirTranscript, StarkProtocolConfig, SystemParams,
};

pub type ProverError<E> =
    <<E as StarkEngine>::PD as ProverDevice<<E as StarkEngine>::PB, <E as StarkEngine>::TS>>::Error;

/// A helper trait to collect the different steps in multi-trace STARK
/// keygen and proving.
pub trait StarkEngine
where
    <Self::PD as MultiRapProver<Self::PB, Self::TS>>::Artifacts:
        Into<<Self::PD as OpeningProver<Self::PB, Self::TS>>::OpeningPoints>,
    <Self::PD as MultiRapProver<Self::PB, Self::TS>>::PartialProof:
        Into<(GkrProof<Self::SC>, BatchConstraintProof<Self::SC>)>,
    <Self::PD as OpeningProver<Self::PB, Self::TS>>::OpeningProof:
        Into<(StackingProof<Self::SC>, WhirProof<Self::SC>)>,
{
    type SC: StarkProtocolConfig;
    type PB: ProverBackend<
        Val = <Self::SC as StarkProtocolConfig>::F,
        Challenge = <Self::SC as StarkProtocolConfig>::EF,
        Commitment = <Self::SC as StarkProtocolConfig>::Digest,
    >;
    type PD: ProverDevice<Self::PB, Self::TS> + DeviceDataTransporter<Self::SC, Self::PB>;
    type TS: FiatShamirTranscript<Self::SC>;

    /// Constructor from only system parameters. In particular, the transcript and hasher must have
    /// a default configuration.
    fn new(params: SystemParams) -> Self;

    fn config(&self) -> &Self::SC;

    fn params(&self) -> &SystemParams {
        self.config().params()
    }

    fn device(&self) -> &Self::PD;

    /// Creates transcript with a deterministic initial state.
    fn initial_transcript(&self) -> Self::TS;

    fn prover_from_transcript(
        &self,
        transcript: Self::TS,
    ) -> Coordinator<Self::SC, Self::PB, Self::PD, Self::TS>;

    fn prover(&self) -> Coordinator<Self::SC, Self::PB, Self::PD, Self::TS> {
        let transcript = self.initial_transcript();
        self.prover_from_transcript(transcript)
    }

    fn keygen(
        &self,
        airs: &[AirRef<Self::SC>],
    ) -> (
        MultiStarkProvingKey<Self::SC>,
        MultiStarkVerifyingKey<Self::SC>,
    ) {
        self.keygen_with_app_prep(airs, &[])
    }

    /// Per-air keygen with the AIRs in `app_prep_air_ids` marked as *application identity*
    /// preprocessed tables: their commitment values are excluded from the lean vk pre-hash
    /// preimage (see `compute_vk_pre_hash`). E.g. the RISC-V machine marks its program table
    /// so the vk pre-hash is app-independent.
    fn keygen_with_app_prep(
        &self,
        airs: &[AirRef<Self::SC>],
        app_prep_air_ids: &[usize],
    ) -> (
        MultiStarkProvingKey<Self::SC>,
        MultiStarkVerifyingKey<Self::SC>,
    ) {
        let mut keygen_builder = MultiStarkKeygenBuilder::new(self.config().clone());
        // Measurement (log-only): add_air runs per-AIR preprocessed trace generation +
        // stacked_commit; generate_pk runs per-AIR symbolic DAG + bus checks.
        let t_add = std::time::Instant::now();
        for air in airs {
            keygen_builder.add_air(air.clone());
        }
        for &air_id in app_prep_air_ids {
            keygen_builder.mark_app_preprocessed(air_id);
        }
        let add_airs_ms = t_add.elapsed().as_millis();

        let t_gen = std::time::Instant::now();
        let pk = keygen_builder.generate_pk().unwrap();
        tracing::info!(
            "mle_keygen_detail: add_airs_ms = {add_airs_ms} (prep gen+commit), generate_pk_ms = {} (DAG+checks)",
            t_gen.elapsed().as_millis()
        );
        let vk = pk.get_vk();
        (pk, vk)
    }

    /// Keygen with ONE multi-matrix stacked commitment over all AIRs' preprocessed traces
    /// (instead of one commitment per AIR) and all AIRs marked required. Used by the
    /// recursion machines, where every chip is always present and all prep traces are
    /// slices of the same program. See
    /// `MultiStarkVerifyingKey0::merged_preprocessed_commit` for the contract.
    fn keygen_merged_preprocessed(
        &self,
        airs: &[AirRef<Self::SC>],
    ) -> (
        MultiStarkProvingKey<Self::SC>,
        MultiStarkVerifyingKey<Self::SC>,
    ) {
        let mut keygen_builder =
            MultiStarkKeygenBuilder::new_with_merged_preprocessed(self.config().clone());
        // Measurement (log-only): in merged mode add_air only generates prep traces;
        // generate_pk runs the joint stacked_commit + per-AIR symbolic DAG + bus checks.
        let t_add = std::time::Instant::now();
        for air in airs {
            keygen_builder.add_required_air(air.clone());
        }
        let add_airs_ms = t_add.elapsed().as_millis();

        let t_gen = std::time::Instant::now();
        let pk = keygen_builder.generate_pk().unwrap();
        tracing::info!(
            "mle_keygen_detail: add_airs_ms = {add_airs_ms} (prep gen only), generate_pk_ms = {} (merged commit + DAG + checks)",
            t_gen.elapsed().as_millis()
        );
        let vk = pk.get_vk();
        (pk, vk)
    }

    /// [`Self::keygen_merged_preprocessed`] without the host stacked commit, for callers that commit the
    /// preprocessed traces themselves (the GPU recursion path already does, then asserts the two
    /// agree — so the host commit is pure duplicate work there).
    ///
    /// The returned key carries a placeholder commitment and MUST be completed with
    /// [`MultiStarkProvingKey::patch_merged_preprocessed_commit`]; no verifying key is returned,
    /// because one taken before the patch would carry the placeholder. `vk_pre_hash` is already
    /// final — merged mode excludes commitment values from the pre-hash preimage.
    ///
    /// Nothing on this path reads a preprocessed trace's *contents* — only its dimensions — so the
    /// builder runs in **dims-only** mode: an AIR that declares its geometry never has a trace
    /// generated, and one that does not still does.
    fn keygen_merged_preprocessed_deferred_commit(
        &self,
        airs: &[AirRef<Self::SC>],
    ) -> MultiStarkProvingKey<Self::SC> {
        let mut keygen_builder =
            MultiStarkKeygenBuilder::new_with_merged_preprocessed_dims_only(self.config().clone());
        let t_add = std::time::Instant::now();
        for air in airs {
            keygen_builder.add_required_air(air.clone());
        }
        let add_airs_ms = t_add.elapsed().as_millis();

        let t_gen = std::time::Instant::now();
        let pk = keygen_builder.generate_pk_deferred_merged_commit().unwrap();
        tracing::info!(
            "mle_keygen_detail: add_airs_ms = {add_airs_ms} (prep dims; gen only where undeclared), generate_pk_ms = {} (DAG + checks, commit deferred)",
            t_gen.elapsed().as_millis()
        );
        pk
    }

    fn prove(
        &self,
        pk: &DeviceMultiStarkProvingKey<Self::PB>,
        ctx: ProvingContext<Self::PB>,
    ) -> Result<Proof<Self::SC>, ProverError<Self>> {
        let mut prover = self.prover();
        prover.prove(pk, ctx)
    }

    /// Verifies using a default instantiation of the Fiat-Shamir transcript.
    fn verify(
        &self,
        vk: &MultiStarkVerifyingKey<Self::SC>,
        proof: &Proof<Self::SC>,
    ) -> Result<(), VerifierError<<Self::SC as StarkProtocolConfig>::EF>> {
        let mut transcript = self.initial_transcript();
        verify(self.config(), vk, proof, &mut transcript)
    }

    /// The indexing of AIR ID in `ctx` should be consistent with the order of `airs`. In
    /// particular, `airs` should correspond to the global proving key with all AIRs, including ones
    /// not present in the `ctx`.
    fn debug(&self, airs: &[AirRef<Self::SC>], ctx: &ProvingContext<Self::PB>) {
        let (pk, _) = self.keygen(airs);
        self.debug_with_pk(airs, ctx, &pk);
    }

    /// Like [`StarkEngine::debug`], but reuses a pre-computed proving key instead of running keygen.
    /// Callers that debug many chunks against the same AIR set (e.g. per-record RISCV debugging)
    /// should keygen once and call this per chunk, rather than paying keygen on every call.
    fn debug_with_pk(
        &self,
        airs: &[AirRef<Self::SC>],
        ctx: &ProvingContext<Self::PB>,
        pk: &MultiStarkProvingKey<Self::SC>,
    ) {
        let transpose = |mat: ColMajorMatrix<<Self::SC as StarkProtocolConfig>::F>| {
            let row_major = StridedColMajorMatrixView::from(mat.as_view()).to_row_major_matrix();
            Arc::new(row_major)
        };
        let (inputs, used_airs, used_pks): (Vec<_>, Vec<_>, Vec<_>) = ctx
            .per_trace
            .iter()
            .map(|(air_id, trace_ctx)| {
                let common_main = self
                    .device()
                    .transport_matrix_from_device_to_host(&trace_ctx.common_main);
                let cached_mains = trace_ctx
                    .cached_mains
                    .iter()
                    .map(|cd| {
                        transpose(
                            self.device()
                                .transport_matrix_from_device_to_host(&cd.trace),
                        )
                    })
                    .collect_vec();
                let common_main = Some(transpose(common_main));
                let public_values = trace_ctx.public_values.clone();
                (
                    AirProofRawInput {
                        cached_mains,
                        common_main,
                        public_values,
                    },
                    airs[*air_id].clone(),
                    &pk.per_air[*air_id],
                )
            })
            .multiunzip();

        debug_constraints_and_interactions(&used_airs, &used_pks, &inputs);
    }
}
