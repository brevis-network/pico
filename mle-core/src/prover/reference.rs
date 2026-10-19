//! Reference (column-major) prover backend and device.
//!
//! The straightforward, readable reference implementation of the prover HAL, split across two
//! types: [ReferenceColMajorBackend] implements [ProverBackend], and the paired [ReferenceDevice]
//! implements [ProverDevice] (with its `TraceCommitter`/`MultiRapProver`/`OpeningProver`/
//! `DeviceDataTransporter` supertraits). This is what the optimized production backends are
//! checked against — exercised by the unit tests, not the RISCV proving path.
//!
//! It is also part of the HAL contract: `DeviceDataTransporter`'s provided methods define the
//! canonical *host* interchange format in terms of [ReferenceColMajorBackend].

use std::marker::PhantomData;

use getset::Getters;
use itertools::Itertools;
use p3_field::{ExtensionField, TwoAdicField};

use crate::{
    keygen::types::{merged_preprocessed_mat_indices, MultiStarkProvingKey},
    poly::{matrix::ColMajorMatrix, Squarable},
    proof::{BatchConstraintProof, GkrProof, StackingProof, WhirProof},
    prover::{
        error::HostProverError,
        logup_zerocheck::evaluator::InteractionEvalPlan,
        prove_zerocheck_and_logup,
        stacked_pcs::{stacked_commit, StackedPcsData},
        stacked_reduction::{prove_stacked_opening_reduction, StackedReductionRef},
        whir::prove_whir_opening,
        CommittedTraceData, DeviceDataTransporter, DeviceMultiStarkProvingKey,
        DeviceStarkProvingKey, MultiRapProver, OpeningProver, ProverBackend, ProverDevice,
        ProvingContext, TraceCommitter, ZerocheckLogupProof,
    },
    FiatShamirTranscript, StarkProtocolConfig, SystemParams,
};

#[derive(Clone, Copy)]
pub struct ReferenceColMajorBackend<SC: StarkProtocolConfig>(PhantomData<SC>);

impl<SC: StarkProtocolConfig> ReferenceColMajorBackend<SC> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<SC: StarkProtocolConfig> Default for ReferenceColMajorBackend<SC> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Getters, derive_new::new)]
pub struct ReferenceDevice<SC> {
    #[getset(get = "pub")]
    config: SC,
}

impl<SC: StarkProtocolConfig> ReferenceDevice<SC> {
    pub fn params(&self) -> &SystemParams {
        self.config.params()
    }
}

impl<SC: StarkProtocolConfig> ProverBackend for ReferenceColMajorBackend<SC> {
    const CHALLENGE_EXT_DEGREE: u8 = SC::D_EF as u8;

    type Val = SC::F;
    type Challenge = SC::EF;
    type Commitment = SC::Digest;
    type Matrix = ColMajorMatrix<SC::F>;
    type OtherAirData = InteractionEvalPlan<SC::F>;
    type PcsData = StackedPcsData<SC::F, SC::Digest>;
}

impl<SC, TS> ProverDevice<ReferenceColMajorBackend<SC>, TS> for ReferenceDevice<SC>
where
    SC: StarkProtocolConfig,
    SC::F: Ord,
    SC::EF: TwoAdicField + ExtensionField<SC::F> + Ord,
    TS: FiatShamirTranscript<SC>,
{
    type Error = HostProverError;
}

impl<SC: StarkProtocolConfig> TraceCommitter<ReferenceColMajorBackend<SC>> for ReferenceDevice<SC>
where
    SC::F: Ord,
{
    type Error = HostProverError;

    fn commit(
        &self,
        traces: &[&ColMajorMatrix<SC::F>],
    ) -> Result<(SC::Digest, StackedPcsData<SC::F, SC::Digest>), Self::Error> {
        Ok(stacked_commit(
            self.config().hasher(),
            self.params().l_skip,
            self.params().n_stack,
            self.params().log_blowup,
            self.params().k_whir(),
            traces,
        )?)
    }
}

impl<SC, TS> MultiRapProver<ReferenceColMajorBackend<SC>, TS> for ReferenceDevice<SC>
where
    SC: StarkProtocolConfig,
    SC::EF: TwoAdicField + ExtensionField<SC::F>,
    TS: FiatShamirTranscript<SC>,
{
    type PartialProof = (GkrProof<SC>, BatchConstraintProof<SC>);
    /// The random opening point `r` where the batch constraint sumcheck reduces to evaluation
    /// claims of trace matrices `T, T_{rot}` at `r_{n_T}`.
    type Artifacts = Vec<SC::EF>;

    type Error = HostProverError;

    fn prove_rap_constraints(
        &self,
        transcript: &mut TS,
        mpk: &DeviceMultiStarkProvingKey<ReferenceColMajorBackend<SC>>,
        ctx: &ProvingContext<ReferenceColMajorBackend<SC>>,
    ) -> Result<((GkrProof<SC>, BatchConstraintProof<SC>), Vec<SC::EF>), Self::Error> {
        let ZerocheckLogupProof {
            gkr,
            batch,
            eval_point,
        } = prove_zerocheck_and_logup::<SC, _>(transcript, mpk, ctx)?;
        Ok(((gkr, batch), eval_point))
    }
}

impl<SC, TS> OpeningProver<ReferenceColMajorBackend<SC>, TS> for ReferenceDevice<SC>
where
    SC: StarkProtocolConfig,
    SC::F: Ord,
    SC::EF: TwoAdicField + ExtensionField<SC::F> + Ord,
    TS: FiatShamirTranscript<SC>,
{
    type OpeningProof = (StackingProof<SC>, WhirProof<SC>);
    /// The shared vector `r` where each trace matrix `T, T_{rot}` is opened at `r_{n_T}`.
    type OpeningPoints = Vec<SC::EF>;

    type Error = HostProverError;

    fn prove_openings(
        &self,
        transcript: &mut TS,
        mpk: &DeviceMultiStarkProvingKey<ReferenceColMajorBackend<SC>>,
        ctx: ProvingContext<ReferenceColMajorBackend<SC>>,
        common_main_pcs_data: StackedPcsData<SC::F, SC::Digest>,
        r: Vec<SC::EF>,
    ) -> Result<(StackingProof<SC>, WhirProof<SC>), Self::Error> {
        let params = self.params();

        let (pre_cached_pcs_data_per_commit, need_rot_per_commit) = mpk.opening_prologue(&ctx);

        let mut stacked_per_commit = vec![&common_main_pcs_data];
        for data in &pre_cached_pcs_data_per_commit {
            stacked_per_commit.push(data);
        }
        #[cfg(debug_assertions)]
        {
            let total_stacked_width: usize =
                stacked_per_commit.iter().map(|d| d.layout.width()).sum();
            debug_assert!(
                total_stacked_width <= params.w_stack,
                "total stacked width across commits ({total_stacked_width}) exceeds w_stack ({})",
                params.w_stack
            );
        }

        let (stacking_proof, u_prisma) =
            prove_stacked_opening_reduction::<SC, _, _, _, StackedReductionRef<SC>>(
                self,
                transcript,
                params.n_stack,
                stacked_per_commit,
                need_rot_per_commit,
                &r,
            );

        let (&u0, u_rest) = u_prisma
            .split_first()
            .ok_or(crate::prover::error::WhirProverError::UPrismaEmpty)?;
        let u_cube = u0
            .exp_powers_of_2()
            .take(params.l_skip)
            .chain(u_rest.iter().copied())
            .collect_vec();

        let committed_mats = std::iter::once(&common_main_pcs_data)
            .chain(pre_cached_pcs_data_per_commit.iter().map(|d| d.as_ref()))
            .map(|d| (&d.matrix, &d.tree))
            .collect_vec();

        let whir_proof = prove_whir_opening::<SC, _>(
            transcript,
            self.config().hasher(),
            params.l_skip,
            params.log_blowup,
            &params.whir,
            &committed_mats,
            &u_cube,
        )?;
        Ok((stacking_proof, whir_proof))
    }
}

impl<SC: StarkProtocolConfig> DeviceDataTransporter<SC, ReferenceColMajorBackend<SC>>
    for ReferenceDevice<SC>
{
    fn transport_pk_to_device(
        &self,
        mpk: &MultiStarkProvingKey<SC>,
    ) -> DeviceMultiStarkProvingKey<ReferenceColMajorBackend<SC>> {
        // Merged-preprocessed mode: share the PCS data; each AIR gets a view of its own
        // matrix (`mat_view(mat_idx)`).
        //
        // Merged mode is carried by `merged_preprocessed_commit`, not by the host PCS data: a key
        // whose commit was deferred to an external committer carries the value with no data, and
        // cannot be transported here (no views to take). Falling through to per-air mode would
        // skip the merged commit against a vk that still expects it — a transcript divergence with
        // no error here — so reject it, and take the value from the SSOT field.
        assert_eq!(
            mpk.merged_preprocessed_commit.is_some(),
            mpk.merged_preprocessed_data.is_some(),
            "merged-preprocessed key with a deferred commit cannot be transported: it carries no \
             host PCS data (see MultiStarkProvingKey::patch_merged_preprocessed_commit)"
        );
        let merged = mpk.merged_preprocessed_data.as_ref().map(|d| {
            let commit = mpk
                .merged_preprocessed_commit
                .expect("host merged PCS data implies a merged commitment (asserted above)");
            (commit, d.clone())
        });
        let merged_mat_indices = merged.is_some().then(|| {
            merged_preprocessed_mat_indices(
                mpk.per_air
                    .iter()
                    .map(|pk| pk.vk.preprocessed_data.as_ref().map(|pd| pd.hypercube_dim)),
            )
        });

        let per_air = mpk
            .per_air
            .iter()
            .enumerate()
            .map(|(air_idx, pk)| {
                let preprocessed_data = if let Some((commit, data)) = &merged {
                    merged_mat_indices.as_ref().unwrap()[air_idx].map(|mat_idx| {
                        CommittedTraceData {
                            commitment: *commit,
                            trace: data.mat_view(mat_idx).to_matrix(),
                            data: data.clone(),
                        }
                    })
                } else {
                    pk.preprocessed_data.as_ref().map(|d| {
                        let trace = d.mat_view(0).to_matrix();
                        CommittedTraceData {
                            commitment: d.commit().unwrap(),
                            trace,
                            data: d.clone(),
                        }
                    })
                };
                DeviceStarkProvingKey {
                    air_name: pk.air_name.clone(),
                    vk: pk.vk.clone(),
                    preprocessed_data,
                    other_data: InteractionEvalPlan::from_dag(&pk.vk.symbolic_constraints),
                    symbolic_constraints_cache: std::sync::OnceLock::new(),
                }
            })
            .collect();
        DeviceMultiStarkProvingKey::new(
            per_air,
            mpk.trace_height_constraints.clone(),
            mpk.max_constraint_degree,
            mpk.params.clone(),
            mpk.vk_pre_hash,
            merged,
        )
    }

    fn transport_matrix_to_device(&self, matrix: &ColMajorMatrix<SC::F>) -> ColMajorMatrix<SC::F> {
        matrix.clone()
    }

    fn transport_pcs_data_to_device(
        &self,
        pcs_data: &StackedPcsData<SC::F, SC::Digest>,
    ) -> StackedPcsData<SC::F, SC::Digest> {
        pcs_data.clone()
    }

    fn transport_matrix_from_device_to_host(
        &self,
        matrix: &ColMajorMatrix<SC::F>,
    ) -> ColMajorMatrix<SC::F> {
        matrix.clone()
    }
}
