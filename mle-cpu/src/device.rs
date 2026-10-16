//! [CpuDevice] implementation: TraceCommitter, DeviceDataTransporter, MultiRapProver,
//! OpeningProver.

use getset::Getters;
use itertools::Itertools;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use pico_mle_core::{
    keygen::types::{merged_preprocessed_mat_indices, MultiStarkProvingKey},
    poly::{
        matrix::{ColMajorMatrix, StridedColMajorMatrixView},
        Squarable,
    },
    proof::{BatchConstraintProof, GkrProof, StackingProof, WhirProof},
    prover::{
        error::HostProverError,
        evaluator::InteractionEvalPlan,
        stacked_pcs::{stacked_matrix, StackedPcsData},
        stacked_reduction::prove_stacked_opening_reduction,
        CommittedTraceData, DeviceDataTransporter, DeviceMultiStarkProvingKey,
        DeviceStarkProvingKey, MultiRapProver, OpeningProver, ProverDevice, ProvingContext,
        TraceCommitter,
    },
    FiatShamirTranscript, StarkProtocolConfig, SystemParams,
};
use tracing::instrument;

use crate::{
    backend::CpuBackend,
    merkle::{rs_encode_and_merkle_cpu, CpuMerkleTree},
    pcs_data::CpuStackedPcsData,
    stacked_reduction::StackedReductionCpu,
};

/// Row-major CPU prover device.
#[derive(Clone, Getters, derive_new::new)]
pub struct CpuDevice<SC> {
    #[getset(get = "pub")]
    config: SC,
}

impl<SC: StarkProtocolConfig> CpuDevice<SC> {
    pub fn params(&self) -> &SystemParams {
        self.config.params()
    }
}

impl<SC, TS> ProverDevice<CpuBackend<SC>, TS> for CpuDevice<SC>
where
    SC: StarkProtocolConfig,
    SC::F: Ord,
    SC::EF: TwoAdicField + ExtensionField<SC::F> + Ord,
    TS: FiatShamirTranscript<SC>,
{
    type Error = HostProverError;
}

impl<SC: StarkProtocolConfig> TraceCommitter<CpuBackend<SC>> for CpuDevice<SC>
where
    SC::F: Ord,
{
    type Error = HostProverError;

    // The tuple return mirrors the HAL trait method's signature, so it can't be aliased away here.
    #[allow(clippy::type_complexity)]
    #[instrument(level = "info", name = "trace_commit_cpu", skip_all)]
    fn commit(
        &self,
        traces: &[&RowMajorMatrix<SC::F>],
    ) -> Result<(SC::Digest, CpuStackedPcsData<SC::F, SC::Digest>), Self::Error> {
        // Convert row-major to col-major for stacking commitment
        let col_major_traces: Vec<ColMajorMatrix<SC::F>> = traces
            .iter()
            .map(|rm| ColMajorMatrix::from_row_major(rm))
            .collect();
        let col_major_refs: Vec<&ColMajorMatrix<SC::F>> = col_major_traces.iter().collect();

        let params = self.params();
        let (q_trace, layout) = stacked_matrix(params.l_skip, params.n_stack, &col_major_refs)?;
        let tree = rs_encode_and_merkle_cpu(
            self.config().hasher(),
            params.l_skip,
            params.log_blowup,
            &q_trace,
            1 << params.k_whir(),
        );
        let root = tree.root()?;
        let data = CpuStackedPcsData::new(layout, q_trace, tree);
        Ok((root, data))
    }
}

impl<SC, TS> MultiRapProver<CpuBackend<SC>, TS> for CpuDevice<SC>
where
    SC: StarkProtocolConfig,
    SC::EF: TwoAdicField + ExtensionField<SC::F>,
    TS: FiatShamirTranscript<SC>,
{
    type PartialProof = (GkrProof<SC>, BatchConstraintProof<SC>);
    type Artifacts = Vec<SC::EF>;

    type Error = HostProverError;

    fn prove_rap_constraints(
        &self,
        transcript: &mut TS,
        mpk: &DeviceMultiStarkProvingKey<CpuBackend<SC>>,
        ctx: &ProvingContext<CpuBackend<SC>>,
    ) -> Result<((GkrProof<SC>, BatchConstraintProof<SC>), Vec<SC::EF>), Self::Error> {
        let pico_mle_core::prover::ZerocheckLogupProof {
            gkr,
            batch,
            eval_point,
        } = crate::logup_zerocheck::prove_zerocheck_and_logup::<SC, _>(transcript, mpk, ctx)?;
        Ok(((gkr, batch), eval_point))
    }
}

impl<SC, TS> OpeningProver<CpuBackend<SC>, TS> for CpuDevice<SC>
where
    SC: StarkProtocolConfig,
    SC::F: Ord,
    SC::EF: TwoAdicField + ExtensionField<SC::F> + Ord,
    TS: FiatShamirTranscript<SC>,
{
    type OpeningProof = (StackingProof<SC>, WhirProof<SC>);
    type OpeningPoints = Vec<SC::EF>;

    type Error = HostProverError;

    fn prove_openings(
        &self,
        transcript: &mut TS,
        mpk: &DeviceMultiStarkProvingKey<CpuBackend<SC>>,
        ctx: ProvingContext<CpuBackend<SC>>,
        common_main_pcs_data: CpuStackedPcsData<SC::F, SC::Digest>,
        r: Vec<SC::EF>,
    ) -> Result<(StackingProof<SC>, WhirProof<SC>), Self::Error> {
        let params = self.params();

        let (pre_cached_pcs_data_per_commit, need_rot_per_commit) = mpk.opening_prologue(&ctx);

        let mut stacked_per_commit = vec![&common_main_pcs_data];
        for data in &pre_cached_pcs_data_per_commit {
            stacked_per_commit.push(data);
        }
        let (stacking_proof, u_prisma) =
            prove_stacked_opening_reduction::<SC, _, _, _, StackedReductionCpu<SC>>(
                self,
                transcript,
                params.n_stack,
                stacked_per_commit,
                need_rot_per_commit,
                &r,
            );

        let (&u0, u_rest) = u_prisma
            .split_first()
            .ok_or(pico_mle_core::prover::error::WhirProverError::UPrismaEmpty)?;
        let u_cube = u0
            .exp_powers_of_2()
            .take(params.l_skip)
            .chain(u_rest.iter().copied())
            .collect_vec();

        // Convert to col-major for WHIR
        let committed_mats = std::iter::once(&common_main_pcs_data)
            .chain(pre_cached_pcs_data_per_commit.iter().map(|d| d.as_ref()))
            .map(|d| (&d.matrix, &d.tree))
            .collect_vec();

        let whir_proof = crate::whir::prove_whir_opening_cpu::<SC, _>(
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

impl<SC: StarkProtocolConfig> DeviceDataTransporter<SC, CpuBackend<SC>> for CpuDevice<SC> {
    fn transport_pk_to_device(
        &self,
        mpk: &MultiStarkProvingKey<SC>,
    ) -> DeviceMultiStarkProvingKey<CpuBackend<SC>> {
        // Merged-preprocessed mode: convert the shared PCS data ONCE and hand each AIR a
        // view of its own matrix (`mat_view(mat_idx)`) backed by the shared data.
        // (Converting per AIR instead would multiply memory/CPU by the AIR count.)
        //
        // ⚠️ Known limitation (test coverage): unit tests cover only the ReferenceDevice
        // copy of this logic; this branch is validated by the e2e convert gates — see the
        // note in prove_openings above.
        //
        // Merged mode is carried by `merged_preprocessed_commit`, not by the host PCS data: a key
        // whose commit was deferred to an external committer carries the value with no data. Such
        // a key cannot be transported here — there is nothing to take the per-AIR views from —
        // and falling through to per-air mode would build a proving key that skips the merged
        // commit against a vk that still expects it, a transcript divergence with no error here.
        // Reject it loudly instead, and read the value from the SSOT field rather than recomputing
        // it from the data.
        assert_eq!(
            mpk.merged_preprocessed_commit.is_some(),
            mpk.merged_preprocessed_data.is_some(),
            "merged-preprocessed key with a deferred commit cannot be CPU-transported: it carries \
             no host PCS data (see MultiStarkProvingKey::patch_merged_preprocessed_commit)"
        );
        let merged = mpk.merged_preprocessed_data.as_ref().map(|d| {
            let commit = mpk
                .merged_preprocessed_commit
                .expect("host merged PCS data implies a merged commitment (asserted above)");
            let cpu_data = std::sync::Arc::new(stacked_pcs_data_to_cpu::<SC>(d));
            (commit, cpu_data)
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
                let preprocessed_data = if let Some((commit, cpu_data)) = &merged {
                    let host_data = mpk.merged_preprocessed_data.as_ref().unwrap();
                    merged_mat_indices.as_ref().unwrap()[air_idx].map(|mat_idx| {
                        let view: StridedColMajorMatrixView<'_, SC::F> =
                            host_data.mat_view(mat_idx);
                        CommittedTraceData {
                            commitment: *commit,
                            trace: view.to_row_major_matrix(),
                            data: cpu_data.clone(),
                        }
                    })
                } else {
                    pk.preprocessed_data.as_ref().map(|d| {
                        let view: StridedColMajorMatrixView<'_, SC::F> = d.mat_view(0);
                        let trace = view.to_row_major_matrix();
                        CommittedTraceData {
                            commitment: d.commit().unwrap(),
                            trace,
                            data: std::sync::Arc::new(stacked_pcs_data_to_cpu::<SC>(d)),
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

    fn transport_matrix_to_device(&self, matrix: &ColMajorMatrix<SC::F>) -> RowMajorMatrix<SC::F> {
        let view: StridedColMajorMatrixView<'_, SC::F> = matrix.as_view().into();
        view.to_row_major_matrix()
    }

    /// This device's native matrix *is* row-major, so skip the HAL default's
    /// row-major → col-major → row-major round-trip.
    fn transport_row_major_matrix_to_device(
        &self,
        matrix: &RowMajorMatrix<SC::F>,
    ) -> RowMajorMatrix<SC::F> {
        matrix.clone()
    }

    fn transport_pcs_data_to_device(
        &self,
        pcs_data: &StackedPcsData<SC::F, SC::Digest>,
    ) -> CpuStackedPcsData<SC::F, SC::Digest> {
        stacked_pcs_data_to_cpu::<SC>(pcs_data)
    }

    fn transport_matrix_from_device_to_host(
        &self,
        matrix: &RowMajorMatrix<SC::F>,
    ) -> ColMajorMatrix<SC::F> {
        ColMajorMatrix::from_row_major(matrix)
    }
}

/// Convert the canonical host-format [`StackedPcsData`] (col-major Merkle backing) to the CPU
/// device's [`CpuStackedPcsData`] (row-major backing).
///
/// The eval matrix is cloned as-is (col-major); only the Merkle tree's backing matrix is
/// transposed to row-major. The `digest_layers` are reused verbatim: transposing the backing
/// changes only the in-memory layout of each leaf's row, not the row's contents, so the leaf
/// hashes — and therefore every digest layer and the root — are unchanged.
fn stacked_pcs_data_to_cpu<SC: StarkProtocolConfig>(
    pcs_data: &StackedPcsData<SC::F, SC::Digest>,
) -> CpuStackedPcsData<SC::F, SC::Digest> {
    // Transpose the col-major Merkle backing to row-major via the same helper
    // `transport_matrix_to_device` uses (a stride-1 view over the dense `ColMajorMatrix`).
    let cm_backing = pcs_data.tree.backing_matrix();
    let view: StridedColMajorMatrixView<'_, SC::F> = cm_backing.as_view().into();
    let rm_backing = view.to_row_major_matrix();
    let cpu_tree = CpuMerkleTree::from_raw_parts(
        rm_backing,
        pcs_data.tree.digest_layers().clone(),
        pcs_data.tree.rows_per_query(),
    );
    CpuStackedPcsData::new(pcs_data.layout.clone(), pcs_data.matrix.clone(), cpu_tree)
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use crate::{
        merkle::rs_encode_and_merkle_cpu, whir::prove_whir_opening_cpu, KoalaBearPoseidon2CpuEngine,
    };
    use pico_mle_core::{
        config::koala_bear_poseidon2::{EF, F},
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        poly::{
            eval_to_coeff_rs_message_with_twiddles, evals_mobius_eq_hypercube,
            matrix::ColMajorMatrix, ntt::TwiddleDft, Mle, Squarable,
        },
        prover::{stacked_pcs::stacked_commit, DeviceDataTransporter},
        test_utils::{test_system_params_small, InteractionsFixture11, TestFixture},
        verifier::whir::verify_whir_opening,
        StarkEngine, StarkProtocolConfig,
    };

    /// The production CPU backend and the reference backend must both prove the same
    /// interaction-bearing AIR set under one verifying key. Besides the per-kernel tests, this
    /// covers the full cached-plan/fused-accumulation path on both layouts. Running it with both
    /// zero and nonzero LogUp PoW also guards the CPU transcript's grinding semantics.
    #[test]
    fn interaction_proof_verifies_on_reference_and_cpu_backends() {
        for pow_bits in [0, 2] {
            let mut params = test_system_params_small(2, 5, 3);
            params.logup.pow_bits = pow_bits;
            let ref_engine: KoalaBearPoseidon2RefEngine = StarkEngine::new(params.clone());
            let cpu_engine: KoalaBearPoseidon2CpuEngine = StarkEngine::new(params);
            let fixture = InteractionsFixture11;
            let (pk, vk) = fixture.keygen(&ref_engine);

            let ref_proof = fixture.prove(&ref_engine, &pk);
            let cpu_proof = fixture.prove(&cpu_engine, &pk);
            ref_engine.verify(&vk, &ref_proof).unwrap();
            cpu_engine.verify(&vk, &cpu_proof).unwrap();
        }
    }

    /// Transporting a reference [`StackedPcsData`] (col-major Merkle backing) to the CPU device's
    /// [`CpuStackedPcsData`] (row-major backing) is a faithful round-trip. The load-bearing check is
    /// `get_opened_rows()`, which reads the *transposed* backing — a transpose bug would corrupt the
    /// opened rows while leaving the (reused) root and proofs intact.
    fn assert_transport_roundtrip(l_skip: usize, n_stack: usize, k_whir: usize) {
        let params = test_system_params_small(l_skip, n_stack, k_whir);
        let engine: KoalaBearPoseidon2CpuEngine = StarkEngine::new(params.clone());
        let config = engine.config();

        // A full-height, multi-column trace so the transpose is non-trivial.
        let height = 1usize << (l_skip + n_stack);
        let width = 3;
        let values: Vec<F> = (0..(width * height) as u32)
            .map(|v| F::from_u32(v + 1))
            .collect();
        let trace = ColMajorMatrix::new(values, width);

        let (root, ref_data) = stacked_commit(
            config.hasher(),
            params.l_skip,
            params.n_stack,
            params.log_blowup,
            params.k_whir(),
            &[&trace],
        )
        .unwrap();

        let cpu_data = engine.device().transport_pcs_data_to_device(&ref_data);

        // Roots agree with each other and with the value `stacked_commit` returned.
        assert_eq!(ref_data.tree.root().unwrap(), root);
        assert_eq!(cpu_data.tree.root().unwrap(), root);

        // Opened rows + authentication paths agree at *every* query index.
        let stride = ref_data.tree.query_stride();
        assert_eq!(cpu_data.tree.query_stride(), stride);
        assert!(stride > 0);
        for q in 0..stride {
            assert_eq!(
                ref_data.tree.get_opened_rows(q).unwrap(),
                cpu_data.tree.get_opened_rows(q).unwrap(),
                "opened rows diverge at query {q} for (l_skip={l_skip}, n_stack={n_stack}, k_whir={k_whir})"
            );
            assert_eq!(
                ref_data.tree.query_merkle_proof(q).unwrap(),
                cpu_data.tree.query_merkle_proof(q).unwrap(),
                "merkle proof diverges at query {q}"
            );
        }
    }

    #[test]
    fn transporter_roundtrip_matches_reference_across_geometries() {
        assert_transport_roundtrip(2, 2, 2);
        assert_transport_roundtrip(0, 3, 1);
    }

    /// The HAL's row-major host-context transport lands the same device context as the
    /// column-major one, including `cached_mains`.
    ///
    /// The RISCV driver only ever uses `AirProvingContext::simple` (`cached_mains = []`), so this
    /// is the only coverage the cached-mains loop and the row-major entry points get.
    #[test]
    fn row_major_ctx_transport_matches_col_major_and_carries_cached_mains() {
        use std::sync::Arc;

        use pico_mle_core::prover::{
            AirProvingContext, CommittedTraceData, ProvingContext, ReferenceColMajorBackend,
            RowMajorHostBackend,
        };

        let (l_skip, n_stack, k_whir) = (2usize, 2usize, 2usize);
        let params = test_system_params_small(l_skip, n_stack, k_whir);
        let engine: KoalaBearPoseidon2CpuEngine = StarkEngine::new(params.clone());
        let device = engine.device();
        let config = engine.config();

        // One cached-main trace (committed) plus a common-main trace.
        let height = 1usize << (l_skip + n_stack);
        let col_major = |off: u32, width: usize| {
            let values: Vec<F> = (0..(width * height) as u32)
                .map(|v| F::from_u32(v + off))
                .collect();
            ColMajorMatrix::new(values, width)
        };
        let cached_trace = col_major(1, 2);
        let common_trace = col_major(500, 3);

        let (commitment, cached_pcs) = stacked_commit(
            config.hasher(),
            params.l_skip,
            params.n_stack,
            params.log_blowup,
            params.k_whir(),
            &[&cached_trace],
        )
        .unwrap();
        let cached_pcs = Arc::new(cached_pcs);

        // Column-major host context (the HAL's anchor format).
        let col_ctx: ProvingContext<ReferenceColMajorBackend<_>> = ProvingContext::new(vec![(
            0,
            AirProvingContext::new(
                vec![CommittedTraceData {
                    commitment,
                    trace: cached_trace.clone(),
                    data: cached_pcs.clone(),
                }],
                common_trace.clone(),
                vec![F::ONE],
            ),
        )]);

        // The same context as a driver holds it: row-major traces, host `StackedPcsData`.
        let to_row_major = |m: &ColMajorMatrix<F>| device.transport_matrix_to_device(m);
        let row_ctx: ProvingContext<RowMajorHostBackend<_>> = ProvingContext::new(vec![(
            0,
            AirProvingContext::new(
                vec![CommittedTraceData {
                    commitment,
                    trace: to_row_major(&cached_trace),
                    data: cached_pcs.clone(),
                }],
                to_row_major(&common_trace),
                vec![F::ONE],
            ),
        )]);

        let from_col = device.transport_proving_ctx_to_device(&col_ctx);
        let from_row = device.transport_row_major_proving_ctx_to_device(&row_ctx);

        assert_eq!(from_col.per_trace.len(), 1);
        assert_eq!(from_row.per_trace.len(), 1);
        let (col_idx, col_air) = &from_col.per_trace[0];
        let (row_idx, row_air) = &from_row.per_trace[0];
        assert_eq!(col_idx, row_idx);
        assert_eq!(col_air.common_main, row_air.common_main);
        assert_eq!(col_air.public_values, row_air.public_values);

        // The cached main survived transport.
        assert_eq!(col_air.cached_mains.len(), 1);
        assert_eq!(row_air.cached_mains.len(), 1);
        let (col_cd, row_cd) = (&col_air.cached_mains[0], &row_air.cached_mains[0]);
        assert_eq!(col_cd.commitment, row_cd.commitment);
        assert_eq!(col_cd.trace, row_cd.trace);
        assert_eq!(
            col_cd.data.tree.root().unwrap(),
            row_cd.data.tree.root().unwrap()
        );
        assert_eq!(row_cd.data.tree.root().unwrap(), commitment);
    }

    /// The true per-column openings `⟨mle_col, evals_mobius_eq_hypercube(u)⟩` of an eval matrix —
    /// exactly the batched claim `prove_whir_opening_cpu` proves — computed with the prover's own
    /// MLE conversion so the two agree by construction.
    fn true_openings(eval_matrix: &ColMajorMatrix<F>, l_skip: usize, u: &[EF]) -> Vec<EF> {
        let twiddles = TwiddleDft::new(l_skip);
        let w = evals_mobius_eq_hypercube(u);
        eval_matrix
            .columns()
            .map(|col| {
                let mut mle = eval_to_coeff_rs_message_with_twiddles(col, &twiddles);
                Mle::coeffs_to_evals_inplace(&mut mle);
                w.iter().zip(&mle).map(|(&wi, &mi)| wi * mi).sum::<EF>()
            })
            .collect()
    }

    fn assert_whir_roundtrip(l_skip: usize, n_stack: usize, k_whir: usize) {
        let params = test_system_params_small(l_skip, n_stack, k_whir);
        let engine: KoalaBearPoseidon2CpuEngine = StarkEngine::new(params.clone());
        let config = engine.config();
        let hasher = config.hasher();

        // Committed eval matrix (height 2^{l_skip+n_stack}) + its CPU RS-codeword Merkle tree.
        let m = l_skip + n_stack;
        let (height, width) = (1usize << m, 2usize);
        let values: Vec<F> = (0..(width * height) as u32)
            .map(|v| F::from_u32(v + 1))
            .collect();
        let eval_matrix = ColMajorMatrix::new(values, width);
        let tree =
            rs_encode_and_merkle_cpu(hasher, l_skip, params.log_blowup, &eval_matrix, 1 << k_whir);
        let commit = tree.root().unwrap();

        // Opening point in cube form: [u0, u0², …, u0^{2^{l_skip-1}}, u_1, …, u_{n_stack}] — the
        // shape the stacked-reduction hands WHIR (see `verifier/mod.rs`'s `u_cube`).
        let u0 = EF::from_u32(0x9e37_79b9);
        let u: Vec<EF> = u0
            .exp_powers_of_2()
            .take(l_skip)
            .chain((0..n_stack).map(|i| EF::from_u32(31 + i as u32)))
            .collect();
        assert_eq!(u.len(), m);

        let openings = vec![true_openings(&eval_matrix, l_skip, &u)];
        let committed_mats = [(&eval_matrix, &tree)];

        // Prove and verify from matching fresh transcripts (WHIR observes no prior state here, so
        // both sides start in lock-step).
        let mut tp = engine.initial_transcript();
        let proof = prove_whir_opening_cpu(
            &mut tp,
            hasher,
            l_skip,
            params.log_blowup,
            &params.whir,
            &committed_mats,
            &u,
        )
        .expect("prove_whir_opening_cpu");

        let mut tv = engine.initial_transcript();
        verify_whir_opening(&mut tv, config, &proof, &openings, &[commit], &u)
            .expect("honest WHIR proof must verify");

        // Tamper #1 — a wrong opening claim (changes `claim` but not the transcript) is rejected.
        let mut bad = openings.clone();
        bad[0][0] += EF::ONE;
        let mut tv = engine.initial_transcript();
        assert!(verify_whir_opening(&mut tv, config, &proof, &bad, &[commit], &u).is_err());

        // Tamper #2 — a mutated proof (a sumcheck round evaluation) is rejected.
        let mut bad_proof = proof.clone();
        bad_proof.whir_sumcheck_polys[0][0] += EF::ONE;
        let mut tv = engine.initial_transcript();
        assert!(
            verify_whir_opening(&mut tv, config, &bad_proof, &openings, &[commit], &u).is_err()
        );

        // Tamper #3 — a wrong commitment (fails the initial-round Merkle check) is rejected.
        let mut bad_commit = commit;
        bad_commit[0] += F::ONE;
        let mut tv = engine.initial_transcript();
        assert!(
            verify_whir_opening(&mut tv, config, &proof, &openings, &[bad_commit], &u).is_err()
        );
    }

    /// `prove_whir_opening_cpu` → `verify_whir_opening` round-trips for an honest opening and rejects a
    /// tampered opening claim, proof, or commitment, across two geometries. The WHIR files otherwise
    /// have no unit coverage (exercised only end-to-end).
    #[test]
    fn whir_cpu_roundtrip_and_tamper_rejection() {
        assert_whir_roundtrip(2, 2, 2);
        assert_whir_roundtrip(0, 3, 1);
    }
}
