//! Optimized WHIR opening prover for the CPU backend.
//!
//! Key optimizations over the shared `prove_whir_opening`:
//! - Uses cached-twiddle eval-to-coeff conversion
//! - Parallelized sumcheck inner loop and folding
//! - Reuses scratch buffers for equality-vector accumulation
//! - Early drop of large intermediate data structures

use itertools::Itertools;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, TwoAdicField};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;
use pico_mle_core::{
    hasher::MerkleHasher,
    poly::{
        accumulate_scaled_eq_hypercube_base_field, accumulate_scaled_eq_hypercube_same_field,
        eval_to_coeff_rs_message_with_twiddles, evals_mobius_eq_hypercube,
        matrix::{ColMajorMatrix, MatrixDimensions},
        ntt::TwiddleDft,
        Mle, Squarable,
    },
    proof::{MerkleProof, WhirProof},
    prover::error::WhirProverError,
    FiatShamirTranscript, StarkProtocolConfig, WhirConfig,
};
use tracing::instrument;

use crate::merkle::{build_digest_layers, hash_rows_with_padding, CpuMerkleTree};

/// Optimized WHIR opening prover for the CPU backend.
///
/// Same protocol as the reference `prove_whir_opening`, but with:
/// - Cached-twiddle MLE conversion
/// - Parallelized sumcheck evaluation and folding
/// - Scratch-buffered equality accumulation
/// - Early memory deallocation
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
#[instrument(name = "prove_whir_opening_cpu", skip_all)]
pub fn prove_whir_opening_cpu<SC, TS>(
    transcript: &mut TS,
    hasher: &SC::Hasher,
    l_skip: usize,
    log_blowup: usize,
    whir_params: &WhirConfig,
    committed_mats: &[(&ColMajorMatrix<SC::F>, &CpuMerkleTree<SC::F, SC::Digest>)],
    u: &[SC::EF],
) -> Result<WhirProof<SC>, WhirProverError>
where
    SC: StarkProtocolConfig,
    SC::F: TwoAdicField + Ord,
    SC::EF: TwoAdicField + ExtensionField<SC::F> + Ord,
    TS: FiatShamirTranscript<SC>,
{
    // PoW grinding before μ batching challenge.
    let mu_pow_witness = transcript.grind(whir_params.mu_pow_bits);

    let mu: SC::EF = transcript.sample_ext();
    let total_width: usize = committed_mats.iter().map(|(mat, _)| mat.width()).sum();
    let mu_powers: Vec<SC::EF> = mu.powers().take(total_width).collect_vec();

    let height = committed_mats[0].0.height();
    debug_assert!(committed_mats.iter().all(|(mat, _)| mat.height() == height));
    let mut m = log2_strict_usize(height);

    let k_whir = whir_params.k;
    let num_whir_rounds = whir_params.num_whir_rounds();
    let num_sumcheck_rounds = whir_params.num_sumcheck_rounds();
    let twiddles = TwiddleDft::new(l_skip);

    // Phase 1: MLE conversion using cached twiddles.
    let mles: Vec<Vec<SC::F>> = tracing::info_span!("whir_mle_conversion").in_scope(|| {
        committed_mats
            .par_iter()
            .flat_map(|(mat, _)| {
                mat.par_columns().map(|col| {
                    let mut x = eval_to_coeff_rs_message_with_twiddles(col, &twiddles);
                    Mle::coeffs_to_evals_inplace(&mut x);
                    x
                })
            })
            .collect()
    });

    // Phase 2: Batch into f_evals, then drop mles to free ~300MB
    let mut f_evals: Vec<SC::EF> = tracing::info_span!("whir_f_evals_batch").in_scope(|| {
        (0..1usize << m)
            .into_par_iter()
            .map(|i| {
                mles.iter()
                    .zip(mu_powers.iter())
                    .fold(SC::EF::ZERO, |acc, (mle_j, mu_j)| acc + *mu_j * mle_j[i])
            })
            .collect()
    });
    drop(mles);

    let mut w_evals = evals_mobius_eq_hypercube(u);

    let mut whir_sumcheck_polys: Vec<[SC::EF; 2]> = Vec::with_capacity(num_sumcheck_rounds);
    let mut codeword_commits = vec![];
    let mut ood_values = vec![];
    let mut initial_round_opened_rows: Vec<Vec<Vec<Vec<SC::F>>>> =
        vec![vec![]; committed_mats.len()];
    let mut initial_round_merkle_proofs: Vec<Vec<MerkleProof<SC::Digest>>> =
        vec![vec![]; committed_mats.len()];
    let mut codeword_opened_values: Vec<Vec<Vec<SC::EF>>> = Vec::with_capacity(num_whir_rounds - 1);
    let mut codeword_merkle_proofs: Vec<Vec<MerkleProof<SC::Digest>>> =
        Vec::with_capacity(num_whir_rounds - 1);
    let mut folding_pow_witnesses = Vec::with_capacity(num_sumcheck_rounds);
    let mut query_phase_pow_witnesses = Vec::with_capacity(num_whir_rounds);
    let mut rs_tree: Option<CpuMerkleTree<SC::EF, SC::Digest>> = None;
    let mut log_rs_domain_size = m + log_blowup;
    let mut final_poly = None;
    let mut w_eq_scratch_ext = Vec::new();
    let mut w_eq_scratch_base = Vec::new();

    for (whir_round, round_params) in whir_params.rounds.iter().enumerate() {
        let is_last_round = whir_round == num_whir_rounds - 1;

        // Sumcheck rounds with parallelized evaluation and folding
        tracing::info_span!("whir_sumcheck", round = whir_round).in_scope(|| {
            for round in 0..k_whir {
                debug_assert_eq!(f_evals.len(), 1 << (m - round));

                let s_deg = 2;
                let hypercube_dim = m - round - 1;

                // Parallelized sumcheck evaluation
                let s_evals: Vec<SC::EF> = (1..=s_deg)
                    .map(|x_idx| {
                        let x: SC::F = SC::F::from_usize(x_idx);
                        (0..(1usize << hypercube_dim))
                            .into_par_iter()
                            .map(|y| {
                                let f_0 = f_evals[y << 1];
                                let f_1 = f_evals[(y << 1) + 1];
                                let f_x = f_0 + (f_1 - f_0) * x;
                                let w_0 = w_evals[y << 1];
                                let w_1 = w_evals[(y << 1) + 1];
                                let w_x = w_0 + (w_1 - w_0) * x;
                                f_x * w_x
                            })
                            .sum::<SC::EF>()
                    })
                    .collect();

                for &eval in &s_evals {
                    transcript.observe_ext(eval);
                }
                whir_sumcheck_polys.push(s_evals.try_into().unwrap());

                folding_pow_witnesses.push(transcript.grind(whir_params.folding_pow_bits));
                let alpha: SC::EF = transcript.sample_ext();

                // Parallelized folding
                let half = f_evals.len() / 2;
                let new_f: Vec<SC::EF> = (0..half)
                    .into_par_iter()
                    .map(|y| {
                        let eval_0 = f_evals[y << 1];
                        let eval_1 = f_evals[(y << 1) + 1];
                        eval_0 + alpha * (eval_1 - eval_0)
                    })
                    .collect();
                let new_w: Vec<SC::EF> = (0..half)
                    .into_par_iter()
                    .map(|y| {
                        let eval_0 = w_evals[y << 1];
                        let eval_1 = w_evals[(y << 1) + 1];
                        eval_0 + alpha * (eval_1 - eval_0)
                    })
                    .collect();
                f_evals = new_f;
                w_evals = new_w;
            }
        });

        // Build g_mle from folded evaluations
        let g_mle = Mle::from_evaluations(&f_evals);
        let (g_tree, z_0) = if !is_last_round {
            let g_coeffs_for_open = g_mle.into_coeffs();
            let g_tree =
                tracing::info_span!("whir_dft_merkle", round = whir_round).in_scope(|| {
                    let dft = Radix2DitParallel::default();
                    let mut g_coeffs = g_coeffs_for_open.clone();
                    debug_assert_eq!(g_coeffs.len(), 1 << (m - k_whir));
                    g_coeffs.resize(1 << (log_rs_domain_size - 1), SC::EF::ZERO);
                    let g_rs = dft.dft(g_coeffs);
                    build_ef_merkle_tree_packed::<SC>(hasher, g_rs, 1 << k_whir)
                });
            let g_commit = g_tree.root()?;
            transcript.observe_commit(g_commit);
            codeword_commits.push(g_commit);

            let z_0: SC::EF = transcript.sample_ext();
            let z_0_vec: Vec<SC::EF> = z_0.exp_powers_of_2().take(m - k_whir).collect_vec();
            let g_opened_value =
                Mle::from_coeffs(g_coeffs_for_open).eval_at_point_inplace(&z_0_vec);
            transcript.observe_ext(g_opened_value);
            ood_values.push(g_opened_value);

            (Some(g_tree), Some(z_0))
        } else {
            let coeffs = g_mle.into_coeffs();
            for coeff in &coeffs {
                transcript.observe_ext(*coeff);
            }
            final_poly = Some(coeffs);
            (None, None)
        };

        // Query phase
        let omega: SC::F = SC::F::two_adic_generator(log_rs_domain_size - k_whir);
        let num_queries = round_params.num_queries;
        let mut query_indices = Vec::with_capacity(num_queries);
        query_phase_pow_witnesses.push(transcript.grind(whir_params.query_phase_pow_bits));
        for _ in 0..num_queries {
            let index = transcript.sample_bits(log_rs_domain_size - k_whir);
            query_indices.push(index as usize);
        }
        let mut zs = Vec::with_capacity(num_queries);
        if !is_last_round {
            codeword_opened_values.push(vec![]);
            codeword_merkle_proofs.push(vec![]);
        }
        for (query_idx, index) in query_indices.into_iter().enumerate() {
            let z_i = omega.exp_u64(index as u64);
            zs.push(z_i);

            let depth = log_rs_domain_size.saturating_sub(k_whir);
            if whir_round == 0 {
                #[allow(clippy::needless_range_loop)]
                for com_idx in 0..committed_mats.len() {
                    debug_assert_eq!(initial_round_merkle_proofs[com_idx].len(), query_idx);
                    let tree = &committed_mats[com_idx].1;
                    assert_eq!(tree.backing_matrix().height(), 1 << log_rs_domain_size);
                    let opened_rows = tree.get_opened_rows(index)?;
                    initial_round_opened_rows[com_idx].push(opened_rows);
                    debug_assert_eq!(tree.proof_depth(), depth);
                    let proof = tree.query_merkle_proof(index)?;
                    debug_assert_eq!(proof.len(), depth);
                    initial_round_merkle_proofs[com_idx].push(proof);
                }
            } else {
                let tree: &CpuMerkleTree<SC::EF, SC::Digest> = rs_tree.as_ref().unwrap();
                assert_eq!(tree.backing_matrix().width(), 1);
                let opened_rows = tree
                    .get_opened_rows(index)?
                    .into_iter()
                    .flatten()
                    .collect_vec();
                codeword_opened_values[whir_round - 1].push(opened_rows);
                debug_assert_eq!(tree.proof_depth(), depth);
                let proof = tree.query_merkle_proof(index)?;
                debug_assert_eq!(proof.len(), depth);
                codeword_merkle_proofs[whir_round - 1].push(proof);
            }
        }
        rs_tree = g_tree;

        let gamma: SC::EF = transcript.sample_ext();

        if !is_last_round {
            // Scratch-buffered equality accumulation. z_0 is in the extension field; z_i are in
            // the base field and can use cheaper F arithmetic before EF accumulation.
            tracing::info_span!("whir_w_evals_accum", round = whir_round).in_scope(|| {
                let dim = log2_strict_usize(w_evals.len());
                let z_0_pows = z_0.unwrap().exp_powers_of_2().take(dim).collect_vec();
                accumulate_scaled_eq_hypercube_same_field(
                    &mut w_evals,
                    &z_0_pows,
                    gamma,
                    &mut w_eq_scratch_ext,
                );
                for (z_i, gamma_pow) in zs.into_iter().zip(gamma.powers().skip(2)) {
                    let z_i_pows = z_i.exp_powers_of_2().take(dim).collect_vec();
                    accumulate_scaled_eq_hypercube_base_field(
                        &mut w_evals,
                        &z_i_pows,
                        gamma_pow,
                        &mut w_eq_scratch_base,
                    );
                }
            });
        }

        m -= k_whir;
        log_rs_domain_size -= 1;
    }

    Ok(WhirProof::<SC> {
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
        final_poly: final_poly.ok_or(WhirProverError::FinalPolyNone)?,
    })
}

/// Build a Merkle tree from extension field codeword values, hashing one row per leaf.
fn build_ef_merkle_tree_packed<SC>(
    hasher: &SC::Hasher,
    g_rs: Vec<SC::EF>,
    rows_per_query: usize,
) -> CpuMerkleTree<SC::EF, SC::Digest>
where
    SC: StarkProtocolConfig,
    SC::F: TwoAdicField + Ord,
    SC::EF: TwoAdicField + ExtensionField<SC::F>,
{
    let height = g_rs.len();
    let num_leaves = height.next_power_of_two();
    let ef_width = SC::D_EF;

    // Phase 1: Hash each extension-field codeword row into a leaf digest (zero-padded).
    let row_hashes: Vec<SC::Digest> = tracing::info_span!("merkle_tree").in_scope(|| {
        let zero_row = vec![SC::F::ZERO; ef_width];
        hash_rows_with_padding(
            num_leaves,
            height,
            |r| hasher.hash_slice(g_rs[r].as_basis_coefficients_slice()),
            || hasher.hash_slice(&zero_row),
        )
    });

    // Phase 2: Build Merkle digest layers using shared helper.
    let layers = build_digest_layers(row_hashes, rows_per_query, hasher);

    let backing_matrix = p3_matrix::dense::RowMajorMatrix::new(g_rs, 1);
    // SAFETY: layers were just computed as correct Merkle hashes over backing_matrix.
    CpuMerkleTree::from_raw_parts(backing_matrix, layers, rows_per_query)
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use p3_field::PrimeCharacteristicRing;
    use pico_mle_core::{
        config::koala_bear_poseidon2::{
            default_duplex_sponge_recorder, default_koalabear_hasher, Digest, DuplexSpongeRecorder,
            KoalaBearPoseidon2Config, EF, F,
        },
        poly::{
            eval_mle_evals_at_point, eval_to_coeff_rs_message, evals_mobius_eq_hypercube,
            matrix::ColMajorMatrix, Mle, Squarable,
        },
        proof::WhirProof,
        prover::{stacked_pcs::stacked_commit, whir::prove_whir_opening},
        test_utils::test_system_params_small,
        verifier::whir::{verify_whir_opening, WhirVerificationError},
        FiatShamirTranscript, SystemParams,
    };

    use super::prove_whir_opening_cpu;
    use crate::merkle::rs_encode_and_merkle_cpu;

    const L_SKIP: usize = 2;
    const N_STACK: usize = 5;
    const K_WHIR: usize = 3;

    /// A committed WHIR opening instance, proved by both the reference and the row-major prover.
    struct Instance {
        config: KoalaBearPoseidon2Config,
        roots: Vec<Digest>,
        u: Vec<EF>,
        openings: Vec<Vec<EF>>,
        proof: WhirProof<KoalaBearPoseidon2Config>,
        cpu_proof: WhirProof<KoalaBearPoseidon2Config>,
    }

    fn small_params() -> SystemParams {
        test_system_params_small(L_SKIP, N_STACK, K_WHIR)
    }

    /// PoW grinding searches witnesses in parallel (`find_any`), so with nonzero PoW bits two
    /// prover runs may find different (equally valid) witnesses and their transcripts
    /// legitimately diverge. Zeroing the bits makes proving fully deterministic.
    fn zero_pow_params() -> SystemParams {
        let mut params = small_params();
        params.whir.mu_pow_bits = 0;
        params.whir.folding_pow_bits = 0;
        params.whir.query_phase_pow_bits = 0;
        params
    }

    fn transcript_with_roots(roots: &[Digest]) -> DuplexSpongeRecorder {
        let mut transcript = default_duplex_sponge_recorder();
        for &root in roots {
            <DuplexSpongeRecorder as FiatShamirTranscript<KoalaBearPoseidon2Config>>::observe_commit(
                &mut transcript,
                root,
            );
        }
        transcript
    }

    /// Commit one matrix per requested width, then prove the batched WHIR opening at a
    /// production-shaped point with both the reference and the CPU prover.
    fn prove_instance(widths: &[usize], params: SystemParams) -> Instance {
        assert!(params.whir.num_whir_rounds() >= 2);
        let hasher = default_koalabear_hasher();
        let height = 1usize << (L_SKIP + N_STACK);

        let mats = widths
            .iter()
            .enumerate()
            .map(|(k, &width)| {
                let values = (0..width * height)
                    .map(|v| F::from_u32((v * 31 + 1000 * k + 7) as u32))
                    .collect();
                ColMajorMatrix::new(values, width)
            })
            .collect_vec();
        let committed = mats
            .iter()
            .map(|mat| {
                stacked_commit(&hasher, L_SKIP, N_STACK, params.log_blowup, K_WHIR, &[mat]).unwrap()
            })
            .collect_vec();

        let u0 = EF::from_u32(0xBEEF);
        let u = u0
            .exp_powers_of_2()
            .take(L_SKIP)
            .chain((0..N_STACK).map(|i| EF::from_u32(1000 + i as u32)))
            .collect_vec();

        // Independent ground truth for each column's claimed opening: the RS-message coefficient
        // vector, read as a multilinear evaluation table and evaluated at `u` via an eq-fold.
        let w_evals = evals_mobius_eq_hypercube(&u);
        let openings = committed
            .iter()
            .map(|(_, data)| {
                data.matrix
                    .columns()
                    .map(|col| {
                        let coeffs = eval_to_coeff_rs_message(L_SKIP, col);
                        let mut lifted = coeffs.iter().map(|&c| EF::from(c)).collect_vec();
                        let claim = eval_mle_evals_at_point(&mut lifted, &u);
                        let mut hat_f = coeffs;
                        Mle::coeffs_to_evals_inplace(&mut hat_f);
                        let pairing: EF = hat_f.iter().zip(&w_evals).map(|(&f, &w)| w * f).sum();
                        assert_eq!(pairing, claim);
                        claim
                    })
                    .collect_vec()
            })
            .collect_vec();

        let roots = committed.iter().map(|(root, _)| *root).collect_vec();
        let mut transcript = transcript_with_roots(&roots);
        let committed_mats = committed
            .iter()
            .map(|(_, data)| (&data.matrix, &data.tree))
            .collect_vec();
        let proof = prove_whir_opening::<KoalaBearPoseidon2Config, _>(
            &mut transcript,
            &hasher,
            L_SKIP,
            params.log_blowup,
            &params.whir,
            &committed_mats,
            &u,
        )
        .unwrap();

        let cpu_trees = committed
            .iter()
            .map(|(root, data)| {
                let tree = rs_encode_and_merkle_cpu(
                    &hasher,
                    L_SKIP,
                    params.log_blowup,
                    &data.matrix,
                    1 << K_WHIR,
                );
                assert_eq!(tree.root().unwrap(), *root);
                tree
            })
            .collect_vec();
        let cpu_mats = committed
            .iter()
            .zip(&cpu_trees)
            .map(|((_, data), tree)| (&data.matrix, tree))
            .collect_vec();
        let mut cpu_transcript = transcript_with_roots(&roots);
        let cpu_proof = prove_whir_opening_cpu::<KoalaBearPoseidon2Config, _>(
            &mut cpu_transcript,
            &hasher,
            L_SKIP,
            params.log_blowup,
            &params.whir,
            &cpu_mats,
            &u,
        )
        .unwrap();

        Instance {
            config: KoalaBearPoseidon2Config::default_from_params(params),
            roots,
            u,
            openings,
            proof,
            cpu_proof,
        }
    }

    fn run_verify(
        instance: &Instance,
        proof: &WhirProof<KoalaBearPoseidon2Config>,
        openings: &[Vec<EF>],
    ) -> Result<(), WhirVerificationError<EF>> {
        let mut transcript = transcript_with_roots(&instance.roots);
        verify_whir_opening::<KoalaBearPoseidon2Config, _>(
            &mut transcript,
            &instance.config,
            proof,
            openings,
            &instance.roots,
            &instance.u,
        )
    }

    /// WHIR-open a single MLE at a point with the CPU prover, then verify.
    #[test]
    fn whir_open_single_mle_round_trip_cpu() {
        let instance = prove_instance(&[1], small_params());
        run_verify(&instance, &instance.cpu_proof, &instance.openings).unwrap();
    }

    /// Batched openings of several columns across several commitments, CPU prover.
    #[test]
    fn whir_open_batched_commitments_round_trip_cpu() {
        let instance = prove_instance(&[2, 1], small_params());
        run_verify(&instance, &instance.cpu_proof, &instance.openings).unwrap();
    }

    /// With PoW grinding disabled, proving is fully deterministic, so the reference and the
    /// CPU-optimized prover must emit identical proofs from identical transcripts.
    #[test]
    fn whir_reference_and_cpu_provers_agree() {
        let instance = prove_instance(&[2, 1], zero_pow_params());
        assert_eq!(instance.proof, instance.cpu_proof);
        run_verify(&instance, &instance.proof, &instance.openings).unwrap();
    }
}
