use core::iter::zip;

use itertools::{izip, Itertools};
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, TwoAdicField};
use thiserror::Error;
use tracing::instrument;

use crate::{
    hasher::MerkleHasher,
    poly::{
        eval_eq_mle, eval_mle_evals_at_point, eval_mobius_eq_mle, horner_eval,
        interpolate_quadratic_at_012, Squarable,
    },
    proof::WhirProof,
    verifier::Pass,
    FiatShamirTranscript, StarkProtocolConfig,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WhirVerificationError<EF: core::fmt::Debug + core::fmt::Display + PartialEq + Eq> {
    #[error("final polynomial has wrong length: {actual} != expected {expected}")]
    FinalPolyDegree { expected: usize, actual: usize },
    #[error("μ batching proof-of-work witness check failed")]
    MuPoWInvalid,
    #[error("folding proof-of-work witness check failed")]
    FoldingPoWInvalid,
    #[error("query phase proof-of-work witness check failed")]
    QueryPhasePoWInvalid,
    #[error(
        "final poly is not in the final constrained RS code: accumulator {acc} != claim {claim}"
    )]
    FinalPolyConstraint { claim: EF, acc: EF },
    #[error("merkle verification failed")]
    MerkleVerify,
}

#[inline]
fn ensure<EF: core::fmt::Debug + core::fmt::Display + PartialEq + Eq>(
    cond: bool,
    err: WhirVerificationError<EF>,
) -> Result<(), WhirVerificationError<EF>> {
    if cond {
        Ok(())
    } else {
        Err(err)
    }
}

/// Verify a WHIR proof.
///
/// Assumes that all inputs have already been checked to have the correct sizes.
pub fn verify_whir_opening<SC: StarkProtocolConfig, TS: FiatShamirTranscript<SC>>(
    transcript: &mut TS,
    config: &SC,
    whir_proof: &WhirProof<SC>,
    stacking_openings: &[Vec<SC::EF>],
    commitments: &[SC::Digest],
    u: &[SC::EF],
) -> Result<(), WhirVerificationError<SC::EF>> {
    verify_whir_opening_inner(
        transcript,
        config,
        whir_proof,
        stacking_openings,
        commitments,
        u,
        Pass::Verify,
    )
}

/// [`verify_whir_opening`] under an explicit [`Pass`].
///
/// Under [`Pass::TranscriptOnly`] the per-query body (leaf hashing, `merkle_verify`, the k-fold),
/// the μ/γ claim accumulation and the final constrained-RS check are all skipped. What stays is
/// every transcript operation, the round and sub-round counts, and the per-round
/// `log_rs_domain_size` decrement — so the query indices this samples are the same ones a full
/// verification would sample.
#[allow(clippy::too_many_arguments)]
#[instrument(name = "verify_whir_opening", level = "debug", skip_all)]
pub(crate) fn verify_whir_opening_inner<SC: StarkProtocolConfig, TS: FiatShamirTranscript<SC>>(
    transcript: &mut TS,
    config: &SC,
    whir_proof: &WhirProof<SC>,
    stacking_openings: &[Vec<SC::EF>],
    commitments: &[SC::Digest],
    u: &[SC::EF],
    pass: Pass,
) -> Result<(), WhirVerificationError<SC::EF>> {
    let params = config.params();
    // widths.len() = stacking_openings.len() = layouts.len(), which proof shape constructs to equal
    // the number of commitments, which equals commitments.len() by construction
    let widths = stacking_openings
        .iter()
        .map(|v| v.len())
        .collect::<Vec<_>>();

    // Check proof-of-work before μ batching challenge. `check_witness` is `observe` + `sample_bits`
    // internally, so it must be CALLED on both passes; only its verdict is conditional.
    let mu_pow_ok = transcript.check_witness(params.whir.mu_pow_bits, whir_proof.mu_pow_witness);
    if pass.checks() {
        ensure(mu_pow_ok, WhirVerificationError::MuPoWInvalid)?;
    }

    let mu = transcript.sample_ext();

    let WhirProof {
        mu_pow_witness: _, // Already checked above
        whir_sumcheck_polys,
        codeword_commits,
        ood_values,
        initial_round_opened_rows,
        initial_round_merkle_proofs,
        codeword_opened_values,
        codeword_merkle_proofs,
        folding_pow_witnesses,
        query_phase_pow_witnesses,
        final_poly,
    } = whir_proof;

    let m = params.l_skip + params.n_stack;
    let k_whir = params.k_whir();
    debug_assert_eq!((m - params.log_final_poly_len()) % k_whir, 0);
    let num_whir_rounds = params.num_whir_rounds();
    let mut log_rs_domain_size = m + params.log_blowup;
    debug_assert!(params.num_whir_sumcheck_rounds() <= m);
    // Proof shape asserts this:
    debug_assert_eq!(
        folding_pow_witnesses.len(),
        params.num_whir_sumcheck_rounds()
    );

    // Proof shape asserts whir_sumcheck_polys.len() == params.num_whir_sumcheck_rounds() :=
    // num_whir_rounds * k_whir
    let mut sumcheck_poly_iter = whir_sumcheck_polys.iter();
    let mut folding_pow_iter = folding_pow_witnesses.iter();
    // μ powers span the total stacked width and only ever batch openings into `claim` or fold the
    // opened rows — neither is observed.
    let mu_pows: Vec<_> = if pass.checks() {
        mu.powers().take(widths.iter().sum::<usize>()).collect()
    } else {
        vec![]
    };
    let mut claim = stacking_openings
        .iter()
        .flatten()
        .zip(mu_pows.iter())
        .fold(SC::EF::ZERO, |acc, (&opening, &mu_pow)| {
            acc + mu_pow * opening
        });

    let mut gammas = Vec::with_capacity(num_whir_rounds);
    let mut zs = Vec::with_capacity(num_whir_rounds);
    let mut z0s = Vec::with_capacity(num_whir_rounds);
    let mut alphas = Vec::with_capacity(m);

    // Proof shape asserts this:
    debug_assert_eq!(query_phase_pow_witnesses.len(), num_whir_rounds);
    // By construction, params.whir.rounds.len() == num_whir_rounds
    for (whir_round, (query_phase_pow_witness, round_params)) in
        zip(query_phase_pow_witnesses, &params.whir.rounds).enumerate()
    {
        // A WHIR round consists of the following steps:
        // 1) Run k rounds of sumcheck to obtain polynomial f'.
        // 2) On non-final rounds, observe commitment f' on shifted domain.
        // 3) On non-final rounds, sample OOD point z0 and observe claim y0 =?= f'(z0).
        // 4) Sample in-domain queries z_i and compute f'(z_i) from openings. On the first round,
        //    the codeword is not committed directly; instead it is derived from the stacking
        //    commitments. In all other rounds, the previous codeword is committed directly.
        // 5) On non-final rounds, sample batching parameter gamma to define next codeword and
        //    derive new WHIR constraint target (`claim`).

        let is_initial_round = whir_round == 0;
        let is_final_round = whir_round == num_whir_rounds - 1;

        let mut alphas_round = Vec::with_capacity(k_whir);

        for _ in 0..k_whir {
            // This is never None because num_whir_sumcheck_rounds == num_whir_rounds * k_whir
            if let Some(evals) = sumcheck_poly_iter.next() {
                let &[ev1, ev2] = evals;

                transcript.observe_ext(ev1);
                transcript.observe_ext(ev2);

                let pow_witness = *folding_pow_iter.next().unwrap();
                let folding_pow_ok =
                    transcript.check_witness(params.whir.folding_pow_bits, pow_witness);
                if pass.checks() {
                    ensure(folding_pow_ok, WhirVerificationError::FoldingPoWInvalid)?;
                }
                let alpha = transcript.sample_ext();
                alphas_round.push(alpha);

                if pass.checks() {
                    let ev0 = claim - ev1;
                    claim = interpolate_quadratic_at_012(&[ev0, ev1, ev2], alpha);
                }
            }
        }

        let y0 = if is_final_round {
            // Observe the final polynomial before the queries on the final
            // round.
            for coeff in final_poly {
                transcript.observe_ext(*coeff);
            }
            None
        } else {
            // Proof shape asserts codeword_commits.len() == num_whir_rounds - 1
            let commit = codeword_commits[whir_round];
            transcript.observe_commit(commit);

            let z0 = transcript.sample_ext();
            z0s.push(z0);

            // Proof shape asserts ood_values.len() == num_whir_rounds - 1
            let y0 = ood_values[whir_round];
            transcript.observe_ext(y0);
            Some(y0)
        };

        let query_pow_ok =
            transcript.check_witness(params.whir.query_phase_pow_bits, *query_phase_pow_witness);
        if pass.checks() {
            ensure(query_pow_ok, WhirVerificationError::QueryPhasePoWInvalid)?;
        }

        let num_queries = round_params.num_queries;
        // Collected, not left lazy: each element is a transcript sample and must be drawn on BOTH
        // passes. Drawing them up front is what lets the per-query state below — two vectors, the
        // hasher and the domain generator, none of which the transcript-only pass reads — sit
        // behind the guard instead of being built and thrown away every round.
        let query_indices = (0..num_queries)
            .map(|_| transcript.sample_bits(log_rs_domain_size - k_whir))
            .collect_vec();

        let mut zs_round = Vec::new();
        let mut ys_round = Vec::new();
        // The indices are the transcript's output; the whole block below — leaf hashing,
        // `merkle_verify`, the k-fold — observes nothing and feeds only the deferred
        // `acc == claim` identity.
        if pass.checks() {
            zs_round.reserve_exact(num_queries);
            ys_round.reserve_exact(num_queries);
            let hasher = config.hasher();
            let omega = SC::F::two_adic_generator(log_rs_domain_size);
            for (query_idx, &index) in query_indices.iter().enumerate() {
                let zi_root = omega.exp_u64(index);
                let zi = zi_root.exp_power_of_2(k_whir);

                let yi = if is_initial_round {
                    let mut codeword_vals = vec![SC::EF::ZERO; 1 << k_whir];
                    let mut mu_pow_iter = mu_pows.iter();
                    // Proof shape asserts everything in the izip! has length equal to layouts.len()
                    for (&commit, &width, opened_rows_per_query, merkle_proofs) in izip!(
                        commitments,
                        &widths,
                        initial_round_opened_rows,
                        initial_round_merkle_proofs
                    ) {
                        // Proof shape asserts
                        // - opened_rows_per_query.len() = whir.rounds[0].num_queries
                        // - opened_rows.len() = 2^k_whir
                        let opened_rows = &opened_rows_per_query[query_idx];
                        let leaf_hashes = opened_rows
                            .iter()
                            .map(|opened_row| hasher.hash_slice(opened_row))
                            .collect_vec();
                        let query_digest = hasher.tree_compress(leaf_hashes);
                        // Proof shape asserts
                        // - merkle_proofs.len() = whir.rounds[0].num_queries
                        // - merkle_proof.len() = l_skip + n_stack + log_blowup - k_whir =:
                        //   log_rs_domain_size - k_whir
                        let merkle_proof = &merkle_proofs[query_idx];
                        merkle_verify(hasher, commit, index as u32, query_digest, merkle_proof)?;

                        // `c` picks a column out of each row the inner loop visits: clippy's
                        // suggested iterator over `opened_rows[j]` needs the inner loop's `j`.
                        #[allow(clippy::needless_range_loop)]
                        for c in 0..width {
                            let mu_pow = mu_pow_iter.next().unwrap(); // ok; mu_pows has total_width length
                            for j in 0..(1 << k_whir) {
                                codeword_vals[j] += *mu_pow * opened_rows[j][c];
                            }
                        }
                    }
                    binary_k_fold::<SC::F, SC::EF>(codeword_vals, &alphas_round, zi_root)
                } else {
                    // Proof shape asserts
                    // - codeword_opened_values.len() == codeword_merkle_proofs.len() == num_whir_rounds
                    //   - 1
                    // - codeword_opened_values[whir_round - 1].len() ==
                    //   codeword_merkle_proofs[whir_round - 1].len() ==
                    //   whir.rounds[whir_round].num_queries
                    // - codeword_opened_values[whir_round - 1][query_idx].len() = 2^k_whir
                    let opened_values = codeword_opened_values[whir_round - 1][query_idx].clone();
                    let merkle_proof = &codeword_merkle_proofs[whir_round - 1][query_idx];
                    let leaf_hashes = opened_values
                        .iter()
                        .map(|opened_value| {
                            hasher.hash_slice(opened_value.as_basis_coefficients_slice())
                        })
                        .collect_vec();
                    let query_digest = hasher.tree_compress(leaf_hashes);
                    // Proof shape asserts `merkle_proof.len() == l_skip + n_stack + log_blowup - k_whir
                    // - round`, which equals `log_rs_domain_size - k_whir` at this point in time
                    merkle_verify(
                        hasher,
                        codeword_commits[whir_round - 1],
                        index as u32,
                        query_digest,
                        merkle_proof,
                    )?;
                    binary_k_fold::<SC::F, SC::EF>(opened_values, &alphas_round, zi_root)
                };
                zs_round.push(zi);
                ys_round.push(yi);
            }
        }
        // We sample `gamma` even in the final round. There are no observations
        // after this challenge and strictly serves to unify the verifier logic.
        // Rather than checking that `final_poly(zi) = yi` for all `i` in the
        // last round, we accumulate them into `claim`. The final WHIR check
        // automatically performs this check for us (now with high probability).
        let gamma = transcript.sample_ext();
        if pass.checks() {
            if let Some(y0) = y0 {
                claim += y0 * gamma;
            }
            for (yi, gamma_pow) in ys_round.iter().zip(gamma.powers().skip(2)) {
                claim += *yi * gamma_pow;
            }
        }
        gammas.push(gamma);
        zs.push(zs_round);
        alphas.extend(alphas_round);

        log_rs_domain_size -= 1;
    }
    debug_assert!(sumcheck_poly_iter.next().is_none());

    // Every observation is behind us: the final polynomial was observed coefficient by
    // coefficient in the last round, so its length shapes nothing that remains.
    if !pass.checks() {
        return Ok(());
    }

    ensure(
        final_poly.len() == 1 << params.log_final_poly_len(),
        WhirVerificationError::FinalPolyDegree {
            expected: 1 << params.log_final_poly_len(),
            actual: final_poly.len(),
        },
    )?;

    debug_assert_eq!(alphas.len(), k_whir * num_whir_rounds);
    debug_assert_eq!(z0s.len(), num_whir_rounds - 1);
    debug_assert_eq!(zs.len(), num_whir_rounds);
    debug_assert_eq!(gammas.len(), num_whir_rounds);

    // Here we perform the final WHIR check, which requires us to compute
    //
    //  sum_{b in H_{m-t}} f(b) (mobius_eq(u, alpha || b) +
    //                           sum_i sum_j gamma_{i,j} eq(pow(z_i) alpha[ki..] || b)),
    //
    // where || denotes concatenation.
    //
    // If we let u' = u[..t] and u'' = u[t..], then by factoring we can rewrite the term
    // ```text
    // sum_{b in H_{m-t}} f(b) mobius_eq(u, alpha || b) = mobius_eq(u', alpha) *
    //                                                    sum_{b in H_{m-t}} f(b) mobius_eq(u'',b)
    // ```
    //
    // For multilinear f with coefficient table `c[S]`, we have the identity:
    //   sum_{b} f(b) mobius_eq(u'', b) = sum_{S} c[S] eq(u'', S),
    // i.e. it is the MLE of the table `c` evaluated at `u''`.
    //
    // Similar algebra allows us to control the terms with eq(pow(z_i)). Note that here we actually
    // end up with f(pow(z_i^{2^p})) for some power p, which is a univariate evaluation.
    let t = k_whir * num_whir_rounds;
    let prefix = eval_mobius_eq_mle(&u[..t], &alphas[..t]);
    let suffix_sum = eval_mle_evals_at_point(&mut final_poly.clone(), &u[t..]);
    let mut acc = prefix * suffix_sum;
    let mut j = k_whir;
    for i in 0..num_whir_rounds {
        let zis = &zs[i];
        let gamma = gammas[i];
        let alpha_slc = &alphas[j..t];
        let slc_len = (t - j) + 1;

        if i != num_whir_rounds - 1 {
            let z0_pow = z0s[i].exp_powers_of_2().take(slc_len).collect_vec();
            let (z0_pow_max, z0_pow_left) = z0_pow.split_last().unwrap();
            acc += gamma
                * eval_eq_mle(alpha_slc, z0_pow_left)
                * horner_eval::<SC::EF, SC::EF, SC::EF>(final_poly, *z0_pow_max);
        }

        debug_assert_eq!(zis.len(), params.whir.rounds[i].num_queries);
        for (zi, gamma_pow) in zip(zis, gamma.powers().skip(2)) {
            let zi_pow = zi.exp_powers_of_2().take(slc_len).collect_vec();
            let (zi_pow_max, zi_pow_left) = zi_pow.split_last().unwrap();
            acc += gamma_pow
                * eval_eq_mle(alpha_slc, zi_pow_left)
                * horner_eval::<SC::EF, SC::F, SC::EF>(final_poly, *zi_pow_max);
        }
        j += k_whir;
    }
    ensure(
        acc == claim,
        WhirVerificationError::FinalPolyConstraint { claim, acc },
    )
}

/// Evaluates the k-fold binary fold of `f` at `x^{2^k}` given its evaluations
/// `values` on the coset `H = {x, ωx, …, ω^{2^k-1}x}` and fold points `alphas`.
///
/// Let `g₀ = f`. For `i >= 1` define
///
///   gᵢ(Y) = fold(g_{i-1}; α_{i-1})(Y),
///
/// where
///
///   fold(h; α)(X²) = h(X) + (α - X) * (h(X) - h(-X)) / (2X).
///
/// If `values = [f(x), f(ωx), …, f(ω^{2^k-1}x)]`, then
/// `binary_k_fold(values, alphas, x)` returns `g_k(x^{2^k})`.
fn binary_k_fold<F: TwoAdicField, EF: ExtensionField<F>>(
    mut values: Vec<EF>,
    alphas: &[EF],
    x: F,
) -> EF {
    let n = values.len();
    let k = alphas.len();
    debug_assert_eq!(n, 1 << k);

    let omega_k = F::two_adic_generator(k);
    let omega_k_inv = omega_k.inverse();

    let tw = omega_k.powers().take(1 << (k - 1)).collect_vec();
    let inv_tw = omega_k_inv.powers().take(1 << (k - 1)).collect_vec();

    for (j, (&alpha, x_pow, x_inv_pow)) in izip!(
        alphas.iter(),
        x.exp_powers_of_2(),
        x.inverse().exp_powers_of_2()
    )
    .enumerate()
    {
        let m = n >> (j + 1);
        let (lo, hi) = values.split_at_mut(m);

        for i in 0..m {
            let t = tw[i << j] * x_pow;
            let t_inv = inv_tw[i << j] * x_inv_pow;
            lo[i] += (alpha - t) * (lo[i] - hi[i]) * t_inv.halve();
        }
    }
    values[0]
}

fn merkle_verify<H: MerkleHasher, EF: core::fmt::Debug + core::fmt::Display + PartialEq + Eq>(
    hasher: &H,
    root: H::Digest,
    mut idx: u32,
    leaf_hash: H::Digest,
    merkle_proof: &[H::Digest],
) -> Result<(), WhirVerificationError<EF>>
where
    H::Digest: Eq,
{
    let mut cur = leaf_hash;
    for &sibling in merkle_proof {
        cur = if idx & 1 == 0 {
            hasher.compress(cur, sibling)
        } else {
            hasher.compress(sibling, cur)
        };
        idx >>= 1;
    }
    if root != cur {
        Err(WhirVerificationError::MerkleVerify)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::koala_bear_poseidon2::{
            default_duplex_sponge_recorder, default_koalabear_hasher, Digest, DuplexSpongeRecorder,
            KoalaBearPoseidon2Config, EF, F,
        },
        poly::{eval_to_coeff_rs_message, evals_mobius_eq_hypercube, matrix::ColMajorMatrix, Mle},
        prover::{stacked_pcs::stacked_commit, whir::prove_whir_opening},
        test_utils::test_system_params_small,
        SystemParams,
    };

    /// A fresh transcript with the initial commitments observed. In the real pipeline the
    /// caller (`prover::prove` / `verifier::verify`) observes them, NOT the WHIR
    /// prover/verifier, so prover and verifier transcripts here must mirror the same
    /// observations.
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

    const L_SKIP: usize = 2;
    const N_STACK: usize = 5;
    const K_WHIR: usize = 3;

    /// A committed WHIR opening instance together with an honestly generated reference proof.
    struct Instance {
        config: KoalaBearPoseidon2Config,
        roots: Vec<Digest>,
        u: Vec<EF>,
        /// Per commitment, per stacked column: the claimed opening, computed independently of
        /// both provers and the verifier.
        openings: Vec<Vec<EF>>,
        proof: WhirProof<KoalaBearPoseidon2Config>,
    }

    fn small_params() -> SystemParams {
        test_system_params_small(L_SKIP, N_STACK, K_WHIR)
    }

    /// Commit one matrix per requested width, then prove the batched WHIR opening at a
    /// production-shaped point with the reference prover.
    fn prove_instance(widths: &[usize], params: SystemParams) -> Instance {
        // A single-round instance would leave the inter-round paths (codeword commits, OOD
        // values, γ accumulation) empty and the test vacuous.
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

        // Opening point with the production "cube" shape: the first `l_skip` coordinates are
        // successive squares of a single univariate point (cf. the u_prism -> u_cube
        // expansion in `verifier::verify`).
        let u0 = EF::from_u32(0xBEEF);
        let u = u0
            .exp_powers_of_2()
            .take(L_SKIP)
            .chain((0..N_STACK).map(|i| EF::from_u32(1000 + i as u32)))
            .collect_vec();

        // Independent ground truth for each column's claimed opening: the RS-message
        // coefficient vector, read as a multilinear evaluation table and evaluated at `u` via
        // an eq-fold — a third code path, distinct from both the prover's mobius_eq pairing
        // and the verifier's closed-form `eval_mobius_eq_mle` chain. Cross-checks the pairing
        // identity the prover relies on:
        //   <coeffs_to_evals(c), mobius_eq(u)> == <c, eq(u)>.
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

        Instance {
            config: KoalaBearPoseidon2Config::default_from_params(params),
            roots,
            u,
            openings,
            proof,
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

    /// WHIR-open a single MLE at a point: prove (reference) + verify.
    #[test]
    fn whir_open_single_mle_round_trip() {
        let instance = prove_instance(&[1], small_params());
        run_verify(&instance, &instance.proof, &instance.openings).unwrap();
    }

    /// Batched openings of several columns across several commitments (exercises μ batching
    /// and the per-commit grouping of initial-round openings).
    #[test]
    fn whir_open_batched_commitments_round_trip() {
        let instance = prove_instance(&[2, 1], small_params());
        run_verify(&instance, &instance.proof, &instance.openings).unwrap();
    }

    /// The claimed evaluation is not observed by the WHIR transcript, so a wrong claim leaves
    /// all challenges and Merkle checks intact — only the deferred final accumulator identity
    /// `acc == claim` can reject it.
    #[test]
    fn whir_verify_rejects_wrong_claim() {
        let instance = prove_instance(&[1], small_params());
        let mut openings = instance.openings.clone();
        openings[0][0] += EF::ONE;
        assert!(matches!(
            run_verify(&instance, &instance.proof, &openings).unwrap_err(),
            WhirVerificationError::FinalPolyConstraint { .. }
        ));
    }

    #[test]
    fn whir_verify_rejects_tampered_proof() {
        let instance = prove_instance(&[1], small_params());
        let honest = &instance.proof;

        // Opened leaves are checked against the (transcript-independent) commitment, so this
        // deterministically trips the Merkle check.
        let mut bad = honest.clone();
        bad.initial_round_opened_rows[0][0][0][0] += F::ONE;
        assert_eq!(
            run_verify(&instance, &bad, &instance.openings).unwrap_err(),
            WhirVerificationError::MerkleVerify
        );

        // PoW witnesses and transcript-observed values (sumcheck polys, OOD values, the final
        // polynomial) re-randomize downstream challenges when tampered, so only rejection is
        // asserted (which check trips first may vary).
        let tampers: [fn(&mut WhirProof<KoalaBearPoseidon2Config>); 7] = [
            |proof| proof.mu_pow_witness += F::ONE,
            |proof| proof.folding_pow_witnesses[0] += F::ONE,
            |proof| proof.query_phase_pow_witnesses[0] += F::ONE,
            |proof| proof.whir_sumcheck_polys[0][0] += EF::ONE,
            |proof| proof.ood_values[0] += EF::ONE,
            |proof| proof.codeword_opened_values[0][0][0] += EF::ONE,
            |proof| {
                proof.final_poly.pop();
            },
        ];
        for (i, tamper) in tampers.into_iter().enumerate() {
            let mut bad = honest.clone();
            tamper(&mut bad);
            assert!(
                run_verify(&instance, &bad, &instance.openings).is_err(),
                "tamper #{i} must be rejected"
            );
        }
    }
}
