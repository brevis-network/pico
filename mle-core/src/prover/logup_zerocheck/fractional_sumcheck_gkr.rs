use std::ops::Add;

use p3_field::{Field, PrimeCharacteristicRing};
use p3_util::log2_strict_usize;
use tracing::{debug, instrument};

use crate::{
    poly::{evals_eq_hypercube_par, matrix::ColMajorMatrix},
    proof::GkrLayerClaims,
    prover::{
        error::LogupZerocheckError,
        sumcheck::{fold_mle_evals, sumcheck_round_poly_evals},
    },
    FiatShamirTranscript, StarkProtocolConfig,
};

/// Proof for fractional sumcheck protocol
pub struct FracSumcheckProof<SC: StarkProtocolConfig> {
    /// The fractional sum p_0 / q_0
    pub fractional_sum: (SC::EF, SC::EF),
    /// The claims for p_j(0, rho), p_j(1, rho), q_j(0, rho), and q_j(1, rho) for each layer j > 0.
    pub claims_per_layer: Vec<GkrLayerClaims<SC>>,
    /// Sumcheck polynomials for each layer, for each sumcheck round, given by their evaluations on
    /// {1, 2, 3}.
    pub sumcheck_polys: Vec<Vec<[SC::EF; 3]>>,
}

#[derive(Clone, Copy, Debug, Default, derive_new::new)]
#[repr(C)]
pub struct Frac<EF> {
    // In the initial round, `p` can remain in the base field.
    pub p: EF,
    pub q: EF,
}

impl<EF: Field> Add<Frac<EF>> for Frac<EF> {
    type Output = Frac<EF>;

    fn add(self, other: Frac<EF>) -> Self::Output {
        Frac {
            p: self.p * other.q + self.q * other.p,
            q: self.q * other.q,
        }
    }
}

/// Runs the fractional sumcheck protocol using GKR layered circuit.
///
/// # Arguments
/// * `transcript` - The Fiat-Shamir transcript
/// * `evals` - list of `(p, q)` pairs of fractions in projective coordinates representing
///   evaluations on the hypercube
/// * `assert_zero` - Whether to assert that the final sum is zero. If `true`, then the transcript
///   will not observe the numerator of the final sum.
///
/// # Returns
/// The fractional sumcheck proof and the final random evaluation vector.
#[instrument(level = "info", skip_all)]
pub fn fractional_sumcheck<SC: StarkProtocolConfig, TS: FiatShamirTranscript<SC>>(
    transcript: &mut TS,
    evals: &[Frac<SC::EF>],
    assert_zero: bool,
) -> Result<(FracSumcheckProof<SC>, Vec<SC::EF>), LogupZerocheckError> {
    if evals.is_empty() {
        return Ok((
            FracSumcheckProof {
                fractional_sum: (SC::EF::ZERO, SC::EF::ONE),
                claims_per_layer: vec![],
                sumcheck_polys: vec![],
            },
            vec![],
        ));
    }
    // total_rounds = l_skip + n_logup
    let total_rounds = log2_strict_usize(evals.len());
    // sumcheck polys for layers j=2,...,total_rounds
    let mut sumcheck_polys = Vec::with_capacity(total_rounds);

    // segment tree: layer i=0,...,total_rounds starts at 2^i (index 0 unused)
    let mut tree_evals: Vec<Frac<SC::EF>> = vec![Frac::default(); 2 << total_rounds];
    tree_evals[(1 << total_rounds)..].copy_from_slice(evals);

    for node_idx in (1..(1 << total_rounds)).rev() {
        tree_evals[node_idx] = tree_evals[2 * node_idx] + tree_evals[2 * node_idx + 1];
    }
    let frac_sum = tree_evals[1];
    if assert_zero {
        if frac_sum.p != SC::EF::ZERO {
            return Err(LogupZerocheckError::NonZeroRootSum);
        }
    } else {
        transcript.observe_ext(frac_sum.p);
    }
    transcript.observe_ext(frac_sum.q);

    // Index i is for layer i+1
    let mut claims_per_layer: Vec<GkrLayerClaims<SC>> = Vec::with_capacity(total_rounds);

    // Process each GKR round
    // `j = round + 1` goes from `1, ..., total_rounds`
    //
    // Round `j = 1` is special since "sumcheck" is directly checked by verifier
    claims_per_layer.push(GkrLayerClaims::<SC> {
        p_xi_0: tree_evals[2].p,
        q_xi_0: tree_evals[2].q,
        p_xi_1: tree_evals[3].p,
        q_xi_1: tree_evals[3].q,
    });
    transcript.observe_ext(claims_per_layer[0].p_xi_0);
    transcript.observe_ext(claims_per_layer[0].q_xi_0);
    transcript.observe_ext(claims_per_layer[0].p_xi_1);
    transcript.observe_ext(claims_per_layer[0].q_xi_1);
    let mu_1 = transcript.sample_ext();
    debug!(gkr_round = 0, mu = %mu_1);
    // ξ^{(j-1)}
    let mut xi_prev = vec![mu_1];

    // GKR rounds
    for round in 1..total_rounds {
        // Number of hypercube points
        let eval_size = 1 << round;
        // We apply batch sumcheck to the polynomials
        // \eq(ξ^{(j-1)}, Y) (\hat p_j(0, Y) \hat q_j(1, Y) + \hat p_j(1, Y) \hat q_j(0, Y))
        // \eq(ξ^{(j-1)}, Y) (\hat q_j(0, Y) \hat q_j(1, Y))
        // Note: these are polynomials of degree 3 in each Y_i coordinate.

        // Sample λ_j for batching
        let lambda = transcript.sample_ext();
        debug!(gkr_round = round, %lambda);

        // Columns are p_j0, q_j0, p_j1, q_j1
        // PERF: use a view instead of re-allocating memory
        let mut pq_j_evals = SC::EF::zero_vec(4 * eval_size);
        let segment = &tree_evals[2 * eval_size..4 * eval_size];
        for x in 0..eval_size {
            pq_j_evals[x] = segment[2 * x].p;
            pq_j_evals[eval_size + x] = segment[2 * x].q;
            pq_j_evals[2 * eval_size + x] = segment[2 * x + 1].p;
            pq_j_evals[3 * eval_size + x] = segment[2 * x + 1].q;
        }
        let mut pq_j_evals = ColMajorMatrix::new(pq_j_evals, 4);
        let mut eq_xis = ColMajorMatrix::new(evals_eq_hypercube_par(&xi_prev), 1);

        // Batch sumcheck where the round polynomials are evaluated at {1, 2, 3}
        let (round_polys_eval, rho) = {
            let n = round;
            let mut round_polys_eval = Vec::with_capacity(n);
            let mut r_vec = Vec::with_capacity(n);

            // Sumcheck rounds: apply fraction addition in projective coordinates to MLEs
            for sumcheck_round in 0..n {
                // Evaluate the univariate polynomial at {1, 2, 3}
                // :projective fraction addition is degree 2, and then another +1 for eq
                let [s_evals] = sumcheck_round_poly_evals(
                    n - sumcheck_round,
                    3,
                    &[eq_xis.as_view(), pq_j_evals.as_view()],
                    |_x, _y, row| {
                        let eq_xi = row[0][0];
                        let &[p_j0, q_j0, p_j1, q_j1] = row[1].as_slice() else {
                            unreachable!("pq_j_evals always has 4 columns")
                        };
                        let p_prev = p_j0 * q_j1 + p_j1 * q_j0;
                        let q_prev = q_j0 * q_j1;
                        // batch using lambda
                        [eq_xi * (p_prev + lambda * q_prev)]
                    },
                );
                let s_evals: [SC::EF; 3] = s_evals.try_into().unwrap();
                for &eval in &s_evals {
                    transcript.observe_ext(eval);
                }
                round_polys_eval.push(s_evals);

                let r_round = transcript.sample_ext();
                pq_j_evals = fold_mle_evals(pq_j_evals, r_round);
                eq_xis = fold_mle_evals(eq_xis, r_round);
                r_vec.push(r_round);
                debug!(gkr_round = round, %sumcheck_round, %r_round);
            }
            (round_polys_eval, r_vec)
        };
        claims_per_layer.push(GkrLayerClaims::<SC> {
            p_xi_0: pq_j_evals.column(0)[0],
            q_xi_0: pq_j_evals.column(1)[0],
            p_xi_1: pq_j_evals.column(2)[0],
            q_xi_1: pq_j_evals.column(3)[0],
        });
        transcript.observe_ext(claims_per_layer[round].p_xi_0);
        transcript.observe_ext(claims_per_layer[round].q_xi_0);
        transcript.observe_ext(claims_per_layer[round].p_xi_1);
        transcript.observe_ext(claims_per_layer[round].q_xi_1);

        // Sample μ_j for reduction to single evaluation point
        let mu = transcript.sample_ext();
        debug!(gkr_round = round, %mu);

        // Update ξ^{(j)} = (μ_j, ρ^{(j-1)})
        xi_prev = [vec![mu], rho].concat();

        sumcheck_polys.push(round_polys_eval);
    }

    Ok((
        FracSumcheckProof {
            fractional_sum: (frac_sum.p, frac_sum.q),
            claims_per_layer,
            sumcheck_polys,
        },
        xi_prev,
    ))
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::{
        config::koala_bear_poseidon2::{
            default_koalabear_poseidon2_16, DuplexSponge, KoalaBearPoseidon2Config as SC, EF, F,
        },
        poly::evals_eq_hypercube_par,
        proof::GkrProof,
        verifier::fractional_sumcheck_gkr::{verify_gkr, GkrVerificationError},
    };

    fn fresh_transcript() -> DuplexSponge {
        DuplexSponge::from(default_koalabear_poseidon2_16())
    }

    fn ef(x: u32) -> EF {
        EF::from_u32(x)
    }

    /// A vector of `n` fractions with unit denominators whose numerators sum to zero (a balanced
    /// LogUp input layer).
    fn zero_sum_evals(n: usize) -> Vec<Frac<EF>> {
        let mut ps: Vec<EF> = (1..n as u32).map(ef).collect();
        let sum: EF = ps.iter().copied().fold(EF::ZERO, |a, b| a + b);
        ps.insert(0, EF::ZERO - sum);
        ps.into_iter().map(|p| Frac::new(p, EF::ONE)).collect()
    }

    fn to_gkr_proof(proof: FracSumcheckProof<SC>) -> GkrProof<SC> {
        GkrProof {
            // Not consulted by `verify_gkr`; the PoW witness is checked one layer up.
            logup_pow_witness: F::ZERO,
            q0_claim: proof.fractional_sum.1,
            claims_per_layer: proof.claims_per_layer,
            sumcheck_polys: proof.sumcheck_polys,
        }
    }

    /// Prover and verifier agree on a balanced input: `verify_gkr` accepts, recovers the prover's
    /// evaluation point ξ, and its reduced `(p̂(ξ), q̂(ξ))` equals the true MLE of the input layer.
    #[test]
    fn gkr_fractional_sum_round_trip() {
        let evals = zero_sum_evals(8);
        let total_rounds = log2_strict_usize(evals.len());

        let mut tp = fresh_transcript();
        let (proof, xi_prover) =
            fractional_sumcheck::<SC, _>(&mut tp, &evals, true).expect("prover");
        let gkr_proof = to_gkr_proof(proof);

        let mut tv = fresh_transcript();
        let (p_xi, q_xi, xi_verifier) =
            verify_gkr::<SC, _>(&gkr_proof, &mut tv, total_rounds).expect("verify");

        assert_eq!(xi_verifier, xi_prover, "Fiat-Shamir point mismatch");

        // The reduced claims must equal the multilinear extension of the input layer at ξ,
        // using the codebase's own eq-hypercube weights (same convention as the prover).
        let eqs = evals_eq_hypercube_par(&xi_verifier);
        let p_mle: EF = eqs
            .iter()
            .zip(&evals)
            .map(|(&e, f)| e * f.p)
            .fold(EF::ZERO, |a, b| a + b);
        let q_mle: EF = eqs
            .iter()
            .zip(&evals)
            .map(|(&e, f)| e * f.q)
            .fold(EF::ZERO, |a, b| a + b);
        assert_eq!(p_mle, p_xi, "p̂(ξ) mismatch");
        assert_eq!(q_mle, q_xi, "q̂(ξ) mismatch");
    }

    /// A corrupted proof (perturbed root denominator claim) must be rejected.
    #[test]
    fn gkr_rejects_corrupted_proof() {
        let evals = zero_sum_evals(8);
        let total_rounds = log2_strict_usize(evals.len());

        let mut tp = fresh_transcript();
        let (proof, _) = fractional_sumcheck::<SC, _>(&mut tp, &evals, true).expect("prover");
        let mut gkr_proof = to_gkr_proof(proof);
        gkr_proof.claims_per_layer[0].q_xi_0 += EF::ONE;

        let mut tv = fresh_transcript();
        let result = verify_gkr::<SC, _>(&gkr_proof, &mut tv, total_rounds);
        // Perturbing a root layer claim breaks the numerator zero-check / denominator consistency.
        assert!(
            matches!(
                result,
                Err(GkrVerificationError::ZeroCheckFailed { .. })
                    | Err(GkrVerificationError::RootConsistencyCheckFailed { .. })
            ),
            "expected a root consistency rejection, got {result:?}"
        );
    }

    /// In `assert_zero` mode, an unbalanced input (non-zero fractional sum, e.g. from a mismatched
    /// LogUp bus) is rejected by the prover.
    #[test]
    fn gkr_prover_rejects_nonzero_sum() {
        let evals = vec![Frac::new(EF::ONE, EF::ONE); 4]; // Σ p = 4 ≠ 0
        let mut tp = fresh_transcript();
        let result = fractional_sumcheck::<SC, _>(&mut tp, &evals, true);
        assert!(matches!(result, Err(LogupZerocheckError::NonZeroRootSum)));
    }

    /// The empty input degenerates to the trivial (0/1) proof and verifies at `total_rounds = 0`.
    #[test]
    fn gkr_empty_input_is_trivial() {
        let mut tp = fresh_transcript();
        let (proof, xi) = fractional_sumcheck::<SC, _>(&mut tp, &[], true).expect("prover");
        assert!(xi.is_empty());
        let gkr_proof = to_gkr_proof(proof);
        assert_eq!(gkr_proof.q0_claim, EF::ONE);

        let mut tv = fresh_transcript();
        let (p_xi, q_xi, xi_v) = verify_gkr::<SC, _>(&gkr_proof, &mut tv, 0).expect("verify");
        assert_eq!(p_xi, EF::ZERO);
        assert_eq!(q_xi, EF::ONE);
        assert!(xi_v.is_empty());
    }
}
