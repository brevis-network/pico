//! Wrap circuit (gnark target) for the **embed** proof: a full in-circuit port of
//! [`pico_mle_core::verifier::verify`] over the outer (BN254-Poseidon2) primitives.
//!
//! Stages (mirroring the Rust verifier exactly, in transcript order):
//! 1. preamble — vk pre-hash, common-main commitment, per-AIR presence / preprocessed /
//!    log-height / cached observations, public values;
//! 2. `verify_zerocheck_and_logup` — logup PoW, α/β, the full GKR fractional sumcheck,
//!    ξ padding, λ, claim totals, μ, the univariate skip round, the `n_max` multilinear
//!    rounds, eq computations, column-opening observations, the per-AIR constraint-DAG and
//!    interaction evaluations, and the final `cur_sum == evaluated_claim` assert;
//! 3. `verify_stacked_reduction` — λ_stack batching, the univariate + `n_stack` sumcheck
//!    rounds, per-column `q_coeffs` recomputation, and the final-sum assert;
//! 4. `verify_whir` — μ PoW + batching, per-round sumcheck folds + folding PoW, OOD claims,
//!    query-phase PoW, in-domain queries (native BN254 Merkle openings via
//!    [`outer_hash`]/[`outer_compress`]), `binary_k_fold`, γ accumulation, and the final
//!    constrained-RS check;
//! 5. completeness — `flag_complete == 1`, the in-circuit KoalaBear-Poseidon2 PV-digest
//!    recomputation, the two gnark public inputs (`CommitVkeyHash` over the riscv vk
//!    digest limbs, `CommitCommittedValuesDigest` over the 32 committed-value bytes), and, when
//!    a whitelist root is pinned, one `AssertVkRoot` against it.
//!
//! Conventions:
//! - vk-side values and the proof's shape (which AIRs are present, their heights) are baked
//!   into the circuit as constants; every other proof value is read from the witness streams
//!   (vars/felts/exts) — ALL proof data is read up front by [`read_wrap_proof`], in the exact
//!   order [`write_wrap_witness`] writes it, so the digit/remainder stream of the transcript
//!   twin (appended by the harness after the proof data) never interleaves with proof reads.
//! - transcript sampling soundness relies on the recomposition constraint documented in
//!   [`super::outer_bn254`].

use p3_bn254::Bn254;
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_koala_bear::KoalaBear;

use super::outer_bn254::OuterTranscript;
use crate::{
    compiler::recursion::{
        circuit::utils::felt_to_byte_bits,
        ir::{Builder, DslIr, Ext, Felt, Var},
    },
    configs::{config::FieldGenericConfig, field_config::KoalaBearBn254},
};

type FC = KoalaBearBn254;
type F = KoalaBear;
type N = Bn254;
type EF = <FC as FieldGenericConfig>::EF;
type ExtV = Ext<F, EF>;

// =============================================================================================
// Generic Ext-arithmetic helpers (twins of `mle::poly_common`)
// =============================================================================================

fn ext_const(builder: &mut Builder<FC>, v: EF) -> ExtV {
    builder.constant(v)
}

/// Lift a base felt into the extension (`x + 0·EF`).
fn felt_to_ext(builder: &mut Builder<FC>, x: Felt<F>) -> ExtV {
    let out: ExtV = builder.uninit();
    builder.push_op(DslIr::AddEFFI(out, x, EF::ZERO));
    out
}

/// `e0 + (e1 - e0)*x` (twin of `interpolate_linear_at_01`).
fn interp_linear(builder: &mut Builder<FC>, e0: ExtV, e1: ExtV, x: ExtV) -> ExtV {
    builder.eval(e0 + (e1 - e0) * x)
}

/// Quadratic interpolation through `(0..=2, evals)` at `x` (twin of
/// `interpolate_quadratic_at_012`).
fn interp_quadratic(builder: &mut Builder<FC>, e: [ExtV; 3], x: ExtV) -> ExtV {
    let inv2 = EF::from_u32(2).inverse();
    let s1: ExtV = builder.eval(e[1] - e[0]);
    let s2: ExtV = builder.eval(e[2] - e[1]);
    let p: ExtV = builder.eval((s2 - s1) * inv2);
    let q: ExtV = builder.eval(s1 - p);
    builder.eval((p * x + q) * x + e[0])
}

/// Cubic interpolation through `(0..=3, evals)` at `x` (twin of `interpolate_cubic_at_0123`).
fn interp_cubic(builder: &mut Builder<FC>, e: [ExtV; 4], x: ExtV) -> ExtV {
    let inv6 = ext_const(builder, EF::from_u64(6).inverse());
    let inv2 = ext_const(builder, EF::from_u64(2).inverse());
    let s1: ExtV = builder.eval(e[1] - e[0]);
    let s2: ExtV = builder.eval(e[2] - e[0]);
    let s3: ExtV = builder.eval(e[3] - e[0]);
    let d3: ExtV = builder.eval(s3 - (s2 - s1) * EF::from_u32(3));
    let pp: ExtV = builder.eval(d3 * inv6);
    let qq: ExtV = builder.eval((s2 - d3) * inv2 - s1);
    let rr: ExtV = builder.eval(s1 - pp - qq);
    builder.eval(((pp * x + qq) * x + rr) * x + e[0])
}

/// Horner evaluation of `coeffs` at `x` (twin of `horner_eval`).
fn horner(builder: &mut Builder<FC>, coeffs: &[ExtV], x: ExtV) -> ExtV {
    let mut acc: ExtV = ext_const(builder, EF::ZERO);
    for &c in coeffs.iter().rev() {
        acc = builder.eval(acc * x + c);
    }
    acc
}

/// `[x, x², x⁴, …]` with `n` entries (twin of `Squarable::exp_powers_of_2().take(n)`).
fn ext_powers_of_2(builder: &mut Builder<FC>, x: ExtV, n: usize) -> Vec<ExtV> {
    let mut out = Vec::with_capacity(n);
    let mut cur = x;
    for _ in 0..n {
        out.push(cur);
        cur = builder.eval(cur * cur);
    }
    out
}

/// `x^{2^n}` by repeated squaring.
fn ext_square_n(builder: &mut Builder<FC>, x: ExtV, n: usize) -> ExtV {
    let mut cur = x;
    for _ in 0..n {
        cur = builder.eval(cur * cur);
    }
    cur
}

/// `∏_i (1 − y_i − x_i + 2·x_i·y_i)` (twin of `eval_eq_mle` with both sides variables).
fn eval_eq_mle_vars(builder: &mut Builder<FC>, x: &[ExtV], y: &[ExtV]) -> ExtV {
    debug_assert_eq!(x.len(), y.len());
    let one = ext_const(builder, EF::ONE);
    let mut acc = one;
    for (&x_i, &y_i) in x.iter().zip(y) {
        let xy: ExtV = builder.eval(x_i * y_i);
        let term: ExtV = builder.eval(one - y_i - x_i + xy + xy);
        acc = builder.eval(acc * term);
    }
    acc
}

/// `eval_eq_mle(x, b)` with a *static boolean* second argument: `∏ (b_i ? x_i : 1 − x_i)`.
fn eval_eq_mle_static(builder: &mut Builder<FC>, x: &[ExtV], b: &[bool]) -> ExtV {
    debug_assert_eq!(x.len(), b.len());
    let one = ext_const(builder, EF::ONE);
    let mut acc = one;
    for (&x_i, &b_i) in x.iter().zip(b) {
        let term: ExtV = if b_i { x_i } else { builder.eval(one - x_i) };
        acc = builder.eval(acc * term);
    }
    acc
}

/// `∏_i ((1 − 2·u_i)(1 − x_i) + u_i·x_i)` (twin of `eval_mobius_eq_mle`).
fn eval_mobius_eq_mle(builder: &mut Builder<FC>, u: &[ExtV], x: &[ExtV]) -> ExtV {
    debug_assert_eq!(u.len(), x.len());
    let one = ext_const(builder, EF::ONE);
    let mut acc = one;
    for (&u_i, &x_i) in u.iter().zip(x) {
        let w0: ExtV = builder.eval(one - u_i - u_i);
        let term: ExtV = builder.eval(w0 * (one - x_i) + u_i * x_i);
        acc = builder.eval(acc * term);
    }
    acc
}

/// MLE evaluation from hypercube evals at `x`, folding MSB-first (twin of
/// `eval_mle_evals_at_point`).
fn eval_mle_evals_at_point(builder: &mut Builder<FC>, mut evals: Vec<ExtV>, x: &[ExtV]) -> ExtV {
    debug_assert_eq!(evals.len(), 1 << x.len());
    let one = ext_const(builder, EF::ONE);
    let mut len = evals.len();
    for &xj in x.iter().rev() {
        len >>= 1;
        for i in 0..len {
            let lo = evals[i];
            let hi = evals[i + len];
            evals[i] = builder.eval(lo * (one - xj) + hi * xj);
        }
    }
    evals[0]
}

/// eq over the univariate-skip domain with both arguments variable (twin of `eval_eq_uni`):
/// `res = ∏-fold [(x_pow + y_pow)·res + (x_pow−1)(y_pow−1)] · 2^{-l}`.
fn eval_eq_uni_vars(builder: &mut Builder<FC>, l: usize, x: ExtV, y: ExtV) -> ExtV {
    let one = ext_const(builder, EF::ONE);
    let mut res = one;
    let mut x_pow = x;
    let mut y_pow = y;
    for i in 0..l {
        res = builder.eval((x_pow + y_pow) * res + (x_pow - one) * (y_pow - one));
        if i + 1 < l {
            x_pow = builder.eval(x_pow * x_pow);
            y_pow = builder.eval(y_pow * y_pow);
        }
    }
    let scale = EF::ONE.halve().exp_u64(l as u64);
    builder.eval(res * scale)
}

/// `eval_eq_uni(l, x, w)` with a constant second argument, given precomputed `x` powers-of-2.
fn eval_eq_uni_xpows_yconst(builder: &mut Builder<FC>, x_pows: &[ExtV], w: F) -> ExtV {
    let l = x_pows.len();
    let one = ext_const(builder, EF::ONE);
    let mut res = one;
    let mut w_pow = EF::from(w);
    for &x_pow in x_pows {
        res = builder.eval((x_pow + w_pow) * res + (x_pow - one) * (w_pow - EF::ONE));
        w_pow = w_pow * w_pow;
    }
    let scale = EF::ONE.halve().exp_u64(l as u64);
    builder.eval(res * scale)
}

/// Twin of `eval_eq_uni_at_one`: `∏ (x_pow + 1) · 2^{-l}`.
fn eval_eq_uni_at_one_var(builder: &mut Builder<FC>, l: usize, x: ExtV) -> ExtV {
    let one = ext_const(builder, EF::ONE);
    let mut res = one;
    let mut x_pow = x;
    for i in 0..l {
        res = builder.eval(res * (x_pow + one));
        if i + 1 < l {
            x_pow = builder.eval(x_pow * x_pow);
        }
    }
    let scale = EF::ONE.halve().exp_u64(l as u64);
    builder.eval(res * scale)
}

/// Hypercube eq-expansion of `x` (twin of `evals_eq_hypercube_serial`): `2^{|x|}` values.
fn evals_eq_hypercube(builder: &mut Builder<FC>, x: &[ExtV]) -> Vec<ExtV> {
    let one = ext_const(builder, EF::ONE);
    let zero = ext_const(builder, EF::ZERO);
    let mut out = vec![zero; 1 << x.len()];
    out[0] = one;
    for (i, &x_i) in x.iter().enumerate() {
        for lo in 0..(1usize << i) {
            let cur = out[lo];
            out[lo + (1 << i)] = builder.eval(cur * x_i);
            out[lo] = builder.eval(cur * (one - x_i));
        }
    }
    out
}

/// Twin of `eval_eq_sharp_uni` (`xi_1.len() == l_skip`, `omega_skip_pows.len() == 2^l_skip`).
fn eval_eq_sharp_uni_var(
    builder: &mut Builder<FC>,
    omega_skip_pows: &[F],
    xi_1: &[ExtV],
    z: ExtV,
) -> ExtV {
    let l = xi_1.len();
    debug_assert_eq!(omega_skip_pows.len(), 1 << l);
    let z_pows = ext_powers_of_2(builder, z, l);
    let eq_xi_evals = evals_eq_hypercube(builder, xi_1);
    let mut res = ext_const(builder, EF::ZERO);
    for (&omega_pow, eq_eval) in omega_skip_pows.iter().zip(eq_xi_evals) {
        let e = eval_eq_uni_xpows_yconst(builder, &z_pows, omega_pow);
        res = builder.eval(res + e * eq_eval);
    }
    res
}

/// Twin of `eval_eq_rot_cube`: returns `(eq, rot)` MLEs on the hypercube.
fn eval_eq_rot_cube_vars(builder: &mut Builder<FC>, x: &[ExtV], y: &[ExtV]) -> (ExtV, ExtV) {
    let n = x.len();
    debug_assert_eq!(n, y.len());
    let one = ext_const(builder, EF::ONE);
    let mut rot = one;
    let mut eq = one;
    for i in (0..n).rev() {
        let xi = x[i];
        let yi = y[i];
        let new_rot: ExtV = builder.eval(xi * (one - yi) * eq + (one - xi) * yi * rot);
        let new_eq: ExtV = builder.eval(xi * yi + (one - xi) * (one - yi));
        rot = new_rot;
        eq = builder.eval(eq * new_eq);
    }
    (eq, rot)
}

/// Twin of `eval_rot_kernel_prism` (`x.len() == y.len() == 1 + cube dims`).
fn eval_rot_kernel_prism_var(builder: &mut Builder<FC>, l: usize, x: &[ExtV], y: &[ExtV]) -> ExtV {
    let omega = EF::from(F::two_adic_generator(l));
    let (eq_cube, rot_cube) = eval_eq_rot_cube_vars(builder, &x[1..], &y[1..]);
    let y0_omega: ExtV = builder.eval(y[0] * omega);
    let a = eval_eq_uni_vars(builder, l, x[0], y0_omega);
    let b = eval_eq_uni_at_one_var(builder, l, x[0]);
    let c = eval_eq_uni_at_one_var(builder, l, y0_omega);
    builder.eval(a * eq_cube + b * c * (rot_cube - eq_cube))
}

/// Twin of `binary_k_fold`: evals on the coset `{x, ωx, …}` folded at `alphas`, giving
/// `g_k(x^{2^k})`. `x` is a base felt; twiddles are circuit constants.
fn binary_k_fold(
    builder: &mut Builder<FC>,
    mut values: Vec<ExtV>,
    alphas: &[ExtV],
    x: Felt<F>,
) -> ExtV {
    let n = values.len();
    let k = alphas.len();
    debug_assert_eq!(n, 1 << k);

    let omega_k = F::two_adic_generator(k);
    let tw: Vec<Felt<F>> = omega_k
        .powers()
        .take(1 << (k - 1))
        .map(|w| builder.constant(w))
        .collect();

    let mut x_pow = x;
    for (j, &alpha) in alphas.iter().enumerate() {
        let m = n >> (j + 1);
        for i in 0..m {
            let t: Felt<F> = builder.uninit();
            builder.push_op(DslIr::MulF(t, x_pow, tw[i << j]));
            let two_t: Felt<F> = builder.eval(t + t);
            let lo = values[i];
            let hi = values[i + m];
            let a_minus_t: ExtV = builder.uninit();
            builder.push_op(DslIr::SubEF(a_minus_t, alpha, t));
            let diff: ExtV = builder.uninit();
            builder.push_op(DslIr::SubE(diff, lo, hi));
            let num: ExtV = builder.uninit();
            builder.push_op(DslIr::MulE(num, a_minus_t, diff));
            let quot: ExtV = builder.uninit();
            builder.push_op(DslIr::DivEF(quot, num, two_t));
            values[i] = builder.eval(lo + quot);
        }
        x_pow = builder.eval(x_pow * x_pow);
    }
    values[0]
}

// =============================================================================================
// GKR fractional-sumcheck twin (validated by the phase-2a probe)
// =============================================================================================

/// In-circuit twin of [`pico_mle_core::proof::GkrProof`].
pub struct GkrProofVar {
    pub logup_pow_witness: Felt<F>,
    pub q0_claim: ExtV,
    /// `[p_xi_0, q_xi_0, p_xi_1, q_xi_1]` per layer.
    pub claims_per_layer: Vec<[ExtV; 4]>,
    /// Round `j` (1-based) has `j` sub-rounds of `[s(1), s(2), s(3)]`.
    pub sumcheck_polys: Vec<Vec<[ExtV; 3]>>,
}

/// Witness order: pow (felt), q0 (ext), per-layer claims (4 exts each), then per round
/// `1..total_rounds` its sub-round polys (3 exts each).
pub fn read_gkr_proof(builder: &mut Builder<FC>, total_rounds: usize) -> GkrProofVar {
    let logup_pow_witness = builder.witness_felt();
    let q0_claim = builder.witness_ext();
    let claims_per_layer = (0..total_rounds)
        .map(|_| core::array::from_fn(|_| builder.witness_ext()))
        .collect();
    let sumcheck_polys = (1..total_rounds)
        .map(|round| {
            (0..round)
                .map(|_| core::array::from_fn(|_| builder.witness_ext()))
                .collect()
        })
        .collect();
    GkrProofVar {
        logup_pow_witness,
        q0_claim,
        claims_per_layer,
        sumcheck_polys,
    }
}

/// Twin of [`pico_mle_core::verifier::fractional_sumcheck_gkr::verify_gkr`]; equality checks become
/// circuit asserts. Returns `(p_hat(xi), q_hat(xi), xi)`.
pub fn wrap_verify_gkr(
    builder: &mut Builder<FC>,
    t: &mut OuterTranscript,
    proof: &GkrProofVar,
    total_rounds: usize,
) -> (ExtV, ExtV, Vec<ExtV>) {
    assert!(total_rounds > 0, "zero-round GKR is handled by the caller");
    let zero = ext_const(builder, EF::ZERO);
    let one = ext_const(builder, EF::ONE);

    t.observe_ext(builder, proof.q0_claim);

    let c0 = proof.claims_per_layer[0];
    for &c in &c0 {
        t.observe_ext(builder, c);
    }
    // p_cross = p0*q1 + p1*q0 must be zero; q_cross = q0*q1 must equal q0_claim.
    let p_cross: ExtV = builder.eval(c0[0] * c0[3] + c0[2] * c0[1]);
    builder.assert_ext_eq(p_cross, zero);
    let q_cross: ExtV = builder.eval(c0[1] * c0[3]);
    builder.assert_ext_eq(q_cross, proof.q0_claim);

    let mu = t.sample_ext(builder);
    let mut numer = interp_linear(builder, c0[0], c0[2], mu);
    let mut denom = interp_linear(builder, c0[1], c0[3], mu);
    let mut gkr_r: Vec<ExtV> = vec![mu];

    for round in 1..total_rounds {
        let lambda = t.sample_ext(builder);
        let mut claim: ExtV = builder.eval(numer + lambda * denom);

        let polys = proof.sumcheck_polys[round - 1].clone();
        let mut round_r: Vec<ExtV> = Vec::with_capacity(round);
        let mut eq = one;
        for (sub, evals) in polys.iter().enumerate() {
            for &e in evals {
                t.observe_ext(builder, e);
            }
            let ri = t.sample_ext(builder);
            round_r.push(ri);
            let ev0: ExtV = builder.eval(claim - evals[0]);
            claim = interp_cubic(builder, [ev0, evals[0], evals[1], evals[2]], ri);
            let xi = gkr_r[sub];
            let term: ExtV = builder.eval(xi * ri + (one - xi) * (one - ri));
            eq = builder.eval(eq * term);
        }

        let cl = proof.claims_per_layer[round];
        for &c in &cl {
            t.observe_ext(builder, c);
        }
        let p_cross: ExtV = builder.eval(cl[0] * cl[3] + cl[2] * cl[1]);
        let q_cross: ExtV = builder.eval(cl[1] * cl[3]);
        let expected: ExtV = builder.eval((p_cross + lambda * q_cross) * eq);
        builder.assert_ext_eq(expected, claim);

        let mu = t.sample_ext(builder);
        numer = interp_linear(builder, cl[0], cl[2], mu);
        denom = interp_linear(builder, cl[1], cl[3], mu);
        gkr_r = std::iter::once(mu).chain(round_r).collect();
    }

    (numer, denom, gkr_r)
}

// =============================================================================================
// Full embed-proof verifier twin (feature-gated: needs the outer config types)
// =============================================================================================

#[cfg(feature = "multi-field-transcript")]
pub use full::*;

#[cfg(feature = "multi-field-transcript")]
mod full {
    use std::cmp::Reverse;

    use super::*;
    use crate::{
        compiler::recursion::ir::Witness,
        emulator::recursion::public_values::{
            NUM_PV_ELMS_TO_HASH, RECURSION_PUBLIC_VALUES_COL_MAP,
        },
        mle::config::koala_bear_bn254_poseidon2::KoalaBearBn254Poseidon2Config as EmbedSc,
        primitives::consts::RECURSION_NUM_PVS,
    };
    use pico_mle_core::{
        air::symbolic::{symbolic_variable::Entry, SymbolicExpressionNode},
        keygen::types::MultiStarkVerifyingKey,
        proof::Proof,
        protocol::stacking::{lambda_slots, present_gkr_shape, StackedLayout},
    };

    use super::super::outer_bn254::{outer_compress, outer_hash};

    // -----------------------------------------------------------------------------------------
    // Host-side shape derivation (identical to `verifier::verify`)
    // -----------------------------------------------------------------------------------------

    /// `trace_id_to_air_id`: present traces sorted by descending log-height, then air id.
    pub fn trace_order(proof: &Proof<EmbedSc>) -> Vec<usize> {
        let num_airs = proof.trace_vdata.len();
        let num_traces = proof.trace_vdata.iter().flatten().count();
        let mut order: Vec<usize> = (0..num_airs).collect();
        order.sort_by_key(|&air_id| {
            (
                proof.trace_vdata[air_id].is_none(),
                proof.trace_vdata[air_id]
                    .as_ref()
                    .map(|vdata| Reverse(vdata.log_height)),
                air_id,
            )
        });
        order.truncate(num_traces);
        order
    }

    /// Twin of the `need_rot_per_commit` construction in `verifier::verify`: one rotation-flag
    /// vector per commitment, in commitment order.
    ///
    /// Merged-preprocessed mode collapses every preprocessed matrix into commitment 1, so that
    /// commitment carries one flag per prep matrix (trace order restricted to prep AIRs) instead of
    /// contributing a separate single-matrix commitment per prep AIR.
    fn need_rot_per_commit(
        mvk: &MultiStarkVerifyingKey<EmbedSc>,
        proof: &Proof<EmbedSc>,
        order: &[usize],
    ) -> Vec<Vec<bool>> {
        let per_air = &mvk.inner.per_air;
        let merged_prep = mvk.inner.merged_preprocessed_commit.is_some();
        let need_rot_per_trace: Vec<bool> =
            order.iter().map(|&a| per_air[a].params.need_rot).collect();
        let mut out = vec![need_rot_per_trace];
        if merged_prep {
            out.push(
                order
                    .iter()
                    .filter(|&&a| per_air[a].preprocessed_data.is_some())
                    .map(|&a| per_air[a].params.need_rot)
                    .collect(),
            );
        }
        for &a in order {
            let need_rot = per_air[a].params.need_rot;
            if !merged_prep && per_air[a].preprocessed_data.is_some() {
                out.push(vec![need_rot]);
            }
            let cached_len = proof.trace_vdata[a]
                .as_ref()
                .unwrap()
                .cached_commitments
                .len();
            for _ in 0..cached_len {
                out.push(vec![need_rot]);
            }
        }
        out
    }

    /// Twin of `column_openings_by_rot` over circuit handles.
    fn openings_by_rot(
        builder: &mut Builder<FC>,
        openings: &[ExtV],
        need_rot: bool,
    ) -> Vec<(ExtV, ExtV)> {
        if need_rot {
            openings
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| (c[0], c[1]))
                .collect()
        } else {
            let zero = ext_const(builder, EF::ZERO);
            openings.iter().map(|&c| (c, zero)).collect()
        }
    }

    // -----------------------------------------------------------------------------------------
    // Proof-data witness streams
    // -----------------------------------------------------------------------------------------

    /// Every proof-dependent value as a circuit variable, read up front in a fixed order.
    pub struct WrapProofVar {
        // preamble
        pub common_main_commit: Var<N>,
        /// Per AIR (vk order): cached commitments.
        pub cached_commits: Vec<Vec<Var<N>>>,
        /// Per AIR (vk order): public values.
        pub public_values: Vec<Vec<Felt<F>>>,
        // gkr + logup
        pub gkr: GkrProofVar,
        /// Per present trace: `(numerator_term, denominator_term)`.
        pub claim_terms: Vec<[ExtV; 2]>,
        // batch constraints
        pub univariate_round_coeffs: Vec<ExtV>,
        pub sumcheck_round_polys: Vec<Vec<ExtV>>,
        /// `[trace][part][elem]` (raw flat layout, rot-interleaved iff `need_rot`).
        pub column_openings: Vec<Vec<Vec<ExtV>>>,
        // stacked reduction
        pub stacking_univariate_round_coeffs: Vec<ExtV>,
        pub stacking_sumcheck_round_polys: Vec<[ExtV; 2]>,
        /// `[commit][col]`.
        pub stacking_openings: Vec<Vec<ExtV>>,
        // whir
        pub mu_pow_witness: Felt<F>,
        pub folding_pow_witnesses: Vec<Felt<F>>,
        pub query_phase_pow_witnesses: Vec<Felt<F>>,
        pub whir_sumcheck_polys: Vec<[ExtV; 2]>,
        pub codeword_commits: Vec<Var<N>>,
        pub ood_values: Vec<ExtV>,
        /// `[commit][query][row (2^k)][col]`.
        pub initial_round_opened_rows: Vec<Vec<Vec<Vec<Felt<F>>>>>,
        /// `[commit][query][node]`.
        pub initial_round_merkle_proofs: Vec<Vec<Vec<Var<N>>>>,
        /// `[round-1][query][2^k]`.
        pub codeword_opened_values: Vec<Vec<Vec<ExtV>>>,
        /// `[round-1][query][node]`.
        pub codeword_merkle_proofs: Vec<Vec<Vec<Var<N>>>>,
        pub final_poly: Vec<ExtV>,
    }

    /// Read all proof data from the witness streams. ORDER IS LOAD-BEARING: it must match
    /// [`write_wrap_witness`] exactly. The transcript digit/remainder stream is appended by the
    /// harness AFTER these values, so it never interleaves with them.
    pub fn read_wrap_proof(
        builder: &mut Builder<FC>,
        mvk: &MultiStarkVerifyingKey<EmbedSc>,
        proof: &Proof<EmbedSc>,
    ) -> WrapProofVar {
        let params = &mvk.inner.params;
        let l_skip = params.l_skip;
        let order = trace_order(proof);
        let num_traces = order.len();

        // preamble values
        let common_main_commit = builder.witness_var();
        let mut cached_commits = Vec::with_capacity(proof.trace_vdata.len());
        let mut public_values = Vec::with_capacity(proof.trace_vdata.len());
        for (tv, pvs) in proof.trace_vdata.iter().zip(&proof.public_values) {
            cached_commits.push(match tv {
                Some(tv) => (0..tv.cached_commitments.len())
                    .map(|_| builder.witness_var())
                    .collect(),
                None => vec![],
            });
            public_values.push((0..pvs.len()).map(|_| builder.witness_felt()).collect());
        }

        // gkr
        let (_, gkr_total_rounds, _) = present_gkr_shape(
            l_skip,
            order.iter().map(|&a| {
                (
                    mvk.inner.per_air[a].symbolic_constraints.interactions.len(),
                    proof.trace_vdata[a].as_ref().unwrap().log_height,
                )
            }),
        );
        let gkr = read_gkr_proof(builder, gkr_total_rounds);
        let claim_terms = (0..num_traces)
            .map(|_| [builder.witness_ext(), builder.witness_ext()])
            .collect();

        // batch constraints
        let bcp = &proof.batch_constraint_proof;
        let univariate_round_coeffs = (0..bcp.univariate_round_coeffs.len())
            .map(|_| builder.witness_ext())
            .collect();
        let sumcheck_round_polys = bcp
            .sumcheck_round_polys
            .iter()
            .map(|p| (0..p.len()).map(|_| builder.witness_ext()).collect())
            .collect();
        let column_openings = bcp
            .column_openings
            .iter()
            .map(|parts| {
                parts
                    .iter()
                    .map(|part| (0..part.len()).map(|_| builder.witness_ext()).collect())
                    .collect()
            })
            .collect();

        // stacked reduction
        let sp = &proof.stacking_proof;
        let stacking_univariate_round_coeffs = (0..sp.univariate_round_coeffs.len())
            .map(|_| builder.witness_ext())
            .collect();
        let stacking_sumcheck_round_polys = (0..sp.sumcheck_round_polys.len())
            .map(|_| [builder.witness_ext(), builder.witness_ext()])
            .collect();
        let stacking_openings = sp
            .stacking_openings
            .iter()
            .map(|cols| (0..cols.len()).map(|_| builder.witness_ext()).collect())
            .collect();

        // whir
        let wp = &proof.whir_proof;
        let mu_pow_witness = builder.witness_felt();
        let folding_pow_witnesses = (0..wp.folding_pow_witnesses.len())
            .map(|_| builder.witness_felt())
            .collect();
        let query_phase_pow_witnesses = (0..wp.query_phase_pow_witnesses.len())
            .map(|_| builder.witness_felt())
            .collect();
        let whir_sumcheck_polys = (0..wp.whir_sumcheck_polys.len())
            .map(|_| [builder.witness_ext(), builder.witness_ext()])
            .collect();
        let codeword_commits = (0..wp.codeword_commits.len())
            .map(|_| builder.witness_var())
            .collect();
        let ood_values = (0..wp.ood_values.len())
            .map(|_| builder.witness_ext())
            .collect();
        let initial_round_opened_rows = wp
            .initial_round_opened_rows
            .iter()
            .map(|per_query| {
                per_query
                    .iter()
                    .map(|rows| {
                        rows.iter()
                            .map(|row| (0..row.len()).map(|_| builder.witness_felt()).collect())
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let initial_round_merkle_proofs = wp
            .initial_round_merkle_proofs
            .iter()
            .map(|per_query| {
                per_query
                    .iter()
                    .map(|path| (0..path.len()).map(|_| builder.witness_var()).collect())
                    .collect()
            })
            .collect();
        let codeword_opened_values = wp
            .codeword_opened_values
            .iter()
            .map(|per_query| {
                per_query
                    .iter()
                    .map(|vals| (0..vals.len()).map(|_| builder.witness_ext()).collect())
                    .collect()
            })
            .collect();
        let codeword_merkle_proofs = wp
            .codeword_merkle_proofs
            .iter()
            .map(|per_query| {
                per_query
                    .iter()
                    .map(|path| (0..path.len()).map(|_| builder.witness_var()).collect())
                    .collect()
            })
            .collect();
        let final_poly = (0..wp.final_poly.len())
            .map(|_| builder.witness_ext())
            .collect();

        WrapProofVar {
            common_main_commit,
            cached_commits,
            public_values,
            gkr,
            claim_terms,
            univariate_round_coeffs,
            sumcheck_round_polys,
            column_openings,
            stacking_univariate_round_coeffs,
            stacking_sumcheck_round_polys,
            stacking_openings,
            mu_pow_witness,
            folding_pow_witnesses,
            query_phase_pow_witnesses,
            whir_sumcheck_polys,
            codeword_commits,
            ood_values,
            initial_round_opened_rows,
            initial_round_merkle_proofs,
            codeword_opened_values,
            codeword_merkle_proofs,
            final_poly,
        }
    }

    /// Host-side writer for the proof-data witness streams. ORDER IS LOAD-BEARING: matches
    /// [`read_wrap_proof`]. The caller appends the transcript digit/remainder stream afterwards.
    pub fn write_wrap_witness(w: &mut Witness<FC>, proof: &Proof<EmbedSc>) {
        // preamble
        w.vars.push(proof.common_main_commit[0]);
        for (tv, pvs) in proof.trace_vdata.iter().zip(&proof.public_values) {
            if let Some(tv) = tv {
                for c in &tv.cached_commitments {
                    w.vars.push(c[0]);
                }
            }
            w.felts.extend_from_slice(pvs);
        }

        // gkr
        let gkrp = &proof.gkr_proof;
        w.felts.push(gkrp.logup_pow_witness);
        w.exts.push(gkrp.q0_claim);
        for cl in &gkrp.claims_per_layer {
            w.exts
                .extend_from_slice(&[cl.p_xi_0, cl.q_xi_0, cl.p_xi_1, cl.q_xi_1]);
        }
        for round_polys in &gkrp.sumcheck_polys {
            for evals in round_polys {
                w.exts.extend_from_slice(evals);
            }
        }
        let bcp = &proof.batch_constraint_proof;
        for (&np, &dp) in bcp
            .numerator_term_per_air
            .iter()
            .zip(&bcp.denominator_term_per_air)
        {
            w.exts.push(np);
            w.exts.push(dp);
        }

        // batch constraints
        w.exts.extend_from_slice(&bcp.univariate_round_coeffs);
        for p in &bcp.sumcheck_round_polys {
            w.exts.extend_from_slice(p);
        }
        for parts in &bcp.column_openings {
            for part in parts {
                w.exts.extend_from_slice(part);
            }
        }

        // stacked reduction
        let sp = &proof.stacking_proof;
        w.exts.extend_from_slice(&sp.univariate_round_coeffs);
        for p in &sp.sumcheck_round_polys {
            w.exts.extend_from_slice(p);
        }
        for cols in &sp.stacking_openings {
            w.exts.extend_from_slice(cols);
        }

        // whir
        let wp = &proof.whir_proof;
        w.felts.push(wp.mu_pow_witness);
        w.felts.extend_from_slice(&wp.folding_pow_witnesses);
        w.felts.extend_from_slice(&wp.query_phase_pow_witnesses);
        for pair in &wp.whir_sumcheck_polys {
            w.exts.extend_from_slice(pair);
        }
        for c in &wp.codeword_commits {
            w.vars.push(c[0]);
        }
        w.exts.extend_from_slice(&wp.ood_values);
        for per_query in &wp.initial_round_opened_rows {
            for rows in per_query {
                for row in rows {
                    w.felts.extend_from_slice(row);
                }
            }
        }
        for per_query in &wp.initial_round_merkle_proofs {
            for path in per_query {
                for d in path {
                    w.vars.push(d[0]);
                }
            }
        }
        for per_query in &wp.codeword_opened_values {
            for vals in per_query {
                w.exts.extend_from_slice(vals);
            }
        }
        for per_query in &wp.codeword_merkle_proofs {
            for path in per_query {
                for d in path {
                    w.vars.push(d[0]);
                }
            }
        }
        w.exts.extend_from_slice(&wp.final_poly);
    }

    // -----------------------------------------------------------------------------------------
    // Constraint-DAG evaluation (twin of `VerifierConstraintEvaluator` + `eval_nodes`)
    // -----------------------------------------------------------------------------------------

    struct DagCtx<'a> {
        preprocessed: Option<&'a [(ExtV, ExtV)]>,
        /// DAG part order: `[cached_0, .., cached_{c-1}, common_main]`.
        partitioned_main: &'a [Vec<(ExtV, ExtV)>],
        public_values: &'a [Felt<F>],
        is_first_row: ExtV,
        is_last_row: ExtV,
        is_transition: ExtV,
    }

    fn eval_dag_nodes(
        builder: &mut Builder<FC>,
        nodes: &[SymbolicExpressionNode<F>],
        ctx: &DagCtx,
    ) -> Vec<ExtV> {
        let mut pv_ext: Vec<Option<ExtV>> = vec![None; ctx.public_values.len()];
        let mut out: Vec<ExtV> = Vec::with_capacity(nodes.len());
        for node in nodes {
            let val = match *node {
                SymbolicExpressionNode::Variable(var) => match var.entry {
                    Entry::Preprocessed { offset } => {
                        let vp = ctx.preprocessed.expect("preprocessed opening missing");
                        if offset == 0 {
                            vp[var.index].0
                        } else {
                            vp[var.index].1
                        }
                    }
                    Entry::Main { part_index, offset } => {
                        let vp = &ctx.partitioned_main[part_index];
                        if offset == 0 {
                            vp[var.index].0
                        } else {
                            vp[var.index].1
                        }
                    }
                    Entry::Public => *pv_ext[var.index]
                        .get_or_insert_with(|| felt_to_ext(builder, ctx.public_values[var.index])),
                    // No catch-all on purpose: a new `Entry` variant must break this match rather
                    // than silently evaluate to something the Rust verifier would not.
                },
                SymbolicExpressionNode::Constant(c) => ext_const(builder, EF::from(c)),
                SymbolicExpressionNode::Add {
                    left_idx,
                    right_idx,
                    ..
                } => builder.eval(out[left_idx] + out[right_idx]),
                SymbolicExpressionNode::Sub {
                    left_idx,
                    right_idx,
                    ..
                } => builder.eval(out[left_idx] - out[right_idx]),
                SymbolicExpressionNode::Neg { idx, .. } => builder.eval(-out[idx]),
                SymbolicExpressionNode::Mul {
                    left_idx,
                    right_idx,
                    ..
                } => builder.eval(out[left_idx] * out[right_idx]),
                SymbolicExpressionNode::IsFirstRow => ctx.is_first_row,
                SymbolicExpressionNode::IsLastRow => ctx.is_last_row,
                SymbolicExpressionNode::IsTransition => ctx.is_transition,
            };
            out.push(val);
        }
        out
    }

    /// Twin of `evaluator::progression_exp_2`: `1 + m + … + m^{2^l−1}`.
    fn progression_exp_2(builder: &mut Builder<FC>, m: ExtV, l: usize) -> ExtV {
        let one = ext_const(builder, EF::ONE);
        let mut pow = m;
        let mut sum = one;
        for i in 0..l {
            sum = builder.eval(sum * (one + pow));
            if i + 1 < l {
                pow = builder.eval(pow * pow);
            }
        }
        sum
    }

    // -----------------------------------------------------------------------------------------
    // The master verifier
    // -----------------------------------------------------------------------------------------

    /// Handles the completeness stage needs from earlier stages.
    pub struct WrapOutput {
        /// Index (vk order) of the AIR carrying the recursion public values.
        pub recursion_pv_air: usize,
    }

    /// Full in-circuit verification of one embed proof, plus the completeness checks and the
    /// two gnark public-input commitments. `layouts` must come from
    /// `verify_proof_shape(&mvk.inner, proof)`.
    /// `trusted_vk_root` is baked into the circuit as constants; pass `None` only in
    /// whitelist-off mode, where there is no root to pin.
    pub fn wrap_verify_embed(
        builder: &mut Builder<FC>,
        mvk: &MultiStarkVerifyingKey<EmbedSc>,
        proof: &Proof<EmbedSc>,
        layouts: &[StackedLayout],
        trusted_vk_root: Option<[F; 8]>,
    ) -> WrapOutput {
        let params = &mvk.inner.params;
        let l_skip = params.l_skip;
        let per_air = &mvk.inner.per_air;
        let order = trace_order(proof);
        let num_traces = order.len();
        let omega_skip = F::two_adic_generator(l_skip);
        let omega_skip_pows: Vec<F> = omega_skip.powers().take(1 << l_skip).collect();

        let p = read_wrap_proof(builder, mvk, proof);
        let mut t = OuterTranscript::new(builder);

        // ── Stage 1: preamble ────────────────────────────────────────────────────────────────
        let pre_hash: Var<N> = builder.constant(mvk.pre_hash[0]);
        t.observe_digest(builder, &[pre_hash]);
        t.observe_digest(builder, &[p.common_main_commit]);
        // Merged-preprocessed mode: the single multi-matrix prep commitment is a vk constant,
        // observed exactly once right here (`verifier::verify`, preamble). Per-air prep heights
        // still reach the transcript: every present AIR observes its `log_height` below.
        let merged_prep_var: Option<Var<N>> = mvk
            .inner
            .merged_preprocessed_commit
            .as_ref()
            .map(|mc| builder.constant(mc[0]));
        if let Some(mc) = merged_prep_var {
            t.observe_digest(builder, &[mc]);
        }
        let merged_prep = merged_prep_var.is_some();
        let mut preprocessed_commit_vars: Vec<Option<Var<N>>> = Vec::with_capacity(per_air.len());
        for (air_id, (tv, avk)) in proof.trace_vdata.iter().zip(per_air).enumerate() {
            if !avk.is_required {
                let flag: Felt<F> = builder.constant(F::from_bool(tv.is_some()));
                t.observe(builder, flag);
            }
            let mut pp_var = None;
            if let Some(tv) = tv {
                match avk.preprocessed_data.as_ref() {
                    // Per-air mode: the AIR's own prep commitment is observed, and it enters the
                    // WHIR commitment list. Merged mode: neither happens — the log_height is
                    // observed instead, uniformly with the AIRs that have no prep data at all.
                    Some(pdata) if !merged_prep => {
                        let c: Var<N> = builder.constant(pdata.commit[0]);
                        t.observe_digest(builder, &[c]);
                        pp_var = Some(c);
                    }
                    // A constant, like `trace_order` and `n_per_trace`, which are built from the
                    // same heights: a witness value here would put a height the rest of the
                    // circuit never uses into the transcript, free for the prover to choose.
                    _ => {
                        let lh: Felt<F> = builder.constant(F::from_usize(tv.log_height));
                        t.observe(builder, lh);
                    }
                }
                for &c in &p.cached_commits[air_id] {
                    t.observe_digest(builder, &[c]);
                }
            }
            for &pv in &p.public_values[air_id] {
                t.observe(builder, pv);
            }
            preprocessed_commit_vars.push(pp_var);
        }

        // ── Stage 2: zerocheck + logup ───────────────────────────────────────────────────────
        let n_per_trace: Vec<isize> = order
            .iter()
            .map(|&a| proof.trace_vdata[a].as_ref().unwrap().log_height as isize - l_skip as isize)
            .collect();
        let (n_logup, gkr_total_rounds, n_max) = present_gkr_shape(
            l_skip,
            order.iter().map(|&a| {
                (
                    per_air[a].symbolic_constraints.interactions.len(),
                    proof.trace_vdata[a].as_ref().unwrap().log_height,
                )
            }),
        );
        let n_global = n_max.max(n_logup);
        let zero = ext_const(builder, EF::ZERO);

        // steps 1-4: logup PoW, α/β, GKR, ξ padding, λ, claim totals, μ, sum_claim
        t.check_witness(builder, params.logup.pow_bits, p.gkr.logup_pow_witness);
        let alpha_logup = t.sample_ext(builder);
        let beta_logup = t.sample_ext(builder);

        let (mut p_xi_claim, mut q_xi_claim, mut xi) = if gkr_total_rounds > 0 {
            wrap_verify_gkr(builder, &mut t, &p.gkr, gkr_total_rounds)
        } else {
            (zero, alpha_logup, vec![])
        };
        while xi.len() != l_skip + n_global {
            xi.push(t.sample_ext(builder));
        }
        let lambda = t.sample_ext(builder);

        for pq in &p.claim_terms {
            p_xi_claim = builder.eval(p_xi_claim - pq[0]);
            q_xi_claim = builder.eval(q_xi_claim - pq[1]);
            t.observe_ext(builder, pq[0]);
            t.observe_ext(builder, pq[1]);
        }
        builder.assert_ext_eq(p_xi_claim, zero);
        builder.assert_ext_eq(q_xi_claim, alpha_logup);

        let mu = t.sample_ext(builder);
        let mut sum_claim = zero;
        {
            let mut mu_pow = ext_const(builder, EF::ONE);
            for pq in &p.claim_terms {
                sum_claim = builder.eval(sum_claim + pq[0] * mu_pow);
                mu_pow = builder.eval(mu_pow * mu);
                sum_claim = builder.eval(sum_claim + pq[1] * mu_pow);
                mu_pow = builder.eval(mu_pow * mu);
            }
        }

        // step 5: univariate skip round
        let s_deg = params.max_constraint_degree + 1;
        assert_eq!(
            p.univariate_round_coeffs.len(),
            (params.max_constraint_degree + 1) * ((1 << l_skip) - 1) + 1
        );
        for &coeff in &p.univariate_round_coeffs {
            t.observe_ext(builder, coeff);
        }
        let r_0 = t.sample_ext(builder);
        let mut dom_sum = zero;
        for &c in p.univariate_round_coeffs.iter().step_by(1 << l_skip) {
            dom_sum = builder.eval(dom_sum + c);
        }
        dom_sum = builder.eval(dom_sum * EF::from_usize(1 << l_skip));
        builder.assert_ext_eq(sum_claim, dom_sum);
        let mut cur_sum = horner(builder, &p.univariate_round_coeffs, r_0);
        let mut rs = vec![r_0];

        // step 6: multilinear rounds (integer-node barycentric interpolation)
        let invfact: Vec<F> = {
            let mut f = vec![F::ONE; s_deg + 1];
            for i in 1..=s_deg {
                f[i] = f[i - 1] * F::from_usize(i);
            }
            f.iter().map(|x| x.inverse()).collect()
        };
        for round in 0..n_max {
            let batch_s_evals = &p.sumcheck_round_polys[round];
            assert_eq!(batch_s_evals.len(), s_deg);
            for &eval in batch_s_evals {
                t.observe_ext(builder, eval);
            }
            let s_1 = batch_s_evals[0];
            let s_0: ExtV = builder.eval(cur_sum - s_1);
            let evals_full: Vec<ExtV> = std::iter::once(s_0)
                .chain(batch_s_evals.iter().copied())
                .collect();

            let r = t.sample_ext(builder);
            let one = ext_const(builder, EF::ONE);
            let mut pref = vec![one; s_deg + 1];
            let mut suf = vec![one; s_deg + 1];
            for i in 0..s_deg {
                pref[i + 1] = builder.eval(pref[i] * (r - EF::from_usize(i)));
                let node_i: ExtV = ext_const(builder, EF::from_usize(s_deg - i));
                suf[i + 1] = builder.eval(suf[i] * (node_i - r));
            }
            let mut acc = zero;
            for i in 0..=s_deg {
                let c_i = EF::from(invfact[i] * invfact[s_deg - i]);
                let term: ExtV = builder.eval(evals_full[i] * pref[i] * suf[s_deg - i] * c_i);
                acc = builder.eval(acc + term);
            }
            cur_sum = acc;
            rs.push(r);
        }

        // step 7: eq_3b per trace (b-vectors are static shape data)
        let mut stacked_idx = 0usize;
        let eq_3b_per_trace: Vec<Vec<ExtV>> = n_per_trace
            .iter()
            .enumerate()
            .map(|(trace_idx, &n)| {
                let air_idx = order[trace_idx];
                let interactions = &per_air[air_idx].symbolic_constraints.interactions;
                if interactions.is_empty() {
                    return vec![];
                }
                let n_lift = n.max(0) as usize;
                (0..interactions.len())
                    .map(|_| {
                        let mut b_int = stacked_idx >> (l_skip + n_lift);
                        let b_vec: Vec<bool> = (0..n_logup - n_lift)
                            .map(|_| {
                                let b = b_int & 1 == 1;
                                b_int >>= 1;
                                b
                            })
                            .collect();
                        stacked_idx += 1 << (l_skip + n_lift);
                        eval_eq_mle_static(builder, &xi[l_skip + n_lift..l_skip + n_logup], &b_vec)
                    })
                    .collect()
            })
            .collect();

        // step 8: eq_ns / eq_sharp_ns
        let one = ext_const(builder, EF::ONE);
        let mut eq_ns = vec![one; n_max + 1];
        let mut eq_sharp_ns = vec![one; n_max + 1];
        eq_ns[0] = eval_eq_uni_vars(builder, l_skip, xi[0], rs[0]);
        eq_sharp_ns[0] = eval_eq_sharp_uni_var(builder, &omega_skip_pows, &xi[..l_skip], rs[0]);
        for i in 1..=n_max {
            let x_i = xi[l_skip + i - 1];
            let r_i = rs[i];
            let xy: ExtV = builder.eval(x_i * r_i);
            let eq_mle: ExtV = builder.eval(one - r_i - x_i + xy + xy);
            eq_ns[i] = builder.eval(eq_ns[i - 1] * eq_mle);
            eq_sharp_ns[i] = builder.eval(eq_sharp_ns[i - 1] * eq_mle);
        }
        let mut r_rev_prod = rs[n_max];
        for i in (0..n_max).rev() {
            eq_ns[i] = builder.eval(eq_ns[i] * r_rev_prod);
            eq_sharp_ns[i] = builder.eval(eq_sharp_ns[i] * r_rev_prod);
            r_rev_prod = builder.eval(r_rev_prod * rs[i]);
        }

        // step 9: observe common-main openings first, then per-trace remaining parts + evals
        let need_rot_per_trace: Vec<bool> =
            order.iter().map(|&a| per_air[a].params.need_rot).collect();
        for (trace_idx, air_openings) in p.column_openings.iter().enumerate() {
            let pairs = openings_by_rot(builder, &air_openings[0], need_rot_per_trace[trace_idx]);
            for (claim, claim_rot) in pairs {
                t.observe_ext(builder, claim);
                t.observe_ext(builder, claim_rot);
            }
        }

        let mut interactions_evals: Vec<ExtV> = Vec::with_capacity(2 * num_traces);
        let mut constraints_evals: Vec<ExtV> = Vec::with_capacity(num_traces);
        for (trace_idx, air_openings) in p.column_openings.iter().enumerate() {
            let air_idx = order[trace_idx];
            let vk = &per_air[air_idx];
            let n = n_per_trace[trace_idx];
            let n_lift = n.max(0) as usize;
            let need_rot = need_rot_per_trace[trace_idx];

            for claims in air_openings.iter().skip(1) {
                let pairs = openings_by_rot(builder, claims, need_rot);
                for (claim, claim_rot) in pairs {
                    t.observe_ext(builder, claim);
                    t.observe_ext(builder, claim_rot);
                }
            }

            let has_preprocessed = vk.preprocessed_data.is_some();
            let common_main = openings_by_rot(builder, &air_openings[0], need_rot);
            let preprocessed =
                has_preprocessed.then(|| openings_by_rot(builder, &air_openings[1], need_rot));
            let cached_idx = 1 + has_preprocessed as usize;
            let mut partitioned_main: Vec<Vec<(ExtV, ExtV)>> = air_openings[cached_idx..]
                .iter()
                .map(|opening| openings_by_rot(builder, opening, need_rot))
                .collect();
            partitioned_main.push(common_main);

            // lift domain: evaluating the lift == evaluating the original on D^{(2^n)}
            let (l, rs_n, norm_factor) = if n.is_negative() {
                (
                    l_skip.wrapping_add_signed(n),
                    vec![ext_square_n(builder, rs[0], (-n) as usize)],
                    F::from_usize(1 << n.unsigned_abs()).inverse(),
                )
            } else {
                (l_skip, rs[..=(n as usize)].to_vec(), F::ONE)
            };

            // is_first_row / is_last_row (twin of `VerifierConstraintEvaluator::new`)
            let omega_l = F::two_adic_generator(l);
            let inv_l = EF::from(F::from_usize(1 << l).inverse());
            let prog_first = progression_exp_2(builder, rs_n[0], l);
            let rs0_omega: ExtV = builder.eval(rs_n[0] * EF::from(omega_l));
            let prog_last = progression_exp_2(builder, rs0_omega, l);
            let mut first_tail = one;
            let mut last_tail = one;
            for &r in &rs_n[1..] {
                first_tail = builder.eval(first_tail * (one - r));
                last_tail = builder.eval(last_tail * r);
            }
            let is_first_row: ExtV = builder.eval(prog_first * first_tail * inv_l);
            let is_last_row: ExtV = builder.eval(prog_last * last_tail * inv_l);
            let is_transition: ExtV = builder.eval(one - is_last_row);

            let ctx = DagCtx {
                preprocessed: preprocessed.as_deref(),
                partitioned_main: &partitioned_main,
                public_values: &p.public_values[air_idx],
                is_first_row,
                is_last_row,
                is_transition,
            };
            let dag = &vk.symbolic_constraints.constraints;
            let nodes = eval_dag_nodes(builder, &dag.nodes, &ctx);

            let mut expr = zero;
            let mut lambda_pow = one;
            for &idx in &dag.constraint_idx {
                expr = builder.eval(expr + nodes[idx] * lambda_pow);
                lambda_pow = builder.eval(lambda_pow * lambda);
            }
            let eq_xi_r = eq_ns[n_lift];
            constraints_evals.push(builder.eval(eq_xi_r * expr));

            // interactions (DAG-indexed; identical values to the tree walk in the Rust verifier)
            let interactions = &vk.symbolic_constraints.interactions;
            let eq_3bs = &eq_3b_per_trace[trace_idx];
            assert_eq!(eq_3bs.len(), interactions.len());
            let mut num_sum = zero;
            let mut denom_sum = zero;
            for (interaction, &eq_3b) in interactions.iter().zip(eq_3bs) {
                let num = nodes[interaction.count];
                let mut denom = zero;
                let mut beta_pow = one;
                for &msg_idx in &interaction.message {
                    denom = builder.eval(denom + nodes[msg_idx] * beta_pow);
                    beta_pow = builder.eval(beta_pow * beta_logup);
                }
                let bus_term = EF::from_u16(interaction.kind as u16) + EF::ONE;
                denom = builder.eval(denom + beta_pow * bus_term);
                num_sum = builder.eval(num_sum + eq_3b * num);
                denom_sum = builder.eval(denom_sum + eq_3b * denom);
            }
            let eq_sharp = eq_sharp_ns[n_lift];
            interactions_evals.push(builder.eval(num_sum * EF::from(norm_factor) * eq_sharp));
            interactions_evals.push(builder.eval(denom_sum * eq_sharp));
        }

        let mut evaluated_claim = zero;
        {
            let mut mu_pow = one;
            for &x in interactions_evals.iter().chain(constraints_evals.iter()) {
                evaluated_claim = builder.eval(evaluated_claim + x * mu_pow);
                mu_pow = builder.eval(mu_pow * mu);
            }
        }
        builder.assert_ext_eq(cur_sum, evaluated_claim);
        let r = rs; // the zerocheck point (n_max + 1 coordinates)

        // ── Stage 3: stacked reduction ───────────────────────────────────────────────────────
        let n_stack = params.n_stack;
        let nrpc = need_rot_per_commit(mvk, proof, &order);
        debug_assert_eq!(layouts.len(), nrpc.len());

        // t_claims in prover order (twin of `verify_stacked_reduction`'s setup): commit 0 is the
        // common main of every trace; under merged prep commit 1 is every preprocessed matrix in
        // merged-layout order; then the remaining single-matrix commitments per trace.
        let has_prep_per_trace: Vec<bool> = order
            .iter()
            .map(|&a| per_air[a].preprocessed_data.is_some())
            .collect();
        let mut t_claims: Vec<(ExtV, ExtV)> = Vec::new();
        for (trace_idx, parts) in p.column_openings.iter().enumerate() {
            let pairs = openings_by_rot(builder, &parts[0], nrpc[0][trace_idx]);
            t_claims.extend(pairs);
        }
        let mut commit_idx = 1usize;
        if merged_prep {
            let need_rots = &nrpc[1];
            let mut mat_idx = 0usize;
            for (trace_idx, parts) in p.column_openings.iter().enumerate() {
                if has_prep_per_trace[trace_idx] {
                    let pairs = openings_by_rot(builder, &parts[1], need_rots[mat_idx]);
                    t_claims.extend(pairs);
                    mat_idx += 1;
                }
            }
            debug_assert_eq!(mat_idx, need_rots.len());
            commit_idx = 2;
        }
        for (trace_idx, parts) in p.column_openings.iter().enumerate() {
            // Merged prep already consumed this trace's part 1 above.
            let skip = if merged_prep && has_prep_per_trace[trace_idx] {
                2
            } else {
                1
            };
            for cols in parts.iter().skip(skip) {
                let pairs = openings_by_rot(builder, cols, nrpc[commit_idx][0]);
                t_claims.extend(pairs);
                commit_idx += 1;
            }
        }
        let t_claims_len = t_claims.len();
        // λ-batching exponents come from the protocol's own SSOT rather than a re-derived walk, so
        // the circuit cannot drift from prover and verifier. `lambda_slots` reserves two
        // consecutive exponents per column (`eq_exp = 2i`, `rot_exp = 2i+1`), which is exactly the
        // `(λ²)^i` / `(λ²)^i·λ` spelling used below — hence `eq_exp / 2` as the power index.
        let slots = lambda_slots(layouts.iter(), &nrpc);
        let lambda_indices_per_layout: Vec<Vec<(usize, bool)>> = slots
            .iter()
            .map(|cols| {
                cols.iter()
                    .map(|slot| (slot.eq_exp / 2, slot.rot_exp.is_some()))
                    .collect()
            })
            .collect();
        assert_eq!(
            slots.iter().map(Vec::len).sum::<usize>(),
            t_claims_len,
            "one λ slot per stacked column must match the t_claims walk"
        );

        let lambda_st = t.sample_ext(builder);
        let lambda_sq: ExtV = builder.eval(lambda_st * lambda_st);
        let mut lambda_sqr_powers = Vec::with_capacity(t_claims_len);
        {
            let mut cur = one;
            for _ in 0..t_claims_len {
                lambda_sqr_powers.push(cur);
                cur = builder.eval(cur * lambda_sq);
            }
        }

        let mut s_0 = zero;
        for ((t0, t1), &lp) in t_claims.iter().zip(&lambda_sqr_powers) {
            s_0 = builder.eval(s_0 + (*t0 + *t1 * lambda_st) * lp);
        }
        let mut st_dom_sum = zero;
        for &c in p
            .stacking_univariate_round_coeffs
            .iter()
            .step_by(1 << l_skip)
        {
            st_dom_sum = builder.eval(st_dom_sum + c);
        }
        st_dom_sum = builder.eval(st_dom_sum * EF::from_usize(1 << l_skip));
        builder.assert_ext_eq(s_0, st_dom_sum);

        for &c in &p.stacking_univariate_round_coeffs {
            t.observe_ext(builder, c);
        }
        let mut u: Vec<ExtV> = Vec::with_capacity(n_stack + 1);
        u.push(t.sample_ext(builder));
        let mut st_claim = horner(builder, &p.stacking_univariate_round_coeffs, u[0]);
        for j in 1..=n_stack {
            let [s_j_1, s_j_2] = p.stacking_sumcheck_round_polys[j - 1];
            t.observe_ext(builder, s_j_1);
            t.observe_ext(builder, s_j_2);
            let u_j = t.sample_ext(builder);
            let s_j_0: ExtV = builder.eval(st_claim - s_j_1);
            st_claim = interp_quadratic(builder, [s_j_0, s_j_1, s_j_2], u_j);
            u.push(u_j);
        }

        // final verification: recompute q_coeffs and match the batched openings
        let mut q_coeffs: Vec<Vec<ExtV>> = p
            .stacking_openings
            .iter()
            .map(|v| vec![zero; v.len()])
            .collect();
        for ((commit_idx, layout), coeffs) in layouts.iter().enumerate().zip(q_coeffs.iter_mut()) {
            let lambda_indices = &lambda_indices_per_layout[commit_idx];
            for (col_idx, s) in layout.sorted_cols.iter().map(|c| c.slice).enumerate() {
                let (lambda_idx, need_rot) = lambda_indices[col_idx];
                let n = s.log_height() as isize - l_skip as isize;
                let n_lift = n.max(0) as usize;
                let b: Vec<bool> = (l_skip + n_lift..l_skip + n_stack)
                    .map(|j| (s.row_idx >> j) & 1 == 1)
                    .collect();
                let eq_mle = eval_eq_mle_static(builder, &u[n_lift + 1..], &b);
                // eval_in_uni(l_skip, n, u[0])
                let ind: Option<ExtV> = if n.is_negative() {
                    let z = ext_square_n(builder, u[0], l_skip.wrapping_add_signed(n));
                    Some(eval_eq_uni_at_one_var(builder, n.unsigned_abs(), z))
                } else {
                    None
                };
                let (l, rs_n) = if n.is_negative() {
                    (
                        l_skip.wrapping_add_signed(n),
                        vec![ext_square_n(builder, r[0], (-n) as usize)],
                    )
                } else {
                    (l_skip, r[..=n_lift].to_vec())
                };
                let eq_uni = eval_eq_uni_vars(builder, l, u[0], rs_n[0]);
                let eq_cube = eval_eq_mle_vars(builder, &u[1..=n_lift], &rs_n[1..]);
                let eq_prism: ExtV = builder.eval(eq_uni * eq_cube);
                let mut batched: ExtV = builder.eval(lambda_sqr_powers[lambda_idx] * eq_prism);
                if need_rot {
                    let rot = eval_rot_kernel_prism_var(builder, l, &u[..=n_lift], &rs_n);
                    batched =
                        builder.eval(batched + lambda_sqr_powers[lambda_idx] * lambda_st * rot);
                }
                let mut add: ExtV = builder.eval(eq_mle * batched);
                if let Some(ind) = ind {
                    add = builder.eval(add * ind);
                }
                coeffs[s.col_idx] = builder.eval(coeffs[s.col_idx] + add);
            }
        }
        let mut final_sum = zero;
        for (q_coeff_vec, q_j_vec) in q_coeffs.iter().zip(p.stacking_openings.iter()) {
            for (&q_coeff, &q_j) in q_coeff_vec.iter().zip(q_j_vec.iter()) {
                t.observe_ext(builder, q_j);
                final_sum = builder.eval(final_sum + q_coeff * q_j);
            }
        }
        builder.assert_ext_eq(st_claim, final_sum);

        // u_prism → u_cube
        let u0_pows = ext_powers_of_2(builder, u[0], l_skip);
        let u_cube: Vec<ExtV> = u0_pows.into_iter().chain(u[1..].iter().copied()).collect();

        // ── Stage 4: WHIR opening ────────────────────────────────────────────────────────────
        // Commitment order must match `verifier::verify`: common main, then (merged prep) the one
        // merged commitment, then per trace the cached commitments — or, in per-air mode, each
        // trace's own prep commitment interleaved before its cached ones.
        let mut commit_vars: Vec<Var<N>> = vec![p.common_main_commit];
        if let Some(mc) = merged_prep_var {
            commit_vars.push(mc);
        }
        for &air_id in &order {
            if let Some(c) = preprocessed_commit_vars[air_id] {
                commit_vars.push(c);
            }
            commit_vars.extend(&p.cached_commits[air_id]);
        }
        assert_eq!(commit_vars.len(), layouts.len());
        wrap_verify_whir(builder, &mut t, params, &p, &commit_vars, &u_cube);

        // ── Stage 5: completeness + public inputs ────────────────────────────────────────────
        let recursion_pv_air = proof
            .public_values
            .iter()
            .position(|pvs| pvs.len() == RECURSION_NUM_PVS)
            .expect("no AIR carries recursion public values");
        wrap_completeness_and_publics(builder, &p.public_values[recursion_pv_air], trusted_vk_root);

        WrapOutput { recursion_pv_air }
    }

    // -----------------------------------------------------------------------------------------
    // WHIR opening twin over the outer primitives
    // -----------------------------------------------------------------------------------------

    /// Merkle path walk with native BN254 digests; `bits` are LSB-first sampled index bits
    /// (`bit == 1` means the current node is the right child).
    fn outer_merkle_verify(
        builder: &mut Builder<FC>,
        root: Var<N>,
        bits: &[Var<N>],
        leaf: Var<N>,
        path: &[Var<N>],
    ) {
        debug_assert!(bits.len() >= path.len());
        let mut cur = leaf;
        for (&bit, &sibling) in bits.iter().zip(path) {
            let left: Var<N> = builder.eval(cur + bit * (sibling - cur));
            let right: Var<N> = builder.eval(sibling + bit * (cur - sibling));
            cur = outer_compress(builder, left, right);
        }
        builder.assert_var_eq(cur, root);
    }

    /// Pairwise-compress `2^k` leaf digests into one root (twin of
    /// `MerkleHasher::tree_compress`).
    fn outer_tree_compress(builder: &mut Builder<FC>, mut leaves: Vec<Var<N>>) -> Var<N> {
        debug_assert!(leaves.len().is_power_of_two());
        while leaves.len() > 1 {
            leaves = leaves
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| outer_compress(builder, pair[0], pair[1]))
                .collect();
        }
        leaves[0]
    }

    fn wrap_verify_whir(
        builder: &mut Builder<FC>,
        t: &mut OuterTranscript,
        params: &pico_mle_core::SystemParams,
        p: &WrapProofVar,
        commitments: &[Var<N>],
        u: &[ExtV],
    ) {
        let m = params.l_skip + params.n_stack;
        let k_whir = params.k_whir();
        let num_whir_rounds = params.num_whir_rounds();
        let two_k = 1usize << k_whir;
        let widths: Vec<usize> = p.stacking_openings.iter().map(Vec::len).collect();
        assert_eq!(p.final_poly.len(), 1 << params.log_final_poly_len());

        let zero = ext_const(builder, EF::ZERO);
        let one = ext_const(builder, EF::ONE);

        // ① μ PoW + batching challenge; claim = Σ μ^j · opening_j.
        t.check_witness(builder, params.whir.mu_pow_bits, p.mu_pow_witness);
        let mu = t.sample_ext(builder);
        let total_width: usize = widths.iter().sum();
        let mut mu_pows: Vec<ExtV> = Vec::with_capacity(total_width);
        {
            let mut cur = one;
            for _ in 0..total_width {
                mu_pows.push(cur);
                cur = builder.eval(cur * mu);
            }
        }
        let mut claim = zero;
        for (opening, &mp) in p.stacking_openings.iter().flatten().zip(&mu_pows) {
            claim = builder.eval(claim + *opening * mp);
        }

        // ② WHIR rounds.
        let mut sumcheck_iter = p.whir_sumcheck_polys.iter();
        let mut folding_pow_iter = p.folding_pow_witnesses.iter();
        let mut alphas: Vec<ExtV> = Vec::new();
        let mut z0s: Vec<ExtV> = Vec::new();
        let mut zs: Vec<Vec<ExtV>> = Vec::new();
        let mut gammas: Vec<ExtV> = Vec::new();
        let mut log_rs_domain_size = m + params.log_blowup;

        for round in 0..num_whir_rounds {
            let is_last = round == num_whir_rounds - 1;
            let num_queries = params.whir.rounds[round].num_queries;

            let mut alphas_round: Vec<ExtV> = Vec::with_capacity(k_whir);
            for _ in 0..k_whir {
                let [ev1, ev2] = *sumcheck_iter.next().unwrap();
                t.observe_ext(builder, ev1);
                t.observe_ext(builder, ev2);
                let pow_witness = *folding_pow_iter.next().unwrap();
                t.check_witness(builder, params.whir.folding_pow_bits, pow_witness);
                let alpha = t.sample_ext(builder);
                let ev0: ExtV = builder.eval(claim - ev1);
                claim = interp_quadratic(builder, [ev0, ev1, ev2], alpha);
                alphas_round.push(alpha);
            }

            let y0: Option<ExtV> = if is_last {
                for &coeff in &p.final_poly {
                    t.observe_ext(builder, coeff);
                }
                None
            } else {
                t.observe_digest(builder, &[p.codeword_commits[round]]);
                let z0 = t.sample_ext(builder);
                z0s.push(z0);
                let y0 = p.ood_values[round];
                t.observe_ext(builder, y0);
                Some(y0)
            };

            t.check_witness(
                builder,
                params.whir.query_phase_pow_bits,
                p.query_phase_pow_witnesses[round],
            );

            let omega = F::two_adic_generator(log_rs_domain_size);
            let n_index_bits = log_rs_domain_size - k_whir;
            let omega_pows: Vec<Felt<F>> = (0..n_index_bits)
                .map(|i| builder.constant(omega.exp_power_of_2(i)))
                .collect();
            let one_f: Felt<F> = builder.constant(F::ONE);

            let mut zs_round: Vec<ExtV> = Vec::with_capacity(num_queries);
            let mut ys_round: Vec<ExtV> = Vec::with_capacity(num_queries);
            for query in 0..num_queries {
                let index_bits = t.sample_bits(builder, n_index_bits);

                // z_root = ω^index (select-product; matches the prover's `exp_u64`).
                let mut z_root: Felt<F> = builder.constant(F::ONE);
                for (i, &bit) in index_bits.iter().enumerate() {
                    let factor: Felt<F> = builder.uninit();
                    builder.push_op(DslIr::CircuitSelectF(bit, omega_pows[i], one_f, factor));
                    z_root = builder.eval(z_root * factor);
                }
                let mut z = z_root;
                for _ in 0..k_whir {
                    z = builder.eval(z * z);
                }
                zs_round.push(felt_to_ext(builder, z));

                let yi = if round == 0 {
                    let mut codeword_vals: Vec<ExtV> = vec![zero; two_k];
                    let mut mu_idx = 0usize;
                    for (ci, &commit) in commitments.iter().enumerate() {
                        let opened_rows = &p.initial_round_opened_rows[ci][query];
                        let leaves: Vec<Var<N>> = opened_rows
                            .iter()
                            .map(|row| outer_hash(builder, row))
                            .collect();
                        let query_digest = outer_tree_compress(builder, leaves);
                        outer_merkle_verify(
                            builder,
                            commit,
                            &index_bits,
                            query_digest,
                            &p.initial_round_merkle_proofs[ci][query],
                        );
                        for c in 0..widths[ci] {
                            let mp = mu_pows[mu_idx];
                            mu_idx += 1;
                            for (j, val) in codeword_vals.iter_mut().enumerate() {
                                let term: ExtV = builder.uninit();
                                builder.push_op(DslIr::MulEF(term, mp, opened_rows[j][c]));
                                *val = builder.eval(*val + term);
                            }
                        }
                    }
                    binary_k_fold(builder, codeword_vals, &alphas_round, z_root)
                } else {
                    let opened_values = p.codeword_opened_values[round - 1][query].clone();
                    let leaves: Vec<Var<N>> = opened_values
                        .iter()
                        .map(|&v| {
                            let limbs: [Felt<F>; 4] = core::array::from_fn(|_| builder.uninit());
                            builder.push_op(DslIr::CircuitExt2Felt(limbs, v));
                            outer_hash(builder, &limbs)
                        })
                        .collect();
                    let query_digest = outer_tree_compress(builder, leaves);
                    outer_merkle_verify(
                        builder,
                        p.codeword_commits[round - 1],
                        &index_bits,
                        query_digest,
                        &p.codeword_merkle_proofs[round - 1][query],
                    );
                    binary_k_fold(builder, opened_values, &alphas_round, z_root)
                };
                ys_round.push(yi);
            }

            // γ accumulation: claim += y0·γ + Σ_i yi·γ^{i+2}.
            let gamma = t.sample_ext(builder);
            if let Some(y0) = y0 {
                claim = builder.eval(claim + y0 * gamma);
            }
            let mut gamma_pow: ExtV = builder.eval(gamma * gamma);
            for &yi in &ys_round {
                claim = builder.eval(claim + yi * gamma_pow);
                gamma_pow = builder.eval(gamma_pow * gamma);
            }
            gammas.push(gamma);
            zs.push(zs_round);
            alphas.extend(alphas_round);
            log_rs_domain_size -= 1;
        }
        debug_assert!(sumcheck_iter.next().is_none());

        // ③ Final constrained-RS check: acc == claim.
        let tt = k_whir * num_whir_rounds;
        let prefix = eval_mobius_eq_mle(builder, &u[..tt], &alphas[..tt]);
        let suffix = eval_mle_evals_at_point(builder, p.final_poly.clone(), &u[tt..]);
        let mut acc: ExtV = builder.eval(prefix * suffix);
        let mut jj = k_whir;
        for i in 0..num_whir_rounds {
            let gamma = gammas[i];
            let alpha_slc = &alphas[jj..tt];
            let slc_len = (tt - jj) + 1;
            if i != num_whir_rounds - 1 {
                let z0_pow = ext_powers_of_2(builder, z0s[i], slc_len);
                let (z0_max, z0_left) = z0_pow.split_last().unwrap();
                let eq = eval_eq_mle_vars(builder, alpha_slc, z0_left);
                let h = horner(builder, &p.final_poly, *z0_max);
                acc = builder.eval(acc + gamma * eq * h);
            }
            let mut gamma_pow: ExtV = builder.eval(gamma * gamma);
            for &zi in &zs[i] {
                let zi_pow = ext_powers_of_2(builder, zi, slc_len);
                let (zi_max, zi_left) = zi_pow.split_last().unwrap();
                let eq = eval_eq_mle_vars(builder, alpha_slc, zi_left);
                let h = horner(builder, &p.final_poly, *zi_max);
                acc = builder.eval(acc + gamma_pow * eq * h);
                gamma_pow = builder.eval(gamma_pow * gamma);
            }
            jj += k_whir;
        }
        builder.assert_ext_eq(acc, claim);
    }

    // -----------------------------------------------------------------------------------------
    // Completeness + gnark public inputs
    // -----------------------------------------------------------------------------------------

    /// Fresh copy of a felt (new id) so the in-place KB permutation can never clobber a live one.
    fn fresh_felt(builder: &mut Builder<FC>, x: Felt<F>) -> Felt<F> {
        builder.eval(x + F::ZERO)
    }

    /// SSA-safe Poseidon2-KoalaBear width-16 permutation.
    fn kb_permute_ssa(builder: &mut Builder<FC>, input: [Felt<F>; 16]) -> [Felt<F>; 16] {
        let st: [Felt<F>; 16] = core::array::from_fn(|i| fresh_felt(builder, input[i]));
        builder.push_op(DslIr::ConstraintPoseidon2KoalaBear(Box::new(st)));
        st
    }

    /// `flag_complete == 1`, in-circuit PV-digest recomputation (twin of the host check in
    /// `verify_complete_root`), and the two gnark public-input commitments.
    fn wrap_completeness_and_publics(
        builder: &mut Builder<FC>,
        pv: &[Felt<F>],
        trusted_vk_root: Option<[F; 8]>,
    ) {
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;

        // flag_complete == 1
        let one_f: Felt<F> = builder.constant(F::ONE);
        builder.assert_felt_eq(pv[col.flag_complete], one_f);

        // PV digest: overwrite-mode sponge (rate 8 / width 16), digest = first 8 lanes.
        let mut state: [Felt<F>; 16] = core::array::from_fn(|_| builder.constant(F::ZERO));
        let mut absorb_idx = 0usize;
        for &v in &pv[..NUM_PV_ELMS_TO_HASH] {
            state[absorb_idx] = v;
            absorb_idx += 1;
            if absorb_idx == 8 {
                state = kb_permute_ssa(builder, state);
                absorb_idx = 0;
            }
        }
        if absorb_idx != 0 {
            state = kb_permute_ssa(builder, state);
        }
        for (j, &digest_idx) in col.digest.iter().enumerate() {
            builder.assert_felt_eq(state[j], pv[digest_idx]);
        }

        // vkey_hash = base-2^31 big-endian pack of the riscv vk digest limbs.
        let shift31: Var<N> = builder.constant(N::from_u64(1 << 31));
        let mut vk_var: Var<N> = builder.constant(N::ZERO);
        for (i, &limb_idx) in col.riscv_vk_digest.iter().enumerate() {
            let v = builder.felt2var_circuit(pv[limb_idx]);
            if i == 0 {
                vk_var = v;
            } else {
                vk_var = builder.eval(vk_var * shift31 + v);
            }
        }
        builder.commit_vkey_hash_circuit(vk_var);

        // committed_values_digest = base-256 big-endian pack of the 32 bytes, with the first
        // byte's top 3 bits truncated (matches pico's `felt_bytes_to_bn254_var`).
        let bytes: Vec<Felt<F>> = col
            .committed_value_digest
            .iter()
            .flat_map(|w| w.0)
            .map(|idx| pv[idx])
            .collect();
        assert_eq!(bytes.len(), 32);
        let shift8: Var<N> = builder.constant(N::from_u32(256));
        let zero_var: Var<N> = builder.constant(N::ZERO);
        let mut cvd_var: Var<N> = builder.constant(N::ZERO);
        for (i, &byte) in bytes.iter().enumerate() {
            // Range check every limb to `[0, 256)` before it enters the accumulation. Without it
            // the pack is not injective: `num2bits_f_circuit` hands back all 31 bits of the felt
            // and `bits2num_v_circuit` recomposes every one of them, so a single non-byte limb
            // makes `256^31 = 2^248` overflow the Bn254 modulus and wraps the accumulator onto a
            // digest of the prover's choosing. The bytes reaching here are only constrained by
            // two packed equalities per word in the RISC-V ecall AIR, which leaves a
            // 16-dimensional kernel -- see the fix in `riscv_cpu/ecall/constraints.rs`.
            //
            // Shared with the FRI path's `felt_bytes_to_bn254_var` rather than re-derived, so the
            // two packs cannot drift apart.
            let byte_bits = felt_to_byte_bits(builder, byte, zero_var);
            if i == 0 {
                for j in 0..3 {
                    builder.assign(byte_bits[8 - j - 1], zero_var);
                }
            }
            let byte_var = builder.bits2num_v_circuit(&byte_bits);
            if i == 0 {
                cvd_var = byte_var;
            } else {
                cvd_var = builder.eval(cvd_var * shift8 + byte_var);
            }
        }
        builder.commit_committed_values_digest_circuit(cvd_var);

        // vk_root: pinned against a BAKED constant, the way the FRI path pins it
        // (`vk_merkle::builder`'s `static_vk_root`), rather than exposed as a public input.
        //
        // The recursion whitelist is keyed on KoalaBear digests, so the embed VK can never be a
        // member of it; the trusted root has to reach the on-chain verifier some other way. Baking
        // it makes the Groth16 verifying key itself the pin — an attacker who swaps the whitelist
        // changes this circuit, hence its vk, and the deployed verifier rejects. The alternative
        // (a third public input) leaves the comparison to the calling contract, which is a silent
        // failure if anyone forgets it.
        //
        // The cost is that changing the whitelist requires a new Groth16 setup. That is already
        // true for any recursion-circuit change; the case it newly costs is admitting a
        // presence pattern the whitelist did not previously enumerate.
        //
        // `None` is whitelist-off mode: nothing to pin, and baking a zero root would assert
        // something meaningless rather than nothing. The pin is one `AssertVkRoot` op, which is
        // how the gnark setup tells from the constraints file whether, and to what, it is pinned.
        if let Some(root) = trusted_vk_root {
            builder.assert_vk_root_circuit(col.vk_root.map(|limb_idx| pv[limb_idx]), root);
        }
    }

    /// Host-side values of the two public inputs (for the gnark witness JSON):
    /// `(vkey_hash, committed_values_digest)`. `vk_root` is not among them — it is pinned by a
    /// baked constant, see `wrap_completeness_and_publics`.
    pub fn wrap_public_inputs(proof: &Proof<EmbedSc>) -> (N, N) {
        use p3_field::PrimeField32;
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        let pvs = proof
            .public_values
            .iter()
            .find(|p| p.len() == RECURSION_NUM_PVS)
            .expect("no AIR carries recursion public values");

        let mut vkey_hash = N::ZERO;
        let shift31 = N::from_u64(1 << 31);
        for (i, &limb_idx) in col.riscv_vk_digest.iter().enumerate() {
            let v = N::from_u32(pvs[limb_idx].as_canonical_u32());
            vkey_hash = if i == 0 { v } else { vkey_hash * shift31 + v };
        }

        let mut cvd = N::ZERO;
        let shift8 = N::from_u32(256);
        for (i, idx) in col
            .committed_value_digest
            .iter()
            .flat_map(|w| w.0)
            .enumerate()
        {
            let byte = pvs[idx].as_canonical_u32();
            debug_assert!(byte < 256);
            if i == 0 {
                cvd = N::from_u32(byte & 0x1f);
            } else {
                cvd = cvd * shift8 + N::from_u32(byte);
            }
        }
        (vkey_hash, cvd)
    }

    #[cfg(test)]
    mod tests {
        use p3_field::PrimeField32;

        use super::*;
        use crate::compiler::recursion::constraints::{
            opcodes::ConstraintOpcode, Constraint, ConstraintCompiler,
        };

        /// The gnark setup reads the pin off the constraints file, so a pinned wrap carries
        /// exactly one `AssertVkRoot` naming the vk_root limbs' felts and the root as canonical
        /// decimals, and an unpinned one carries none.
        #[test]
        fn the_constraints_carry_the_pinned_root_in_one_op() {
            // The top limb is p - 1, so a non-canonical rendering would show.
            let root: [F; 8] = core::array::from_fn(|i| F::NEG_ONE - F::from_usize(7 - i));
            let emit = |pin: Option<[F; 8]>| -> (Vec<Constraint>, Vec<String>) {
                let mut builder = Builder::<FC>::default();
                let pv: Vec<Felt<F>> = (0..RECURSION_NUM_PVS)
                    .map(|_| builder.witness_felt())
                    .collect();
                wrap_completeness_and_publics(&mut builder, &pv, pin);
                let limbs = RECURSION_PUBLIC_VALUES_COL_MAP
                    .vk_root
                    .iter()
                    .map(|&i| pv[i].id())
                    .collect();
                let ops = ConstraintCompiler::<FC>::default()
                    .emit(builder.into_operations())
                    .into_iter()
                    .filter(|c| matches!(c.opcode, ConstraintOpcode::AssertVkRoot))
                    .collect();
                (ops, limbs)
            };

            let (pinned, limbs) = emit(Some(root));
            assert_eq!(pinned.len(), 1, "one AssertVkRoot per pinned wrap");
            let expected_root: Vec<String> = root
                .iter()
                .map(|r| r.as_canonical_u32().to_string())
                .collect();
            assert_eq!(expected_root[7], (F::ORDER_U32 - 1).to_string());
            assert_eq!(pinned[0].args, vec![limbs, expected_root]);

            assert!(emit(None).0.is_empty(), "an unpinned wrap asserts no root");
        }
    }
}
