use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// GKR cubic sumcheck sub-round verifier.
///
/// One row verifies one degree-3 sumcheck round of the GKR fractional sumcheck:
/// given the running claim, prover evaluations s1 = s(1), s2 = s(2), s3 = s(3) and
/// the challenge r, it derives s0 = claim - s1 (enforcing s(0) + s(1) == claim by
/// construction) and binds next_claim = p(r), the unique cubic through
/// (0, s0), (1, s1), (2, s2), (3, s3) evaluated at r:
///   6*p(r) = -s0*(r-1)(r-2)(r-3) + 3*s1*r*(r-2)(r-3) - 3*s2*r*(r-1)(r-3)
///            + s3*r*(r-1)(r-2).
/// It additionally folds the running eq product of the round:
///   eq_out = eq_in * eq_factor(xi, r),  eq_factor(x, y) = 2xy - x - y + 1.
///
/// An auxiliary column r_sq = r*r keeps every constraint within
/// max_constraint_degree = 4 (products of three linear factors are rewritten as
/// degree-2 expressions in (r, r_sq)).
///
/// Replaces a ~43-instruction ExtAlu/Mem/AssertZeroExt chain per GKR sub-round
/// with a single instruction.
#[derive(Default)]
pub struct GkrSumcheckRoundChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
