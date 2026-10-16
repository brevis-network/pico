use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// Degree-2 sumcheck round verifier (fused `lagrange_eval_d2`).
///
/// One row verifies one quadratic sumcheck round: given the running claim and the
/// prover-supplied evaluations s1 = s(1), s2 = s(2) plus the challenge r, it derives
/// s0 = claim - s1 (enforcing s(0) + s(1) == claim by construction) and binds
/// next_claim = p(r) = (s0*(r-1)*(r-2) - 2*s1*r*(r-2) + s2*r*(r-1)) / 2,
/// the unique quadratic through (0, s0), (1, s1), (2, s2) evaluated at r.
///
/// Replaces a 16-instruction ExtAlu/AssertZeroExt chain per sumcheck round
/// (stacking rounds and WHIR folding rounds) with a single instruction.
#[derive(Default)]
pub struct LagrangeEvalD2Chip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
