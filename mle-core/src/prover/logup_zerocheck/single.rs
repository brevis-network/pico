//! Single AIR constraint evaluation helpers

use p3_field::{ExtensionField, TwoAdicField};

use crate::{
    air::symbolic::SymbolicExpressionDag,
    poly::matrix::{ColMajorMatrix, StridedColMajorMatrixView},
    prover::{
        logup_zerocheck::evaluator::{build_evaluator, ConstraintEvaluator, InteractionEvalPlan},
        AirProvingContext, ProverBackend,
    },
};

/// Per-AIR constraint + interaction evaluator over the reference backend's column-major strided
/// trace views. This is the column-major counterpart to `RowMajorEvalHelper` (in
/// `cpu::logup_zerocheck`), which does the same job over the optimized CPU backend's row-major
/// layout.
pub struct ColMajorEvalHelper<'a, F> {
    /// AIR constraints
    pub constraints_dag: &'a SymbolicExpressionDag<F>,
    /// LogUp interactions as a compact sub-DAG evaluated by node index (see [`InteractionEvalPlan`]).
    pub interactions: &'a InteractionEvalPlan<F>,
    pub public_values: Vec<F>,
    pub preprocessed_trace: Option<StridedColMajorMatrixView<'a, F>>,
    // PERF: skip rotation if vk dictates it is never used
    pub needs_next: bool,
    pub constraint_degree: u8,
}

impl<'a, F: TwoAdicField> ColMajorEvalHelper<'a, F> {
    /// Returns list of (ref to column-major matrix, is_rot) pairs in the order:
    /// - (if has_preprocessed) (preprocessed, false), (preprocessed, true)
    /// - (cached_0, false), (cached_0, true), ..., (cached_{m-1}, false), (cached_{m-1}, true)
    /// - (common, false), (common, true)
    ///
    /// Note: currently every matrix returns both non-rotated and rotated versions. This will change
    /// in the future for perf.
    pub fn view_mats<PB>(
        &self,
        ctx: &'a AirProvingContext<PB>,
    ) -> Vec<(StridedColMajorMatrixView<'a, F>, bool)>
    where
        PB: ProverBackend<Val = F, Matrix = ColMajorMatrix<F>>,
    {
        let base_mats = usize::from(self.has_preprocessed()) + 1 + ctx.cached_mains.len();
        let mut mats = Vec::with_capacity(if self.needs_next {
            2 * base_mats
        } else {
            base_mats
        });
        if let Some(mat) = self.preprocessed_trace {
            mats.push((mat, false));
            if self.needs_next {
                mats.push((mat, true));
            }
        }
        for cd in ctx.cached_mains.iter() {
            let trace_view: StridedColMajorMatrixView<'a, F> = cd.trace.as_view().into();
            mats.push((trace_view, false));
            if self.needs_next {
                mats.push((trace_view, true));
            }
        }
        mats.push((ctx.common_main.as_view().into(), false));
        if self.needs_next {
            mats.push((ctx.common_main.as_view().into(), true));
        }
        mats
    }

    pub fn has_preprocessed(&self) -> bool {
        self.preprocessed_trace.is_some()
    }

    /// Builds the shared [`ConstraintEvaluator`] over this AIR's column-major row views.
    ///
    /// `row_parts` must be ordered as: selectors `[is_first_row, is_transition, is_last_row]`, then
    /// each partition (preprocessed, cached_0.., common) — each followed by its rotated `next` row
    /// when `needs_next`.
    fn evaluator<'r, FF: ExtensionField<F>>(
        &'r self,
        row_parts: &'r [Vec<FF>],
    ) -> ConstraintEvaluator<'r, F, FF> {
        build_evaluator(
            row_parts,
            self.has_preprocessed(),
            self.needs_next,
            &self.public_values,
        )
    }

    // Assumes that `z[0] != 1` or `omega_D^{-1}` to avoid handling division by zero.
    pub fn acc_constraints<FF: ExtensionField<F>, EF: ExtensionField<FF>>(
        &self,
        row_parts: &[Vec<FF>],
        lambda_pows: &[EF],
    ) -> EF {
        self.evaluator(row_parts)
            .acc_constraints(self.constraints_dag, lambda_pows)
    }

    /// Sum of the ordered `interactions`, weighted by `eq(\xi_3, b_{T,\hat\sigma})` terms, as a
    /// (numerator, denominator) pair. The denominator does not include the `alpha` term.
    pub fn acc_interactions<FF, EF>(
        &self,
        row_parts: &[Vec<FF>],
        beta_pows: &[EF],
        eq_3bs: &[EF],
    ) -> [EF; 2]
    where
        FF: ExtensionField<F>,
        EF: ExtensionField<FF> + ExtensionField<F>,
    {
        self.evaluator(row_parts)
            .acc_interactions(self.interactions, beta_pows, eq_3bs)
    }

    pub fn eval_interactions<FF, EF>(
        &self,
        row_parts: &[Vec<FF>],
        beta_pows: &[EF],
    ) -> Vec<(FF, EF)>
    where
        FF: ExtensionField<F>,
        EF: ExtensionField<FF> + ExtensionField<F>,
    {
        self.evaluator(row_parts)
            .eval_interactions(self.interactions, beta_pows)
    }
}
