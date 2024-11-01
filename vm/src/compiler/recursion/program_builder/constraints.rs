use super::{
    p3::{commit::PolynomialSpaceVariable, fri::TwoAdicMultiplicativeCosetVariable},
    proof::{ChipOpenedValuesVariable, ChipOpening},
    stark::StarkVerifier,
};
use crate::{
    compiler::recursion::ir::{Array, Builder, Ext, ExtConst, Felt, SymbolicExt},
    configs::config::{FieldGenericConfig, StarkGenericConfig},
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::RecursiveVerifierConstraintFolder,
    },
    primitives::consts::MAX_NUM_PVS,
};
use p3_air::Air;
use p3_commit::LagrangeSelectors;
use p3_field::{AbstractExtensionField, AbstractField, TwoAdicField};
use p3_matrix::{dense::RowMajorMatrixView, stack::VerticalPair};

impl<FC: FieldGenericConfig, SC: StarkGenericConfig> StarkVerifier<FC, SC>
where
    // todo: check in the future
    SC: StarkGenericConfig<Val = FC::F, Challenge = FC::EF>,
    // SC: StarkGenericConfig<Challenge = FC::EF>,
    FC::F: TwoAdicField,
{
    fn eval_constrains<A>(
        builder: &mut Builder<FC>,
        chip: &MetaChip<SC::Val, A>,
        opening: &ChipOpening<FC>,
        public_values: Array<FC, Felt<FC::F>>,
        selectors: &LagrangeSelectors<Ext<FC::F, FC::EF>>,
        alpha: Ext<FC::F, FC::EF>,
        permutation_challenges: &[Ext<FC::F, FC::EF>],
    ) -> Ext<FC::F, FC::EF>
    where
        A: for<'b> Air<RecursiveVerifierConstraintFolder<'b, FC>>,
    {
        let mut unflatten = |v: &[Ext<FC::F, FC::EF>]| {
            v.chunks_exact(SC::Challenge::D)
                .map(|chunk| {
                    builder.eval(
                        chunk
                            .iter()
                            .enumerate()
                            .map(|(e_i, &x)| x * FC::EF::monomial(e_i).cons())
                            .sum::<SymbolicExt<_, _>>(),
                    )
                })
                .collect::<Vec<Ext<_, _>>>()
        };

        let permutation_opening_local = unflatten(&opening.permutation_local);
        let permutation_opening_next = unflatten(&opening.permutation_next);

        let mut folder_pv = Vec::new();
        for i in 0..MAX_NUM_PVS {
            folder_pv.push(builder.get(&public_values, i));
        }

        let mut folder = RecursiveVerifierConstraintFolder::<FC> {
            preprocessed: VerticalPair::new(
                RowMajorMatrixView::new_row(&opening.preprocessed_local),
                RowMajorMatrixView::new_row(&opening.preprocessed_next),
            ),
            main: VerticalPair::new(
                RowMajorMatrixView::new_row(&opening.main_local),
                RowMajorMatrixView::new_row(&opening.main_next),
            ),
            perm: VerticalPair::new(
                RowMajorMatrixView::new_row(&permutation_opening_local),
                RowMajorMatrixView::new_row(&permutation_opening_next),
            ),
            perm_challenges: permutation_challenges,
            cumulative_sum: opening.cumulative_sum,
            public_values: &folder_pv,
            is_first_row: selectors.is_first_row,
            is_last_row: selectors.is_last_row,
            is_transition: selectors.is_transition,
            alpha,
            accumulator: SymbolicExt::zero(),
            _marker: std::marker::PhantomData,
        };

        chip.eval(&mut folder);
        builder.eval(folder.accumulator)
    }

    fn recompute_quotient(
        builder: &mut Builder<FC>,
        opening: &ChipOpening<FC>,
        qc_domains: Vec<TwoAdicMultiplicativeCosetVariable<FC>>,
        zeta: Ext<FC::F, FC::EF>,
    ) -> Ext<FC::F, FC::EF> {
        let zps = qc_domains
            .iter()
            .enumerate()
            .map(|(i, domain)| {
                qc_domains
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, other_domain)| {
                        let first_point: Ext<_, _> = builder.eval(domain.first_point());
                        other_domain.zp_at_point(builder, zeta)
                            * other_domain.zp_at_point(builder, first_point).inverse()
                    })
                    .product::<SymbolicExt<_, _>>()
            })
            .collect::<Vec<SymbolicExt<_, _>>>()
            .into_iter()
            .map(|x| builder.eval(x))
            .collect::<Vec<Ext<_, _>>>();

        builder.eval(
            opening
                .quotient
                .iter()
                .enumerate()
                .map(|(ch_i, ch)| {
                    assert_eq!(ch.len(), FC::EF::D);
                    ch.iter()
                        .enumerate()
                        .map(|(e_i, &c)| zps[ch_i] * FC::EF::monomial(e_i) * c)
                        .sum::<SymbolicExt<_, _>>()
                })
                .sum::<SymbolicExt<_, _>>(),
        )
    }

    /// Reference: [pico_machine::stark::Verifier::verify_constraints]
    pub fn verify_constraints<A>(
        builder: &mut Builder<FC>,
        chip: &MetaChip<SC::Val, A>,
        opening: &ChipOpenedValuesVariable<FC>,
        public_values: Array<FC, Felt<FC::F>>,
        trace_domain: TwoAdicMultiplicativeCosetVariable<FC>,
        qc_domains: Vec<TwoAdicMultiplicativeCosetVariable<FC>>,
        zeta: Ext<FC::F, FC::EF>,
        alpha: Ext<FC::F, FC::EF>,
        permutation_challenges: &[Ext<FC::F, FC::EF>],
    ) where
        A: ChipBehavior<SC::Val> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, FC>>,
    {
        let opening = ChipOpening::from_variable(builder, chip, opening);
        let sels = trace_domain.selectors_at_point(builder, zeta);

        let folded_constraints = Self::eval_constrains(
            builder,
            chip,
            &opening,
            public_values,
            &sels,
            alpha,
            permutation_challenges,
        );

        let quotient: Ext<_, _> = Self::recompute_quotient(builder, &opening, qc_domains, zeta);

        // Assert that the quotient times the zerofier is equal to the folded constraints.
        builder.assert_ext_eq(folded_constraints * sels.inv_zeroifier, quotient);
    }
}
