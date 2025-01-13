use super::{
    config::{CircuitConfig, FieldFriConfigVariable},
    domain::PolynomialSpaceVariable,
    stark::StarkVerifier,
};
use crate::{
    compiler::recursion_v2::ir::{
        Builder, Ext, ExtConst, ExtensionOperand, Felt, SymbolicExt, SymbolicFelt,
    },
    configs::config::FieldGenericConfig,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::GenericVerifierConstraintFolder,
        proof::ChipOpenedValues,
    },
};
use core::iter::Iterator;
use p3_air::Air;
use p3_commit::{LagrangeSelectors, Mmcs, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra, TwoAdicField};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
};

pub type RecursiveVerifierConstraintFolder<'a, FC> = GenericVerifierConstraintFolder<
    'a,
    <FC as FieldGenericConfig>::F,
    <FC as FieldGenericConfig>::EF,
    Felt<<FC as FieldGenericConfig>::F>,
    Ext<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF>,
    SymbolicExt<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF>,
>;

impl<C, SC, A> StarkVerifier<C, SC, A>
where
    C::F: TwoAdicField,
    SC: FieldFriConfigVariable<C>,
    C: CircuitConfig<F = SC::Val>,
    <SC::ValMmcs as Mmcs<SC::Val>>::ProverData<RowMajorMatrix<SC::Val>>: Clone,
    A: ChipBehavior<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
{
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    pub fn verify_constraints(
        builder: &mut Builder<C>,
        chip: &MetaChip<SC::Val, A>,
        opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
        trace_domain: TwoAdicMultiplicativeCoset<C::F>,
        qc_domains: Vec<TwoAdicMultiplicativeCoset<C::F>>,
        zeta: Ext<C::F, C::EF>,
        alpha: Ext<C::F, C::EF>,
        permutation_challenges: &[Ext<C::F, C::EF>],
        public_values: &[Felt<C::F>],
    ) {
        let sels = trace_domain.selectors_at_point_variable(builder, zeta);

        // Recompute the quotient at zeta from the chunks.
        let quotient = Self::recompute_quotient(builder, opening, &qc_domains, zeta);

        // Calculate the evaluations of the constraints at zeta.
        let folded_constraints = Self::eval_constraints(
            builder,
            chip,
            opening,
            &sels,
            alpha,
            permutation_challenges,
            public_values,
        );

        // Assert that the quotient times the zerofier is equal to the folded constraints.
        builder.assert_ext_eq(folded_constraints * sels.inv_zeroifier, quotient);
    }

    #[allow(clippy::type_complexity)]
    pub fn eval_constraints(
        builder: &mut Builder<C>,
        chip: &MetaChip<SC::Val, A>,
        opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
        selectors: &LagrangeSelectors<Ext<C::F, C::EF>>,
        alpha: Ext<C::F, C::EF>,
        permutation_challenges: &[Ext<C::F, C::EF>],
        public_values: &[Felt<C::F>],
    ) -> Ext<C::F, C::EF> {
        let mut unflatten = |v: &[Ext<C::F, C::EF>]| {
            v.chunks_exact(<SC::Challenge as FieldExtensionAlgebra<C::F>>::D)
                .map(|chunk| {
                    builder.eval(
                        chunk
                            .iter()
                            .enumerate()
                            .map(
                                |(e_i, x): (usize, &Ext<C::F, C::EF>)| -> SymbolicExt<C::F, C::EF> {
                                    SymbolicExt::from(*x) * C::EF::monomial(e_i)
                                },
                            )
                            .sum::<SymbolicExt<_, _>>(),
                    )
                })
                .collect::<Vec<Ext<_, _>>>()
        };

        let permutation_opening_local = unflatten(&opening.permutation_local);
        let permutation_opening_next = unflatten(&opening.permutation_next);

        let mut folder = RecursiveVerifierConstraintFolder::<C> {
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
            regional_cumulative_sum: &opening.regional_cumulative_sum,
            global_cumulative_sum: &opening.global_cumulative_sum,
            public_values,
            is_first_row: selectors.is_first_row,
            is_last_row: selectors.is_last_row,
            is_transition: selectors.is_transition,
            alpha,
            accumulator: SymbolicExt::ZERO,
            _marker: std::marker::PhantomData,
        };

        chip.eval(&mut folder);
        builder.eval(folder.accumulator)
    }

    #[allow(clippy::type_complexity)]
    pub fn recompute_quotient(
        builder: &mut Builder<C>,
        opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
        qc_domains: &[TwoAdicMultiplicativeCoset<C::F>],
        zeta: Ext<C::F, C::EF>,
    ) -> Ext<C::F, C::EF> {
        // Compute the maximum power of zeta we will need.
        let max_domain_log_n = qc_domains.iter().map(|d| d.log_n).max_by(Ord::cmp).unwrap();

        // Compute all powers of zeta of the form zeta^(2^i) up to `zeta^(2^max_domain_log_n)`.
        let mut zetas: Vec<Ext<_, _>> = vec![zeta];
        for _ in 1..max_domain_log_n + 1 {
            let last_zeta = zetas.last().unwrap();
            let new_zeta = builder.eval(*last_zeta * *last_zeta);
            builder.reduce_e(new_zeta);
            zetas.push(new_zeta);
        }
        let zps = qc_domains
            .iter()
            .enumerate()
            .map(|(i, domain)| {
                let (zs, zinvs) = qc_domains
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, other_domain)| {
                        // `shift_power` is used in the computation of
                        let shift_power = other_domain
                            .shift
                            .exp_power_of_2(other_domain.log_n)
                            .inverse();
                        // This is `other_domain.zp_at_point_f(builder, domain.first_point())`.
                        // We compute it as a constant here.
                        let z_f = domain.first_point().exp_power_of_2(other_domain.log_n)
                            * shift_power
                            - C::F::ONE;
                        (
                            {
                                // We use the precomputed powers of zeta to compute (inline) the value of
                                // `other_domain.zp_at_point_variable(builder, zeta)`.
                                let z: Ext<_, _> = builder.eval(
                                    zetas[other_domain.log_n] * SymbolicFelt::from_f(shift_power)
                                        - SymbolicExt::from_f(C::EF::ONE),
                                );
                                z.to_operand().symbolic()
                            },
                            builder.constant::<Felt<_>>(z_f),
                        )
                    })
                    .unzip::<_, _, Vec<SymbolicExt<C::F, C::EF>>, Vec<Felt<_>>>();
                let symbolic_prod: SymbolicFelt<_> = zinvs
                    .into_iter()
                    .map(|x| x.into())
                    .product::<SymbolicFelt<_>>();
                (zs.into_iter().product::<SymbolicExt<_, _>>(), symbolic_prod)
            })
            .collect::<Vec<(SymbolicExt<_, _>, SymbolicFelt<_>)>>()
            .into_iter()
            .map(|(x, y)| builder.eval(x / y))
            .collect::<Vec<Ext<_, _>>>();
        zps.iter().for_each(|zp| builder.reduce_e(*zp));
        builder.eval(
            opening
                .quotient
                .iter()
                .enumerate()
                .map(|(ch_i, ch)| {
                    assert_eq!(ch.len(), C::EF::D);
                    zps[ch_i].to_operand().symbolic()
                        * ch.iter()
                            .enumerate()
                            .map(|(e_i, &c)| C::EF::monomial(e_i).cons() * SymbolicExt::from(c))
                            .sum::<SymbolicExt<_, _>>()
                })
                .sum::<SymbolicExt<_, _>>(),
        )
    }
}
