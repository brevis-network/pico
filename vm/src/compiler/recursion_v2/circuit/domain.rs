use crate::{compiler::recursion_v2::prelude::*, configs::config::FieldGenericConfig};
use p3_commit::{LagrangeSelectors, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra, TwoAdicField};

/// Reference: [p3_commit::PolynomialSpace]
pub trait PolynomialSpaceVariable<FC: FieldGenericConfig>:
    Sized + PolynomialSpace<Val = FC::F>
{
    fn selectors_at_point_variable(
        &self,
        builder: &mut Builder<FC>,
        point: Ext<FC::F, FC::EF>,
    ) -> LagrangeSelectors<Ext<FC::F, FC::EF>>;

    fn zp_at_point_variable(
        &self,
        builder: &mut Builder<FC>,
        point: Ext<FC::F, FC::EF>,
    ) -> Ext<FC::F, FC::EF>;

    fn next_point_variable(
        &self,
        builder: &mut Builder<FC>,
        point: Ext<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF>,
    ) -> Ext<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF>;

    fn zp_at_point_f(
        &self,
        builder: &mut Builder<FC>,
        point: Felt<<FC as FieldGenericConfig>::F>,
    ) -> Felt<<FC as FieldGenericConfig>::F>;
}

impl<FC: FieldGenericConfig> PolynomialSpaceVariable<FC> for TwoAdicMultiplicativeCoset<FC::F>
where
    FC::F: TwoAdicField,
{
    fn next_point_variable(
        &self,
        builder: &mut Builder<FC>,
        point: Ext<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF>,
    ) -> Ext<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF> {
        let g = FC::F::two_adic_generator(self.log_n);
        // let g: Felt<_> = builder.eval(g);
        builder.eval(point * g)
    }

    fn selectors_at_point_variable(
        &self,
        builder: &mut Builder<FC>,
        point: Ext<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF>,
    ) -> LagrangeSelectors<Ext<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF>> {
        let unshifted_point: Ext<_, _> = builder.eval(point * self.shift.inverse());
        let z_h_expr = builder
            .exp_power_of_2_v::<Ext<_, _>>(unshifted_point, Usize::Const(self.log_n))
            - FC::EF::ONE;
        let z_h: Ext<_, _> = builder.eval(z_h_expr);
        let g = FC::F::two_adic_generator(self.log_n);
        let ginv = g.inverse();
        LagrangeSelectors {
            is_first_row: builder.eval(z_h / (unshifted_point - FC::EF::ONE)),
            is_last_row: builder.eval(z_h / (unshifted_point - ginv)),
            is_transition: builder.eval(unshifted_point - ginv),
            inv_zeroifier: builder.eval(z_h.inverse()),
        }
    }

    fn zp_at_point_variable(
        &self,
        builder: &mut Builder<FC>,
        point: Ext<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF>,
    ) -> Ext<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF> {
        let unshifted_power = builder.exp_power_of_2_v::<Ext<_, _>>(
            point
                * FC::EF::from_base_slice(&[self.shift, FC::F::ZERO, FC::F::ZERO, FC::F::ZERO])
                    .inverse()
                    .cons(),
            Usize::Const(self.log_n),
        );
        builder.eval(unshifted_power - FC::EF::ONE)
    }
    fn zp_at_point_f(
        &self,
        builder: &mut Builder<FC>,
        point: Felt<<FC as FieldGenericConfig>::F>,
    ) -> Felt<<FC as FieldGenericConfig>::F> {
        let unshifted_power = builder
            .exp_power_of_2_v::<Felt<_>>(point * self.shift.inverse(), Usize::Const(self.log_n));
        builder.eval(unshifted_power - FC::F::ONE)
    }
}
