use super::fri::types::{FriConfigVariable, TwoAdicPcsRoundVariable};
use crate::compiler::recursion::ir::{Array, Builder, Config, Ext, FromConstant, Usize};
use p3_commit::{LagrangeSelectors, PolynomialSpace};

/// Reference: [p3_commit::PolynomialSpace]
pub trait PolynomialSpaceVariable<CF: Config>: Sized + FromConstant<CF> {
    type Constant: PolynomialSpace<Val = CF::F>;

    fn next_point(
        &self,
        builder: &mut Builder<CF>,
        point: Ext<CF::F, CF::EF>,
    ) -> Ext<CF::F, CF::EF>;

    fn selectors_at_point(
        &self,
        builder: &mut Builder<CF>,
        point: Ext<CF::F, CF::EF>,
    ) -> LagrangeSelectors<Ext<CF::F, CF::EF>>;

    fn zp_at_point(
        &self,
        builder: &mut Builder<CF>,
        point: Ext<CF::F, CF::EF>,
    ) -> Ext<CF::F, CF::EF>;

    fn split_domains(
        &self,
        builder: &mut Builder<CF>,
        log_num_chunks: impl Into<Usize<CF::N>>,
        num_chunks: impl Into<Usize<CF::N>>,
    ) -> Array<CF, Self>;

    fn split_domains_const(&self, _: &mut Builder<CF>, log_num_chunks: usize) -> Vec<Self>;

    fn create_disjoint_domain(
        &self,
        builder: &mut Builder<CF>,
        log_degree: Usize<CF::N>,
        config: Option<FriConfigVariable<CF>>,
    ) -> Self;
}

/// Reference: [p3_commit::Pcs]
pub trait PcsVariable<CF: Config, Challenger> {
    type Domain: PolynomialSpaceVariable<CF>;

    type Commitment;

    type Proof;

    fn natural_domain_for_log_degree(
        &self,
        builder: &mut Builder<CF>,
        log_degree: Usize<CF::N>,
    ) -> Self::Domain;

    fn verify(
        &self,
        builder: &mut Builder<CF>,
        rounds: Array<CF, TwoAdicPcsRoundVariable<CF>>,
        proof: Self::Proof,
        challenger: &mut Challenger,
    );
}
