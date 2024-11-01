use super::fri::types::{FriConfigVariable, TwoAdicPcsRoundVariable};
use crate::{
    compiler::recursion::ir::{Array, Builder, Ext, FromConstant, Usize},
    configs::config::FieldGenericConfig,
};
use p3_commit::{LagrangeSelectors, PolynomialSpace};

/// Reference: [p3_commit::PolynomialSpace]
pub trait PolynomialSpaceVariable<FC: FieldGenericConfig>: Sized + FromConstant<FC> {
    type Constant: PolynomialSpace<Val = FC::F>;

    fn next_point(
        &self,
        builder: &mut Builder<FC>,
        point: Ext<FC::F, FC::EF>,
    ) -> Ext<FC::F, FC::EF>;

    fn selectors_at_point(
        &self,
        builder: &mut Builder<FC>,
        point: Ext<FC::F, FC::EF>,
    ) -> LagrangeSelectors<Ext<FC::F, FC::EF>>;

    fn zp_at_point(
        &self,
        builder: &mut Builder<FC>,
        point: Ext<FC::F, FC::EF>,
    ) -> Ext<FC::F, FC::EF>;

    fn split_domains(
        &self,
        builder: &mut Builder<FC>,
        log_num_chunks: impl Into<Usize<FC::N>>,
        num_chunks: impl Into<Usize<FC::N>>,
    ) -> Array<FC, Self>;

    fn split_domains_const(&self, _: &mut Builder<FC>, log_num_chunks: usize) -> Vec<Self>;

    fn create_disjoint_domain(
        &self,
        builder: &mut Builder<FC>,
        log_degree: Usize<FC::N>,
        config: Option<FriConfigVariable<FC>>,
    ) -> Self;
}

/// Reference: [p3_commit::Pcs]
pub trait PcsVariable<FC: FieldGenericConfig, Challenger> {
    type Domain: PolynomialSpaceVariable<FC>;

    type Commitment;

    type Proof;

    fn natural_domain_for_log_degree(
        &self,
        builder: &mut Builder<FC>,
        log_degree: Usize<FC::N>,
    ) -> Self::Domain;

    fn verify(
        &self,
        builder: &mut Builder<FC>,
        rounds: Array<FC, TwoAdicPcsRoundVariable<FC>>,
        proof: Self::Proof,
        challenger: &mut Challenger,
    );
}
