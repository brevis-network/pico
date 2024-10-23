use super::fri::types::{FriConfigVariable, TwoAdicPcsRoundVariable};
use crate::{
    compiler::recursion::ir::{Array, Builder, Ext, FromConstant, Usize},
    configs::config::FieldGenericConfig,
};
use p3_commit::{LagrangeSelectors, PolynomialSpace};

/// Reference: [p3_commit::PolynomialSpace]
pub trait PolynomialSpaceVariable<RC: FieldGenericConfig>: Sized + FromConstant<RC> {
    type Constant: PolynomialSpace<Val = RC::F>;

    fn next_point(
        &self,
        builder: &mut Builder<RC>,
        point: Ext<RC::F, RC::EF>,
    ) -> Ext<RC::F, RC::EF>;

    fn selectors_at_point(
        &self,
        builder: &mut Builder<RC>,
        point: Ext<RC::F, RC::EF>,
    ) -> LagrangeSelectors<Ext<RC::F, RC::EF>>;

    fn zp_at_point(
        &self,
        builder: &mut Builder<RC>,
        point: Ext<RC::F, RC::EF>,
    ) -> Ext<RC::F, RC::EF>;

    fn split_domains(
        &self,
        builder: &mut Builder<RC>,
        log_num_chunks: impl Into<Usize<RC::N>>,
        num_chunks: impl Into<Usize<RC::N>>,
    ) -> Array<RC, Self>;

    fn split_domains_const(&self, _: &mut Builder<RC>, log_num_chunks: usize) -> Vec<Self>;

    fn create_disjoint_domain(
        &self,
        builder: &mut Builder<RC>,
        log_degree: Usize<RC::N>,
        config: Option<FriConfigVariable<RC>>,
    ) -> Self;
}

/// Reference: [p3_commit::Pcs]
pub trait PcsVariable<RC: FieldGenericConfig, Challenger> {
    type Domain: PolynomialSpaceVariable<RC>;

    type Commitment;

    type Proof;

    fn natural_domain_for_log_degree(
        &self,
        builder: &mut Builder<RC>,
        log_degree: Usize<RC::N>,
    ) -> Self::Domain;

    fn verify(
        &self,
        builder: &mut Builder<RC>,
        rounds: Array<RC, TwoAdicPcsRoundVariable<RC>>,
        proof: Self::Proof,
        challenger: &mut Challenger,
    );
}
