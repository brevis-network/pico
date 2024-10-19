use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{ExtensionField, Field, PrimeField, TwoAdicField};
use std::marker::PhantomData;

// Resembling Plonky3: https://github.com/Plonky3/Plonky3/blob/main/uni-stark/src/config.rs
pub type PackedVal<SC> = <<SC as StarkGenericConfig>::Val as Field>::Packing;

pub type PackedChallenge<SC> = <<SC as StarkGenericConfig>::Challenge as ExtensionField<
    <SC as StarkGenericConfig>::Val,
>>::ExtensionPacking;

// Resembling Plonky3: unistark/src/proof.rs, representing types in pcs.rs
pub type Com<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Commitment;

pub type PcsProverData<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::ProverData;

pub type PcsProof<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Proof;

pub type PcsError<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Error;

// shorthand for types used in the StarkGenericConfig
pub type Val<SC> = <SC as StarkGenericConfig>::Val;

pub type Domain<SC> = <SC as StarkGenericConfig>::Domain;

pub type Challenge<SC> = <SC as StarkGenericConfig>::Challenge;

pub type Challenger<SC> = <SC as StarkGenericConfig>::Challenger;

/// A generic config for machines
pub trait StarkGenericConfig: Sync + Clone {
    type Val: Field;

    type Domain: PolynomialSpace<Val = Self::Val> + Sync;

    /// The field from which most random challenges are drawn.
    type Challenge: ExtensionField<Self::Val>;

    /// The challenger (Fiat-Shamir) implementation used.
    type Challenger: FieldChallenger<Self::Val>
        + CanObserve<<Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment>
        + CanSample<Self::Challenge>
        + Clone;

    /// The PCS used to commit to trace polynomials.
    type Pcs: Pcs<Self::Challenge, Self::Challenger, Domain = Self::Domain> + Sync;

    /// Get the PCS used by this configuration.
    fn pcs(&self) -> &Self::Pcs;

    /// Initialize a new challenger.
    fn challenger(&self) -> Self::Challenger;

    /// Name of config
    fn name(&self) -> String;
}

pub trait RecursionGenericConfig: Clone + Default {
    type N: PrimeField;
    type F: PrimeField + TwoAdicField;
    type EF: ExtensionField<Self::F> + TwoAdicField;
}

#[derive(Debug, Clone, Default)]
pub struct RecursionSimpleConfig<F, EF>(PhantomData<(F, EF)>);

impl<F: PrimeField + TwoAdicField, EF: ExtensionField<F> + TwoAdicField> RecursionGenericConfig
    for RecursionSimpleConfig<F, EF>
{
    type N = F;
    type F = F;
    type EF = EF;
}
