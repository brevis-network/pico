use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{ExtensionField, Field, PrimeField, TwoAdicField};
use serde::Serialize;
// Resembling Plonky3: https://github.com/Plonky3/Plonky3/blob/main/uni-stark/src/config.rs

pub type PackedVal<SC> = <Val<SC> as Field>::Packing;

pub type PackedChallenge<SC> = <Challenge<SC> as ExtensionField<Val<SC>>>::ExtensionPacking;

pub type Com<SC> =
    <<SC as StarkGenericConfig>::Pcs as Pcs<Challenge<SC>, Challenger<SC>>>::Commitment;

// todo: this is confusing and should be considered for refactor
pub type Dom<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<Challenge<SC>, Challenger<SC>>>::Domain;

pub type PcsProverData<SC> =
    <<SC as StarkGenericConfig>::Pcs as Pcs<Challenge<SC>, Challenger<SC>>>::ProverData;

pub type PcsProof<SC> =
    <<SC as StarkGenericConfig>::Pcs as Pcs<Challenge<SC>, Challenger<SC>>>::Proof;

pub type PcsError<SC> =
    <<SC as StarkGenericConfig>::Pcs as Pcs<Challenge<SC>, Challenger<SC>>>::Error;

// shorthand for types used in the StarkGenericConfig
pub type Val<SC> = <SC as StarkGenericConfig>::Val;

pub type Challenge<SC> = <SC as StarkGenericConfig>::Challenge;

pub type Challenger<SC> = <SC as StarkGenericConfig>::Challenger;

/// A generic config for machines
pub trait StarkGenericConfig: Clone + Serialize + Sync {
    type Val: Field;

    type Domain: PolynomialSpace<Val = Self::Val> + Copy + Sync;

    /// The field from which most random challenges are drawn.
    type Challenge: ExtensionField<Self::Val>;

    /// The challenger (Fiat-Shamir) implementation used.
    type Challenger: FieldChallenger<Self::Val>
        + CanObserve<<Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment>
        + CanSample<Self::Challenge>
        + Clone;

    /// The PCS used to commit to trace polynomials.
    type Pcs: Pcs<Self::Challenge, Self::Challenger, Domain = Self::Domain>
        + Sync
        + ZeroCommitment<Self>;

    /// Get the PCS used by this configuration.
    fn pcs(&self) -> &Self::Pcs;

    /// Initialize a new challenger.
    fn challenger(&self) -> Self::Challenger;

    /// Name of config
    fn name(&self) -> String;
}

pub trait FieldGenericConfig: Clone + Default {
    type N: PrimeField;
    type F: PrimeField + TwoAdicField;
    type EF: ExtensionField<Self::F> + TwoAdicField;
}

pub trait ZeroCommitment<SC: StarkGenericConfig> {
    fn zero_commitment(&self) -> Com<SC>;
}

pub struct SimpleFriConfig {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
}
