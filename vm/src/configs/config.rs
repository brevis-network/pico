use crate::primitives::consts::DIGEST_SIZE;
use core::ops::Add;
use hybrid_array::ArraySize;
use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{ExtensionField, Field, PrimeField, TwoAdicField};
use serde::Serialize;
use typenum::Same;
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
    // TODO: figure out how to fix the ProverData: Sync bound within the context of prove
    type Pcs: Pcs<Self::Challenge, Self::Challenger, Domain = Self::Domain, ProverData: Sync>
        + ZeroCommitment<Self>;

    fn new() -> Self;

    /// Get the PCS used by this configuration.
    fn pcs(&self) -> Self::Pcs;

    /// Initialize a new challenger.
    fn challenger(&self) -> Self::Challenger;

    /// Name of config
    fn name(&self) -> String;

    fn hash_slice(&self, input: &[Val<Self>]) -> [Val<Self>; DIGEST_SIZE];
}

pub trait FieldGenericConfig: Clone + Default {
    type N: PrimeField;
    type F: PrimeField + TwoAdicField;
    type EF: ExtensionField<Self::F> + TwoAdicField;
}

pub trait ZeroCommitment<SC: StarkGenericConfig> {
    fn zero_commitment(&self) -> Com<SC>;
}

/// Trait that allows us to implement Poseidon2 chips without a bunch of const
/// generics
///
/// We also slap on a bunch of typenum math bounds here because every
/// instantiation should satisfy them here rather than at chip instantiation.
pub trait Poseidon2Config: Copy {
    type FullRounds: ArraySize + Add<typenum::U3, Output: ArraySize> + core::fmt::Debug;
    // the add constraint enforces that external rounds is even
    type HalfFullRounds: ArraySize
        + Add<Self::HalfFullRounds, Output: Same<Self::FullRounds>>
        + core::fmt::Debug;
    type PartialRounds: ArraySize + core::fmt::Debug;
    type PartialRoundsM1: ArraySize
        + Add<typenum::U16, Output: ArraySize>
        + Add<typenum::U1, Output: Same<Self::PartialRounds>>
        + core::fmt::Debug;
    type SBoxRegisters: ArraySize + core::fmt::Debug;
}

#[derive(Clone, Copy)]
pub struct SimpleFriConfig {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
}
