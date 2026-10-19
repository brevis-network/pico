use core::ops::Add;
use hybrid_array::ArraySize;
use p3_field::{ExtensionField, Field, PrimeField, TwoAdicField};
use serde::Serialize;
use typenum::Same;

// shorthand for types used in the StarkGenericConfig
pub type Val<SC> = <SC as StarkGenericConfig>::Val;

pub type Challenge<SC> = <SC as StarkGenericConfig>::Challenge;

/// Field-level configuration tag shared by the emulators, the chip helpers and the MLE machines:
/// names the base field and the extension field a machine works over. The FRI-specific members
/// (PCS, challenger, domain) were removed together with the FRI proving path; see tag
/// `legacy-fri-last`. The MLE backend carries its own `StarkConfig` in `pico-mle-core`.
pub trait StarkGenericConfig: Clone + Serialize + Sync {
    type Val: Field;

    /// The field from which most random challenges are drawn.
    type Challenge: ExtensionField<Self::Val>;

    fn new() -> Self;

    /// Name of config
    fn name(&self) -> String;
}

pub trait FieldGenericConfig: Clone + Default {
    type N: PrimeField;
    type F: PrimeField + TwoAdicField;
    type EF: ExtensionField<Self::F> + TwoAdicField;
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
    /// `HalfFullRounds - 1`: the ending full rounds the riscv (rate-8) Poseidon2 layout commits
    /// in full; its last ending full round commits only the lanes the Poseidon2 lookup reads.
    type HalfFullRoundsM1: ArraySize
        + Add<typenum::U1, Output: Same<Self::HalfFullRounds>>
        + core::fmt::Debug;
    type PartialRounds: ArraySize + core::fmt::Debug;
    type PartialRoundsM1: ArraySize
        + Add<typenum::U16, Output: ArraySize>
        + Add<typenum::U1, Output: Same<Self::PartialRounds>>
        + core::fmt::Debug;
    type SBoxRegisters: ArraySize + core::fmt::Debug;
}
