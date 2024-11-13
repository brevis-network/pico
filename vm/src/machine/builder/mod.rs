//! This module includes the functions of the main chip builder we used in the VM.

use crate::machine::lookup::SymbolicLookup;
use p3_air::{AirBuilder, FilteredAirBuilder};
use p3_field::Field;

mod base;
mod extension;
mod lookup;
mod permutation;
mod public_values;
mod range_check;
mod recursion_lookup;
mod recursion_memory;
mod recursion_v2;
mod riscv_memory;
mod sub_builder;
mod word;

pub use base::ChipBaseBuilder;
pub use extension::ExtensionBuilder;
pub use lookup::{ChipLookupBuilder, EmptyLookupBuilder, LookupBuilder};
pub use permutation::PermutationBuilder;
pub use public_values::PublicValuesBuilder;
pub use range_check::ChipRangeBuilder;
pub use recursion_lookup::RecursionLookupBuilder;
pub use recursion_memory::RecursionMemoryBuilder;
pub use recursion_v2::RecursionBuilder;
pub use riscv_memory::RiscVMemoryBuilder;
pub use sub_builder::SubAirBuilder;
pub use word::ChipWordBuilder;

/// Chip builder
pub trait ChipBuilder<F: Field>:
    ChipBaseBuilder<F> + LookupBuilder<SymbolicLookup<Self::Expr>> + PublicValuesBuilder
{
    /// get preprocessed trace
    /// Originally from PaiBuilder in p3
    fn preprocessed(&self) -> Self::M;
}

// aggregation of chip-related builders
impl<F: Field, CB: ChipBuilder<F>> ChipBaseBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> ChipLookupBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> ChipRangeBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> ChipWordBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> ExtensionBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> RecursionBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> RecursionLookupBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> RecursionMemoryBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> RiscVMemoryBuilder<F> for CB {}
