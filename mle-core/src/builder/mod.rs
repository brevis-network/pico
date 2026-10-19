//! The main chip builder trait stack shared across proving backends.
//!
//! `ChipBuilder` is the generic builder every chip's `Air<CB: ChipBuilder<F>>` is written against,
//! so the same chip constraints run on every backend that implements it. The trait cluster lives
//! here (rather than in `vm`) because the MLE backend *implements* it (see `crate::air::symbolic` /
//! `crate::air::debug`), and `cuda-mle` needs it too — both consumers sit above `pico-mle-core`, so
//! this is their shared ancestor.

use crate::lookup::SymbolicLookup;
use p3_field::Field;

mod base;
mod lookup;
mod public_values;
mod scoped;

pub use base::ChipBaseBuilder;
pub use lookup::{EmptyLookupBuilder, LookupBuilder};
pub use public_values::PublicValuesBuilder;
pub use scoped::ScopedBuilder;

/// Chip builder
pub trait ChipBuilder<F: Field>:
    ChipBaseBuilder<F> + LookupBuilder<SymbolicLookup<Self::Expr>> + PublicValuesBuilder
{
    // `preprocessed()` and `public_values()` come from Plonky3's `AirBuilder` since 0.5.
}

impl<F: Field, CB: ChipBuilder<F>> ChipBaseBuilder<F> for CB {}
