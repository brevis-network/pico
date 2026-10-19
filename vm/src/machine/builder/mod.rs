//! This module includes the functions of the main chip builder we used in the VM.
//!
//! The core `ChipBuilder` trait stack (`ChipBuilder`, `ChipBaseBuilder`, `LookupBuilder`,
//! `EmptyLookupBuilder`, `PublicValuesBuilder`, `ScopedBuilder`) now lives in `pico-mle-core` and
//! is re-exported below at the same paths; the sibling chip-helper builders stay here.

use p3_field::Field;

mod extension;
mod lookup;
mod range_check;
mod recursion;
mod riscv_memory;
mod septic;
mod sub_builder;
mod word;

// Re-export shim: these are literally the `pico_mle_core::builder` traits (this `pub use`), used
// identically by both backends — so this is not FRI-gated.
//
// TODO: repoint the ~40 chip `constraints.rs` sites to `pico_mle_core::builder::…` and delete these
// re-exports. Mechanical cross-file rename, no FRI dependency.
pub use pico_mle_core::builder::{
    ChipBaseBuilder, ChipBuilder, EmptyLookupBuilder, LookupBuilder, PublicValuesBuilder,
    ScopedBuilder,
};

pub use extension::ExtensionBuilder;
pub use lookup::ChipLookupBuilder;
pub use range_check::ChipRangeBuilder;
pub use recursion::RecursionBuilder;
pub use riscv_memory::RiscVMemoryBuilder;
pub use septic::SepticExtensionBuilder;
pub use sub_builder::SubAirBuilder;
pub use word::ChipWordBuilder;

// aggregation of chip-related builders (each impls a vm-local helper trait for any
// `CB: ChipBuilder`, so these blanket impls are legal here). The `ChipBaseBuilder` blanket moved
// to `pico-mle-core` alongside the trait itself.
impl<F: Field, CB: ChipBuilder<F>> ChipLookupBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> ChipRangeBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> ChipWordBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>, const D: usize> ExtensionBuilder<F, D> for CB {}
impl<F: Field, CB: ChipBuilder<F>> RecursionBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> RiscVMemoryBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> SepticExtensionBuilder<F> for CB {}
