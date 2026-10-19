//! Lookup message-builder traits.
//!
//! `LookupBuilder` is a `ChipBuilder` supertrait, so it must live in `pico-mle-core`. The no-op
//! `EmptyLookupBuilder` path exists only so the legacy FRI constraint folders (which never emit
//! lookups) can satisfy that supertrait; the blanket impl and the `FilteredAirBuilder` impl live
//! here because moving `LookupBuilder` out of `vm` would otherwise make them orphan-rule
//! violations (`impl <foreign trait> for <bare type param / foreign p3 type>`). The concrete
//! `EmptyLookupBuilder for {Prover,Verifier}ConstraintFolder` impls stay in `vm` (local types).

use p3_air::{AirBuilder, FilteredAirBuilder};

/// message builder for the chips.
pub trait LookupBuilder<M> {
    fn looking(&mut self, message: M);

    fn looked(&mut self, message: M);
}

/// A message builder for which sending and receiving messages is a no-op.
// TODO(fri-removal): no-op LookupBuilder mechanism exists only to satisfy FRI constraint folders
// — delete the whole EmptyLookupBuilder path (trait + blanket impl + FilteredAirBuilder impl) with FRI.
pub trait EmptyLookupBuilder: AirBuilder {}

// TODO(fri-removal): no-op LookupBuilder blanket for FRI constraint folders — delete with FRI.
impl<AB: EmptyLookupBuilder, M> LookupBuilder<M> for AB {
    fn looking(&mut self, _message: M) {}

    fn looked(&mut self, _message: M) {}
}

// TODO(fri-removal): no-op LookupBuilder for the p3 `FilteredAirBuilder` — delete with FRI.
impl<AB: AirBuilder> EmptyLookupBuilder for FilteredAirBuilder<'_, AB> {}
