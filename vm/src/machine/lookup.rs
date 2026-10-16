//! Lookup vocabulary re-exported from `pico-mle-core` so the existing `crate::machine::lookup::…`
//! call sites keep resolving. The FRI-only `VirtualPairCol` lowering that used to live here went
//! with the FRI path; a chip's lookups are now summarised by `MetaChip` through the MLE symbolic
//! builder (`LookupSummary`).
pub use pico_mle_core::lookup::{
    assert_global_kind_is_bounded_constant, LookupScope, LookupSummary, LookupType, SymbolicLookup,
    GLOBAL_KIND_VALUE_INDEX,
};
