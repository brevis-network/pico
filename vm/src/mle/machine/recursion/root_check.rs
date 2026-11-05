//! Host-side acceptance checks on a COMPLETE recursion root proof's public values.
//!
//! Config-free, so the combine root, the compress proof over it and the embed proof over that
//! share them: both outer layers pass the root's public values down unchanged. The implementation
//! is `pico_verifier::public_values`, which `pico_verifier`'s apex runs too; this crate's apex
//! (`apex.rs`) keeps an inline copy of the same checks (`TODO(compress-apex)`).

pub use pico_verifier::public_values::{
    check_complete_root_public_values, recursion_public_values,
};
