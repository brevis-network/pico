//! Host-side acceptance checks on a COMPLETE recursion root proof's public values.
//!
//! Config-free, so the combine root and its embed re-proof share them. The implementation is
//! `pico_verifier::public_values`, which the standalone apex runs too.

pub use pico_verifier::public_values::{
    check_complete_root_public_values, recursion_public_values,
};
