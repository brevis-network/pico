//! Standalone apex verification: accept a root combine proof from nothing but shipped artifacts.
//!
//! The implementation lives in `pico_verifier::apex`, which builds on stable Rust; `MleVkMap`
//! plugs into it through `pico_verifier::whitelist::VkWhitelist`.

pub use pico_verifier::apex::MleApexVerifier;
