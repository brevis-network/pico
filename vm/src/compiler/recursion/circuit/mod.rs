// Circuit twins of the outer (BN254-Poseidon2) transcript and Merkle hasher; see the module docs.
#[cfg(feature = "multi-field-transcript")]
pub mod outer_bn254;
pub mod utils;
// Full in-circuit twin of the MLE verifier over the outer BN254 primitives; see the module docs.
#[cfg(feature = "multi-field-transcript")]
pub mod wrap_mle;
