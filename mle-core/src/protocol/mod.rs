//! Protocol-level types: proof struct, codec (Encode/Decode), the stacked layout shared by prover
//! and verifier, and a proof's wire size from its shape.

pub mod codec;
pub mod proof;
pub mod proof_size;
pub mod stacking;
