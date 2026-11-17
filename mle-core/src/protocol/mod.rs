//! Protocol-level types: proof struct, codec (Encode/Decode), the stacked layout shared by prover
//! and verifier, a proof's wire size from its shape, and its multiproof wire form.

pub mod codec;
pub mod multiproof;
pub mod proof;
pub mod proof_size;
pub mod stacking;
