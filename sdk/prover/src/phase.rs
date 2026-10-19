//! The phase chain, as a value.

use serde::{Deserialize, Serialize};

/// A stopping point in the proving chain — the `--step` vocabulary of `vm/examples/test_mle_e2e.rs`.
///
/// All five variants exist on every build. Only the implementations are feature- and
/// branch-gated, so a caller can always *name* a phase in order to be told it is unavailable:
/// [`Phase::Embed`] and [`Phase::Wrap`] return [`crate::ProveError::FeatureMissing`] without
/// `multi-field-transcript`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Phase {
    /// One proof per emulation chunk, verified against a key derived from the ELF.
    Riscv,
    /// Each RISC-V chunk proof wrapped in a recursion proof.
    Convert,
    /// The convert proofs tree-reduced to one complete root. What [`crate::Prover::prove`] returns.
    Combine,
    /// The complete root re-proved under the outer BN254-hashed config.
    Embed,
    /// The embed-proof verifier emitted as a gnark circuit plus its witness.
    Wrap,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Phase::Riscv => "riscv",
            Phase::Convert => "convert",
            Phase::Combine => "combine",
            Phase::Embed => "embed",
            Phase::Wrap => "wrap",
        };
        f.write_str(s)
    }
}

impl Phase {
    /// Refuses a phase this build cannot prove, so a caller can ask before spending keygen on it:
    /// [`Phase::Embed`] and [`Phase::Wrap`] need `multi-field-transcript`.
    pub fn ensure_available(self) -> Result<(), crate::ProveError> {
        if !cfg!(feature = "multi-field-transcript") && matches!(self, Phase::Embed | Phase::Wrap) {
            return Err(crate::ProveError::FeatureMissing {
                phase: self,
                feature: "multi-field-transcript",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CLI's `--phase` values and proof file names are these spellings, and
    /// [`crate::Proof::binds_complete_execution`] reads the order.
    #[test]
    fn phases_display_and_order_as_the_chain_runs() {
        let chain = [
            Phase::Riscv,
            Phase::Convert,
            Phase::Combine,
            Phase::Embed,
            Phase::Wrap,
        ];
        let names: Vec<String> = chain.iter().map(Phase::to_string).collect();
        assert_eq!(names, ["riscv", "convert", "combine", "embed", "wrap"]);
        assert!(chain.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
