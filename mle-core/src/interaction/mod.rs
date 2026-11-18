use p3_field::Field;
use p3_util::log2_ceil_usize;
use serde::{Deserialize, Serialize};

use crate::{air::symbolic::symbolic_expression::SymbolicExpression, lookup::LookupType};

/// Interaction debugging tools
pub mod debug;

/// A logUp bus interaction, recorded during keygen by the builders' `LookupBuilder` impls:
/// `looking` records `(+multiplicity, count_weight = 1)` and `looked` records
/// `(-multiplicity, count_weight = 0)`, so each bus's fractional sum cancels iff the
/// queries are a sub-multiset of the keys.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Interaction<Expr> {
    pub message: Vec<Expr>,
    pub count: Expr,
    /// The lookup kind specifying the bus to send the message over. Discriminants are
    /// at most 17, far below the field characteristic p, so the bus label folded into
    /// the logUp fingerprint can never wrap around.
    pub kind: LookupType,
    /// Determines the contribution of each interaction message to a linear constraint on the trace
    /// heights in the verifier.
    ///
    /// For each bus index and trace, `count_weight` values are summed per interaction on that
    /// bus index and multiplied by the trace height. The total sum over all traces is constrained
    /// by the verifier to not overflow the field characteristic \( p \).
    ///
    /// This is used to impose sufficient conditions for bus constraint soundness and setting a
    /// proper value depends on the bus and the constraint it imposes.
    pub count_weight: u32,
}

pub type SymbolicInteraction<F> = Interaction<SymbolicExpression<F>>;

/// Parameters to ensure sufficient soundness of the LogUp part of the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct LogUpSecurityParameters {
    /// A bound on the total number of interactions.
    /// Determines a constraint at keygen that is checked by the verifier.
    pub max_interaction_count: u32,
    /// A bound on the base-2 logarithm of the length of the longest interaction. Checked in
    /// keygen.
    pub log_max_message_length: u32,
    /// The number of proof-of-work bits for the LogUp proof-of-work phase.
    pub pow_bits: usize,
    /// Where the LogUp challenges come from. It is part of the verifying key (the params are in
    /// the vk pre-hash), and the key is the only place a prover or verifier reads it from.
    ///
    /// Absent from a self-describing encoding (the JSON manifests written before the field
    /// existed), it is the internal mode, which is what every machine was then.
    #[serde(default)]
    pub challenge_mode: LogUpChallengeMode,
}

/// Where a proof's LogUp challenges `(alpha, beta)` come from, and with that what its GKR root
/// has to be.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogUpChallengeMode {
    /// The proof draws them from its own transcript after the LogUp proof of work, and its
    /// fractional sum must be zero. Every machine but the global-LogUp group machines.
    #[default]
    Internal,
    /// The caller hands them in and the proof absorbs them: no LogUp proof of work, nothing
    /// sampled. The fractional sum is not asserted zero; the proof carries its numerator
    /// (`GkrProof::p0_claim`) and the verifier returns the pair `(p0, q0)` for the caller to
    /// add up across proofs that share the challenges.
    ///
    /// The prover knows the challenges before it commits the common main trace, so a machine in
    /// this mode must not let that trace into an interaction: its interactions read cached main
    /// columns only, which were committed before the challenges existed.
    External,
}

impl LogUpSecurityParameters {
    /// The number of bits of security with grinding.
    pub fn bits_of_security<F: Field>(&self) -> u32 {
        let log_order = u32::try_from(F::order().bits() - 1).unwrap();
        log_order
            - log2_ceil_usize(2 * self.max_interaction_count as usize) as u32  // multiply by two to account for the poles as well
            - self.log_max_message_length
            + u32::try_from(self.pow_bits).unwrap()
    }
    pub fn max_message_length(&self) -> usize {
        2usize
            .checked_pow(self.log_max_message_length)
            .expect("max_message_length overflowed usize")
    }
}
