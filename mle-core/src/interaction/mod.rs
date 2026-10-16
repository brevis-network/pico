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
    /// at most 12, far below the field characteristic p, so the bus label folded into
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
