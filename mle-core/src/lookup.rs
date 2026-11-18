//! The lookup (interaction) vocabulary shared across proving backends.
//!
//! `LookupType`/`LookupScope`/`SymbolicLookup` are what a chip's `looking()`/`looked()` calls
//! speak, so they live in `pico-mle-core` alongside the `ChipBuilder` stack. The legacy FRI
//! lowering of these into `VirtualPairCol` (`VirtualPairLookup`, `symbolic_to_virtual_pair`) stays
//! in `vm`.

use p3_field::Field;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter};

/// message type enum for lookups
///
/// Each variant is a logUp bus of the MLE backend. STABILITY: the explicit
/// discriminants enter the logUp fingerprint (`kind as u32 + 1`) and the vk's
/// trace-height-constraint ordering, and the *declaration order* enters the vk's
/// serde encoding (serde uses variant indices) — do not renumber or reorder
/// variants; only append new ones (see `lookup_type_discriminants_are_pinned`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LookupType {
    /// Interaction with the memory table, such as read and write.
    Memory = 1,

    /// Interaction with the program table, loading an instruction at a given pc address.
    Program = 2,

    /// Interaction with instruction oracle.
    Instruction = 3,

    /// Interaction with the ALU operations.
    Alu = 4,

    /// Interaction with the byte lookup table for byte operations.
    Byte = 5,

    /// Requesting a range check for a given value and range.
    Range = 6,

    /// Interaction with the field op table for field operations.
    Field = 7,

    /// Interaction with a syscall.
    Syscall = 8,

    /// Interaction with the Poseidon2.
    Poseidon2 = 9,

    /// Interaction with the global table.
    Global = 10,

    /// Interaction with the `ShaCompress` chip.
    ShaCompress = 11,

    /// Interaction with the `ShaExtend` chip.
    ShaExtend = 12,

    /// Interaction between the Cpu chip and the dedicated Ecall chip.
    Ecall = 13,

    /// State bus between `KeccakControl` (syscall + memory, one row per permutation) and the
    /// `KeccakPermute` compute AIR: two messages per permutation, `[chunk, clk, tag, 100 limbs]`
    /// with tag 0 = input state and 1 = output state (one message of both would exceed the logUp
    /// message-length limit).
    KeccakPermute = 14,

    /// Sliced Keccak chi row (`[key, out0..out4]`) against the chi table (`KeccakTables`).
    KeccakChi = 15,

    /// Sliced Keccak theta column parities (`[key, c0..c3]`) against the xor5 table
    /// (`KeccakTables`).
    KeccakXor5 = 16,

    /// The bus of the global-LogUp group proofs: each row of a committed Global event table
    /// (or of the memory image table), `[m0..m7, kind]`, with its signed multiplicity, under the
    /// block's external `(alpha, beta)`. No machine but the group machines uses it, and no AIR
    /// receives on it: the fractional sums are added up across the block's group proofs.
    GlobalLogUp = 17,
}

impl LookupType {
    /// Omits [`Self::ShaCompress`], [`Self::ShaExtend`] and [`Self::KeccakPermute`]. It now has
    /// no caller at all -- it existed for the legacy FRI
    /// verifier's per-bus cumulative-sum check, which predates those buses, and adding them there
    /// would change FRI verification.
    // TODO(fri-removal): delete with FRI.
    pub fn all_types() -> impl Iterator<Item = Self> {
        [
            Self::Memory,
            Self::Program,
            Self::Instruction,
            Self::Alu,
            Self::Byte,
            Self::Range,
            Self::Field,
            Self::Syscall,
            Self::Poseidon2,
            Self::Global,
            Self::Ecall,
        ]
        .into_iter()
    }
}

/// Index of the `kind` element in a Global-bus lookup message (8 message words, `is_send`,
/// `is_receive`, `kind`).
pub const GLOBAL_KIND_VALUE_INDEX: usize = 10;

/// Enforce, at keygen, that every Global-bus sender passes its `kind` as a compile-time constant.
/// The kind separates the domains of the cross-chunk messages (a memory event and a syscall
/// event with the same words must not cancel), and nothing in the Global AIR constrains its
/// `kind` column: the regional multiset pins it to what the senders sent. Were a sender to take
/// the kind from a column, a prover could send a syscall-side message under the memory kind.
/// Callers reduce the kind element of their own expression type to `Some(constant)` first,
/// passing `None` when it is not a constant.
///
/// `values_len` is checked because the kind is read at a fixed index: a longer message would put
/// `is_receive` there, and that IS a constant, so the guard would pass while the real kind went
/// unchecked.
pub fn assert_global_kind_is_constant<F: Field>(kind: Option<F>, values_len: usize) {
    assert_eq!(
        values_len,
        GLOBAL_KIND_VALUE_INDEX + 1,
        "Global-bus message must be exactly {} elements with the kind last",
        GLOBAL_KIND_VALUE_INDEX + 1
    );
    assert!(
        kind.is_some(),
        "Global-bus looking interaction must carry a compile-time constant kind at values \
         index {GLOBAL_KIND_VALUE_INDEX}"
    );
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Display,
    EnumIter,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
pub enum LookupScope {
    /// Global scope
    Global = 0,
    /// Regional scope
    Regional,
}

/// Bus and scope of one lookup, without its expressions -- what a machine needs to count or
/// classify a chip's lookups without lowering them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LookupSummary {
    pub kind: LookupType,
    pub scope: LookupScope,
}

/// An interaction is a cross-table lookup.
pub struct SymbolicLookup<E> {
    /// The values of the interaction.
    pub values: Vec<E>,
    /// The multiplicity of the interaction.
    pub multiplicity: E,
    /// The kind of interaction.
    pub kind: LookupType,
    /// The scope of the interaction.
    pub scope: LookupScope,
}

impl<E> SymbolicLookup<E> {
    /// Create a new [`SymbolicLookup`].
    pub const fn new(
        values: Vec<E>,
        multiplicity: E,
        kind: LookupType,
        scope: LookupScope,
    ) -> Self {
        Self {
            values,
            multiplicity,
            kind,
            scope,
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::{assert_global_kind_is_constant, LookupType, GLOBAL_KIND_VALUE_INDEX};

    /// The length every Global-bus message has, so the tests below exercise the guard's kind
    /// leg rather than its length leg.
    const LEN: usize = GLOBAL_KIND_VALUE_INDEX + 1;

    // Nothing in the Global AIR constrains its `kind` column, so the tests below cover each way
    // the guard can be defeated: a kind that is not a compile-time constant, and a message whose
    // length moves the kind out of the slot the guard reads.

    #[test]
    fn global_kind_guard_accepts_a_constant() {
        for kind in [LookupType::Memory, LookupType::Syscall] {
            assert_global_kind_is_constant(Some(KoalaBear::from_u8(kind as u8)), LEN);
        }
    }

    #[test]
    #[should_panic(expected = "must carry a compile-time constant kind")]
    fn global_kind_guard_rejects_a_non_constant_kind() {
        assert_global_kind_is_constant::<KoalaBear>(None, LEN);
    }

    /// A longer message shifts the kind out of the slot the guard reads, and what lands there
    /// (`is_receive`) is itself a constant -- so without this leg the guard would pass while the
    /// real kind went unchecked.
    #[test]
    #[should_panic(expected = "must be exactly 11 elements")]
    fn global_kind_guard_rejects_a_message_of_the_wrong_length() {
        assert_global_kind_is_constant(Some(KoalaBear::ZERO), LEN + 1);
    }

    /// The discriminants enter the MLE backend's logUp fingerprint and the vk's
    /// trace-height-constraint ordering; changing them breaks transcript/vk
    /// compatibility. Only appending new variants is allowed.
    #[test]
    fn lookup_type_discriminants_are_pinned() {
        for (kind, value) in [
            (LookupType::Memory, 1),
            (LookupType::Program, 2),
            (LookupType::Instruction, 3),
            (LookupType::Alu, 4),
            (LookupType::Byte, 5),
            (LookupType::Range, 6),
            (LookupType::Field, 7),
            (LookupType::Syscall, 8),
            (LookupType::Poseidon2, 9),
            (LookupType::Global, 10),
            (LookupType::ShaCompress, 11),
            (LookupType::ShaExtend, 12),
            (LookupType::Ecall, 13),
            (LookupType::KeccakPermute, 14),
            (LookupType::KeccakChi, 15),
            (LookupType::KeccakXor5, 16),
            (LookupType::GlobalLogUp, 17),
        ] {
            assert_eq!(kind as u16, value);
        }
    }
}
