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

/// Exclusive bound on a Global-bus `kind`. The global-interaction digest packs the kind above a
/// 25-bit message element (`values[0] + kind * 2^25`), and this bound keeps the sum under 2^30:
/// (2^25 - 1) + 31 * 2^25 = 2^30 - 1 < p. Comfortably sufficient rather than tight.
pub const GLOBAL_KIND_LIMIT: u8 = 32;

/// Enforce, at keygen, the invariant that the Global chip's `kind` column rests on now that its
/// range check is gone: every Global-bus sender passes a compile-time constant kind below
/// [`GLOBAL_KIND_LIMIT`], so the multiset pins the receiver's column. Callers reduce the kind
/// element of their own expression type to `Some(constant)` first, passing `None` when it is not
/// a constant.
///
/// `values_len` is checked because the kind is read at a fixed index: a longer message would put
/// `is_receive` there, and that IS a bounded constant, so the guard would pass while the real kind
/// went unchecked. The digest gadget takes exactly 8 message words, so the layout is fixed.
pub fn assert_global_kind_is_bounded_constant<F: Field>(kind: Option<F>, values_len: usize) {
    assert_eq!(
        values_len,
        GLOBAL_KIND_VALUE_INDEX + 1,
        "Global-bus message must be exactly {} elements with the kind last",
        GLOBAL_KIND_VALUE_INDEX + 1
    );
    let kind = kind.unwrap_or_else(|| {
        panic!(
            "Global-bus looking interaction must carry a compile-time constant kind at values \
             index {GLOBAL_KIND_VALUE_INDEX} (its range check was removed on that invariant)"
        )
    });
    assert!(
        (0..GLOBAL_KIND_LIMIT).any(|k| kind == F::from_u8(k)),
        "Global-bus sender kind constant must be < {GLOBAL_KIND_LIMIT}"
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
    use super::{
        assert_global_kind_is_bounded_constant, LookupType, GLOBAL_KIND_LIMIT,
        GLOBAL_KIND_VALUE_INDEX,
    };
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_koala_bear::KoalaBear;

    /// The length every Global-bus message has, so the tests below exercise the guard's kind
    /// legs rather than its length leg.
    const LEN: usize = GLOBAL_KIND_VALUE_INDEX + 1;

    // The guard stands in for the range check the Global chip used to carry, so the tests below
    // cover each way it can be defeated -- a kind that is not a compile-time constant, a constant
    // at or above the packing budget, and a message whose length moves the kind out of the slot
    // the guard reads -- alongside a positive test that every admissible constant is accepted.

    #[test]
    fn global_kind_guard_accepts_every_admissible_constant() {
        for k in 0..GLOBAL_KIND_LIMIT {
            assert_global_kind_is_bounded_constant(Some(KoalaBear::from_u8(k)), LEN);
        }
    }

    #[test]
    #[should_panic(expected = "must carry a compile-time constant kind")]
    fn global_kind_guard_rejects_a_non_constant_kind() {
        assert_global_kind_is_bounded_constant::<KoalaBear>(None, LEN);
    }

    #[test]
    #[should_panic(expected = "must be < 32")]
    fn global_kind_guard_rejects_a_constant_at_the_budget() {
        assert_global_kind_is_bounded_constant(
            Some(KoalaBear::from_u32(GLOBAL_KIND_LIMIT as u32)),
            LEN,
        );
    }

    /// A longer message shifts the kind out of the slot the guard reads, and what lands there
    /// (`is_receive`) is itself a bounded constant -- so without this leg the guard would pass
    /// while the real kind went unchecked.
    #[test]
    #[should_panic(expected = "must be exactly 11 elements")]
    fn global_kind_guard_rejects_a_message_of_the_wrong_length() {
        assert_global_kind_is_bounded_constant(Some(KoalaBear::ZERO), LEN + 1);
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
        ] {
            assert_eq!(kind as u16, value);
        }
    }

    /// The global-interaction digest packs the interaction kind above a 25-bit message element
    /// (`values[0] + kind * 2^25`). The budget we hold ourselves to is a 5-bit kind, keeping the
    /// sum under 2^30: (2^25 - 1) + 31 * 2^25 = 2^30 - 1. The modulus alone would permit more, so
    /// this is the declared bound rather than a hard one -- but it is the bound keygen enforces
    /// and the one the CUDA mirror documents, so a new kind past it must fail loudly here.
    #[test]
    fn lookup_type_kinds_fit_the_global_digest_packing() {
        /// Exclusive upper bound on the kind discriminant imposed by the bit-25 packing.
        const KIND_LIMIT: u32 = GLOBAL_KIND_LIMIT as u32;
        // Every variant, including the two `all_types()` omits for legacy-FRI compatibility. The
        // exhaustive `match` below makes the compiler fail this test when a variant is appended,
        // so a new kind cannot slip past the budget check.
        let all = [
            LookupType::Memory,
            LookupType::Program,
            LookupType::Instruction,
            LookupType::Alu,
            LookupType::Byte,
            LookupType::Range,
            LookupType::Field,
            LookupType::Syscall,
            LookupType::Poseidon2,
            LookupType::Global,
            LookupType::ShaCompress,
            LookupType::ShaExtend,
            LookupType::Ecall,
            LookupType::KeccakPermute,
        ];
        for kind in all {
            // Exhaustiveness guard: adding a variant breaks this `match` until it is listed above.
            match kind {
                LookupType::Memory
                | LookupType::Program
                | LookupType::Instruction
                | LookupType::Alu
                | LookupType::Byte
                | LookupType::Range
                | LookupType::Field
                | LookupType::Syscall
                | LookupType::Poseidon2
                | LookupType::Global
                | LookupType::ShaCompress
                | LookupType::ShaExtend
                | LookupType::Ecall
                | LookupType::KeccakPermute => {}
            }
            assert!(
                (kind as u32) < KIND_LIMIT,
                "LookupType::{kind:?} = {} does not fit the global-digest packing budget \
                 (must be < {KIND_LIMIT}); widening it requires re-deriving the packing shift \
                 in the Global interaction gadget and its CUDA mirror",
                kind as u32,
            );
        }
        // The worst case must stay inside the field: max value + max kind shifted.
        let max_packed = ((1u64 << 25) - 1) + (KIND_LIMIT as u64 - 1) * (1u64 << 25);
        let koala_bear_modulus = u64::from(p3_koala_bear::KoalaBear::ORDER_U32);
        assert!(
            max_packed < koala_bear_modulus,
            "packing budget exceeds the field"
        );
    }
}
