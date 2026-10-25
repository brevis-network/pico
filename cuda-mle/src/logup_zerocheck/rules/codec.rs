// Fixed-width integer packing of rules and their operands. The layout is deliberately simple so
// the CUDA interpreter can unpack it with a handful of shifts and masks.

use mle_core::air::symbolic::symbolic_variable::{Entry, SymbolicVariable};
use p3_field::{Field, PrimeField32};

use super::{Rule, RuleWithFlag, Source};

/// Round-trip conversion between a value and its packed integer form.
pub trait Codec {
    type Encoded;

    fn encode(&self) -> Self::Encoded;

    #[allow(unused)]
    fn decode(encoded: Self::Encoded) -> Self
    where
        Self: Sized;
}

// Reserved 4-bit source codes 0..=5. These mirror the CUDA `EntryType` enum
// (`cuda/include/codec.cuh`) byte-for-byte and must stay in sync with it. `ENTRY_PERMUTATION`
// and `ENTRY_EXPOSED` are no longer produced (the corresponding `Entry` variants were removed
// from mle-core), but the code space stays reserved so `ENTRY_CHALLENGE == 4` keeps its wire value —
// `gkr_input.cu`'s `case ENTRY_CHALLENGE` keys on exactly that byte.
const ENTRY_PREPROCESSED: u64 = 0;
const ENTRY_MAIN: u64 = 1;
#[allow(dead_code)]
const ENTRY_PERMUTATION: u64 = 2;
const ENTRY_PUBLIC: u64 = 3;
const ENTRY_CHALLENGE: u64 = 4;
const ENTRY_EXPOSED: u64 = 5;

// An `Entry` fits in the low 16 bits.
impl Codec for Entry {
    type Encoded = u64;

    fn encode(&self) -> u64 {
        let (tag, part, off) = match self {
            Entry::Preprocessed { offset } => (ENTRY_PREPROCESSED, 0, *offset),
            Entry::Main { part_index, offset } => (ENTRY_MAIN, *part_index, *offset),
            Entry::Public => (ENTRY_PUBLIC, 0, 0),
        };
        // bits [0,4) tag, [4,12) part index, [12,16) row offset
        assert!(tag < 16);
        assert!(part < 256);
        assert!(off < 16);
        tag | (part << 4) as u64 | (off << 12) as u64
    }

    fn decode(encoded: u64) -> Self {
        // inverse of `encode`: tag in bits 0..4, part index in 4..12, row offset in 12..16
        let tag = encoded & 0x0f;
        let part = ((encoded >> 4) & 0xff) as usize;
        let off = ((encoded >> 12) & 0x0f) as usize;
        match tag {
            ENTRY_PREPROCESSED => Entry::Preprocessed { offset: off },
            ENTRY_MAIN => Entry::Main {
                part_index: part,
                offset: off,
            },
            ENTRY_PUBLIC => Entry::Public,
            // PERMUTATION (2) / CHALLENGE (4) / EXPOSED (5) are no longer `Entry` variants:
            // mle-core no longer has them, and challenges now decode to `Source::Challenge`
            // one level up (in `Source::decode`) rather than as a `SymbolicVariable`.
            _ => panic!(
                "cannot decode Entry (tag={} part_index={} offset={})",
                tag, part, off
            ),
        }
    }
}

// A `SymbolicVariable` fits in the low 32 bits.
impl<F: Field> Codec for SymbolicVariable<F> {
    type Encoded = u64;

    fn encode(&self) -> u64 {
        let tag_bits = self.entry.encode();
        let slot_in_part = self.index as u64;

        assert!(tag_bits <= 0xffff);
        assert!(slot_in_part <= 0xffff);
        // entry in the low half-word, column index in the next
        const INDEX_SHIFT: u64 = 16;
        tag_bits | (slot_in_part << INDEX_SHIFT)
    }

    fn decode(encoded: u64) -> Self {
        // entry in the low half-word, column index in the next
        const ENTRY_BITS_MASK: u64 = 0xffff;
        const INDEX_SHIFT: u64 = 16;
        let ent = Entry::decode(encoded & ENTRY_BITS_MASK);
        let col = (encoded >> INDEX_SHIFT) as usize;
        Self::new(ent, col)
    }
}

// Codes 0..=5 belong to `Source::Var`; the remaining sources are numbered after them.
const SRC_INTERMEDIATE: u64 = ENTRY_EXPOSED + 1;
const SRC_CONSTANT: u64 = SRC_INTERMEDIATE + 1;
const SRC_IS_FIRST: u64 = SRC_CONSTANT + 1;
const SRC_IS_LAST: u64 = SRC_IS_FIRST + 1;
const SRC_IS_TRANSITION: u64 = SRC_IS_LAST + 1;

// A `Source` takes at most 48 bits; its kind always sits in the lowest 4 bits.
impl<F: Field + PrimeField32> Codec for Source<F> {
    type Encoded = u64;

    fn encode(&self) -> u64 {
        match self {
            Source::IsFirst => SRC_IS_FIRST,
            Source::IsLast => SRC_IS_LAST,
            Source::IsTransition => SRC_IS_TRANSITION,
            Source::Constant(val) => {
                // kind in the low 16 bits, canonical u32 value above it
                const VALUE_SHIFT: u64 = 16;
                // go through the canonical representative (no direct u32 accessor here)
                let canon = val.as_canonical_u32();

                SRC_CONSTANT | ((canon as u64) << VALUE_SHIFT)
            }
            Source::Var(v) => v.encode(),
            // Byte-identical to the legacy `Source::Var(SymbolicVariable{ Entry::Challenge, i })`
            // encoding (`CHALLENGE | (i << 16)`): 4-bit src = CHALLENGE, index in bits 16.., no
            // part/offset. Keeps the CUDA `d_rules` stream unchanged.
            Source::Challenge(i) => {
                const CHALLENGE_INDEX_SHIFT: u64 = 16;
                debug_assert!(*i <= 0xffff, "challenge index exceeds 16-bit wire field");
                ENTRY_CHALLENGE | ((*i as u64) << CHALLENGE_INDEX_SHIFT)
            }
            Source::Intermediate(slot) => {
                // kind in bits 0..4, slot number (20 bits) above it
                const SLOT_SHIFT: u64 = 4;
                const SLOT_MASK: u64 = 0xf_ffff; // 20 bits
                SRC_INTERMEDIATE | (((*slot as u64) & SLOT_MASK) << SLOT_SHIFT)
            }
            Source::TerminalIntermediate => SRC_INTERMEDIATE,
        }
    }

    // Note: terminal intermediates are not distinguished at this level. Encoding a
    // Source::TerminalIntermediate and decoding it yields a Source::Intermediate.
    fn decode(encoded: u64) -> Self {
        const KIND_MASK: u64 = 0xf; // low 4 bits
        match encoded & KIND_MASK {
            SRC_IS_FIRST => Source::IsFirst,
            SRC_IS_LAST => Source::IsLast,
            SRC_IS_TRANSITION => Source::IsTransition,
            SRC_CONSTANT => {
                // kind in the low 16 bits, canonical u32 value above it
                const VALUE_SHIFT: u64 = 16;
                Source::Constant(F::from_u32((encoded >> VALUE_SHIFT) as u32))
            }
            ENTRY_CHALLENGE => {
                const CHALLENGE_INDEX_SHIFT: u64 = 16;
                Source::Challenge((encoded >> CHALLENGE_INDEX_SHIFT) as usize)
            }
            // Only PREPROCESSED (0) | MAIN (1) | PUBLIC (3) are produced as real symbolic
            // variables now; PERMUTATION (2) / EXPOSED (5) are never emitted.
            ENTRY_PREPROCESSED | ENTRY_MAIN | ENTRY_PUBLIC => {
                Source::Var(SymbolicVariable::decode(encoded))
            }
            SRC_INTERMEDIATE => {
                const SLOT_SHIFT: u64 = 4;
                const SLOT_MASK: u64 = 0xf_ffff; // 20 bits
                Source::Intermediate(((encoded >> SLOT_SHIFT) & SLOT_MASK) as usize)
            }
            _ => unreachable!(),
        }
    }
}

const OPCODE_ADD: u8 = 0;
const OPCODE_SUB: u8 = 1;
const OPCODE_MUL: u8 = 2;
const OPCODE_NEG: u8 = 3;
const OPCODE_VAR: u8 = 4;

const IN_OPERAND_MASK: u64 = (1 << 48) - 1; // low 48 bits
const OUT_OPERAND_MASK: u64 = (1 << 24) - 1; // low 24 bits

impl<F: Field + PrimeField32> Codec for RuleWithFlag<F> {
    type Encoded = u128;

    // From the least significant bit up: lhs (48) | rhs (48) | dst (24) | opcode (6) |
    // writes-slot flag (1) | accumulate flag (1).
    fn encode(&self) -> u128 {
        let filler = Source::Constant(F::ZERO);
        let (lhs, rhs, dst, opcode, writes_slot) = match &self.inner {
            Rule::Add(a, b, d) => (
                a.encode(),
                b.encode(),
                d.encode(),
                OPCODE_ADD,
                !matches!(d, Source::TerminalIntermediate),
            ),
            Rule::Sub(a, b, d) => (
                a.encode(),
                b.encode(),
                d.encode(),
                OPCODE_SUB,
                !matches!(d, Source::TerminalIntermediate),
            ),
            Rule::Mul(a, b, d) => (
                a.encode(),
                b.encode(),
                d.encode(),
                OPCODE_MUL,
                !matches!(d, Source::TerminalIntermediate),
            ),
            // unary: the unused rhs operand is padded with a zero constant
            Rule::Neg(a, d) => (
                a.encode(),
                filler.encode(),
                d.encode(),
                OPCODE_NEG,
                !matches!(d, Source::TerminalIntermediate),
            ),
            Rule::Variable(a) => (
                a.encode(),
                filler.encode(),
                filler.encode(),
                OPCODE_VAR,
                false,
            ),
            Rule::BufferVar(a, d) => (a.encode(), filler.encode(), d.encode(), OPCODE_VAR, true),
        };

        let lhs = lhs & IN_OPERAND_MASK; // 48 bits
        let rhs = rhs & IN_OPERAND_MASK; // 48 bits
        let dst = dst & OUT_OPERAND_MASK; // 24 bits

        (lhs as u128)
            | ((rhs as u128) << 48)
            | ((dst as u128) << 96)
            | ((opcode as u128) << 120)
            | ((writes_slot as u128) << 126)
            | ((self.need_accumulate as u128) << 127)
    }

    fn decode(encoded: u128) -> Self {
        let raw_lhs = encoded & (IN_OPERAND_MASK as u128); // 48 bits
        let raw_rhs = (encoded >> 48) & (IN_OPERAND_MASK as u128); // 48 bits
        let raw_dst = (encoded >> 96) & (OUT_OPERAND_MASK as u128); // 24 bits

        let lhs = Source::decode(raw_lhs as u64);
        let rhs = Source::decode(raw_rhs as u64);
        let writes_slot = (encoded >> 126) & 1 == 1;
        let dst = if writes_slot {
            Source::decode(raw_dst as u64)
        } else {
            Source::TerminalIntermediate
        };
        let opcode = (encoded >> 120) as u8 & 0x3F; // 6 bits
        let acc = (encoded >> 127) & 1 == 1;

        let rule = match opcode {
            OPCODE_ADD => Rule::Add(lhs, rhs, dst),
            OPCODE_SUB => Rule::Sub(lhs, rhs, dst),
            OPCODE_MUL => Rule::Mul(lhs, rhs, dst),
            OPCODE_NEG => Rule::Neg(lhs, dst),
            OPCODE_VAR => {
                if writes_slot {
                    Rule::BufferVar(lhs, dst)
                } else {
                    Rule::Variable(lhs)
                }
            }
            _ => panic!(
                "cannot decode rule: opcode={} raw lhs/rhs/dst={}/{}/{}, lhs={:?} rhs={:?} dst={:?}",
                opcode, raw_lhs, raw_rhs, raw_dst, lhs, rhs, dst
            ),
        };

        Self {
            inner: rule,
            need_accumulate: acc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::F;

    /// The GKR LogUp challenge β used to encode as
    /// `Source::Var(SymbolicVariable{ Entry::Challenge, i })`, whose wire byte was
    /// `Entry::Challenge.encode() | (i << 16) = CHALLENGE(4) | (i << 16)`.
    /// `Entry::Challenge` was removed from mle-core, so the challenge now lives in
    /// cuda-mle's own `Source::Challenge(i)`. The CUDA interpreter is unchanged — it still
    /// keys on `ENTRY_CHALLENGE == 4` and reads `d_challenges[src.index]` — so the new
    /// encoding MUST reproduce that exact byte. This test pins the wire contract.
    #[test]
    fn challenge_source_wire_byte_matches_legacy_entry_challenge() {
        const CHALLENGE_INDEX_SHIFT: u64 = 16;
        for i in [0usize, 1, 2, 7, 255, 4096, 0xffff] {
            let expected_legacy_byte = ENTRY_CHALLENGE | ((i as u64) << CHALLENGE_INDEX_SHIFT);
            let encoded = Source::<F>::Challenge(i).encode();
            assert_eq!(
                encoded, expected_legacy_byte,
                "Source::Challenge({i}) wire byte drifted from the legacy Entry::Challenge encoding"
            );
            // Low 4 bits must be exactly ENTRY_CHALLENGE for gkr_input.cu's switch.
            assert_eq!(encoded & 0xf, ENTRY_CHALLENGE);
            // Round-trips back to a challenge with the same index.
            match Source::<F>::decode(encoded) {
                Source::Challenge(j) => assert_eq!(j, i, "challenge index round-trip mismatch"),
                other => panic!("Source::decode of a challenge byte gave {other:?}"),
            }
        }
    }

    /// Real symbolic-variable sources (`Preprocessed`/`Main`/`Public`) must NOT be mistaken
    /// for a challenge, and vice versa — the 4-bit discriminants stay disjoint.
    #[test]
    fn var_sources_do_not_collide_with_challenge() {
        let public = Source::<F>::Var(SymbolicVariable::new(Entry::Public, 3));
        assert_ne!(public.encode() & 0xf, ENTRY_CHALLENGE);
        match Source::<F>::decode(public.encode()) {
            Source::Var(v) => assert_eq!(v.entry, Entry::Public),
            other => panic!("expected Var, got {other:?}"),
        }
    }
}
