//! Range check that a `Word` holds a value below the field modulus.
//!
//! # History
//!
//! This gadget used to be the RV32 version: it decomposed the *most significant byte of a
//! u32* (bits 24..31) into 8 bits and asserted the recomposition equalled `value[3]`. That
//! was correct while `Word` was 4 × u8 limbs. In this RV64 fork `Word` is 4 × **u16**
//! limbs, so `value[3]` is bits 48..63 — a completely different field. The file even
//! carried a `#[deprecated]` note saying so.
//!
//! The consequences were:
//!
//! * **completeness** — the trace populated from bits 24..31 while the AIR compared
//!   against bits 48..63, so the constraint read `bits(24..31) == bits(48..63)`. Any HALT
//!   with an exit code ≥ 2^24 became unprovable.
//! * **soundness** — for every operand below 2^48 the check collapsed to `0 == 0`, so it
//!   never actually bounded anything.
//!
//! # Current formulation
//!
//! The KoalaBear modulus satisfies `(p - 1) % 2^16 == 0`, so writing
//! `TOP_LIMB = (p - 1) >> 16` gives
//!
//! ```text
//!   value < p   <=>   value[2] == value[3] == 0
//!                     AND ( value[1] < TOP_LIMB
//!                           OR (value[1] == TOP_LIMB AND value[0] == 0) )
//! ```
//!
//! The `value[1] < TOP_LIMB` decision uses the standard one-bit trick: `bit` is boolean
//! and `value[1] - TOP_LIMB + bit * 2^16` is range checked as a u16, which is only
//! satisfiable when `bit` is the true comparison result.

use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    compiler::{riscv::opcode::ByteOpcode, word::Word},
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder},
        field::{FieldBehavior, FieldType},
    },
};
use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};
use pico_derive::AlignedBorrow;

/// Columns needed to prove that a `Word` is a canonical field element.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct FieldWordRangeChecker<T> {
    /// `1` iff `value[1] < TOP_LIMB`.
    pub ms_limb_lt_top: T,

    /// Vestigial: the witness a Mersenne31 base field needed to rule out `value[0] == 0xFFFF`
    /// on the rows where the most significant limb is maxed. KoalaBear closes that case with a
    /// plain `value[0] == 0` assertion and needs no witness, so the column is pinned to zero
    /// rather than left free.
    pub low_limb_not_max_inv: T,
}

/// `(p - 1) >> 16`, the largest value the most significant u16 limb may take.
fn top_limb<F: Field + FieldBehavior>() -> u16 {
    match F::field_type() {
        // 2^31 - 2^24 + 1 => (p - 1) >> 16 == 0x7F00
        FieldType::TypeKoalaBear => 0x7F00,
        _ => unimplemented!("Unsupported field type"),
    }
}

impl<F: Field + FieldBehavior> FieldWordRangeChecker<F> {
    /// The byte event `range_check`'s lookup needs, without the column population.
    ///
    /// Split out because a chip whose trace generator banks byte events in a pass separate from
    /// column filling (`EcallChip::extra_record`, and its GPU kernel) has to emit this from that
    /// other pass. Only the event's value is shared — each caller still writes its own gate, and
    /// getting either wrong is a bus imbalance at prove time, not a compile error.
    pub fn range_check_event(record: &mut impl ByteRecordBehavior, value: u64) {
        let top = top_limb::<F>();
        let ms_limb = ((value >> 16) & 0xFFFF) as u16;
        // `ms_limb - top + lt * 2^16` as a u16; the wrapping subtraction produces exactly
        // that in both branches.
        record.add_u16_range_check(ms_limb.wrapping_sub(top));
    }

    /// `value` is the full 64-bit operand; only its low 32 bits may be non-zero for the
    /// constraints to be satisfiable.
    pub fn populate(&mut self, record: &mut impl ByteRecordBehavior, value: u64) {
        let top = top_limb::<F>();
        let ms_limb = ((value >> 16) & 0xFFFF) as u16;

        self.ms_limb_lt_top = F::from_bool(ms_limb < top);
        Self::range_check_event(record, value);

        // Pinned to zero by the `eval` side.
        self.low_limb_not_max_inv = F::ZERO;
    }
}

impl<F: Field + FieldBehavior> FieldWordRangeChecker<F> {
    /// Constrains that `value` represents a canonical field element.
    ///
    /// Constrains that `is_real` is boolean. Assumes `value` is a valid `Word` of u16
    /// limbs -- see the note on that assumption in the module header.
    pub fn range_check<CB: ChipBuilder<F>>(
        builder: &mut CB,
        value: Word<CB::Var>,
        cols: FieldWordRangeChecker<CB::Var>,
        is_real: CB::Expr,
    ) {
        // Everything below is gated on `is_real`, so a non-boolean gate would leave the
        // whole gadget saying nothing. The only caller derives `is_real` from a product of
        // two `IsZero` results, which is boolean only by an argument spanning three files;
        // asserting it here makes the guarantee local and unconditional.
        builder.assert_bool(is_real.clone());

        // The value must fit in 32 bits.
        builder.when(is_real.clone()).assert_zero(value[2]);
        builder.when(is_real.clone()).assert_zero(value[3]);

        // The comparison itself, over the two limbs that carry the value.
        //
        // Emission order matters beyond readability: the per-AIR digests in
        // `vm/tests/riscv_constraint_dump.txt` are taken over the vk's serialized
        // `symbolic_constraints`, so moving an assertion across this call would change the
        // Ecall AIR's digest and turn the cross-branch parity gate red for no semantic reason.
        // The three assertions above therefore stay here, ahead of the delegation, exactly
        // where they were when this body was one function.
        Self::range_check_u32_limbs::<CB>(builder, value[0].into(), value[1].into(), cols, is_real);
    }

    /// The `value < p` comparison for a 32-bit value supplied as its two u16 limbs.
    ///
    /// **Assumes `is_real` is already constrained boolean** -- unlike [`Self::range_check`],
    /// which asserts it. Split out for callers whose value is *structurally* 32 bits and who
    /// already gate on a column they have asserted boolean themselves: a precompile reading one
    /// half of a dword has no limbs 2 and 3 to bound, and passing literal zeros to
    /// [`Self::range_check`] would spend two constraints per call asserting that a literal is
    /// zero. The poseidon2 precompile makes 32 such calls per row.
    ///
    /// `ls_limb` is bits 0..15, `ms_limb` bits 16..31. Both are assumed to be u16 -- the caller
    /// range checks them (a precompile's memory-value limbs already are, via
    /// `slice_range_check_u16`). Without that this bounds nothing: the comparison reasons about
    /// `ms_limb` alone, so an out-of-range `ls_limb` would slip through.
    pub fn range_check_u32_limbs<CB: ChipBuilder<F>>(
        builder: &mut CB,
        ls_limb: CB::Expr,
        ms_limb: CB::Expr,
        cols: FieldWordRangeChecker<CB::Var>,
        is_real: CB::Expr,
    ) {
        let top = CB::F::from_u16(top_limb::<F>());

        // `ms_limb_lt_top` is the boolean result of `ms_limb < TOP_LIMB`. The range check
        // on `ms_limb - TOP_LIMB + bit * 2^16` is only satisfiable for the correct bit:
        // if `ms_limb < TOP_LIMB` the difference is negative and needs the `+2^16` to land
        // back in u16; if it is `>= TOP_LIMB` the difference is already a u16 and adding
        // `2^16` would overflow the range.
        // Gated on `is_real`, like everything else in this gadget: the caller only populates
        // `cols` on the rows its gate selects (`riscv_ecall/traces.rs`, the HALT and
        // COMMIT_DEFERRED_PROOFS branches), so an ungated assertion would be a claim about rows
        // the gadget is not being asked to say anything about. The gate costs nothing.
        // (The comment here used to justify the gate by an aliasing hazard in a
        // `OpcodeSpecificCols` union holding `JumpCols`/`AuipcCols`; none of those types exist
        // any more -- these columns are the Ecall chip's own.)
        builder
            .when(is_real.clone())
            .assert_bool(cols.ms_limb_lt_top);
        let diff = ms_limb.clone() - top + cols.ms_limb_lt_top * CB::F::from_u32(1 << 16);
        builder.looking_rangecheck(
            ByteOpcode::U16Range,
            diff,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            is_real.clone(),
        );

        // If the most significant limb is not strictly below the top, it must equal it.
        let is_top = is_real * (CB::Expr::ONE - cols.ms_limb_lt_top);
        builder.when(is_top.clone()).assert_eq(ms_limb, top);

        match F::field_type() {
            FieldType::TypeKoalaBear => {
                // `p - 1 == TOP_LIMB * 2^16`, so once the top limb is maxed the low limb
                // must be zero.
                builder.when(is_top).assert_zero(ls_limb);
                // Vestigial column. Pin it so it is not a free column.
                builder.assert_zero(cols.low_limb_not_max_inv);
            }
            _ => unimplemented!("Unsupported field type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chips::chips::byte::event::ByteLookupEvent,
        configs::{config::StarkGenericConfig, stark_config::KoalaBearPoseidon2},
        machine::{debug_folder::DebugConstraintFolder, septic::SepticDigest},
    };
    use p3_air::RowWindow;
    use p3_field::PrimeField32;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = <KoalaBearPoseidon2 as StarkGenericConfig>::Challenge;

    /// Minimal `ByteRecordBehavior` sink so `populate` can be driven standalone.
    #[derive(Default)]
    struct Blu(Vec<ByteLookupEvent>);
    impl crate::chips::chips::byte::event::ByteRecordBehavior for Blu {
        fn add_byte_lookup_event(&mut self, e: ByteLookupEvent) {
            self.0.push(e);
        }
    }

    /// Returns `true` if the gadget's constraints are satisfiable for `value`.
    fn accepts(value: u64) -> bool {
        let mut cols = FieldWordRangeChecker::<F>::default();
        let mut blu = Blu::default();
        cols.populate(&mut blu, value);

        let word: Word<F> = Word::from(value);
        let empty_f: [F; 0] = [];

        let mut builder = DebugConstraintFolder::<F, EF> {
            preprocessed: RowWindow::from_two_rows(&empty_f, &empty_f),
            main: RowWindow::from_two_rows(&empty_f, &empty_f),
            global_cumulative_sum: SepticDigest::<F>::zero(),
            is_first_row: F::ZERO,
            is_last_row: F::ZERO,
            is_transition: F::ONE,
            public_values: &empty_f,
            failures: Vec::new(),
            scopes: Vec::new(),
            // Only this branch's folder carries it, so upstream's copy of this test omits it.
            constraint_count: 0,
        };

        FieldWordRangeChecker::<F>::range_check(&mut builder, word, cols, F::ONE);

        // The u16 range check is a lookup, not an assertion, so `builder.failures` cannot
        // see it -- `DebugConstraintFolder` is an `EmptyLookupBuilder`. Two things are
        // checked here instead:
        //
        //  1. the value `populate` actually recorded equals the `diff` the AIR's formula
        //     produces. This is the failure mode that matters: if the two sides disagree
        //     the lookup is unmatchable and the proof dies at `verifier.rs:391`.
        //  2. that `diff` lies in `[0, 2^16)`. Outside it no byte-table row exists, so the
        //     lookup can never be satisfied however the rest of the trace is filled.
        //
        // Caveat: this recomputes the formula rather than observing the AIR's emitted
        // tuple, so it does not catch an edit to the `diff` expression in `range_check`
        // itself. Doing that needs a builder that collects lookups instead of ignoring them.
        let top = F::from_u16(top_limb::<F>());
        let expected = word[1] - top + cols.ms_limb_lt_top * F::from_u32(1 << 16);
        let recorded: Vec<u32> = blu
            .0
            .iter()
            .filter(|e| e.opcode == ByteOpcode::U16Range)
            .map(|e| ((e.b as u32) << 8) | e.c as u32)
            .collect();
        let diff_ok = recorded.len() == 1
            && recorded[0] == expected.as_canonical_u32()
            && recorded[0] < (1 << 16);

        builder.failures.is_empty() && diff_ok
    }

    /// The gadget must accept exactly the canonical field elements.
    ///
    /// Before the u16 port it compared bits 24..31 against bits 48..63, which rejected
    /// every operand in `[2^24, 2^48)` (completeness) and accepted everything below 2^48
    /// unconditionally (soundness).
    #[test]
    fn field_word_range_check_accepts_exactly_canonical_values() {
        let p = u64::from(<F as p3_field::PrimeField32>::ORDER_U32);

        let accept = [
            0u64,
            1,
            0xFF,
            0xFFFF,
            0x1_0000,
            // the value that used to break completeness
            1 << 24,
            (1 << 24) + 12345,
            0x7EFF_FFFF,
            p - 1,
        ];
        for v in accept {
            assert!(
                accepts(v),
                "should accept canonical value {v:#x} (p = {p:#x})"
            );
        }

        let reject = [
            p,
            p + 1,
            0x7FFF_FFFF,
            0xFFFF_FFFF,
            // must not fit in 32 bits
            1u64 << 32,
            0xFFFF_FFFF_FFFF_FFFF,
        ];
        for v in reject {
            assert!(
                !accepts(v),
                "should reject non-canonical value {v:#x} (p = {p:#x})"
            );
        }
    }
}
