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
//! For BabyBear and KoalaBear the modulus satisfies `(p - 1) % 2^16 == 0`, so writing
//! `TOP_LIMB = (p - 1) >> 16` gives
//!
//! ```text
//!   value < p   <=>   value[2] == value[3] == 0
//!                     AND ( value[1] < TOP_LIMB
//!                           OR (value[1] == TOP_LIMB AND value[0] == 0) )
//! ```
//!
//! Mersenne31 does not satisfy that divisibility (`p - 1 = 0x7FFF_FFFE`), so its final
//! case is `value[0] != 0xFFFF` instead of `value[0] == 0`.
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
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

/// Columns needed to prove that a `Word` is a canonical field element.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct FieldWordRangeChecker<T> {
    /// `1` iff `value[1] < TOP_LIMB`.
    pub ms_limb_lt_top: T,

    /// Mersenne31 only: the inverse witnessing `value[0] != 0xFFFF` on the rows where the
    /// most significant limb is maxed, i.e. `is_real * (1 - ms_limb_lt_top) / (value[0] -
    /// 0xFFFF)`.
    ///
    /// BabyBear and KoalaBear close that case with a plain `value[0] == 0` assertion and
    /// need no witness, so there the column is pinned to zero rather than left free.
    pub low_limb_not_max_inv: T,
}

/// `(p - 1) >> 16`, the largest value the most significant u16 limb may take.
fn top_limb<F: Field + FieldBehavior>() -> u16 {
    match F::field_type() {
        // 2^31 - 2^27 + 1 => (p - 1) >> 16 == 0x7800
        FieldType::TypeBabyBear => 0x7800,
        // 2^31 - 2^24 + 1 => (p - 1) >> 16 == 0x7F00
        FieldType::TypeKoalaBear => 0x7F00,
        // 2^31 - 1 => (p - 1) >> 16 == 0x7FFF
        FieldType::TypeMersenne31 => 0x7FFF,
        _ => unimplemented!("Unsupported field type"),
    }
}

impl<F: Field + FieldBehavior> FieldWordRangeChecker<F> {
    /// `value` is the full 64-bit operand; only its low 32 bits may be non-zero for the
    /// constraints to be satisfiable.
    pub fn populate(&mut self, record: &mut impl ByteRecordBehavior, value: u64) {
        let top = top_limb::<F>();
        let ms_limb = ((value >> 16) & 0xFFFF) as u16;
        let ls_limb = (value & 0xFFFF) as u16;

        let lt = ms_limb < top;
        self.ms_limb_lt_top = F::from_bool(lt);
        // `ms_limb - top + lt * 2^16` as a u16; the wrapping subtraction produces exactly
        // that in both branches.
        record.add_u16_range_check(ms_limb.wrapping_sub(top));

        // Only reached with `is_real = 1` (the caller sets the gate in the same branch that
        // calls this), so the `eval` side's `is_real * (1 - ms_limb_lt_top)` is just `!lt`.
        // On the `lt` rows that product is zero, and the witness has to be zero with it --
        // supplying the inverse there would assert `1 == 0`.
        self.low_limb_not_max_inv = if F::field_type() == FieldType::TypeMersenne31 && !lt {
            (F::from_canonical_u16(ls_limb) - F::from_canonical_u16(u16::MAX))
                .try_inverse()
                .unwrap_or(F::ZERO)
        } else {
            F::ZERO
        };
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
        let top = CB::F::from_canonical_u16(top_limb::<F>());

        // Everything below is gated on `is_real`, so a non-boolean gate would leave the
        // whole gadget saying nothing. The only caller derives `is_real` from a product of
        // two `IsZero` results, which is boolean only by an argument spanning three files;
        // asserting it here makes the guarantee local and unconditional.
        builder.assert_bool(is_real.clone());

        // The value must fit in 32 bits.
        builder.when(is_real.clone()).assert_zero(value[2]);
        builder.when(is_real.clone()).assert_zero(value[3]);

        // `ms_limb_lt_top` is the boolean result of `value[1] < TOP_LIMB`. The range check
        // on `value[1] - TOP_LIMB + bit * 2^16` is only satisfiable for the correct bit:
        // if `value[1] < TOP_LIMB` the difference is negative and needs the `+2^16` to land
        // back in u16; if it is `>= TOP_LIMB` the difference is already a u16 and adding
        // `2^16` would overflow the range.
        // Gated on `is_real`: `OpcodeSpecificCols` is a union, and on non-ecall rows these
        // columns alias much smaller views (`JumpCols`/`AuipcCols` are `PhantomData`), so
        // an ungated assertion would start failing the moment any sibling view grows.
        // The gate costs nothing.
        builder
            .when(is_real.clone())
            .assert_bool(cols.ms_limb_lt_top);
        let diff = value[1].into() - top + cols.ms_limb_lt_top * CB::F::from_canonical_u32(1 << 16);
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
        builder.when(is_top.clone()).assert_eq(value[1], top);

        match F::field_type() {
            FieldType::TypeBabyBear | FieldType::TypeKoalaBear => {
                // `p - 1 == TOP_LIMB * 2^16`, so once the top limb is maxed the low limb
                // must be zero.
                builder.when(is_top).assert_zero(value[0]);
                // The Mersenne31 witness is unused here. Pin it so it is not a free column.
                builder.assert_zero(cols.low_limb_not_max_inv);
            }
            FieldType::TypeMersenne31 => {
                // `p == 0x7FFF_FFFF`, so the single forbidden combination is
                // `value[1] == 0x7FFF && value[0] == 0xFFFF`.
                //
                // `witness * (value[0] - 0xFFFF) == is_top` says exactly that: where
                // `is_top` is one the difference must be invertible, hence non-zero; where
                // it is zero the product is zero and the honest witness is zero too. Both
                // sides are degree 2, which keeps this a degree-2 constraint.
                builder.assert_eq(
                    cols.low_limb_not_max_inv
                        * (value[0].into() - CB::F::from_canonical_u16(u16::MAX)),
                    is_top,
                );
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
        machine::{folder::DebugConstraintFolder, septic::SepticDigest},
    };
    use p3_field::PrimeField32;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::{dense::RowMajorMatrixView, stack::VerticalPair};

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
        let empty_ef: [EF; 0] = [];

        let mut builder = DebugConstraintFolder::<F, EF> {
            preprocessed: VerticalPair::new(
                RowMajorMatrixView::new_row(&empty_f),
                RowMajorMatrixView::new_row(&empty_f),
            ),
            main: VerticalPair::new(
                RowMajorMatrixView::new_row(&empty_f),
                RowMajorMatrixView::new_row(&empty_f),
            ),
            permutation: VerticalPair::new(
                RowMajorMatrixView::new_row(&empty_ef),
                RowMajorMatrixView::new_row(&empty_ef),
            ),
            permutation_challenges: [EF::ZERO; 2],
            regional_cumulative_sum: EF::ZERO,
            global_cumulative_sum: SepticDigest::<F>::zero(),
            is_first_row: F::ZERO,
            is_last_row: F::ZERO,
            is_transition: F::ONE,
            public_values: &empty_f,
            failures: Vec::new(),
            scopes: Vec::new(),
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
        let top = F::from_canonical_u16(top_limb::<F>());
        let expected = word[1] - top + cols.ms_limb_lt_top * F::from_canonical_u32(1 << 16);
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
