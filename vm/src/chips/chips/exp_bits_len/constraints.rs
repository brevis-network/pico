use crate::machine::builder::{ChipBuilder, RecursionBuilder};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use std::borrow::Borrow;

use super::{
    assert_koalabear_field, ExpBitsLenChip, ExpBitsLenCols, ExpBitsLenPreprocessedCols,
    LOW_BITS_COUNT, NUM_BITS_MAX_PLUS_ONE, NUM_EXP_BITS_LEN_COLS,
};

impl<F> BaseAir<F> for ExpBitsLenChip<F> {
    fn width(&self) -> usize {
        NUM_EXP_BITS_LEN_COLS
    }
}

impl<F: PrimeField32> ExpBitsLenChip<F> {
    pub fn eval_exp_bits_len<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &ExpBitsLenCols<CB::Var>,
        prep_local: &ExpBitsLenPreprocessedCols<CB::Var>,
        next: &ExpBitsLenCols<CB::Var>,
        prep_next: &ExpBitsLenPreprocessedCols<CB::Var>,
    ) {
        // ── Memory I/O (values exported to the recursion memory bus) ──
        // Input: read the field element to decompose. `bit_src_in.mult` is `-1` on the first row
        // and `0` elsewhere, so this reads `local.bit_src` (the full value) exactly once.
        builder.looking_single(
            prep_local.bit_src_in.addr,
            local.bit_src,
            prep_local.bit_src_in.mult,
        );
        // Output: write the final `result`. `result_out.mult` is nonzero only on the first row,
        // where `local.result` is the reverse-product accumulator's final value.
        builder.looking_single(
            prep_local.result_out.addr,
            local.result,
            prep_local.result_out.mult,
        );
        // Output: write this row's canonical decomposition bit. The terminal row (and padding)
        // carry `mult = 0`, so only the 31 decomposition rows publish a bit.
        builder.looking_single(
            prep_local.bit_out.addr,
            local.bit_src_mod_2,
            prep_local.bit_out.mult,
        );

        // ── Booleanity (ungated) ──
        builder.assert_bool(local.apply_bit);
        builder.assert_bool(local.in_low_region);
        builder.assert_bool(local.bit_src_mod_2);
        builder.assert_bool(local.low_bits_are_zero);
        builder.assert_bool(local.high_bits_all_one);
        // `local_in_high_region = is_real - in_low_region - is_last` must be boolean. Besides
        // classifying the row, this also forces `in_low_region = 0` on the terminal row.
        let local_in_high_region: CB::Expr =
            prep_local.is_real - local.in_low_region - prep_local.is_last;
        builder.assert_bool(local_in_high_region.clone());

        // Single degree-1 transition gate (preprocessed). Equals `is_real*(1-is_last)` for the
        // well-formed preprocessed flags, but is degree 1 (not 2), so degree-2 transition
        // expressions (next.base = base^2, result = next.result*mult) stay within max_degree=4.
        // It is 0 on the last trace row (padding or terminal), so the cyclic wrap is gated off —
        // no `when_transition()` needed.
        let is_transition: CB::Expr = prep_local.is_real - prep_local.is_last;

        // ── Structural whens ──
        builder.when(local.num_bits).assert_one(local.apply_bit);
        builder
            .when(local.low_bits_left)
            .assert_one(local.in_low_region);

        // ── Exponentiation core (ungated, degree-3) ──
        // result_multiplier = base if (apply_bit && bit) else 1.
        builder.assert_eq(
            local.result_multiplier - CB::Expr::ONE,
            local.apply_bit * local.bit_src_mod_2 * (local.base - CB::Expr::ONE),
        );

        // ── is_first anchors ──
        builder
            .when(prep_local.is_first)
            .assert_one(local.in_low_region);
        builder.when(prep_local.is_first).assert_zero(local.bit_idx);
        builder
            .when(prep_local.is_first)
            .assert_eq(local.low_bits_left, CB::Expr::from_usize(LOW_BITS_COUNT));
        builder
            .when(prep_local.is_first)
            .assert_one(local.low_bits_are_zero);
        builder
            .when(prep_local.is_first)
            .assert_zero(local.high_bits_all_one);
        // Inject the program-fixed per-request constants (`base`/`num_bits` are preprocessed
        // constants, not carried on a lookup bus).
        builder
            .when(prep_local.is_first)
            .assert_eq(local.base, prep_local.base_const);
        builder
            .when(prep_local.is_first)
            .assert_eq(local.num_bits, prep_local.num_bits_const);

        // ── Terminal (is_last) anchors ──
        builder
            .when(prep_local.is_last)
            .assert_zero(local.in_low_region);
        builder.when(prep_local.is_last).assert_eq(
            local.bit_idx,
            CB::Expr::from_usize(NUM_BITS_MAX_PLUS_ONE - 1),
        );
        builder.when(prep_local.is_last).assert_zero(local.bit_src);
        builder.when(prep_local.is_last).assert_zero(local.num_bits);
        builder
            .when(prep_local.is_last)
            .assert_zero(local.apply_bit);
        builder
            .when(prep_local.is_last)
            .assert_zero(local.low_bits_left);
        builder.when(prep_local.is_last).assert_one(local.result);
        builder
            .when(prep_local.is_last)
            .assert_one(local.result_multiplier);
        // KoalaBear canonicality terminal check: reject `x >= p`, i.e. (all 7 high bits set) AND
        // (some low bit set). `x = p - 1 = 0x7F000000` stays canonical (low bits all zero).
        builder
            .when(prep_local.is_last)
            .assert_zero(local.high_bits_all_one * (CB::Expr::ONE - local.low_bits_are_zero));

        // ── Transition constraints (within a 32-row request block) ──
        // Gated by the baked preprocessed flags, equivalent to
        // `when_transition() & is_real & !is_last`.
        builder
            .when(is_transition.clone())
            .assert_eq(next.bit_idx, local.bit_idx + CB::Expr::ONE);
        builder
            .when(is_transition.clone())
            .assert_eq(next.base, local.base * local.base);
        // LSB-first halving: bit_src = 2*next.bit_src + bit_src_mod_2.
        builder.when(is_transition.clone()).assert_eq(
            local.bit_src,
            next.bit_src * CB::Expr::TWO + local.bit_src_mod_2,
        );
        builder
            .when(is_transition.clone())
            .assert_eq(next.num_bits, local.num_bits - local.apply_bit);
        builder.when(is_transition.clone()).assert_eq(
            next.low_bits_left,
            local.low_bits_left - local.in_low_region,
        );
        // Reverse product: the accumulator is threaded terminal → first, so `local.result` holds
        // `next.result * local.result_multiplier`.
        builder
            .when(is_transition.clone())
            .assert_eq(local.result, next.result * local.result_multiplier);

        // ── Canonicality region-flag updates ──
        // Gated by region flags that are zero on terminal and padding rows, so cross-block and
        // wrap-around transitions are vacuous (these need no explicit `is_transition` gate).
        builder.when(local.in_low_region).assert_eq(
            next.low_bits_are_zero,
            local.low_bits_are_zero * (CB::Expr::ONE - local.bit_src_mod_2),
        );
        builder
            .when(local_in_high_region.clone())
            .assert_eq(next.low_bits_are_zero, local.low_bits_are_zero);
        builder
            .when(local.in_low_region * next.in_low_region)
            .assert_zero(next.high_bits_all_one);
        let next_is_not_low_region: CB::Expr = prep_next.is_real - next.in_low_region;
        builder
            .when(local.in_low_region * next_is_not_low_region)
            .assert_one(next.high_bits_all_one);
        builder.when(local_in_high_region).assert_eq(
            next.high_bits_all_one,
            local.high_bits_all_one * local.bit_src_mod_2,
        );
    }
}

impl<F: PrimeField32, CB> Air<CB> for ExpBitsLenChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        assert_koalabear_field::<F>();

        let main = builder.main();
        let (local, next) = (main.current_slice(), main.next_slice());
        let local: &ExpBitsLenCols<CB::Var> = (*local).borrow();
        let next: &ExpBitsLenCols<CB::Var> = (*next).borrow();

        let prep = builder.preprocessed().clone();
        let (prep_local, prep_next) = (prep.current_slice(), prep.next_slice());
        let prep_local: &ExpBitsLenPreprocessedCols<CB::Var> = (*prep_local).borrow();
        let prep_next: &ExpBitsLenPreprocessedCols<CB::Var> = (*prep_next).borrow();

        self.eval_exp_bits_len::<CB>(builder, local, prep_local, next, prep_next);
    }
}
