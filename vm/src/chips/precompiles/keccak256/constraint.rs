use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakAir, NUM_ROUNDS, U64_LIMBS};

use super::{
    columns::{KeccakMemCols, NUM_KECCAK_PERM_COLS},
    p3_eval, KeccakPermuteChip, KECCAK_STATE_BUS_INPUT_TAG, KECCAK_STATE_BUS_OUTPUT_TAG,
    STATE_SIZE,
};
use crate::machine::{
    builder::{ChipBuilder, SubAirBuilder},
    lookup::{LookupScope, LookupType, SymbolicLookup},
};

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for KeccakPermuteChip<F> {
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();

        let (local, next) = (main.current_slice(), main.next_slice());
        let local: &KeccakMemCols<CB::Var> = (*local).borrow();
        let next: &KeccakMemCols<CB::Var> = (*next).borrow();

        let first_step = local.keccak.step_flags[0];
        let final_step = local.keccak.step_flags[NUM_ROUNDS - 1];
        let not_final_step = CB::Expr::ONE - final_step;

        // The syscall receive, the address gadgets and the state memory accesses live in
        // `KeccakControlChip` (one row per permutation). What is left here is the p3 permutation
        // AIR plus the state bus that ties the two together.
        builder.assert_bool(local.is_real);

        // The state bus fires exactly once per real permutation, on its final step. p3 already
        // constrains `export` to be boolean and zero off the final step; this pins it on the final
        // step too, so a dummy permutation (`is_real = 0`) never sends.
        builder.assert_eq(local.keccak.export, final_step * local.is_real);

        // The input is exported from the first step, where `a` is the permutation input; the
        // flag is pinned the same way, so it fires exactly once per real permutation and never
        // on a dummy one. The round flags put exactly one first step and one final step in every
        // 24-row cycle, and `chunk / clk / is_real` are copied across the cycle below, so the
        // input and the output message of a permutation carry the same key.
        builder.assert_eq(local.export_in, first_step * local.is_real);

        // Constrain that the inputs stay the same throughout the 24 rows of each cycle
        let mut transition_builder = builder.when_transition();
        let mut transition_not_final_builder = transition_builder.when(not_final_step);
        transition_not_final_builder.assert_eq(local.chunk, next.chunk);
        transition_not_final_builder.assert_eq(local.clk, next.clk);
        transition_not_final_builder.assert_eq(local.is_real, next.is_real);

        // The last row must be nonreal because NUM_ROUNDS is not a power of 2. This constraint
        // ensures that the table does not end abruptly.
        builder.when_last_row().assert_zero(local.is_real);

        // Receive the permutation's input (on the first step) and output (on the final step) from
        // the control AIR, as two tagged messages `[chunk, clk, tag, 100 limbs]` (a single message
        // would exceed the logUp message-length limit of 128). Word `i` of the state (memory
        // `state_addr + 8 * i`) is `(y, x) = (i / 5, i % 5)` in the p3 y-major layout; each word
        // is 4 u16 limbs. On the first step `a` is the permutation input and on the final step
        // `a'''` is the permutation output; both are pinned to u16 limbs by the p3 bit
        // decompositions (theta_4 for `a`), which is what makes the control side's memory values
        // u16 too. The two messages of one permutation share the `(chunk, clk)` key, which the
        // syscall bus makes unique per control row.
        let mut input: Vec<CB::Expr> = Vec::with_capacity(3 + STATE_SIZE * U64_LIMBS);
        input.push(local.chunk.into());
        input.push(local.clk.into());
        input.push(CB::Expr::from_u32(KECCAK_STATE_BUS_INPUT_TAG));
        let mut output: Vec<CB::Expr> = Vec::with_capacity(3 + STATE_SIZE * U64_LIMBS);
        output.push(local.chunk.into());
        output.push(local.clk.into());
        output.push(CB::Expr::from_u32(KECCAK_STATE_BUS_OUTPUT_TAG));
        for i in 0..STATE_SIZE {
            let (y, x) = (i / 5, i % 5);
            for limb in 0..U64_LIMBS {
                input.push(local.keccak.a[y][x][limb].into());
                output.push(local.keccak.a_prime_prime_prime(y, x, limb).into());
            }
        }
        builder.looked(SymbolicLookup::new(
            input,
            local.export_in.into(),
            LookupType::KeccakPermute,
            LookupScope::Regional,
        ));
        builder.looked(SymbolicLookup::new(
            output,
            local.keccak.export.into(),
            LookupType::KeccakPermute,
            LookupScope::Regional,
        ));

        let mut sub_builder =
            SubAirBuilder::<CB, KeccakAir, CB::Var>::new(builder, 0..NUM_KECCAK_PERM_COLS);

        // Eval the keccak permutation air. `KeccakAir` is the `SubAir` type parameter only (its
        // own width is the upstream 2633 and is not read); the column window is the local
        // permutation layout given by the range above.
        p3_eval::eval_keccak(&mut sub_builder);
    }
}
