//! The Keccak-f permutation constraints of `p3_keccak_air::KeccakAir`, held here so the theta step
//! can be regrouped into a smaller constraint DAG.
//!
//! [`eval_keccak`] is `KeccakAir::eval` with one shape change. It keeps every constraint
//! polynomial, and therefore the same zero set, while sharing more DAG nodes:
//!
//! - theta_4 asserts `E[x][z] + A'[y][x][z]·W[x][z]` in place of `xor3(A', C, C')`, where
//!   `E[x][z] = xor(C'[x][z], C[x][z])` and `W[x][z] = 1 - double(E[x][z])` are both hoisted out of
//!   the `y` loop so the five `y` share them. `xor(u, v)` is `u + v - u·double(v)`, so
//!   `E + A'·(1 - double(E))` is `xor(A', E)`, and `xor3` expands to a symmetric polynomial in its
//!   three operands, so this is `xor3(A', C, C')` term by term. Two nodes per bit rather than the
//!   six the upstream spelling needs. `xor` doubles its second operand and theta_2 already doubles
//!   `C[x][z]` for all 320 `(x, z)`, so `E` reuses that node, and `W` consumes `double(E)`: two
//!   expressions per `(x, z)` stay live across the `y` loop.
//!
//! Rewriting the `A'` boolean check as `(1 - a')·a'` to share the chi step's `1 - a'` node saves
//! a further 1600 rules and is deliberately not done: the shared node stays live from theta_4 to
//! chi, which raises the rule interpreter's live-intermediate buffer from 2350 to 3694 slots,
//! crosses its temporary budget and serialises the x loop in two passes, for a net 3.2% slower
//! round-0 zerocheck, measured on the `xor(A', E)` spelling of theta_4 (a sweep of this file's
//! theta spellings).
//!
//! The column layout is the local `columns::KeccakCols`: the upstream layout without `preimage`,
//! because the chip exports the permutation input from the first step (where it is `a`) instead of
//! carrying a copy across the 24 rows (`constraint.rs`). The 200 upstream constraints that pinned
//! that copy are the only ones missing here; the trace rows still come from the upstream generator,
//! projected onto the local layout. The tests below pin the shape against the upstream evaluator.

use core::{array, borrow::Borrow};

use p3_air::{AirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{NUM_ROUNDS, NUM_ROUNDS_MIN_1, RC, U64_LIMBS};

use super::columns::KeccakCols;

/// Number of bits in each limb used to represent 64-bit words. `p3_keccak_air` keeps its own copy
/// private, so it is rederived from the public limb count.
const BITS_PER_LIMB: usize = 64 / U64_LIMBS;

/// Bit `i` of the round constant of round `round`. `p3_keccak_air::rc_value_bit` reads a private
/// table holding exactly these bits for all 24 x 64 entries.
const fn rc_bit(round: usize, i: usize) -> bool {
    (RC[round] >> i) & 1 == 1
}

/// Round flags: the first row starts the schedule and every transition rotates it forward, so
/// exactly one flag is active per row.
fn eval_round_flags<AB: AirBuilder>(builder: &mut AB) {
    let main = builder.main();
    let local: &KeccakCols<AB::Var> = main.current_slice().borrow();
    let next: &KeccakCols<AB::Var> = main.next_slice().borrow();

    // In the first row, the first flag is 1 and all others are 0.
    builder.when_first_row().assert_one(local.step_flags[0]);
    builder
        .when_first_row()
        .assert_zeros::<NUM_ROUNDS_MIN_1, _>(local.step_flags[1..].try_into().unwrap());

    // In all transitions, flag `i` of the local row equals flag `(i + 1) % NUM_ROUNDS` of the next.
    builder
        .when_transition()
        .assert_zeros::<NUM_ROUNDS, _>(array::from_fn(|i| {
            local.step_flags[i] - next.step_flags[(i + 1) % NUM_ROUNDS]
        }));
}

/// Assumes the field size is at least 16 bits.
pub(super) fn eval_keccak<AB: AirBuilder>(builder: &mut AB) {
    eval_round_flags(builder);

    let main = builder.main();
    let local: &KeccakCols<AB::Var> = main.current_slice().borrow();
    let next: &KeccakCols<AB::Var> = main.next_slice().borrow();

    let final_step = local.step_flags[NUM_ROUNDS_MIN_1];
    let not_final_step = AB::Expr::ONE - final_step;

    // Upstream pins a `preimage` copy of the input to `a` on the first step and carries it across
    // the cycle (200 constraints). This layout has no `preimage`: the chip exports the input from
    // the first step's `a` directly (`constraint.rs`).

    // The export flag must be 0 or 1.
    builder.assert_bool(local.export);

    // If this is not the final step, the export flag must be off.
    builder
        .when(not_final_step.clone())
        .assert_zero(local.export);

    // C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
    // Note that if all entries of C are boolean, the arithmetic generalization
    // xor3 function only outputs 0, 1 and so this check also ensures that all
    // entries of C'[x, z] are boolean.
    for x in 0..5 {
        builder.assert_bools(local.c[x]);
        builder.assert_zeros::<64, _>(array::from_fn(|z| {
            let xor = local.c[x][z].into().xor3(
                &local.c[(x + 4) % 5][z].into(),
                &local.c[(x + 1) % 5][(z + 63) % 64].into(),
            );
            local.c_prime[x][z] - xor
        }));
    }

    // Check that the input limbs are consistent with A' and D.
    // A[x, y, z] = xor(A'[x, y, z], D[x, y, z])
    //            = xor(A'[x, y, z], C[x - 1, z], C[x + 1, z - 1])
    //            = xor(A'[x, y, z], C[x, z], C'[x, z])
    //            = xor(A'[x, y, z], E[x, z])
    //            = E[x, z] + A'[x, y, z]·W[x, z],
    // where E[x, z] = xor(C'[x, z], C[x, z]) and W[x, z] = 1 - double(E[x, z]). The third step is
    // valid based on the identity we checked above, the fourth on the associativity of the
    // arithmetic xor, the fifth by expanding xor(u, v) = u + v - u·double(v). Neither E nor W
    // depends on y, so both are built once for all five y.
    // We also check that all entries of A' are bools.
    // This has the side effect of also range checking the limbs of A.
    let e: [[AB::Expr; 64]; 5] = array::from_fn(|x| {
        array::from_fn(|z| {
            let c_prime: AB::Expr = local.c_prime[x][z].into();
            let c: AB::Expr = local.c[x][z].into();
            c_prime.xor(&c)
        })
    });
    let w: [[AB::Expr; 64]; 5] =
        array::from_fn(|x| array::from_fn(|z| AB::Expr::ONE - e[x][z].double()));
    for y in 0..5 {
        for x in 0..5 {
            let get_bit =
                |z: usize| e[x][z].clone() + local.a_prime[y][x][z].into() * w[x][z].clone();

            // Check that all entries of A'[y][x] are boolean.
            builder.assert_bools(local.a_prime[y][x]);

            builder.assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
                let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                    .rev()
                    .fold(AB::Expr::ZERO, |acc, z| {
                        // Check to ensure all entries of A' are bools.
                        acc.double() + get_bit(z)
                    });
                computed_limb - local.a[y][x][limb]
            }));
        }
    }

    // xor_{i=0}^4 A'[x, i, z] = C'[x, z], so for each x, z,
    // diff * (diff - 2) * (diff - 4) = 0, where
    // diff = sum_{i=0}^4 A'[x, i, z] - C'[x, z]
    for x in 0..5 {
        let four = AB::Expr::TWO.double();
        builder.assert_zeros::<64, _>(array::from_fn(|z| {
            let sum: AB::Expr = (0..5).map(|y| local.a_prime[y][x][z].into()).sum();
            let diff = sum - local.c_prime[x][z];
            diff.clone() * (diff.clone() - AB::Expr::TWO) * (diff - four.clone())
        }));
    }

    // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
    // As B is a rotation of A', all entries must be bools and so
    // this check also range checks A''.
    for y in 0..5 {
        for x in 0..5 {
            let get_bit = |z| {
                let andn = local
                    .b((x + 1) % 5, y, z)
                    .into()
                    .andn(&local.b((x + 2) % 5, y, z).into());
                andn.xor(&local.b(x, y, z).into())
            };
            builder.assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
                let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                    .rev()
                    .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_bit(z));
                computed_limb - local.a_prime_prime[y][x][limb]
            }));
        }
    }

    // A'''[0, 0] = A''[0, 0] XOR RC
    // Check to ensure the bits of A''[0, 0] are boolean.
    builder.assert_bools(local.a_prime_prime_0_0_bits);
    builder.assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
        let computed_a_prime_prime_0_0_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
            .rev()
            .fold(AB::Expr::ZERO, |acc, z| {
                acc.double() + local.a_prime_prime_0_0_bits[z]
            });
        computed_a_prime_prime_0_0_limb - local.a_prime_prime[0][0][limb]
    }));

    let get_xored_bit = |i| {
        let mut rc_bit_i = AB::Expr::ZERO;
        for r in 0..NUM_ROUNDS {
            let this_round = local.step_flags[r];
            let this_round_constant = AB::Expr::from_bool(rc_bit(r, i));
            rc_bit_i += this_round * this_round_constant;
        }

        rc_bit_i.xor(&local.a_prime_prime_0_0_bits[i].into())
    };

    builder.assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
        let computed_a_prime_prime_prime_0_0_limb = (limb * BITS_PER_LIMB
            ..(limb + 1) * BITS_PER_LIMB)
            .rev()
            .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_xored_bit(z));
        computed_a_prime_prime_prime_0_0_limb - local.a_prime_prime_prime_0_0_limbs[limb]
    }));

    // Enforce that this round's output equals the next round's input.
    for x in 0..5 {
        for y in 0..5 {
            builder
                .when_transition()
                .when(not_final_step.clone())
                .assert_zeros::<U64_LIMBS, _>(array::from_fn(|limb| {
                    local.a_prime_prime_prime(y, x, limb) - next.a[y][x][limb]
                }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chips::{
            precompiles::keccak256::{
                columns::{NUM_KECCAK_MEM_COLS, NUM_KECCAK_PERM_COLS},
                KeccakPermuteChip,
            },
            tests::reachable_constraint_nodes,
        },
        primitives::consts::MAX_NUM_PVS,
    };
    use core::borrow::BorrowMut;
    use p3_air::{Air, RowWindow};

    use p3_keccak_air::{
        generate_trace_rows, KeccakAir, KeccakCols as UpstreamKeccakCols, NUM_KECCAK_COLS,
    };
    use p3_koala_bear::KoalaBear;
    use pico_mle_core::{
        air::symbolic::{get_symbolic_builder_with_public_values, SymbolicConstraintsDag},
        keygen::types::TraceWidth,
    };
    use rand::{rngs::SmallRng, RngExt, SeedableRng};

    type F = KoalaBear;

    /// An `AirBuilder` that evaluates over field values and records every assertion in call order.
    ///
    /// None of `assert_zeros` / `assert_bools` / `assert_one` / `assert_eq` / `assert_bool` is
    /// overridden: their default implementations all route through `assert_zero`, so what is
    /// recorded is the value of the constraint polynomial itself.
    struct RecordingBuilder<'a> {
        main: RowWindow<'a, F>,
        preprocessed: RowWindow<'a, F>,
        is_first_row: F,
        is_last_row: F,
        is_transition: F,
        out: Vec<F>,
    }

    impl<'a> AirBuilder for RecordingBuilder<'a> {
        type F = F;
        type Expr = F;
        type Var = F;
        type PreprocessedWindow = RowWindow<'a, F>;
        type MainWindow = RowWindow<'a, F>;
        type PublicVar = F;

        fn main(&self) -> Self::MainWindow {
            self.main
        }

        fn preprocessed(&self) -> &Self::PreprocessedWindow {
            &self.preprocessed
        }

        fn is_first_row(&self) -> Self::Expr {
            self.is_first_row
        }

        fn is_last_row(&self) -> Self::Expr {
            self.is_last_row
        }

        fn is_transition_window(&self, size: usize) -> Self::Expr {
            assert_eq!(size, 2, "only a two-row window is supported");
            self.is_transition
        }

        fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
            self.out.push(x.into());
        }
    }

    /// Which of the two evaluators a [`RecordingBuilder`] run drives.
    enum Evaluator {
        Upstream,
        Local,
    }

    fn record(
        current: &[F],
        next: &[F],
        is_first_row: F,
        is_last_row: F,
        is_transition: F,
        evaluator: Evaluator,
    ) -> Vec<F> {
        let empty: [F; 0] = [];
        let mut builder = RecordingBuilder {
            main: RowWindow::from_two_rows(current, next),
            preprocessed: RowWindow::from_two_rows(&empty, &empty),
            is_first_row,
            is_last_row,
            is_transition,
            out: Vec::new(),
        };
        match evaluator {
            Evaluator::Upstream => KeccakAir {}.eval(&mut builder),
            Evaluator::Local => eval_keccak(&mut builder),
        }
        builder.out
    }

    // Constraint counts per section of the evaluator, in emission order. Each line names the
    // section that emits it; the sum is checked against the recorded length below.
    /// Round flags: one `assert_one` plus `NUM_ROUNDS - 1` on the first row, `NUM_ROUNDS` on
    /// transitions.
    const ROUND_FLAG_CONSTRAINTS: usize = 1 + NUM_ROUNDS_MIN_1 + NUM_ROUNDS;
    /// Upstream only: `preimage == a` on the first step, then `preimage` carried across the
    /// cycle, 25 words each. The local layout has no `preimage`, so these are the constraints the
    /// local evaluator does not emit.
    const PREIMAGE_CONSTRAINTS: usize = 2 * 25 * U64_LIMBS;
    /// The upstream constraint list minus its preimage block, which is what the local evaluator
    /// must reproduce.
    fn without_preimage(up: &[F]) -> Vec<F> {
        let mut v = up.to_vec();
        v.drain(ROUND_FLAG_CONSTRAINTS..ROUND_FLAG_CONSTRAINTS + PREIMAGE_CONSTRAINTS);
        v
    }
    /// Projects an upstream row (`NUM_KECCAK_COLS` wide) onto the local layout.
    fn project(row: &[F]) -> Vec<F> {
        let src: &UpstreamKeccakCols<F> = row.borrow();
        let mut out = vec![F::ZERO; NUM_KECCAK_PERM_COLS];
        let dst: &mut KeccakCols<F> = out.as_mut_slice().borrow_mut();
        dst.copy_from_upstream(src);
        out
    }
    /// `export` is boolean, and off outside the final step.
    const EXPORT_CONSTRAINTS: usize = 2;
    /// Per `x`: 64 `C` booleans followed by 64 `C'` equations.
    const THETA_C_CONSTRAINTS: usize = 5 * (64 + 64);
    /// Constraints emitted before the first `(y, x)` block of the `A'` step.
    const A_PRIME_START: usize =
        ROUND_FLAG_CONSTRAINTS + PREIMAGE_CONSTRAINTS + EXPORT_CONSTRAINTS + THETA_C_CONSTRAINTS;
    /// Each `(y, x)` block emits 64 `A'` booleans followed by `U64_LIMBS` limb equations.
    const A_PRIME_BLOCK: usize = 64 + U64_LIMBS;
    /// All of the above plus theta_5 (`5 * 64`), chi (`25 * U64_LIMBS`), iota (64 bit booleans and
    /// two groups of `U64_LIMBS` limb equations) and the round link (`25 * U64_LIMBS`).
    const TOTAL_CONSTRAINTS: usize = A_PRIME_START
        + 25 * A_PRIME_BLOCK
        + 5 * 64
        + 25 * U64_LIMBS
        + (64 + 2 * U64_LIMBS)
        + 25 * U64_LIMBS;

    /// The local evaluator, run on the projected rows, emits the same constraints as
    /// `KeccakAir::eval` minus the 200 preimage constraints, in the same order and with the same
    /// values: theta_4's regrouping is a polynomial identity and dropping `preimage` removes
    /// exactly that block.
    #[test]
    fn keccak_local_eval_matches_upstream() {
        let mut rng = SmallRng::seed_from_u64(20250918);
        let inputs: Vec<[u64; 25]> = (0..2).map(|_| array::from_fn(|_| rng.random())).collect();
        let trace = generate_trace_rows::<F>(inputs, 0);
        let height = trace.values.len() / NUM_KECCAK_COLS;

        // Honest rows: the upstream AIR is satisfied and the local one agrees constraint by
        // constraint (both families evaluate to zero there).
        for i in 0..height {
            let j = (i + 1) % height;
            let current = &trace.values[i * NUM_KECCAK_COLS..(i + 1) * NUM_KECCAK_COLS];
            let next = &trace.values[j * NUM_KECCAK_COLS..(j + 1) * NUM_KECCAK_COLS];
            let is_first_row = F::from_bool(i == 0);
            let is_last_row = F::from_bool(i + 1 == height);
            let is_transition = F::ONE - is_last_row;

            let up = record(
                current,
                next,
                is_first_row,
                is_last_row,
                is_transition,
                Evaluator::Upstream,
            );
            assert_eq!(up.len(), TOTAL_CONSTRAINTS);
            assert!(
                up.iter().all(|v| *v == F::ZERO),
                "row {i} does not satisfy the upstream AIR"
            );
            let loc = record(
                &project(current),
                &project(next),
                is_first_row,
                is_last_row,
                is_transition,
                Evaluator::Local,
            );
            assert_eq!(loc, without_preimage(&up), "row {i}");
        }

        // Perturbed rows: arbitrary field values and selectors, so the arithmetic generalizations
        // of xor / andn leave {0, 1} and every constraint is compared as a polynomial.
        for round in 0..8 {
            let current: Vec<F> = (0..NUM_KECCAK_COLS)
                .map(|_| F::from_u32(rng.random()))
                .collect();
            let next: Vec<F> = (0..NUM_KECCAK_COLS)
                .map(|_| F::from_u32(rng.random()))
                .collect();
            let is_first_row = F::from_u32(rng.random());
            let is_last_row = F::from_u32(rng.random());
            let is_transition = F::from_u32(rng.random());

            let up = record(
                &current,
                &next,
                is_first_row,
                is_last_row,
                is_transition,
                Evaluator::Upstream,
            );
            let loc = record(
                &project(&current),
                &project(&next),
                is_first_row,
                is_last_row,
                is_transition,
                Evaluator::Local,
            );
            assert_eq!(up.len(), TOTAL_CONSTRAINTS, "round {round}");
            assert_eq!(loc.len(), up.len() - PREIMAGE_CONSTRAINTS, "round {round}");

            // The boolean family is upstream's own, so every constraint compares equal. A
            // perturbed row leaves the arithmetic xor's {0, 1} range, so a theta_4 limb equation
            // that reads the wrong cell, or regroups into a different polynomial, shows up here.
            // A regrouping that keeps the polynomial but changes the DAG shape - swapping the two
            // operands of an xor, say - is invisible to this test and is what the rule-count pin
            // below is for.
            assert_eq!(loc, without_preimage(&up), "round {round}");
        }
    }

    /// Pins the zerocheck rule count of `KeccakPermuteChip`: one rule per DAG node reachable from
    /// the constraint roots. A different expression shape changes this number.
    #[test]
    fn keccak_permute_reachable_rule_count() {
        let width = TraceWidth {
            preprocessed: None,
            cached_mains: vec![],
            common_main: NUM_KECCAK_MEM_COLS,
        };
        let builder = get_symbolic_builder_with_public_values::<F, _>(
            &KeccakPermuteChip::<F>::default(),
            &width,
            MAX_NUM_PVS,
        );
        let constraints = builder.constraints();
        // The round-0 zerocheck coset count is `max_constraint_degree - 1`, and the riscv machine
        // rejects an AIR above `RISCV_MAX_CONSTRAINT_DEGREE`; the interaction count fixes the
        // LogUp side. Neither is reachable from the constraint roots, so the rule count below
        // would not notice a change in either.
        assert_eq!(constraints.max_constraint_degree(), 3);
        assert_eq!(constraints.interactions.len(), 2);
        let dag: SymbolicConstraintsDag<F> = constraints.into();
        assert_eq!(reachable_constraint_nodes(&dag.constraints), 33420);
    }
}
