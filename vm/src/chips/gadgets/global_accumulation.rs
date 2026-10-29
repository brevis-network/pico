use crate::{
    chips::gadgets::global_interaction::GlobalInteractionOperation,
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, SepticExtensionBuilder},
        septic::{FieldSepticCurve, SepticBlock, SepticCurve, SepticDigest, SepticExtension},
    },
};
use p3_air::AirBuilder;
use p3_field::{BasedVectorSpace, Field, PrimeField};
use pico_derive::AlignedBorrow;
use std::any::Any;

/// A set of columns needed to compute the global interaction elliptic curve digest.
///
/// Row `r` carries `cum` = the running sum *before* this row's point(s) (`START + Σ_{j<r} P_j`) and
/// the slope witness `lambda` of the line through `cum` and the row's interaction point. The sum
/// *after* the row is the next row's `cum`; the last row is always padding (`is_real = 0`), so its
/// `cum` is the chunk total and is what `GcsBindAir` binds to the public values.
///
/// It is critical that this struct is at the end of the main trace, as the permutation constraints
/// will be dependent on this fact. It is also critical that `cum` is at the end of this struct, for
/// the same reason.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct GlobalAccumulationOperation<T, const N: usize> {
    /// `lambda[i]`: slope of the chord from `cum[i]` to point `i` (the tangent slope when the two
    /// coincide). Zero on padding rows by trace convention (only read under `is_real`).
    pub lambda: [SepticBlock<T>; N],
    /// `cum[i]`: `(x, y)` of the running sum before point `i` is added. For `N > 1`, `cum[i + 1]`
    /// is the sum after point `i`; the sum after point `N - 1` is `next.cum[0]`.
    pub cum: [[SepticBlock<T>; 2]; N],
}

impl<T: Default, const N: usize> Default for GlobalAccumulationOperation<T, N> {
    fn default() -> Self {
        Self {
            lambda: core::array::from_fn(|_| SepticBlock::<T>::default()),
            cum: core::array::from_fn(|_| {
                [SepticBlock::<T>::default(), SepticBlock::<T>::default()]
            }),
        }
    }
}

impl<F: PrimeField, const N: usize> GlobalAccumulationOperation<F, N> {
    /// Slope of the line through `cum` and `point`: the chord slope when the x-coordinates differ,
    /// the tangent slope (doubling) when `point == cum`. Together with the A5/A6 formulas this
    /// reproduces the complete addition used by the prefix scan (`SepticCurveComplete::add`).
    /// `point == -cum` (same x, opposite y) is never produced by an honest trace (the scan would
    /// have hit the point at infinity first) and is rejected by A4 (it forces `y1 = y2`).
    ///
    /// The GPU tracegen (`global_accumulation.cuh`) mirrors this branch structure exactly.
    pub fn slope(cum: SepticCurve<F>, point: SepticCurve<F>) -> SepticExtension<F> {
        if point.x != cum.x {
            (point.y - cum.y) / (point.x - cum.x)
        } else {
            assert!(
                point.y == cum.y,
                "global accumulation: point == -cum (sum hits the point at infinity)"
            );
            F::curve_slope(&cum)
        }
    }

    /// `cum + point` computed from the slope witness, i.e. exactly what constraints A5/A6 pin.
    fn add_with_slope(
        cum: SepticCurve<F>,
        point: SepticCurve<F>,
        lambda: SepticExtension<F>,
    ) -> SepticCurve<F> {
        let x3 = lambda.square() - cum.x - point.x;
        let y3 = lambda * (cum.x - x3) - cum.y;
        SepticCurve { x: x3, y: y3 }
    }

    fn write_cum(&mut self, i: usize, cum: SepticCurve<F>) {
        self.cum[i][0] = SepticBlock::from(cum.x.0);
        self.cum[i][1] = SepticBlock::from(cum.y.0);
    }

    /// Padding row: `cum = final_digest` (the chunk total, kept constant by A7), `lambda = 0`.
    pub fn populate_dummy(&mut self, final_digest: SepticCurve<F>) {
        for i in 0..N {
            self.lambda[i] = SepticBlock::from([F::ZERO; 7]);
            self.write_cum(i, final_digest);
        }
    }

    /// Real row from a precomputed prefix sum: `cum[0] = cum` (the sum before this row's points)
    /// and `lambda[i] = slope(cum[i], points[i])`. The sum after the row is not stored here — it
    /// is the next row's `cum[0]`.
    pub fn populate_real(&mut self, cum: SepticCurve<F>, points: [SepticCurve<F>; N]) {
        let mut cum = cum;
        for i in 0..N {
            self.write_cum(i, cum);
            let lambda = Self::slope(cum, points[i]);
            self.lambda[i] = SepticBlock::from(lambda.0);
            cum = Self::add_with_slope(cum, points[i], lambda);
        }
    }
}

impl<F: Field, const N: usize> GlobalAccumulationOperation<F, N> {
    /// Constraints (N = 1; `(x1, y1) = cum`, `(x2, y2)` = interaction point, `(x3, y3) = next.cum`,
    /// `λ = lambda`):
    ///
    /// | # | constraint | gate | count | degree |
    /// |---|---|---|---|---|
    /// | A1 | `is_real · (is_real − 1) = 0` | — | 1 | 2 |
    /// | A2 | `(1 − is_real) · next.is_real = 0` | TRANS | 1 | 3 |
    /// | A3 | `cum − START = 0` | FIRST | 14 | 2 |
    /// | A4 | `λ · (x2 − x1) − (y2 − y1) = 0` | is_real | 7 | 3 |
    /// | A5 | `x3 − λ² + x1 + x2 = 0` | is_real | 7 | 3 |
    /// | A6 | `y3 − λ · (x1 − x3) + y1 = 0` | is_real | 7 | 3 |
    /// | A7 | `next.cum − cum = 0` | TRANS · (1 − is_real) | 14 | 3 |
    /// | A8 | `is_real = 0` | LAST | 1 | 2 |
    ///
    /// A1 + A2 make `is_real` a monotone prefix; A8 pins the last row as padding so every `next`
    /// reference of A5/A6 is dead there (the cyclic `next` of the last row never enters a live
    /// constraint). Hence `cum_last = START + Σ real points`, which `GcsBindAir` exposes.
    pub fn eval_accumulation<AB: ChipBuilder<F>>(
        builder: &mut AB,
        global_interaction_cols: [GlobalInteractionOperation<AB::Var>; N],
        local_is_real: [AB::Var; N],
        next_is_real: [AB::Var; N],
        local_accumulation: GlobalAccumulationOperation<AB::Var, N>,
        next_accumulation: GlobalAccumulationOperation<AB::Var, N>,
    ) where
        AB::Expr: Any,
    {
        // First, constrain the control flow regarding `is_real`.
        // A1: all `is_real` values are boolean.
        for i in 0..N {
            builder.assert_bool(local_is_real[i]);
        }

        // Within a row, `is_real[i] == 0` implies `is_real[i + 1] == 0`.
        for i in 0..N - 1 {
            builder
                .when_not(local_is_real[i])
                .assert_zero(local_is_real[i + 1]);
        }

        // A2: `is_real[N - 1] == 0` implies `next.is_real[0] == 0`.
        builder
            .when_transition()
            .when_not(local_is_real[N - 1])
            .assert_zero(next_is_real[0]);

        // A8: the last row is padding. Tracegen guarantees at least one padding row.
        builder.when_last_row().assert_zero(local_is_real[0]);

        // Next, constrain the accumulation.
        let ext = |block: &SepticBlock<AB::Var>| {
            SepticExtension::<AB::Expr>::from_basis_coefficients_fn(|i| block.0[i].into())
        };
        let ith_cum = |idx: usize| SepticCurve::<AB::Expr> {
            x: ext(&local_accumulation.cum[idx][0]),
            y: ext(&local_accumulation.cum[idx][1]),
        };
        let next_cum = SepticCurve::<AB::Expr> {
            x: ext(&next_accumulation.cum[0][0]),
            y: ext(&next_accumulation.cum[0][1]),
        };
        let ith_point = |idx: usize| SepticCurve::<AB::Expr> {
            x: ext(&global_interaction_cols[idx].x_coordinate),
            y: ext(&global_interaction_cols[idx].y_coordinate),
        };

        // A3: the first row starts from the zero digest.
        let starting_digest = SepticDigest::<AB::Expr>::zero().0;
        let first_cum = ith_cum(0);
        builder
            .when_first_row()
            .assert_septic_ext_eq(first_cum.x, starting_digest.x);
        builder
            .when_first_row()
            .assert_septic_ext_eq(first_cum.y, starting_digest.y);

        for i in 0..N {
            let current_sum = ith_cum(i);
            let next_sum = if i + 1 < N {
                ith_cum(i + 1)
            } else {
                next_cum.clone()
            };
            let point_to_add = ith_point(i);
            let lambda = ext(&local_accumulation.lambda[i]);

            // A4: λ · (x2 − x1) = y2 − y1 — λ is the slope of the chord (or tangent when P == cum).
            let x_diff = point_to_add.x.clone() - current_sum.x.clone();
            let y_diff = point_to_add.y.clone() - current_sum.y.clone();
            builder
                .when(local_is_real[i])
                .assert_septic_ext_eq(lambda.clone() * x_diff, y_diff);

            // A5: x3 = λ² − x1 − x2.
            builder.when(local_is_real[i]).assert_septic_ext_eq(
                next_sum.x.clone() + current_sum.x.clone() + point_to_add.x,
                lambda.square(),
            );

            // A6: y3 = λ · (x1 − x3) − y1.
            builder.when(local_is_real[i]).assert_septic_ext_eq(
                next_sum.y.clone() + current_sum.y.clone(),
                lambda * (current_sum.x.clone() - next_sum.x.clone()),
            );

            // A7: `is_real == 0` keeps the sum. The last point's "next" lives on the next row, so
            // that instance is gated by TRANS (the cyclic next of the last row is not a row).
            if i + 1 < N {
                builder
                    .when_not(local_is_real[i])
                    .assert_septic_ext_eq(next_sum.x, current_sum.x);
                builder
                    .when_not(local_is_real[i])
                    .assert_septic_ext_eq(next_sum.y, current_sum.y);
            } else {
                builder
                    .when_transition()
                    .when_not(local_is_real[i])
                    .assert_septic_ext_eq(next_sum.x, current_sum.x);
                builder
                    .when_transition()
                    .when_not(local_is_real[i])
                    .assert_septic_ext_eq(next_sum.y, current_sum.y);
            }
        }
    }
}
