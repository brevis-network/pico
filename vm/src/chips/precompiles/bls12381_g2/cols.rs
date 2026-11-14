//! Columns the G2 add and double chips share: the slope `λ = n / d` in $\mathbb{F}_{p^2}$, and the
//! point `(x3, y3)` that follows from it.

use crate::{
    chips::{
        chips::byte::event::ByteRecordBehavior,
        gadgets::{
            curves::weierstrass::bls381::Bls381BaseField,
            field::{
                field_inner_product::FieldInnerProductCols,
                field_lt::FieldLtCols,
                field_op::{FieldOpCols, FieldOperation},
            },
            utils::{field_params::FieldParameters, limbs::Limbs, polynomial::Polynomial},
        },
    },
    machine::builder::ChipBuilder,
};
use hybrid_array::typenum::U48;
use num::BigUint;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use pico_derive::AlignedBorrow;

/// The base field of every column here.
pub type P = Bls381BaseField;

/// An $\mathbb{F}_{p^2}$ element as two limb vectors.
pub type Fp2Limbs<E> = [Limbs<E, U48>; 2];

/// `λ = n / d` as `n · conj(d) · N⁻¹` with `N = d0² + d1²`.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct SlopeCols<T> {
    /// `N = d0² + d1²`.
    pub norm: FieldInnerProductCols<T, P>,
    /// `N⁻¹`, from `N⁻¹ · N = is_real`: on a real row `N ≠ 0`, so `d ≠ 0`.
    pub norm_inv: FieldOpCols<T, P>,
    /// `n0 d0 + n1 d1`, the real part of `n · conj(d)`.
    pub e0: FieldInnerProductCols<T, P>,
    pub n1_d0: FieldOpCols<T, P>,
    pub n0_d1: FieldOpCols<T, P>,
    /// `n1 d0 - n0 d1`, the imaginary part.
    pub e1: FieldOpCols<T, P>,
    pub lambda0: FieldOpCols<T, P>,
    pub lambda1: FieldOpCols<T, P>,
}

/// `x3 = λ² - x1 - x2` and `y3 = λ(x1 - x3) - y1`, both below the modulus.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct ResultCols<T> {
    pub l0_sq: FieldOpCols<T, P>,
    pub l1_sq: FieldOpCols<T, P>,
    /// `λ0² - λ1²`.
    pub sq0: FieldOpCols<T, P>,
    pub l0_l1: FieldOpCols<T, P>,
    /// `2 λ0 λ1`.
    pub sq1: FieldOpCols<T, P>,
    /// `x1 + x2`, per component.
    pub sum0: FieldOpCols<T, P>,
    pub sum1: FieldOpCols<T, P>,
    pub x3_0: FieldOpCols<T, P>,
    pub x3_1: FieldOpCols<T, P>,
    /// `x1 - x3`, per component.
    pub f0: FieldOpCols<T, P>,
    pub f1: FieldOpCols<T, P>,
    pub l0_f0: FieldOpCols<T, P>,
    pub l1_f1: FieldOpCols<T, P>,
    /// `λ0 f0 - λ1 f1`.
    pub g0: FieldOpCols<T, P>,
    /// `λ0 f1 + λ1 f0`.
    pub g1: FieldInnerProductCols<T, P>,
    pub y3_0: FieldOpCols<T, P>,
    pub y3_1: FieldOpCols<T, P>,
    pub x3_0_range: FieldLtCols<T, P>,
    pub x3_1_range: FieldLtCols<T, P>,
    pub y3_0_range: FieldLtCols<T, P>,
    pub y3_1_range: FieldLtCols<T, P>,
}

impl<F: PrimeField32> SlopeCols<F> {
    /// Populates `λ = n / d`; `is_real` false only on padding, where `n = d = 0`.
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        n: &[BigUint; 2],
        d: &[BigUint; 2],
        is_real: bool,
    ) -> [BigUint; 2] {
        use FieldOperation::{Div, Mul, Sub};
        let norm = self.norm.populate(
            record,
            &[d[0].clone(), d[1].clone()],
            &[d[0].clone(), d[1].clone()],
        );
        let one = BigUint::from(u32::from(is_real));
        let norm_inv = self.norm_inv.populate(record, &one, &norm, Div);
        let e0 = self.e0.populate(
            record,
            &[n[0].clone(), n[1].clone()],
            &[d[0].clone(), d[1].clone()],
        );
        let n1_d0 = self.n1_d0.populate(record, &n[1], &d[0], Mul);
        let n0_d1 = self.n0_d1.populate(record, &n[0], &d[1], Mul);
        let e1 = self.e1.populate(record, &n1_d0, &n0_d1, Sub);
        [
            self.lambda0.populate(record, &e0, &norm_inv, Mul),
            self.lambda1.populate(record, &e1, &norm_inv, Mul),
        ]
    }
}

impl<F: PrimeField32> ResultCols<F> {
    /// Populates `(x3, y3)` from `λ` through `(x1, y1)` and `x2`; returns `x3.c0, x3.c1, y3.c0,
    /// y3.c1`.
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        lambda: &[BigUint; 2],
        x1: &[BigUint; 2],
        y1: &[BigUint; 2],
        x2: &[BigUint; 2],
    ) -> [BigUint; 4] {
        use FieldOperation::{Add, Mul, Sub};
        let l0_sq = self.l0_sq.populate(record, &lambda[0], &lambda[0], Mul);
        let l1_sq = self.l1_sq.populate(record, &lambda[1], &lambda[1], Mul);
        let sq0 = self.sq0.populate(record, &l0_sq, &l1_sq, Sub);
        let l0_l1 = self.l0_l1.populate(record, &lambda[0], &lambda[1], Mul);
        let sq1 = self.sq1.populate(record, &l0_l1, &l0_l1, Add);
        let sum0 = self.sum0.populate(record, &x1[0], &x2[0], Add);
        let sum1 = self.sum1.populate(record, &x1[1], &x2[1], Add);
        let x3_0 = self.x3_0.populate(record, &sq0, &sum0, Sub);
        let x3_1 = self.x3_1.populate(record, &sq1, &sum1, Sub);
        let f0 = self.f0.populate(record, &x1[0], &x3_0, Sub);
        let f1 = self.f1.populate(record, &x1[1], &x3_1, Sub);
        let l0_f0 = self.l0_f0.populate(record, &lambda[0], &f0, Mul);
        let l1_f1 = self.l1_f1.populate(record, &lambda[1], &f1, Mul);
        let g0 = self.g0.populate(record, &l0_f0, &l1_f1, Sub);
        let g1 = self.g1.populate(
            record,
            &[lambda[0].clone(), lambda[1].clone()],
            &[f1.clone(), f0.clone()],
        );
        let y3_0 = self.y3_0.populate(record, &g0, &y1[0], Sub);
        let y3_1 = self.y3_1.populate(record, &g1, &y1[1], Sub);
        let modulus = P::modulus();
        self.x3_0_range.populate(record, &x3_0, &modulus);
        self.x3_1_range.populate(record, &x3_1, &modulus);
        self.y3_0_range.populate(record, &y3_0, &modulus);
        self.y3_1_range.populate(record, &y3_1, &modulus);
        [x3_0, x3_1, y3_0, y3_1]
    }
}

impl<V: Copy> SlopeCols<V>
where
    Limbs<V, U48>: Copy,
{
    /// Constrains `λ = n / d` with `d ≠ 0` on a real row; returns `λ`.
    pub fn eval<F: Field, CB: ChipBuilder<F, Var = V>>(
        &self,
        builder: &mut CB,
        n: &[Polynomial<CB::Expr>; 2],
        d: &[Polynomial<CB::Expr>; 2],
        is_real: CB::Expr,
    ) -> [Limbs<V, U48>; 2]
    where
        V: Into<CB::Expr>,
    {
        use FieldOperation::{Div, Mul, Sub};
        self.norm.eval(
            builder,
            &[d[0].clone(), d[1].clone()],
            &[d[0].clone(), d[1].clone()],
            is_real.clone(),
        );
        // `N⁻¹ · N = is_real`: zero on padding, one on a real row.
        let mut coeffs = vec![CB::Expr::ZERO; P::NUM_LIMBS];
        coeffs[0] = is_real.clone();
        let real = Polynomial::from_coefficients(&coeffs);
        self.norm_inv
            .eval(builder, &real, &self.norm.result, Div, is_real.clone());
        self.e0.eval(
            builder,
            &[n[0].clone(), n[1].clone()],
            &[d[0].clone(), d[1].clone()],
            is_real.clone(),
        );
        self.n1_d0.eval(builder, &n[1], &d[0], Mul, is_real.clone());
        self.n0_d1.eval(builder, &n[0], &d[1], Mul, is_real.clone());
        self.e1.eval(
            builder,
            &self.n1_d0.result,
            &self.n0_d1.result,
            Sub,
            is_real.clone(),
        );
        self.lambda0.eval(
            builder,
            &self.e0.result,
            &self.norm_inv.result,
            Mul,
            is_real.clone(),
        );
        self.lambda1.eval(
            builder,
            &self.e1.result,
            &self.norm_inv.result,
            Mul,
            is_real,
        );
        [self.lambda0.result, self.lambda1.result]
    }
}

impl<V: Copy> ResultCols<V>
where
    Limbs<V, U48>: Copy,
{
    /// Constrains `(x3, y3)` from `λ`, `(x1, y1)` and `x2`; returns `x3.c0, x3.c1, y3.c0, y3.c1`.
    pub fn eval<F: Field, CB: ChipBuilder<F, Var = V>>(
        &self,
        builder: &mut CB,
        lambda: &[Limbs<V, U48>; 2],
        x1: &[Polynomial<CB::Expr>; 2],
        y1: &[Polynomial<CB::Expr>; 2],
        x2: &[Polynomial<CB::Expr>; 2],
        is_real: CB::Expr,
    ) -> [Limbs<V, U48>; 4]
    where
        V: Into<CB::Expr>,
    {
        use FieldOperation::{Add, Mul, Sub};
        let r = is_real;
        let [l0, l1] = lambda;
        self.l0_sq.eval(builder, l0, l0, Mul, r.clone());
        self.l1_sq.eval(builder, l1, l1, Mul, r.clone());
        self.sq0.eval(
            builder,
            &self.l0_sq.result,
            &self.l1_sq.result,
            Sub,
            r.clone(),
        );
        self.l0_l1.eval(builder, l0, l1, Mul, r.clone());
        self.sq1.eval(
            builder,
            &self.l0_l1.result,
            &self.l0_l1.result,
            Add,
            r.clone(),
        );
        self.sum0.eval(builder, &x1[0], &x2[0], Add, r.clone());
        self.sum1.eval(builder, &x1[1], &x2[1], Add, r.clone());
        self.x3_0
            .eval(builder, &self.sq0.result, &self.sum0.result, Sub, r.clone());
        self.x3_1
            .eval(builder, &self.sq1.result, &self.sum1.result, Sub, r.clone());
        self.f0
            .eval(builder, &x1[0], &self.x3_0.result, Sub, r.clone());
        self.f1
            .eval(builder, &x1[1], &self.x3_1.result, Sub, r.clone());
        self.l0_f0
            .eval(builder, l0, &self.f0.result, Mul, r.clone());
        self.l1_f1
            .eval(builder, l1, &self.f1.result, Mul, r.clone());
        self.g0.eval(
            builder,
            &self.l0_f0.result,
            &self.l1_f1.result,
            Sub,
            r.clone(),
        );
        self.g1.eval(
            builder,
            &[*l0, *l1],
            &[self.f1.result, self.f0.result],
            r.clone(),
        );
        self.y3_0
            .eval(builder, &self.g0.result, &y1[0], Sub, r.clone());
        self.y3_1
            .eval(builder, &self.g1.result, &y1[1], Sub, r.clone());
        let modulus = P::to_limbs_field::<CB::Expr, CB::F>(&P::modulus());
        self.x3_0_range
            .eval(builder, &self.x3_0.result, &modulus, r.clone());
        self.x3_1_range
            .eval(builder, &self.x3_1.result, &modulus, r.clone());
        self.y3_0_range
            .eval(builder, &self.y3_0.result, &modulus, r.clone());
        self.y3_1_range
            .eval(builder, &self.y3_1.result, &modulus, r);
        [
            self.x3_0.result,
            self.x3_1.result,
            self.y3_0.result,
            self.y3_1.result,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{debug_folder::DebugConstraintFolder, septic::SepticDigest};
    use core::borrow::{Borrow, BorrowMut};
    use p3_air::{Air, AirBuilder, BaseAir, RowWindow, WindowAccess};
    use p3_field::extension::QuinticTrinomialExtensionField;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = QuinticTrinomialExtensionField<KoalaBear>;

    /// `is_real`, then `n`, `d` and the slope columns.
    #[derive(AlignedBorrow)]
    #[repr(C)]
    struct SlopeOnlyCols<T> {
        is_real: T,
        n: [Limbs<T, U48>; 2],
        d: [Limbs<T, U48>; 2],
        slope: SlopeCols<T>,
    }

    struct SlopeOnly;

    impl<T> BaseAir<T> for SlopeOnly {
        fn width(&self) -> usize {
            core::mem::size_of::<SlopeOnlyCols<u8>>()
        }
    }

    impl<'a> Air<DebugConstraintFolder<'a, F, EF>> for SlopeOnly {
        fn eval(&self, builder: &mut DebugConstraintFolder<'a, F, EF>) {
            let main = builder.main();
            let local: &SlopeOnlyCols<F> = (*main.current_slice()).borrow();
            let n = [local.n[0].into(), local.n[1].into()];
            let d = [local.d[0].into(), local.d[1].into()];
            local.slope.eval(builder, &n, &d, local.is_real);
        }
    }

    fn failures(row: &[F]) -> usize {
        let dummy = [F::ZERO];
        let mut folder = DebugConstraintFolder::<F, EF> {
            preprocessed: RowWindow::from_two_rows(&dummy, &dummy),
            main: RowWindow::from_two_rows(row, row),
            global_cumulative_sum: SepticDigest::<F>::zero(),
            is_first_row: F::ZERO,
            is_last_row: F::ZERO,
            is_transition: F::ONE,
            public_values: &[],
            failures: Vec::new(),
            scopes: Vec::new(),
            constraint_count: 0,
        };
        SlopeOnly.eval(&mut folder);
        folder.failures.len()
    }

    fn row(n: [u32; 2], d: [u32; 2], is_real: bool) -> Vec<F> {
        let mut row = vec![F::ZERO; BaseAir::<F>::width(&SlopeOnly)];
        let cols: &mut SlopeOnlyCols<F> = row.as_mut_slice().borrow_mut();
        let (n, d) = (n.map(BigUint::from), d.map(BigUint::from));
        cols.is_real = F::from_bool(is_real);
        for i in 0..2 {
            cols.n[i] = P::to_limbs_field::<F, _>(&n[i]);
            cols.d[i] = P::to_limbs_field::<F, _>(&d[i]);
        }
        cols.slope.populate(&mut vec![], &n, &d, is_real);
        row
    }

    #[test]
    fn the_slope_needs_a_nonzero_denominator_on_a_real_row() {
        // 5 / (1 + 2u), and padding, satisfy the slope.
        assert_eq!(failures(&row([5, 0], [1, 2], true)), 0);
        assert_eq!(failures(&row([0, 0], [0, 0], false)), 0);
        // The padding's columns on a real row: `d = 0` leaves `N⁻¹ · N = 1` unsatisfiable.
        let mut forged = row([0, 0], [0, 0], false);
        forged[0] = F::ONE;
        assert!(failures(&forged) > 0);
    }
}
