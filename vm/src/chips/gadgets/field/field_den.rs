use std::fmt::Debug;

use num::BigUint;
use p3_air::AirBuilder;
use p3_field::{Field, PrimeField32};
use pico_derive::AlignedBorrow;

use crate::{
    chips::{
        chips::rangecheck::event::RangeRecordBehavior,
        gadgets::utils::{field_params::FieldParameters, limbs::Limbs, polynomial::Polynomial},
    },
    machine::builder::{ChipBuilder, ChipRangeBuilder},
};

use super::{
    field_op::eval_field_operation,
    utils::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs},
};

/// A set of columns to compute `FieldDen(a, b)` where `a`, `b` are field elements.
///
/// `a / (1 + b)` if `sign`
/// `a / (1 - b) ` if `!sign`
///
/// *Safety*: the operation assumes that the denominators are never zero. It is the responsibility
/// of the caller to ensure that condition.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldDenCols<T, P: FieldParameters> {
    /// The result of `a den b`, where a, b are field elements
    pub result: Limbs<T, P::Limbs>,
    pub(crate) carry: Limbs<T, P::Limbs>,
    pub(crate) witness_low: Limbs<T, P::Witness>,
    pub(crate) witness_high: Limbs<T, P::Witness>,
}

impl<F: PrimeField32, P: FieldParameters> FieldDenCols<F, P> {
    pub fn populate(
        &mut self,
        record: &mut impl RangeRecordBehavior,
        chunk: u32,
        a: &BigUint,
        b: &BigUint,
        sign: bool,
    ) -> BigUint {
        let p = P::modulus();
        let minus_b_int = &p - b;
        let b_signed = if sign { b.clone() } else { minus_b_int };
        let denominator = (b_signed + 1u32) % &(p.clone());
        let den_inv = denominator.modpow(&(&p - 2u32), &p);
        let result = (a * &den_inv) % &p;
        debug_assert_eq!(&den_inv * &denominator % &p, BigUint::from(1u32));
        debug_assert!(result < p);

        let equation_lhs = if sign {
            b * &result + &result
        } else {
            b * &result + a
        };
        let equation_rhs = if sign { a.clone() } else { result.clone() };
        let carry = (&equation_lhs - &equation_rhs) / &p;
        debug_assert!(carry < p);
        debug_assert_eq!(&carry * &p, &equation_lhs - &equation_rhs);

        let p_a: Polynomial<F> = P::to_limbs_field::<F, _>(a).into();
        let p_b: Polynomial<F> = P::to_limbs_field::<F, _>(b).into();
        let p_p: Polynomial<F> = P::to_limbs_field::<F, _>(&p).into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F, _>(&result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F, _>(&carry).into();

        // Compute the vanishing polynomial.
        let vanishing_poly = if sign {
            &p_b * &p_result + &p_result - &p_a - &p_carry * &p_p
        } else {
            &p_b * &p_result + &p_a - &p_result - &p_carry * &p_p
        };
        debug_assert_eq!(vanishing_poly.degree(), P::NUM_WITNESS_LIMBS);

        let p_witness = compute_root_quotient_and_shift(
            &vanishing_poly,
            P::WITNESS_OFFSET,
            P::NUM_BITS_PER_LIMB as u32,
            P::NUM_WITNESS_LIMBS,
        );
        let (p_witness_low, p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = p_result.into();
        self.carry = p_carry.into();
        self.witness_low = Limbs((&*p_witness_low).try_into().unwrap());
        self.witness_high = Limbs((&*p_witness_high).try_into().unwrap());

        // Range checks
        record.add_u8_range_checks_field(&self.result.0, Some(chunk));
        record.add_u8_range_checks_field(&self.carry.0, Some(chunk));
        record.add_u8_range_checks_field(&self.witness_low.0, Some(chunk));
        record.add_u8_range_checks_field(&self.witness_high.0, Some(chunk));

        result
    }
}

impl<V: Copy, P: FieldParameters> FieldDenCols<V, P>
where
    Limbs<V, P::Limbs>: Copy,
{
    #[allow(clippy::too_many_arguments)]
    pub fn eval<F: Field, CB: ChipBuilder<F, Var = V>>(
        &self,
        builder: &mut CB,
        a: &Limbs<CB::Var, P::Limbs>,
        b: &Limbs<CB::Var, P::Limbs>,
        sign: bool,
        chunk: CB::Var,
        is_real: impl Into<CB::Expr> + Clone,
    ) where
        V: Into<CB::Expr>,
    {
        let p_a: Polynomial<<CB as AirBuilder>::Expr> = (*a).into();
        let p_b: Polynomial<<CB as AirBuilder>::Expr> = (*b).into();
        let p_result: Polynomial<<CB as AirBuilder>::Expr> = self.result.into();
        let p_carry: Polynomial<<CB as AirBuilder>::Expr> = self.carry.into();

        // Compute the vanishing polynomial:
        //      lhs(x) = sign * (b(x) * result(x) + result(x)) + (1 - sign) * (b(x) * result(x) +
        // a(x))      rhs(x) = sign * a(x) + (1 - sign) * result(x)
        //      lhs(x) - rhs(x) - carry(x) * p(x)
        let p_equation_lhs = if sign {
            &p_b * &p_result + &p_result
        } else {
            &p_b * &p_result + &p_a
        };
        let p_equation_rhs = if sign { p_a } else { p_result };

        let p_lhs_minus_rhs = &p_equation_lhs - &p_equation_rhs;
        let p_limbs: Polynomial<<CB as AirBuilder>::Expr> =
            Polynomial::from_iter(P::modulus_field_iter::<CB::F>().map(CB::Expr::from));

        let p_vanishing: Polynomial<<CB as AirBuilder>::Expr> =
            p_lhs_minus_rhs - &p_carry * &p_limbs;

        let p_witness_low = self.witness_low.0.iter().into();
        let p_witness_high = self.witness_high.0.iter().into();

        eval_field_operation::<F, CB, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high);

        // Range checks for the result, carry, and witness columns.
        builder.slice_range_check_u8(&self.result.0, chunk, is_real.clone());
        builder.slice_range_check_u8(&self.carry.0, chunk, is_real.clone());
        builder.slice_range_check_u8(&self.witness_low.0, chunk, is_real.clone());
        builder.slice_range_check_u8(&self.witness_high.0, chunk, is_real);
    }
}
