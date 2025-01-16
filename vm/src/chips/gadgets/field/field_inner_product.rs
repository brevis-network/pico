use std::fmt::Debug;

use num::{BigUint, Zero};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra, PrimeField32};
use pico_derive::AlignedBorrow;

use crate::{
    chips::{
        chips::byte::event::ByteRecordBehavior,
        gadgets::utils::{field_params::FieldParameters, limbs::Limbs, polynomial::Polynomial},
    },
    machine::builder::{ChipBuilder, ChipRangeBuilder},
};

use super::{
    field_op::eval_field_operation,
    utils::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs},
};

/// A set of columns to compute `InnerProduct([a], [b])` where a, b are emulated elements.
///
/// *Safety*: The `FieldInnerProductCols` asserts that `result = sum_i a_i * b_i mod M` where
/// `M` is the modulus `P::modulus()` under the assumption that the length of `a` and `b` is small
/// enough so that the vanishing polynomial has limbs bounded by the witness shift. It is the
/// responsibility of the caller to ensure that the length of `a` and `b` is small enough.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldInnerProductCols<T, P: FieldParameters> {
    /// The result of `a inner product b`, where a, b are field elements
    pub result: Limbs<T, P::Limbs>,
    pub(crate) carry: Limbs<T, P::Limbs>,
    pub(crate) witness_low: Limbs<T, P::Witness>,
    pub(crate) witness_high: Limbs<T, P::Witness>,
}

impl<F: PrimeField32, P: FieldParameters> FieldInnerProductCols<F, P> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        chunk: u32,
        a: &[BigUint],
        b: &[BigUint],
    ) -> BigUint {
        let p_a_vec: Vec<Polynomial<F>> = a
            .iter()
            .map(|x| P::to_limbs_field::<F, _>(x).into())
            .collect();
        let p_b_vec: Vec<Polynomial<F>> = b
            .iter()
            .map(|x| P::to_limbs_field::<F, _>(x).into())
            .collect();

        let modulus = &P::modulus();
        let inner_product = a
            .iter()
            .zip(b.iter())
            .fold(BigUint::zero(), |acc, (c, d)| acc + c * d);

        let result = &(&inner_product % modulus);
        let carry = &((&inner_product - result) / modulus);
        assert!(result < modulus);
        assert!(carry < &(2u32 * modulus));
        assert_eq!(carry * modulus, inner_product - result);

        let p_modulus: Polynomial<F> = P::to_limbs_field::<F, _>(modulus).into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F, _>(result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F, _>(carry).into();

        // Compute the vanishing polynomial.
        let p_inner_product = p_a_vec
            .into_iter()
            .zip(p_b_vec)
            .fold(Polynomial::<F>::new(vec![F::ZERO]), |acc, (c, d)| {
                acc + &c * &d
            });
        let p_vanishing = p_inner_product - &p_result - &p_carry * &p_modulus;
        assert_eq!(p_vanishing.degree(), P::NUM_WITNESS_LIMBS);

        let p_witness = compute_root_quotient_and_shift(
            &p_vanishing,
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

        result.clone()
    }
}

impl<V: Copy, P: FieldParameters> FieldInnerProductCols<V, P>
where
    Limbs<V, P::Limbs>: Copy,
{
    #[allow(clippy::too_many_arguments)]
    pub fn eval<F: Field, CB: ChipBuilder<F, Var = V>>(
        &self,
        builder: &mut CB,
        a: &[impl Into<Polynomial<CB::Expr>> + Clone],
        b: &[impl Into<Polynomial<CB::Expr>> + Clone],
        is_real: impl Into<CB::Expr> + Clone,
    ) where
        V: Into<CB::Expr>,
    {
        let p_a_vec: Vec<Polynomial<CB::Expr>> = a.iter().cloned().map(|x| x.into()).collect();
        let p_b_vec: Vec<Polynomial<CB::Expr>> = b.iter().cloned().map(|x| x.into()).collect();
        let p_result: Polynomial<<CB as AirBuilder>::Expr> = self.result.into();
        let p_carry: Polynomial<<CB as AirBuilder>::Expr> = self.carry.into();

        let p_zero = Polynomial::<CB::Expr>::new(vec![CB::Expr::ZERO]);

        let p_inner_product = p_a_vec
            .iter()
            .zip(p_b_vec.iter())
            .map(|(p_a, p_b)| p_a * p_b)
            .collect::<Vec<_>>()
            .iter()
            .fold(p_zero, |acc, x| acc + x);

        let p_inner_product_minus_result = &p_inner_product - &p_result;
        let p_limbs = Polynomial::from_iter(P::modulus_field_iter::<CB::F>().map(CB::Expr::from));
        let p_vanishing = &p_inner_product_minus_result - &(&p_carry * &p_limbs);

        let p_witness_low = self.witness_low.0.iter().into();
        let p_witness_high = self.witness_high.0.iter().into();

        eval_field_operation::<F, CB, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high);

        // Range checks for the result, carry, and witness columns.
        builder.slice_range_check_u8(&self.result.0, is_real.clone());
        builder.slice_range_check_u8(&self.carry.0, is_real.clone());
        builder.slice_range_check_u8(&self.witness_low.0, is_real.clone());
        builder.slice_range_check_u8(&self.witness_high.0, is_real);
    }
}
