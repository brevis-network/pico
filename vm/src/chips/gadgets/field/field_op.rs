use crate::chips::gadgets::utils::{field_params::FieldParameters, limbs::Limbs};
use num::{BigUint, Zero};
use p3_field::{Field, PrimeField32};
use pico_derive::AlignedBorrow;

use crate::{
    chips::{
        chips::rangecheck::event::RangeRecordBehavior,
        gadgets::{
            field::utils::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs},
            utils::polynomial::Polynomial,
        },
    },
    machine::builder::{ChipBuilder, ChipRangeBuilder},
};
use p3_air::AirBuilder;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

/// A set of columns to compute an emulated modular arithmetic operation.
///
/// *Safety* The input operands (a, b) (not included in the operation columns) are assumed to be
/// elements within the range `[0, 2^{P::nb_bits()})`. the result is also assumed to be within the
/// same range. Let `M = P:modulus()`. The constraints of the function [`FieldOpCols::eval`] assert
/// that:
/// * When `op` is `FieldOperation::Add`, then `result = a + b mod M`.
/// * When `op` is `FieldOperation::Mul`, then `result = a * b mod M`.
/// * When `op` is `FieldOperation::Sub`, then `result = a - b mod M`.
/// * When `op` is `FieldOperation::Div`, then `result * b = a mod M`.
///
/// **Warning**: The constraints do not check for division by zero. The caller is responsible for
/// ensuring that the division operation is valid.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldOpCols<T, P: FieldParameters> {
    /// The result of `a op b`, where a, b are field elements
    pub result: Limbs<T, P::Limbs>,
    pub(crate) carry: Limbs<T, P::Limbs>,
    pub(crate) witness_low: Limbs<T, P::Witness>,
    pub(crate) witness_high: Limbs<T, P::Witness>,
}

/// This is an arithmetic operation for emulating modular arithmetic.
#[derive(Default, PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
pub enum FieldOperation {
    /// Addition.
    #[default]
    Add,
    /// Multiplication.
    Mul,
    /// Subtraction.
    Sub,
    /// Division.
    Div,
}

impl<F: PrimeField32, P: FieldParameters> FieldOpCols<F, P> {
    pub fn populate_carry_and_witness(
        &mut self,
        a: &BigUint,
        b: &BigUint,
        op: FieldOperation,
        modulus: &BigUint,
    ) -> BigUint {
        let p_a: Polynomial<F> = P::to_limbs_field::<F, _>(a).into();
        let p_b: Polynomial<F> = P::to_limbs_field::<F, _>(b).into();
        let (result, carry) = match op {
            FieldOperation::Add => ((a + b) % modulus, (a + b - (a + b) % modulus) / modulus),
            FieldOperation::Mul => ((a * b) % modulus, (a * b - (a * b) % modulus) / modulus),
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        };
        debug_assert!(&result < modulus);
        debug_assert!(&carry < modulus);
        match op {
            FieldOperation::Add => debug_assert_eq!(&carry * modulus, a + b - &result),
            FieldOperation::Mul => debug_assert_eq!(&carry * modulus, a * b - &result),
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        }

        // Here we have special logic for p_modulus because to_limbs_field only works for numbers in
        // the field, but modulus can == the field modulus so it can have 1 extra limb (ex.
        // uint256).
        let p_modulus_limbs = modulus
            .to_bytes_le()
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .collect::<Vec<F>>();
        let p_modulus: Polynomial<F> = p_modulus_limbs.iter().into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F, _>(&result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F, _>(&carry).into();

        // Compute the vanishing polynomial.
        let p_op = match op {
            FieldOperation::Add => &p_a + &p_b,
            FieldOperation::Mul => &p_a * &p_b,
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        };
        let p_vanishing: Polynomial<F> = &p_op - &p_result - &p_carry * &p_modulus;

        let p_witness = compute_root_quotient_and_shift(
            &p_vanishing,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
            P::NB_WITNESS_LIMBS,
        );
        let (mut p_witness_low, mut p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = p_result.into();
        self.carry = p_carry.into();

        p_witness_low.resize(P::Witness::USIZE, F::zero());
        p_witness_high.resize(P::Witness::USIZE, F::zero());
        self.witness_low = Limbs(p_witness_low.try_into().unwrap());
        self.witness_high = Limbs(p_witness_high.try_into().unwrap());

        result
    }

    /// Populate these columns with a specified modulus. This is useful in the `mulmod` precompile
    /// as an example.
    #[allow(clippy::too_many_arguments)]
    pub fn populate_with_modulus(
        &mut self,
        record: &mut impl RangeRecordBehavior,
        chunk: u32,
        a: &BigUint,
        b: &BigUint,
        modulus: &BigUint,
        op: FieldOperation,
    ) -> BigUint {
        if b == &BigUint::zero() && op == FieldOperation::Div {
            // Division by 0 is allowed only when dividing 0 so that padded rows can be all 0.
            assert_eq!(
                *a,
                BigUint::zero(),
                "division by zero is allowed only when dividing zero"
            );
        }

        let result = match op {
            // If doing the subtraction operation, a - b = result, equivalent to a = result + b.
            FieldOperation::Sub => {
                let result = (modulus.clone() + a - b) % modulus;
                // We populate the carry, witness_low, witness_high as if we were doing an addition
                // with result + b. But we populate `result` with the actual result
                // of the subtraction because those columns are expected to contain
                // the result by the user. Note that this reversal means we have to
                // flip result, a correspondingly in the `eval` function.
                self.populate_carry_and_witness(&result, b, FieldOperation::Add, modulus);
                self.result = P::to_limbs_field::<F, _>(&result);
                result
            }
            // a / b = result is equivalent to a = result * b.
            FieldOperation::Div => {
                // As modulus is prime, we can use Fermat's little theorem to compute the
                // inverse.
                let result =
                    (a * b.modpow(&(modulus.clone() - 2u32), &modulus.clone())) % modulus.clone();
                // We populate the carry, witness_low, witness_high as if we were doing a
                // multiplication with result * b. But we populate `result` with the
                // actual result of the multiplication because those columns are
                // expected to contain the result by the user. Note that this
                // reversal means we have to flip result, a correspondingly in the `eval`
                // function.
                self.populate_carry_and_witness(&result, b, FieldOperation::Mul, modulus);
                self.result = P::to_limbs_field::<F, _>(&result);
                result
            }
            _ => self.populate_carry_and_witness(a, b, op, modulus),
        };

        // Range checks
        record.add_u8_range_checks_field(&self.result.0, Some(chunk));
        record.add_u8_range_checks_field(&self.carry.0, Some(chunk));
        record.add_u8_range_checks_field(&self.witness_low.0, Some(chunk));
        record.add_u8_range_checks_field(&self.witness_high.0, Some(chunk));

        result
    }

    /// Populate these columns without a specified modulus (will use the modulus of the field
    /// parameters).
    pub fn populate(
        &mut self,
        record: &mut impl RangeRecordBehavior,
        chunk: u32,
        a: &BigUint,
        b: &BigUint,
        op: FieldOperation,
    ) -> BigUint {
        self.populate_with_modulus(record, chunk, a, b, &P::modulus(), op)
    }
}

impl<V: Copy, P: FieldParameters> FieldOpCols<V, P> {
    /// Allows an evaluation over opetations specified by boolean flags.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_variable<F: Field, CB: ChipBuilder<F, Var = V>>(
        &self,
        builder: &mut CB,
        a: &(impl Into<Polynomial<CB::Expr>> + Clone),
        b: &(impl Into<Polynomial<CB::Expr>> + Clone),
        modulus: &(impl Into<Polynomial<CB::Expr>> + Clone),
        is_add: impl Into<CB::Expr> + Clone,
        is_sub: impl Into<CB::Expr> + Clone,
        is_mul: impl Into<CB::Expr> + Clone,
        is_div: impl Into<CB::Expr> + Clone,
        chunk: impl Into<CB::Expr> + Clone,
        is_real: impl Into<CB::Expr> + Clone,
    ) where
        V: Into<CB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        let p_a_param: Polynomial<CB::Expr> = (a).clone().into();
        let p_b: Polynomial<CB::Expr> = (b).clone().into();
        let p_res_param: Polynomial<CB::Expr> = self.result.into();

        let is_add: CB::Expr = is_add.into();
        let is_sub: CB::Expr = is_sub.into();
        let is_mul: CB::Expr = is_mul.into();
        let is_div: CB::Expr = is_div.into();

        let p_result = p_res_param.clone() * (is_add.clone() + is_mul.clone())
            + p_a_param.clone() * (is_sub.clone() + is_div.clone());

        let p_add = p_a_param.clone() + p_b.clone();
        let p_sub = p_res_param.clone() + p_b.clone();
        let p_mul = p_a_param.clone() * p_b.clone();
        let p_div = p_res_param * p_b.clone();
        let p_op = p_add * is_add + p_sub * is_sub + p_mul * is_mul + p_div * is_div;

        self.eval_with_polynomials(builder, p_op, modulus.clone(), p_result, chunk, is_real);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_with_modulus<F: Field, CB: ChipBuilder<F, Var = V>>(
        &self,
        builder: &mut CB,
        a: &(impl Into<Polynomial<CB::Expr>> + Clone),
        b: &(impl Into<Polynomial<CB::Expr>> + Clone),
        modulus: &(impl Into<Polynomial<CB::Expr>> + Clone),
        op: FieldOperation,
        chunk: impl Into<CB::Expr> + Clone,
        is_real: impl Into<CB::Expr> + Clone,
    ) where
        V: Into<CB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        let p_a_param: Polynomial<CB::Expr> = (a).clone().into();
        let p_b: Polynomial<CB::Expr> = (b).clone().into();

        let (p_a, p_result): (Polynomial<_>, Polynomial<_>) = match op {
            FieldOperation::Add | FieldOperation::Mul => (p_a_param, self.result.into()),
            FieldOperation::Sub | FieldOperation::Div => (self.result.into(), p_a_param),
        };
        let p_op: Polynomial<<CB as AirBuilder>::Expr> = match op {
            FieldOperation::Add | FieldOperation::Sub => p_a + p_b,
            FieldOperation::Mul | FieldOperation::Div => p_a * p_b,
        };
        self.eval_with_polynomials(builder, p_op, modulus.clone(), p_result, chunk, is_real);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_with_polynomials<F: Field, CB: ChipBuilder<F, Var = V>>(
        &self,
        builder: &mut CB,
        op: impl Into<Polynomial<CB::Expr>>,
        modulus: impl Into<Polynomial<CB::Expr>>,
        result: impl Into<Polynomial<CB::Expr>>,
        chunk: impl Into<CB::Expr> + Clone,
        is_real: impl Into<CB::Expr> + Clone,
    ) where
        V: Into<CB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        let p_op: Polynomial<CB::Expr> = op.into();
        let p_result: Polynomial<CB::Expr> = result.into();
        let p_modulus: Polynomial<CB::Expr> = modulus.into();
        let p_carry: Polynomial<<CB as AirBuilder>::Expr> = self.carry.into();
        let p_op_minus_result: Polynomial<CB::Expr> = p_op - &p_result;
        let p_vanishing = p_op_minus_result - &(&p_carry * &p_modulus);
        let p_witness_low = self.witness_low.0.iter().into();
        let p_witness_high = self.witness_high.0.iter().into();
        eval_field_operation::<F, CB, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high);

        // TODO: remove chunk here after recursion v2
        // Range checks for the result, carry, and witness columns.
        builder.slice_range_check_u8(&self.result.0, chunk.clone(), is_real.clone());
        builder.slice_range_check_u8(&self.carry.0, chunk.clone(), is_real.clone());
        builder.slice_range_check_u8(p_witness_low.coefficients(), chunk.clone(), is_real.clone());
        builder.slice_range_check_u8(p_witness_high.coefficients(), chunk.clone(), is_real);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval<F: Field, CB: ChipBuilder<F, Var = V>>(
        &self,
        builder: &mut CB,
        a: &(impl Into<Polynomial<CB::Expr>> + Clone),
        b: &(impl Into<Polynomial<CB::Expr>> + Clone),
        op: FieldOperation,
        chunk: impl Into<CB::Expr> + Clone,
        is_real: impl Into<CB::Expr> + Clone,
    ) where
        V: Into<CB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        let p_limbs = Polynomial::from_iter(P::modulus_field_iter::<CB::F>().map(CB::Expr::from));
        self.eval_with_modulus::<F, CB>(builder, a, b, &p_limbs, op, chunk, is_real);
    }
}

pub fn eval_field_operation<F: Field, CB: ChipBuilder<F>, P: FieldParameters>(
    builder: &mut CB,
    p_vanishing: &Polynomial<CB::Expr>,
    p_witness_low: &Polynomial<CB::Expr>,
    p_witness_high: &Polynomial<CB::Expr>,
) {
    // Reconstruct and shift back the witness polynomial
    let limb: CB::Expr = CB::F::from_canonical_u32(2u32.pow(P::NB_BITS_PER_LIMB as u32)).into();

    let p_witness_shifted = p_witness_low + &(p_witness_high * limb.clone());

    // Shift down the witness polynomial. Shifting is needed to range check that each
    // coefficient w_i of the witness polynomial satisfies |w_i| < 2^WITNESS_OFFSET.
    let offset: CB::Expr = CB::F::from_canonical_u32(P::WITNESS_OFFSET as u32).into();
    let len = p_witness_shifted.coefficients().len();
    let p_witness = p_witness_shifted - Polynomial::new(vec![offset; len]);

    // Multiply by (x-2^NB_BITS_PER_LIMB) and make the constraint
    let root_monomial = Polynomial::new(vec![-limb, CB::F::one().into()]);

    let constraints = p_vanishing - &(p_witness * root_monomial);
    for constraint in constraints.as_coefficients() {
        builder.assert_zero(constraint);
    }
}
