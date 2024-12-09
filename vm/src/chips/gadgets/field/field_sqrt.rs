use std::fmt::Debug;

use num::BigUint;
use p3_air::AirBuilder;
use p3_field::{Field, PrimeField32};
use pico_derive::AlignedBorrow;

use crate::{
    chips::{
        chips::{
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            rangecheck::event::RangeRecordBehavior,
        },
        gadgets::{
            field::field_op::FieldOperation,
            utils::{
                field_params::{limbs_from_slice, FieldParameters},
                limbs::Limbs,
            },
        },
    },
    compiler::riscv::opcode::ByteOpcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder},
};

use super::{field_lt::FieldLtCols, field_op::FieldOpCols};

/// A set of columns to compute the square root in emulated arithmetic.
///
/// *Safety*: The `FieldSqrtCols` asserts that `multiplication.result` is a square root of the given
/// input lying within the range `[0, modulus)` with the least significant bit `lsb`.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldSqrtCols<T, P: FieldParameters>
where
    P: FieldParameters,
    P::Witness: Debug,
    P::Limbs: Debug,
{
    /// The multiplication operation to verify that the sqrt and the input match.
    ///
    /// In order to save space, we actually store the sqrt of the input in `multiplication.result`
    /// since we'll receive the input again in the `eval` function.
    pub multiplication: FieldOpCols<T, P>,

    pub range: FieldLtCols<T, P>,

    // The least significant bit of the square root.
    pub lsb: T,
}

impl<F, P> FieldSqrtCols<F, P>
where
    F: PrimeField32,
    P: FieldParameters,
    P::Witness: Debug,
    P::Limbs: Debug,
{
    /// Populates the trace.
    ///
    /// `P` is the parameter of the field that each limb lives in.
    pub fn populate(
        &mut self,
        blu: &mut impl ByteRecordBehavior,
        rlu: &mut impl RangeRecordBehavior,
        chunk: u32,
        a: &BigUint,
        sqrt_fn: impl Fn(&BigUint) -> BigUint,
    ) -> BigUint {
        let modulus = P::modulus();
        assert!(a < &modulus);
        let sqrt = sqrt_fn(a);

        // Use FieldOpCols to compute result * result.
        let sqrt_squared =
            self.multiplication
                .populate(rlu, chunk, &sqrt, &sqrt, FieldOperation::Mul);

        // If the result is indeed the square root of a, then result * result = a.
        assert_eq!(sqrt_squared, a.clone());

        // This is a hack to save a column in FieldSqrtCols. We will receive the value a again in
        // the eval function, so we'll overwrite it with the sqrt.
        self.multiplication.result = P::to_limbs_field::<F, _>(&sqrt);

        // Populate the range columns.
        self.range.populate(blu, chunk, &sqrt, &modulus);

        let sqrt_bytes = P::to_limbs(&sqrt);
        self.lsb = F::from_canonical_u8(sqrt_bytes[0] & 1);

        let and_event = ByteLookupEvent {
            chunk,
            opcode: ByteOpcode::AND,
            a1: self.lsb.as_canonical_u32() as u16,
            a2: 0,
            b: sqrt_bytes[0],
            c: 1,
        };
        blu.add_byte_lookup_event(and_event);

        // Add the byte range check for `sqrt`.
        rlu.add_u8_range_checks(
            self.multiplication
                .result
                .0
                .as_slice()
                .iter()
                .map(|x| x.as_canonical_u32() as u8)
                .collect::<Vec<_>>(),
            Some(chunk),
        );

        sqrt
    }
}

impl<V: Copy, P: FieldParameters> FieldSqrtCols<V, P>
where
    V: Copy,
    Limbs<V, P::Limbs>: Copy,
    P::Witness: Debug,
    P::Limbs: Debug,
{
    /// Calculates the square root of `a`.
    pub fn eval<F: Field, CB: ChipBuilder<F, Var = V>>(
        &self,
        builder: &mut CB,
        a: &Limbs<CB::Var, P::Limbs>,
        is_odd: impl Into<CB::Expr>,
        chunk: CB::Var,
        is_real: impl Into<CB::Expr> + Clone,
    ) where
        V: Into<CB::Expr>,
    {
        // As a space-saving hack, we store the sqrt of the input in `self.multiplication.result`
        // even though it's technically not the result of the multiplication. Now, we should
        // retrieve that value and overwrite that member variable with a.
        let sqrt = self.multiplication.result;
        let mut multiplication = self.multiplication.clone();
        multiplication.result = *a;

        // Compute sqrt * sqrt. We pass in P since we want its BaseField to be the mod.
        multiplication.eval(
            builder,
            &sqrt,
            &sqrt,
            FieldOperation::Mul,
            chunk,
            is_real.clone(),
        );

        let modulus_limbs = P::to_limbs_field_slice(&P::modulus());
        self.range.eval(
            builder,
            &sqrt,
            &limbs_from_slice::<CB::Expr, P::Limbs, CB::F>(modulus_limbs),
            is_real.clone(),
        );

        // Range check that `sqrt` limbs are bytes.
        builder.slice_range_check_u8(sqrt.0.as_slice(), chunk, is_real.clone());

        // Assert that the square root is the positive one, i.e., with least significant bit 0.
        // This is done by computing LSB = least_significant_byte & 1.
        builder.assert_bool(self.lsb);
        builder.when(is_real.clone()).assert_eq(self.lsb, is_odd);
        builder.looking_byte(
            ByteOpcode::AND.as_field::<CB::F>(),
            self.lsb,
            sqrt[0],
            CB::F::ONE,
            is_real,
        );
    }
}
