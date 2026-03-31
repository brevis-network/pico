//! A gadget to convert four u16 limbs into eight u8 bytes.
//!
//! The idea is that for u16 limbs `a[i]`, we want to compute `low_bytes[i]` such that:
//! - `low_bytes[i] = a[i] & 0xFF` (the lower 8 bits of each limb)
//!
//! This is done using the constraint: `a[i] - low_bytes[i]` is in range [0, 256).
//! This ensures that `low_bytes[i]` is indeed the lower byte of `a[i]`.
//!
//! The gadget also computes the high bytes: `high_bytes[i] = (a[i] >> 8) & 0xFF`.

use crate::{
    machine::builder::{ChipLookupBuilder, ChipRangeBuilder},
    primitives::consts::{u64_to_u16_limbs, WORD_BYTE_SIZE, WORD_SIZE},
};

use p3_field::Field;
use pico_derive::AlignedBorrow;

/// A set of columns needed to convert four u16 limbs to eight u8 bytes.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct U16ToU8Gadget<T> {
    /// The lower bytes from each u16 limb (4 bytes total).
    pub low_bytes: [T; WORD_SIZE],
}

impl<T> U16ToU8Gadget<T> {
    pub fn new(low_bytes: [T; WORD_SIZE]) -> Self {
        Self { low_bytes }
    }
}

impl<F: Field> U16ToU8Gadget<F> {
    /// Populate the gadget from a u64 value.
    /// This converts the u64 to 4 u16 limbs and extracts the lower byte from each.
    pub fn populate_u16_to_u8_unsafe(&mut self, a_u64: u64) {
        let a_limbs = u64_to_u16_limbs(a_u64);

        for i in 0..WORD_SIZE {
            let low_byte = (a_limbs[i] & 0xFF) as u8;
            self.low_bytes[i] = F::from_canonical_u8(low_byte);
        }
    }

    pub fn populate_u16_to_u8_safe(
        &mut self,
        record: &mut impl crate::chips::chips::byte::event::ByteRecordBehavior,
        a_u64: u64,
    ) {
        let a_limbs = u64_to_u16_limbs(a_u64);

        for i in 0..WORD_SIZE {
            let low_byte = (a_limbs[i] & 0xFF) as u8;
            let high_byte = ((a_limbs[i] >> 8) & 0xFF) as u8;
            self.low_bytes[i] = F::from_canonical_u8(low_byte);
            record.add_u8_range_checks([low_byte, high_byte]);
        }
    }

    /// Converts four u16 limbs into eight u8 limbs.
    /// This function assumes that the u8 limbs will be range checked.
    pub fn eval_u16_to_u8_unsafe<CB: ChipLookupBuilder<F>>(
        _: &mut CB,
        a: [CB::Expr; WORD_SIZE],
        cols: U16ToU8Gadget<CB::Var>,
    ) -> [CB::Expr; WORD_BYTE_SIZE] {
        let mut ret: [CB::Expr; WORD_BYTE_SIZE] = core::array::from_fn(|_| CB::F::ZERO.into());
        let divisor = CB::F::from_canonical_u32(1 << 8).inverse();

        for i in 0..WORD_SIZE {
            ret[i * 2] = cols.low_bytes[i].into();
            ret[i * 2 + 1] = (a[i].clone() - ret[i * 2].clone()) * divisor;
        }

        ret
    }

    /// Converts four u16 limbs into eight u8 limbs.
    /// This function range checks the eight u8 limbs.
    pub fn eval_u16_to_u8_safe<CB: ChipLookupBuilder<F>>(
        builder: &mut CB,
        a: [CB::Expr; WORD_SIZE],
        cols: U16ToU8Gadget<CB::Var>,
        is_real: CB::Expr,
    ) -> [CB::Expr; WORD_BYTE_SIZE] {
        let ret = Self::eval_u16_to_u8_unsafe(builder, a, cols);
        builder.slice_range_check_u8(&ret, is_real);
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::folder::SymbolicConstraintFolder;
    use p3_air::AirBuilder;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use pico_derive::AlignedBorrow;
    use std::borrow::Borrow;
    use std::mem::size_of;

    #[derive(AlignedBorrow, Clone, Copy)]
    #[repr(C)]
    struct TestCols<T> {
        a: [T; 4],
        u16_to_u8: U16ToU8Gadget<T>,
        is_real: T,
    }

    #[test]
    fn test_u16_to_u8_gadget_unsafe_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        let _ret = U16ToU8Gadget::<KoalaBear>::eval_u16_to_u8_unsafe(
            &mut builder,
            [
                local.a[0].into(),
                local.a[1].into(),
                local.a[2].into(),
                local.a[3].into(),
            ],
            local.u16_to_u8,
        );

        let _ = builder.num_constraints();
        let _ = builder.num_lookups();
    }

    #[test]
    fn test_u16_to_u8_gadget_safe_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        let _ret = U16ToU8Gadget::<KoalaBear>::eval_u16_to_u8_safe(
            &mut builder,
            [
                local.a[0].into(),
                local.a[1].into(),
                local.a[2].into(),
                local.a[3].into(),
            ],
            local.u16_to_u8,
            local.is_real.into(),
        );

        let _ = builder.num_constraints();
        let _ = builder.num_lookups();
    }
}
