use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    compiler::riscv::opcode::ByteOpcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct U16MSBGadget<T> {
    /// The result of the msb gadget.
    pub msb: T,
}

impl<F: Field> U16MSBGadget<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecordBehavior, a_u16: u16) -> u32 {
        let msb = (a_u16 >> 15) & 1;
        self.msb = F::from_canonical_u16(msb);
        let diff = a_u16.wrapping_mul(2u16);
        record.add_u16_range_check(diff);
        msb as u32
    }

    /// Evaluate the `U16MSBGadget` on the given inputs.
    /// Assumes that `a` is a valid u16.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, it constrains that the result is the msb of `a`.
    pub fn eval<AB: ChipBuilder<F>>(
        builder: &mut AB,
        a: AB::Expr,
        cols: U16MSBGadget<AB::Var>,
        is_real: AB::Expr,
    ) {
        // Constrain that `is_real` is boolean.
        builder.assert_bool(is_real.clone());
        // Constrain that `msb` is boolean.
        builder.assert_bool(cols.msb);
        let two = AB::Expr::from_canonical_u32(2);
        let base = AB::Expr::from_canonical_u32(1 << 16);
        let diff = two * a - cols.msb * base;
        // Constrains that `2 * a - msb * 2^16` is in u16 range, while `msb` is boolean.
        // If `0 <= a < 2^15`, then `msb` must be 0.
        // If `2^15 <= a < 2^16`, then `msb` must be 1.
        builder.looking_rangecheck(
            ByteOpcode::U16Range,
            diff,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
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
        a: T,
        msb: U16MSBGadget<T>,
        is_real: T,
    }

    #[test]
    fn test_u16_msb_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        U16MSBGadget::<KoalaBear>::eval(
            &mut builder,
            local.a.into(),
            local.msb,
            local.is_real.into(),
        );

        let _ = builder.num_constraints();
        let _ = builder.num_lookups();
    }
}
