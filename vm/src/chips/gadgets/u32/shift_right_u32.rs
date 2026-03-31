use crate::{
    chips::chips::byte::event::ByteRecordBehavior, compiler::riscv::opcode::ByteOpcode,
    machine::builder::ChipLookupBuilder, primitives::consts::u32_to_u16_limbs,
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FixedShiftRightU32Gadget<T> {
    pub value: [T; 2],
    pub higher_limb: [T; 2],
}

impl<F: Field> FixedShiftRightU32Gadget<F> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        input: u32,
        shift: usize,
    ) -> u32 {
        let input_limbs = u32_to_u16_limbs(input);
        let expected = input >> shift;
        self.value = [
            F::from_canonical_u16((expected & 0xFFFF) as u16),
            F::from_canonical_u16((expected >> 16) as u16),
        ];

        let nb_limbs_to_shift = shift / 16;
        let nb_bits_to_shift = shift % 16;

        let mut word = [0u16; 2];
        for i in 0..2 {
            if i + nb_limbs_to_shift < 2 {
                word[i] = input_limbs[i + nb_limbs_to_shift];
            }
        }

        for i in (0..2).rev() {
            let limb = word[i];
            let lower_limb = limb & ((1 << nb_bits_to_shift) - 1);
            let higher_limb_val = limb >> nb_bits_to_shift;
            self.higher_limb[i] = F::from_canonical_u16(higher_limb_val);
            record.add_bit_range_check(lower_limb, nb_bits_to_shift as u8);
            record.add_bit_range_check(higher_limb_val, (16 - nb_bits_to_shift) as u8);
        }

        expected
    }

    pub fn eval<CB: ChipLookupBuilder<F>>(
        builder: &mut CB,
        input: [CB::Var; 2],
        shift: usize,
        cols: FixedShiftRightU32Gadget<CB::Var>,
        is_real: CB::Var,
    ) {
        builder.assert_bool(is_real);

        let nb_limbs_to_shift = shift / 16;
        let nb_bits_to_shift = shift % 16;
        let carry_multiplier = CB::F::from_canonical_u32(1 << (16 - nb_bits_to_shift));

        let input_limbs_shifted: [CB::Expr; 2] = std::array::from_fn(|i| {
            if i + nb_limbs_to_shift < 2 {
                input[i + nb_limbs_to_shift].into()
            } else {
                CB::Expr::ZERO
            }
        });

        let mut lower_limb = [CB::Expr::ZERO, CB::Expr::ZERO];
        for i in 0..2 {
            let limb = input_limbs_shifted[i].clone();

            lower_limb[i] =
                limb - cols.higher_limb[i] * CB::F::from_canonical_u32(1 << nb_bits_to_shift);

            // Check that `lower_limb < 2^(bit_shift)`
            builder.looking_byte(
                CB::F::from_canonical_u32(ByteOpcode::BitRange as u32),
                lower_limb[i].clone(),
                CB::F::from_canonical_u32(nb_bits_to_shift as u32),
                CB::F::ZERO,
                is_real,
            );
            // Check that `higher_limb < 2^(16 - bit_shift)`
            builder.looking_byte(
                CB::F::from_canonical_u32(ByteOpcode::BitRange as u32),
                cols.higher_limb[i],
                CB::F::from_canonical_u32((16 - nb_bits_to_shift) as u32),
                CB::F::ZERO,
                is_real,
            );
        }

        builder
            .when(is_real)
            .assert_eq(cols.value[1], cols.higher_limb[1]);
        builder.when(is_real).assert_eq(
            cols.value[0],
            cols.higher_limb[0] + lower_limb[1].clone() * carry_multiplier,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::folder::SymbolicConstraintFolder;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use pico_derive::AlignedBorrow;
    use std::borrow::Borrow;
    use p3_air::AirBuilder;
    use std::mem::size_of;

    #[derive(AlignedBorrow, Clone, Copy)]
    #[repr(C)]
    struct TestCols<T> {
        input: [T; 2],
        shift_right_u32: FixedShiftRightU32Gadget<T>,
        is_real: T,
    }

    #[test]
    fn test_shift_right_u32_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        FixedShiftRightU32Gadget::<KoalaBear>::eval(
            &mut builder,
            local.input,
            7,
            local.shift_right_u32,
            local.is_real,
        );
    }
}
