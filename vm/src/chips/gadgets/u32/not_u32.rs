use crate::{machine::builder::ChipBuilder, primitives::consts::u32_to_u16_limbs};
use p3_air::AirBuilder;
use p3_field::Field;
use pico_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct NotU32Gadget<T> {
    pub value: [T; 2],
}

impl<F: Field> NotU32Gadget<F> {
    pub fn populate(&mut self, a: u32) -> u32 {
        let expected = !a;
        let a_limbs = u32_to_u16_limbs(a);
        self.value = [
            F::from_canonical_u16(!a_limbs[0]),
            F::from_canonical_u16(!a_limbs[1]),
        ];
        expected
    }

    pub fn eval<CB: ChipBuilder<F>>(
        builder: &mut CB,
        a: [CB::Var; 2],
        cols: NotU32Gadget<CB::Var>,
        is_real: CB::Var,
    ) {
        builder.assert_bool(is_real);

        for i in 0..2 {
            builder
                .when(is_real)
                .assert_eq(cols.value[i] + a[i], CB::F::from_canonical_u16(u16::MAX));
        }
    }
}
