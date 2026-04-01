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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::folder::SymbolicConstraintFolder;
    use crate::machine::builder::PublicValuesBuilder;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use pico_derive::AlignedBorrow;
    use std::borrow::Borrow;
    use p3_air::AirBuilder;
    use std::mem::size_of;

    #[derive(AlignedBorrow, Clone, Copy)]
    #[repr(C)]
    struct TestCols<T> {
        a: [T; 2],
        not_u32: NotU32Gadget<T>,
        is_real: T,
    }

    #[test]
    fn test_not_u32_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        NotU32Gadget::<KoalaBear>::eval(
            &mut builder,
            local.a,
            local.not_u32,
            local.is_real,
        );
    
        assert_eq!(builder.num_constraints(), 3);
        assert_eq!(builder.public_values().len(), 119);
        assert_eq!(builder.num_lookups(), 0);
    }
}
