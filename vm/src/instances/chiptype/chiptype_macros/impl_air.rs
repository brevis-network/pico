#[macro_export]
macro_rules! impl_air {
    ($enum_name:ident, $F:ident, [ $( ($variant:ident, $chip_type:ident) ),+ ]) => {
        impl<$F: PrimeField32 + $crate::machine::field::FieldSpecificPoseidon2Config, CB: ChipBuilder<$F>> Air<CB> for $enum_name<$F>
        where
            Poseidon2Chip<$F>: Air<CB>,
        {
            fn eval(&self, b: &mut CB) {
                match self {
                    $( Self::$variant(chip) => chip.eval(b), )+
                }
            }
        }
    };
}
