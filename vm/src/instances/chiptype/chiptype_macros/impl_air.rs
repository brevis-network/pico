#[macro_export]
macro_rules! impl_air {
    ($enum_name:ident, $F:ident, [ $( ($variant:ident, $chip_type:ident) ),+ ]) => {
        impl<$F, CB> Air<CB> for $enum_name<$F>
        where
            $F: PrimeField32 + $crate::machine::field::FieldSpecificPoseidon2Config,
            CB: ChipBuilder<$F> + $crate::machine::builder::ScopedBuilder,
            FieldSpecificPoseidon2Chip<$F>: Air<CB>,
            CB::Expr: std::any::Any,
        {
            fn eval(&self, b: &mut CB) {
                match self {
                    $( Self::$variant(chip) => chip.eval(b), )+
                }
            }
        }
    };
}
