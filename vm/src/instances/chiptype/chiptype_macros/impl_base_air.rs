#[macro_export]
macro_rules! impl_base_air {
    ($enum_name:ident, $F:ident, [ $( ($variant:ident, $chip_type:ident) ),+ ]) => {
        impl<$F> BaseAir<$F> for $enum_name<$F>
        where
            $F: PrimeField32 + $crate::machine::field::FieldSpecificPoseidon2Config,
        {
            fn width(&self) -> usize {
                match self {
                    $( Self::$variant(chip) => chip.width(), )+
                }
            }

            fn preprocessed_trace(&self) -> Option<RowMajorMatrix<$F>> {
                match self {
                    $( Self::$variant(chip) => chip.preprocessed_trace(), )+
                }
            }
        }
    };
}
