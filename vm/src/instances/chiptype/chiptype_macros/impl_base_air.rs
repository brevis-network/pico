#[macro_export]
macro_rules! impl_base_air {
    ($enum_name:ident, $F:ident, [ $( ($variant:ident, $chip_type:ident) ),+ ]) => {

        impl<$F: PrimeField32, const HALF_EXTERNAL_ROUNDS: usize, const NUM_INTERNAL_ROUNDS: usize> BaseAir<$F> for $enum_name<$F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>
        where Poseidon2PermuteChip<$F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>: BaseAir<F> {
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
