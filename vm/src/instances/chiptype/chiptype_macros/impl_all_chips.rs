#[macro_export]
macro_rules! impl_all_chips {
    ($enum_name:ident, $F:ident, [ $( ($variant:ident, $chip_type:ident) ),+ ]) => {

        impl<$F: PrimeField32, const HALF_EXTERNAL_ROUNDS: usize, const NUM_INTERNAL_ROUNDS: usize> $enum_name<$F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>
        where Poseidon2PermuteChip<$F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>: ChipBehavior<$F, Record = EmulationRecord, Program = Program> {
            pub fn all_chips() -> Vec<MetaChip<$F, Self>> {
                vec![
                    $(
                        $crate::define_meta_chip!($variant, $chip_type, $F)
                    ),+
                ]
            }
        }
    };
}
