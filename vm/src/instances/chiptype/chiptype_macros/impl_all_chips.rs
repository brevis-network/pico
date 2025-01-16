#[macro_export]
macro_rules! impl_all_chips {
    ($enum_name:ident, $F:ident, [ $( ($variant:ident, $chip_type:ident) ),+ ]) => {
        impl<$F: PrimeField32 + crate::machine::field::FieldSpecificPoseidon2Config> $enum_name<$F> {
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
