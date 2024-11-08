#[macro_export]
macro_rules! enum_chip_type {
    (RangeCheckChip<$F:ident>) => {
        RangeCheckChip<EmulationRecord, Program, $F>
    };

    ($chip_type:ident<$F:ident>) => {
        $chip_type<$F>
    };
}
