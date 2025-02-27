#[macro_export]
macro_rules! enum_chip_type {
    ($variant:ident, RangeCheckChip<$F:ident>) => {
        RangeCheckChip<EmulationRecord, Program, $F>
    };

    ($variant:ident, EdAddAssignChip<$F:ident>) => {
        EdAddAssignChip<$F, Ed25519>
    };

    ($variant:ident, EdDecompressChip<$F:ident>) => {
        EdDecompressChip<$F, Ed25519Parameters>
    };

    ($variant:ident, $chip_type:ident<$F:ident>) => {
        $chip_type<$F>
    };
}
