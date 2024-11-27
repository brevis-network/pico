#[macro_export]
macro_rules! enum_chip_type {
    (RangeCheckChip<$F:ident>) => {
        RangeCheckChip<EmulationRecord, Program, $F>
    };

    (EdAddAssignChip<$F:ident>) => {
        EdAddAssignChip<$F, Ed25519>
    };

    (EdDecompressChip<$F:ident>) => {
        EdDecompressChip<$F, Ed25519Parameters>
    };

    ($chip_type:ident<$F:ident>) => {
        $chip_type<$F>
    };
}
