#[macro_export]
macro_rules! impl_chip_behavior {
    ($enum_name:ident, $F:ident, [ $( ($variant:ident, $chip_type:ident) ),+ ]) => {

        impl<$F: PrimeField32> ChipBehavior<$F> for $enum_name<$F> {
            type Record = EmulationRecord;
            type Program = Program;

            fn name(&self) -> String {
                match self {
                    $(
                        Self::$variant(chip) => chip.name(),
                    )+
                }
            }

            fn generate_preprocessed(&self, program: &Program) -> Option<RowMajorMatrix<$F>> {
                match self {
                    $(
                        Self::$variant(chip) => chip.generate_preprocessed(program),
                    )+
                }
            }

            fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<$F> {
                match self {
                    $(
                        Self::$variant(chip) => chip.generate_main(input, output),
                    )+
                }
            }

            fn preprocessed_width(&self) -> usize {
                match self {
                    $(
                        Self::$variant(chip) => chip.preprocessed_width(),
                    )+
                }
            }

            fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
                match self {
                    $(
                        Self::$variant(chip) => chip.extra_record(input, extra),
                    )+
                }
            }

            fn is_active(&self, record: &Self::Record) -> bool {
                match self {
                    $(
                        Self::$variant(chip) => chip.is_active(record),
                    )+
                }
            }

            fn lookup_scope(&self) -> LookupScope {
                match self {
                    $(
                        Self::$variant(chip) => chip.lookup_scope(),
                    )+
                }
            }
        }

    };
}
