#[macro_export]
macro_rules! impl_chip_behavior {
    ($enum_name:ident, $F:ident, [ $( ($variant:ident, $chip_type:ident) ),+ ]) => {

        impl<$F: PrimeField32 + $crate::machine::field::FieldSpecificPoseidon2Config> ChipBehavior<$F> for $enum_name<$F> {
            type Record = EmulationRecord;
            type GpuRecord = FFIEmulationRecord;
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

            fn gpu_generate_preprocessed(&self, device_id: usize, program: &Program) -> Option<TraceData<'_, $F>> {
                match self {
                    $(
                        Self::$variant(chip) => chip.gpu_generate_preprocessed(device_id, program),
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

            fn local_only(&self) -> bool {
                match self {
                    $(
                        Self::$variant(chip) => chip.local_only(),
                    )+
                }
            }

            fn gpu_generate_main(&self, device_id: usize, input: &Self::Record, output: &mut Self::Record, gpu_input: Option<&Self::GpuRecord>) -> TraceData<'_, $F> {
                match self {
                    $(
                        Self::$variant(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
                    )+
                }
            }

            fn is_active_for_extra_record(&self, prepared_events: &PreparedGpuEvents) -> bool {
                match self {
                    $(
                        Self::$variant(chip) => chip.is_active_for_extra_record(prepared_events),
                    )+
                }
            }

            fn gpu_generate_extra_record_and_main(&self, device_id: usize, input: &Self::Record, prepared_events: &PreparedGpuEvents, preallocated_gpu_memory: &mut PreallocatedGpuMemory) -> TraceData<'_, $F> {
                match self {
                    $(
                        Self::$variant(chip) => chip.gpu_generate_extra_record_and_main(device_id, input, prepared_events, preallocated_gpu_memory),
                    )+
                }
            }
        }
    };
}
