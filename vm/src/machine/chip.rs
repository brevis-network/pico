use crate::{
    chips::trace::TraceData,
    compiler::program::ProgramBehavior,
    cuda_adaptor::resource_pool::stream_pool::get_global_stream_pool,
    emulator::record::RecordBehavior,
    instances::preparer::{EventCounter, PreallocatedGpuMemory, PreparedGpuEvents},
    machine::{
        builder::ChipBuilder,
        lookup::{LookupScope, LookupSummary},
    },
    primitives::consts::MAX_NUM_PVS,
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use pico_mle_core::{
    air::symbolic::{get_symbolic_builder_with_public_values, SymbolicRapBuilder},
    keygen::types::TraceWidth,
};
use std::marker::PhantomData;
use tracing::debug;

/// A chip's declared preprocessed height, from [`ChipBehavior::preprocessed_rows`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreprocessedRows {
    /// Raw, unpadded row count; the caller pads it the way the generators do (the program's
    /// shape if present, else `next_power_of_two`'s 16-row floor).
    Unpadded(usize),
    /// Padded to `1 << log2` unconditionally; the chip never consults the program's shape
    /// (`PublicValuesChip`, which hardcodes `PUB_VALUES_LOG_HEIGHT`).
    FixedLog2(usize),
}

/// Chip behavior
pub trait ChipBehavior<F: Field>: BaseAir<F> + Sync {
    type Record: RecordBehavior;
    type GpuRecord;

    type Program: ProgramBehavior<F>;

    /// Returns the name of the chip.
    fn name(&self) -> String;

    fn generate_preprocessed(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        None
    }

    /// Declared preprocessed height, derived from the program without building the trace; the
    /// width comes from [`Self::preprocessed_width`]. `None` means "not declared" — the caller
    /// falls back to [`Self::generate_preprocessed`].
    ///
    /// A declaration must reproduce the generator's row count exactly; the parity test in
    /// `mle::machine::recursion::chips` checks every chip against its own generator.
    fn preprocessed_rows(&self, _program: &Self::Program) -> Option<PreprocessedRows> {
        None
    }

    /// Emulate record to extract extra record
    fn extra_record(&self, _input: &Self::Record, _extra: &mut Self::Record) {}

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F>;

    fn preprocessed_width(&self) -> usize {
        0
    }

    fn is_active(&self, record: &Self::Record) -> bool;

    /// Get the lookup scope for the chip. It's used in core prover.
    /// Set to local scope as default.
    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Regional
    }

    /// Specifies whether the air only uses the local row, and not the next row.
    fn local_only(&self) -> bool {
        false
    }

    fn gpu_generate_preprocessed(
        &self,
        _device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        self.generate_preprocessed(program).map(TraceData::Cpu)
    }

    fn gpu_generate_main(
        &self,
        _device_id: usize,
        input: &Self::Record,
        output: &mut Self::Record,
        _gpu_input: Option<&Self::GpuRecord>,
    ) -> TraceData<'_, F> {
        TraceData::Cpu(self.generate_main(input, output))
    }

    fn debug_gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        output: &mut Self::Record,
        gpu_input: Option<&Self::GpuRecord>,
    ) -> TraceData<'_, F> {
        // TODO: change to prover related device ID
        let sync_stream = get_global_stream_pool(device_id);
        let stream = &sync_stream.0;

        let trace_data = self.gpu_generate_main(device_id, input, output, gpu_input);
        let host_gpu_trace = trace_data.to_host(stream);

        match trace_data {
            TraceData::Gpu(_, gpu_trace) => {
                let cpu_trace = self.generate_main(input, output);

                // compare the cpu and gpu traces
                let chip_name = self.name();
                let width = cpu_trace.width();
                assert_eq!(
                    cpu_trace.values.len(),
                    host_gpu_trace.values.len(),
                    "[debug_gpu_generate_main] {} chip: trace lengths are not equal",
                    chip_name,
                );
                assert_eq!(
                    cpu_trace.values[0..width],
                    host_gpu_trace.values[0..width],
                    "[debug_gpu_generate_main] {} chip: first rows are not equal",
                    chip_name,
                );
                assert_eq!(
                    cpu_trace.values, host_gpu_trace.values,
                    "[debug_gpu_generate_main] {} chip: total trace values are not equal",
                    chip_name,
                );

                TraceData::Debug(cpu_trace, gpu_trace)
            }
            TraceData::Cpu(_) | TraceData::Debug(_, _) => trace_data,
        }
    }

    fn count_extra_records(_record: &Self::Record, _counter: &mut EventCounter) {}

    fn gpu_generate_extra_record_and_main(
        &self,
        _device_id: usize,
        input: &Self::Record,
        _prepared_gpu_events: &PreparedGpuEvents,
        _preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        TraceData::Cpu(self.generate_main(input, &mut Self::Record::default()))
    }

    fn is_active_for_extra_record(&self, _record: &PreparedGpuEvents) -> bool {
        false
    }
}

/// Chip wrapper, includes interactions
#[derive(Clone, Debug)]
pub struct MetaChip<F: Field, C> {
    /// Underlying chip
    pub chip: C,
    /// bus + scope of every lookup the chip sends
    pub(crate) looking: Vec<LookupSummary>,
    /// bus + scope of every lookup the chip receives
    pub(crate) looked: Vec<LookupSummary>,
    _field: PhantomData<F>,
}

impl<F: Field, C: ChipBehavior<F>> MetaChip<F, C> {
    pub fn new(chip: C) -> Self
    where
        C: ChipBehavior<F> + Air<SymbolicRapBuilder<F>>,
    {
        // Same symbolic evaluation the MLE keygen runs, sized like the legacy folder was
        // (`MAX_NUM_PVS` public values, so every chip's PV reads resolve regardless of which
        // machine it lands in); only the lookup summaries are kept.
        let preprocessed_width = chip.preprocessed_width();
        let width = TraceWidth {
            preprocessed: (preprocessed_width > 0).then_some(preprocessed_width),
            cached_mains: vec![],
            common_main: chip.width(),
        };
        let builder = get_symbolic_builder_with_public_values(&chip, &width, MAX_NUM_PVS);
        let (looking, looked) = builder.lookup_summaries();
        let (looking, looked) = (looking.to_vec(), looked.to_vec());

        debug!(
            "new chip {:<21} pre_width {:<2} looking_len {:<3} looked_len {:<3}",
            chip.name(),
            preprocessed_width,
            looking.len(),
            looked.len()
        );

        Self {
            chip,
            looking,
            looked,
            _field: PhantomData,
        }
    }

    /// Create a new chip without any lookup constraints.
    /// Useful for testing individual chips without lookup dependencies.
    pub fn test_no_lookup(chip: C) -> Self
    where
        C: ChipBehavior<F> + Air<SymbolicRapBuilder<F>>,
    {
        let mut chip = Self::new(chip);
        chip.looking.clear();
        chip.looked.clear();
        chip
    }

    /// The looking of the chip.
    pub fn get_looking(&self) -> &[LookupSummary] {
        &self.looking
    }

    pub fn get_looked(&self) -> &[LookupSummary] {
        &self.looked
    }

    pub fn lookup_scope(&self) -> LookupScope {
        self.chip.lookup_scope()
    }

    pub fn local_only(&self) -> bool {
        self.chip.local_only()
    }
}

/// BaseAir implementation for the chip
impl<F, C> BaseAir<F> for MetaChip<F, C>
where
    F: Field,
    C: BaseAir<F>,
{
    fn width(&self) -> usize {
        self.chip.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        panic!("Chip should not use the `BaseAir` method, but the `ChipBehavior` method.")
    }
}

/// Air implementation for the chip
impl<F, C, CB> Air<CB> for MetaChip<F, C>
where
    F: Field,
    C: Air<CB> + ChipBehavior<F>,
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        self.chip.eval(builder);
    }
}

/// Chip Behavior implementation for the chip
impl<F, C> ChipBehavior<F> for MetaChip<F, C>
where
    F: Field,
    C: ChipBehavior<F>,
{
    type Record = C::Record;
    type GpuRecord = C::GpuRecord;
    type Program = C::Program;

    fn name(&self) -> String {
        self.chip.name()
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        self.chip.generate_preprocessed(program)
    }

    /// Forwarded alongside `generate_preprocessed`: falling through to the trait default would
    /// report "does not declare" for a chip that does, sending merged deferred-commit keygen back
    /// to generating the trace.
    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        self.chip.preprocessed_rows(program)
    }

    fn extra_record(&self, input: &C::Record, extra: &mut C::Record) {
        self.chip.extra_record(input, extra);
    }

    fn generate_main(&self, input: &C::Record, output: &mut C::Record) -> RowMajorMatrix<F> {
        self.chip.generate_main(input, output)
    }

    fn preprocessed_width(&self) -> usize {
        self.chip.preprocessed_width()
    }

    fn is_active(&self, record: &C::Record) -> bool {
        self.chip.is_active(record)
    }

    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        self.chip.gpu_generate_preprocessed(device_id, program)
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &C::Record,
        output: &mut C::Record,
        gpu_input: Option<&C::GpuRecord>,
    ) -> TraceData<'_, F> {
        self.chip
            .gpu_generate_main(device_id, input, output, gpu_input)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        self.chip.is_active_for_extra_record(record)
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &C::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        self.chip.gpu_generate_extra_record_and_main(
            device_id,
            input,
            prepared_gpu_events,
            preallocated_gpu_memory,
        )
    }
}
