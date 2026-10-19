use crate::{
    compiler::program::ProgramBehavior,
    emulator::record::RecordBehavior,
    machine::{
        builder::ChipBuilder,
        lookup::{LookupScope, LookupSummary},
    },
    primitives::consts::MAX_NUM_PVS,
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
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
}

/// Chip wrapper, includes interactions
#[derive(Clone, Debug)]
pub struct MetaChip<F: Field, C> {
    /// Underlying chip
    chip: C,
    /// messages for chip as looking table
    pub(crate) looking: Vec<LookupSummary>,
    /// messages for chip as looked table
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
            chip.preprocessed_width(),
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
}
