use crate::{
    compiler::program::ProgramBehavior,
    emulator::record::RecordBehavior,
    machine::{
        builder::{ChipBuilder, PermutationBuilder},
        folder::SymbolicConstraintFolder,
        lookup::{LookupScope, VirtualPairLookup},
        permutation::{eval_permutation_constraints, generate_permutation_trace, get_grouped_maps},
        utils::get_log_quotient_degree,
    },
};
use p3_air::{Air, BaseAir};
use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;
use tracing::debug;

/// Chip behavior
pub trait ChipBehavior<F: Field>: BaseAir<F> + Sync {
    type Record: RecordBehavior;

    type Program: ProgramBehavior<F>;

    /// Returns the name of the chip.
    fn name(&self) -> String;

    fn generate_preprocessed(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
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
    pub(crate) looking: Vec<VirtualPairLookup<F>>,
    /// messages for chip as looked table
    pub(crate) looked: Vec<VirtualPairLookup<F>>,
    /// log degree of quotient polynomial
    log_quotient_degree: usize,
}

impl<F: Field, C: ChipBehavior<F>> MetaChip<F, C> {
    pub fn new(chip: C) -> Self
    where
        C: ChipBehavior<F> + Air<SymbolicConstraintFolder<F>>,
    {
        let mut builder = SymbolicConstraintFolder::new(chip.preprocessed_width(), chip.width());
        chip.eval(&mut builder);
        let (looking, looked) = builder.lookups();

        // need to dive deeper, currently following p3.
        let log_quotient_degree = get_log_quotient_degree::<F, C>(
            &chip,
            chip.preprocessed_width(),
            !(looking.is_empty() && looked.is_empty()),
        );

        debug!(
            "new chip {:<21} pre_width {:<2} quotient_degree {:<2} looking_len {:<3} looked_len {:<3}",
            chip.name(),
            chip.preprocessed_width(),
            log_quotient_degree,
            looking.len(),
            looked.len()
        );
        Self {
            chip,
            looking,
            looked,
            log_quotient_degree,
        }
    }

    pub fn generate_permutation<EF: ExtensionField<F>>(
        &self,
        preprocessed: Option<&RowMajorMatrix<F>>,
        main: &RowMajorMatrix<F>,
        perm_challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, EF) {
        let batch_size = 1 << self.log_quotient_degree;

        generate_permutation_trace(
            &self.looking,
            &self.looked,
            preprocessed,
            main,
            perm_challenges,
            batch_size,
        )
    }

    /// Returns the width of the permutation trace.
    #[inline]
    pub fn permutation_width(&self) -> usize {
        let (_, _, grouped_widths) =
            get_grouped_maps(&self.looking, &self.looked, self.logup_batch_size());

        grouped_widths
            .get(&LookupScope::Regional)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns the log2 of the batch size.
    #[inline]
    pub const fn logup_batch_size(&self) -> usize {
        1 << self.log_quotient_degree
    }

    pub fn get_log_quotient_degree(&self) -> usize {
        self.log_quotient_degree
    }

    /// The looking of the chip.
    pub fn get_looking(&self) -> &[VirtualPairLookup<F>] {
        &self.looking
    }

    pub fn get_looked(&self) -> &[VirtualPairLookup<F>] {
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
    CB: ChipBuilder<F> + PermutationBuilder,
{
    fn eval(&self, builder: &mut CB) {
        self.chip.eval(builder);
        eval_permutation_constraints(
            &self.looking,
            &self.looked,
            1 << self.log_quotient_degree,
            self.lookup_scope(),
            builder,
        )
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
