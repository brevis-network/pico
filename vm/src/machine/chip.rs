use crate::{
    compiler::program::ProgramBehavior,
    emulator::record::RecordBehavior,
    machine::{
        builder::{ChipBuilder, LookupBuilder, PermutationBuilder},
        folder::SymbolicConstraintFolder,
        lookup::VirtualPairLookup,
        permutation::{
            eval_permutation_constraints, generate_permutation_trace, permutation_trace_width,
        },
        utils::get_log_quotient_degree,
    },
};
use log::debug;
use p3_air::{Air, BaseAir};
use p3_field::{ExtensionField, Field};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use std::time::Instant;

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
    fn extra_record(&self, _input: &mut Self::Record, _extra: &mut Self::Record) {}

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F>;

    fn preprocessed_width(&self) -> usize {
        0
    }

    fn is_active(&self, record: &Self::Record) -> bool;
}

/// Chip wrapper, includes interactions
pub struct MetaChip<F: Field, C> {
    /// Underlying chip
    chip: C,
    /// messages for chip as looking table
    looking: Vec<VirtualPairLookup<F>>,
    /// messages for chip as looked table
    looked: Vec<VirtualPairLookup<F>>,
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

        // need to dive deeper, currently following p3 and some constants aren't included in chip.rs of sp1
        let log_quotient_degree = get_log_quotient_degree::<F, C>(
            &chip,
            chip.preprocessed_width(),
            !(looking.is_empty() && looked.is_empty()),
        );

        debug!(
            "{:<17} pre_width {:<2} quotient_degree {:<2} looking_len {:<3} looked_len {:<3}",
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
    ) -> RowMajorMatrix<EF> {
        let begin = Instant::now();
        let batch_size = 1 << self.log_quotient_degree;

        // Generate the RLC elements to uniquely identify each interaction.
        let alpha = perm_challenges[0];

        // Generate the RLC elements to uniquely identify each item in the looked up tuple.
        let beta = perm_challenges[1];

        let trace = generate_permutation_trace(
            &self.looking,
            &self.looked,
            preprocessed,
            main,
            alpha,
            beta,
            batch_size,
        );
        debug!(
            "generated permutation: {:<17} | width {:<4} rows {:<8} cells {:<11} | in {:?}",
            self.name(),
            trace.width(),
            trace.height(),
            trace.values.len(),
            begin.elapsed()
        );
        trace
    }

    /// Returns the width of the permutation trace.
    #[inline]
    pub fn permutation_width(&self) -> usize {
        permutation_trace_width(
            self.looking.len() + self.looked.len(),
            self.logup_batch_size(),
        )
    }

    /// Returns the log2 of the batch size.
    #[inline]
    pub const fn logup_batch_size(&self) -> usize {
        1 << self.log_quotient_degree
    }

    pub fn get_log_quotient_degree(&self) -> usize {
        self.log_quotient_degree
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
    C: Air<CB>,
    CB: ChipBuilder<F> + PermutationBuilder,
{
    fn eval(&self, builder: &mut CB) {
        self.chip.eval(builder);
        eval_permutation_constraints(
            &self.looking,
            &self.looked,
            1 << self.log_quotient_degree,
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

    fn extra_record(&self, input: &mut C::Record, extra: &mut C::Record) {
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

#[cfg(test)]
mod test {}
