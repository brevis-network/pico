use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{get_log_quotient_degree, SymbolicAirBuilder};
use pico_compiler::record::ExecutionRecord;

/// Chip behavior
pub trait ChipBehavior<F: Field>: BaseAir<F> + Air<SymbolicAirBuilder<F>> + Sync {
    /// Returns the name of the chip.
    fn name(&self) -> String;

    fn generate_preprocessed(&self, _input: &ExecutionRecord) -> Option<RowMajorMatrix<F>> {
        None
    }

    fn generate_main(&self, input: &ExecutionRecord) -> RowMajorMatrix<F>;

    fn preprocessed_width(&self) -> usize {
        0
    }
}

/// Chip builder
pub trait ChipBuilder<F: Field>: AirBuilder<F = F> {}
impl<F: Field> ChipBuilder<F> for SymbolicAirBuilder<F> {}

/// Chip wrapper, includes interactions
pub struct BaseChip<F: Field, C> {
    /// Underlying chip
    chip: C,
    // Interactions that the chip sends, ignore for now
    sends: Vec<F>,
    // Interactions that the chip receives, ignore for now
    receives: Vec<F>,
    /// log degree of quotient polynomial
    log_quotient_degree: usize,
}

impl<F: Field, C> BaseChip<F, C> {
    pub fn new(chip: C) -> Self
    where
        C: ChipBehavior<F>,
    {
        // need to dive deeper, currently following p3 and some constants aren't included in chip.rs of sp1
        let log_quotient_degree =
            get_log_quotient_degree::<F, C>(&chip, chip.preprocessed_width(), 0);
        Self {
            chip,
            sends: vec![],
            receives: vec![],
            log_quotient_degree,
        }
    }

    pub fn get_log_quotient_degree(&self) -> usize {
        self.log_quotient_degree
    }
}

/// BaseAir implementation for the chip
impl<F, C> BaseAir<F> for BaseChip<F, C>
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
impl<F, C, CB> Air<CB> for BaseChip<F, C>
where
    F: Field,
    C: Air<CB>,
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        self.chip.eval(builder);
    }
}

/// Chip Behavior implementation for the chip
impl<F, C> ChipBehavior<F> for BaseChip<F, C>
where
    F: Field,
    C: ChipBehavior<F>,
{
    fn name(&self) -> String {
        self.chip.name()
    }

    fn generate_preprocessed(&self, input: &ExecutionRecord) -> Option<RowMajorMatrix<F>> {
        self.chip.generate_preprocessed(input)
    }

    fn generate_main(&self, input: &ExecutionRecord) -> RowMajorMatrix<F> {
        self.chip.generate_main(input)
    }
}

#[cfg(test)]
mod test {}
