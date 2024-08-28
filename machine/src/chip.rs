use p3_air::{Air, BaseAir, AirBuilder};
use p3_field::{Field, ExtensionField};
use p3_matrix::dense::RowMajorMatrix;

pub trait ChipBahavior<F: Field>: Air<F> + BaseAir<F> {
    /// Returns the name of the chip.
    fn name(&self) -> String;

    fn generate_preprocessed(&self) -> Option<RowMajorMatrix<F>>;

    fn generate_main(&self) -> RowMajorMatrix<F>;
}

pub struct Chip<F: Field, C: ChipBehavior<F>, B: Air> {
    /// Underlying chip
    chip: C,
    /// Interactions that the chip sends, ignore for now
    // sends: Vec<Interaction<F>>,
    /// Interactions that the chip receives, ignore for now
    // receives: Vec<Interaction<F>>,
}

impl<F, C> Chip<F, C>
where
    F: Field,
    C: ChipBehavior<F>,
{
    pub fn new(chip: C) -> Self { }

    pub fn generate_permutation<EF: ExtensionField<F>>( ) -> RowMajorMatrix<EF> { }
}

impl<F, C> BaseAir<F> for Chip<F, C>
where
    F: Field,
    C: ChipBahavior<F>,
{
    fn width(&self) -> usize {
        self.chip.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        panic!("Chip should not use the `BaseAir` method, but the `ChipBehavior` method.")
    }
}

impl<F, C, AB> Air<AB> for Chip<F, C>
where
    F: Field,
    C: ChipBahavior<F>,
    AB: AirBuilder<F>,
{
    fn eval(&self, builder: &mut AB) {
        self.chip.eval(builder);
        eval_permutation(builder);
    }

    fn eval_permutation(&self, builder: &mut AB) { }
}