use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::{Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SymbolicAirBuilder;
use pico_chips::toy::ToyChip;
use pico_configs::{
    bb_poseidon2::BabyBearPoseidon2,
    config::{StarkGenericConfig, Val},
};
use pico_machine::{
    chip::{BaseChip, ChipBehavior, ChipBuilder},
    folder::ProverConstraintFolder,
    prover::BaseProver,
    verifier::BaseVerifier,
};
use std::marker::PhantomData;

pub enum ToyChipType<F: Field> {
    Toy(ToyChip<F>),
}

// NOTE: These trait implementations are used to save this `ToyChipType` to `BaseChip`.
// Since BaseChip has a generic parameter which is one type (cannot be two chip types).
// This code is annoyed, we could refactor to use macro later (but less readable).
impl<F: Field> ChipBehavior<F> for ToyChipType<F> {
    fn name(&self) -> String {
        match self {
            Self::Toy(chip) => chip.name(),
        }
    }

    fn generate_preprocessed(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Toy(chip) => chip.generate_preprocessed(),
        }
    }

    fn generate_main(&self) -> RowMajorMatrix<F> {
        match self {
            Self::Toy(chip) => chip.generate_main(),
        }
    }
}
impl<F: Field> BaseAir<F> for ToyChipType<F> {
    fn width(&self) -> usize {
        match self {
            Self::Toy(chip) => chip.width(),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Toy(chip) => chip.preprocessed_trace(),
        }
    }
}

impl<F, CB> Air<CB> for ToyChipType<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, b: &mut CB) {
        match self {
            Self::Toy(chip) => chip.eval(b),
        }
    }
}

/// Factory for creating prover and verifier instances
trait ProvingFactory<SC: StarkGenericConfig> {
    /// Create a new prover.
    fn get_prover(config: &SC) -> BaseProver<SC, ToyChipType<Val<SC>>>;

    /// Create a new verifier.
    fn get_verifier(config: &SC) -> BaseVerifier<SC, ToyChipType<Val<SC>>>;
}

impl<SC: StarkGenericConfig> ProvingFactory<SC> for ToyChipType<Val<SC>> {
    fn get_prover(config: &SC) -> BaseProver<SC, Self> {
        // }-> BaseProver<'a, SC, Self> {
        let chips = Self::all_chips();

        BaseProver::new(config, chips)
    }

    fn get_verifier(config: &SC) -> BaseVerifier<SC, Self> {
        // }-> BaseProver<'a, SC, Self> {
        let chips = Self::all_chips();

        BaseVerifier::new(config, chips)
    }
}

impl<F: Field> ToyChipType<F> {
    pub fn all_chips() -> Vec<BaseChip<F, Self>> {
        vec![BaseChip::new(Self::Toy(ToyChip::default()))]
    }
}

fn main() {
    // Create the prover.
    println!("Creating prover");
    let config = BabyBearPoseidon2::new();
    let prover = ToyChipType::get_prover(&config);

    // Setup PK and VK.
    println!("Setup PK and VK");
    let (pk, vk) = prover.setup_keys_for_main();

    println!("Generating proof");
    let mut challenger = config.challenger();
    // Generate the proof.
    let proof = prover.prove(&pk, &mut challenger);

    // Create the verifier.
    println!("Creating verifier");
    let verifier = ToyChipType::get_verifier(&config);

    // Verify the proof.
    println!("Verifying proof");
    let mut challenger = config.challenger();
    let result = verifier.verify(&vk, &mut challenger, &proof);
    println!("The proof is verified: {}", result.is_ok());
}
