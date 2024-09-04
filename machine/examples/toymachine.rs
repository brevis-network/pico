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
    folder::{ProverConstraintFolder, VerifierConstraintFolder},
    prover::BaseProver,
    utils::{get_prover, get_verifier},
    verifier::BaseVerifier,
};
use std::{any::type_name, marker::PhantomData};

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

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Toy(chip) => chip.preprocessed_width(),
        }
    }
}
impl<F: Field> BaseAir<F> for ToyChipType<F> {
    fn width(&self) -> usize {
        match self {
            Self::Toy(chip) => chip.width(),
        }
    }

    /// todo: this should not be called. all should go to generate_preprocessed.
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

impl<F: Field> ToyChipType<F> {
    pub fn all_chips() -> Vec<BaseChip<F, Self>> {
        vec![BaseChip::new(Self::Toy(ToyChip::default()))]
    }
}

fn print_type_of<T>(_: &T) {
    println!("Type: {}", type_name::<T>());
}

fn main() {
    // Create the prover.
    println!("Creating prover");
    let config = BabyBearPoseidon2::new();

    //println!("{:?}", Val<config>);
    let chips = ToyChipType::all_chips();
    let prover = get_prover(&config, chips);

    // Setup PK and VK.
    println!("Setup PK and VK");
    let (pk, vk) = prover.setup_keys_for_main();

    println!("Generating proof");
    let mut challenger = config.challenger();
    // Generate the proof.
    let proof = prover.prove(&pk, &mut challenger);

    // Create the verifier.
    println!("Creating verifier");
    // let verifier = ToyChipType::get_verifier(&config);
    let chips = ToyChipType::all_chips();
    let verifier = get_verifier(&config, chips);

    // Verify the proof.
    println!("Verifying proof");
    let mut challenger = config.challenger();
    let result = verifier.verify(&vk, &mut challenger, &proof);
    println!("The proof is verified: {}", result.is_ok());
}
