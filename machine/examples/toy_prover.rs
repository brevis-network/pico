use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_chips::chips::toy::ToyChip;
use pico_compiler::program::Program;
use pico_configs::{bb_poseidon2::BabyBearPoseidon2, config::StarkGenericConfig};
use pico_emulator::{executor::Executor, opts::PicoCoreOpts, record::EmulationRecord};
use pico_machine::{
    chip::{ChipBehavior, ChipBuilder, MetaChip},
    prover::BaseProver,
    verifier::BaseVerifier,
};
use std::any::type_name;

pub enum ToyChipType<F: Field> {
    Toy(ToyChip<F>),
}

// NOTE: These trait implementations are used to save this `ToyChipType` to `MetaChip`.
// Since MetaChip has a generic parameter which is one type (cannot be two chip types).
// This code is annoyed, we could refactor to use macro later (but less readable).
impl<F: Field> ChipBehavior<F> for ToyChipType<F> {
    fn name(&self) -> String {
        match self {
            Self::Toy(chip) => chip.name(),
        }
    }

    fn generate_preprocessed(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Toy(chip) => chip.generate_preprocessed(program),
        }
    }

    fn generate_main(&self, input: &EmulationRecord) -> RowMajorMatrix<F> {
        match self {
            Self::Toy(chip) => chip.generate_main(input),
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
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        vec![MetaChip::new(Self::Toy(ToyChip::default()))]
    }
}

fn print_type_of<T>(_: &T) {
    println!("Type: {}", type_name::<T>());
}

fn main() {
    println!("Creating Program..");
    const ELF: &[u8] = include_bytes!("../../compiler/test_data/riscv32im-succinct-zkvm-elf");
    let program = Program::from(ELF).unwrap();

    println!("Creating Runtime..");
    let mut runtime = Executor::new(program, PicoCoreOpts::default());
    runtime.state.input_stream.push(vec![2, 0, 0, 0]);
    runtime.run().unwrap();

    let record = &runtime.records[0];

    // Create the prover.
    println!("Creating prover");
    let config = BabyBearPoseidon2::new();

    let chips = ToyChipType::all_chips();
    let prover = BaseProver::new();

    // Setup PK and VK.
    println!("Setup PK and VK");
    let (pk, vk) = prover.setup_keys(&config, &chips, &record.program);

    println!("Generating proof");
    let mut challenger = config.challenger();
    // Generate the proof.
    let proof = prover.prove(&config, &chips, &pk, &mut challenger, record);

    // Create the verifier.
    println!("Creating verifier");
    // let verifier = ToyChipType::get_verifier(&config);
    //let chips = ToyChipType::all_chips();
    let verifier = BaseVerifier::new();

    // Verify the proof.
    println!("Verifying proof");
    let mut challenger = config.challenger();
    let result = verifier.verify(&config, &chips, &vk, &mut challenger, &proof);
    println!("The proof is verified: {}", result.is_ok());
}
