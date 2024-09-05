use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_chips::toy::ToyChip;
use pico_compiler::{events::alu::AluEvent, opcode::Opcode, record::ExecutionRecord};
use pico_configs::{bb_poseidon2::BabyBearPoseidon2, config::StarkGenericConfig};
use pico_machine::{
    chip::{BaseChip, ChipBehavior, ChipBuilder},
    utils::{get_prover, get_verifier},
};
use std::{any::type_name, collections::HashMap};

// Testing input events used to generate the main trace
const TEST_INPUT_EVENTS: [AluEvent; 5] = [
    AluEvent::new(Opcode::ADD, 1, 2, 3),
    AluEvent::new(Opcode::SUB, 6, 2, 4),
    AluEvent::new(Opcode::ADD, 4, 5, 9),
    AluEvent::new(Opcode::SUB, 6, 6, 0),
    AluEvent::new(Opcode::SUB, 9, 1, 8),
];

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

    fn generate_preprocessed(&self, input: &ExecutionRecord) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Toy(chip) => chip.generate_preprocessed(input),
        }
    }

    fn generate_main(&self, input: &ExecutionRecord) -> RowMajorMatrix<F> {
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
    pub fn all_chips() -> Vec<BaseChip<F, Self>> {
        vec![BaseChip::new(Self::Toy(ToyChip::default()))]
    }
}

fn print_type_of<T>(_: &T) {
    println!("Type: {}", type_name::<T>());
}

fn main() {
    // Create a test input exection record.
    let mut record = ExecutionRecord::new();
    let mut events = HashMap::new();
    TEST_INPUT_EVENTS.into_iter().for_each(|event| {
        events
            .entry(event.opcode)
            .or_insert_with(Vec::new)
            .push(event);
    });
    record.add_alu_events(events);

    // Create the prover.
    println!("Creating prover");
    let config = BabyBearPoseidon2::new();

    let chips = ToyChipType::all_chips();
    let prover = get_prover(&config, chips);

    // Setup PK and VK.
    println!("Setup PK and VK");
    let (pk, vk) = prover.setup_keys(&record);

    println!("Generating proof");
    let mut challenger = config.challenger();
    // Generate the proof.
    let proof = prover.prove(&pk, &mut challenger, &record);

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
