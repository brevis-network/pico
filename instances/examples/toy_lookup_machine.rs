use log::info;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_chips::chips::examples::lookup_toy::{AddLookedChip, AddLookingChip};
use pico_compiler::program::Program;
use pico_configs::bb_poseidon2::BabyBearPoseidon2;
use pico_emulator::riscv::record::EmulationRecord;
use pico_instances::simple_machine::SimpleMachine;
use pico_machine::{
    builder::ChipBuilder,
    chip::{ChipBehavior, MetaChip},
    machine::MachineBehavior,
};
use std::sync::Arc;

pub enum LookupToyChipType<F: Field> {
    LookingChip(AddLookingChip<F>),
    LookedChip(AddLookedChip<F>),
}

impl<F: Field> LookupToyChipType<F> {
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::LookingChip(AddLookingChip::default())),
            MetaChip::new(Self::LookedChip(AddLookedChip::default())),
        ]
    }
}

impl<F: Field> ChipBehavior<F> for LookupToyChipType<F> {
    type Record = EmulationRecord;

    fn name(&self) -> String {
        match self {
            Self::LookingChip(chip) => chip.name(),
            Self::LookedChip(chip) => chip.name(),
        }
    }

    fn generate_preprocessed(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::LookingChip(chip) => chip.generate_preprocessed(program),
            Self::LookedChip(chip) => chip.generate_preprocessed(program),
        }
    }

    fn generate_main(&self, input: &Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::LookingChip(chip) => chip.generate_main(input),
            Self::LookedChip(chip) => chip.generate_main(input),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::LookingChip(chip) => chip.preprocessed_width(),
            Self::LookedChip(chip) => chip.preprocessed_width(),
        }
    }
}
impl<F: Field> BaseAir<F> for LookupToyChipType<F> {
    fn width(&self) -> usize {
        match self {
            Self::LookingChip(chip) => chip.width(),
            Self::LookedChip(chip) => chip.width(),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::LookingChip(chip) => chip.preprocessed_trace(),
            Self::LookedChip(chip) => chip.preprocessed_trace(),
        }
    }
}

impl<F, CB> Air<CB> for LookupToyChipType<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, b: &mut CB) {
        match self {
            Self::LookingChip(chip) => chip.eval(b),
            Self::LookedChip(chip) => chip.eval(b),
        }
    }
}

fn main() {
    env_logger::init();

    // Create the prover.
    info!("Creating prover");
    let config = BabyBearPoseidon2::new();

    let chips = LookupToyChipType::all_chips();
    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, chips);
    info!("{} created.", simple_machine.name());

    // Setup PK and VK.
    info!("Setup PK and VK");

    let record = EmulationRecord::new(Arc::new(Program::default()));
    let mut records = vec![record.clone(), record.clone()];
    let (pk, vk) = simple_machine.setup_keys(&record.program);

    info!("Complement records..");
    simple_machine.complement_record(&mut records);

    info!("Generating proof..");
    let proof = simple_machine.prove(&pk, &records);
    info!("{} generated.", proof.name());

    // Verify the proof.
    let result = simple_machine.verify(&vk, &proof);
    info!("The proof is verified: {}", result.is_ok());
    assert_eq!(result.is_ok(), true);
}
