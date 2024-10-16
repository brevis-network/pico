use log::info;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_vm::{
    chips::chips::toys::lookup_toy::{AddLookedChip, AddLookingChip},
    compiler::riscv::program::Program,
    configs::bb_poseidon2::BabyBearPoseidon2,
    emulator::riscv::record::EmulationRecord,
    instances::machine::simple_machine::SimpleMachine,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        logger::setup_logger,
        machine::MachineBehavior,
        witness::ProvingWitness,
    },
    primitives::consts::{RECURSION_NUM_PVS, RISCV_NUM_PVS},
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
    type Program = Program;

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

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::LookingChip(chip) => chip.generate_main(input, output),
            Self::LookedChip(chip) => chip.generate_main(input, output),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::LookingChip(chip) => chip.preprocessed_width(),
            Self::LookedChip(chip) => chip.preprocessed_width(),
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        match self {
            Self::LookingChip(chip) => chip.is_active(record),
            Self::LookedChip(chip) => chip.is_active(record),
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
    setup_logger();

    // Create the prover.
    info!("\n Creating prover");
    let config = BabyBearPoseidon2::new();

    let chips = LookupToyChipType::all_chips();
    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, RISCV_NUM_PVS, chips);
    info!("{} created.", simple_machine.name());

    // Setup PK and VK.
    info!("\n Setup machine");
    let record = EmulationRecord::new(Arc::new(Program::default()));
    let mut records = vec![record.clone(), record.clone()];
    let (pk, vk) = simple_machine.setup_keys(&record.program);

    info!("\n Complement records..");
    simple_machine.complement_record(&mut records);

    info!("\n Construct proving witness..");
    let witness = ProvingWitness::new_with_records(records);

    info!("Generating proof..");
    let proof = simple_machine.prove(&pk, &witness);
    info!("{} generated.", proof.name());

    // Verify the proof.
    let result = simple_machine.verify(&vk, &proof);
    info!("\n The proof is verified: {}", result.is_ok());
    assert_eq!(result.is_ok(), true);
}
