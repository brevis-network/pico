use log::info;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_chips::chips::examples::toy::ToyChip;
use pico_compiler::program::Program;
use pico_configs::bb_poseidon2::BabyBearPoseidon2;
use pico_emulator::riscv::{record::EmulationRecord, riscv_emulator::RiscvEmulator};
use pico_machine::{
    builder::ChipBuilder,
    chip::{ChipBehavior, MetaChip},
    machine::{BaseMachine, MachineBehavior},
};

use pico_compiler::compiler::{Compiler, SourceType};
use pico_emulator::opts::PicoCoreOpts;
use pico_instances::simple_machine::SimpleMachine;
use std::any::type_name;

pub enum ToyChipType<F: Field> {
    Toy(ToyChip<F>),
}

// NOTE: These trait implementations are used to save this `ToyChipType` to `MetaChip`.
// Since MetaChip has a generic parameter which is one type (cannot be two chip types).
// This code is annoyed, we could refactor to use macro later (but less readable).
impl<F: Field> ChipBehavior<F> for ToyChipType<F> {
    type Record = EmulationRecord;

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

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::Toy(chip) => chip.generate_main(input, output),
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

fn main() {
    env_logger::init();

    info!("\n Creating Program..");
    const ELF: &[u8] = include_bytes!("../../compiler/test_data/riscv32im-pico-fibonacci-elf");
    let compiler = Compiler::new(SourceType::RiscV, ELF);
    let program = compiler.compile();

    info!("\n Creating Runtime..");
    let mut runtime = RiscvEmulator::new(program, PicoCoreOpts::default());
    runtime.state.input_stream.push(vec![2, 0, 0, 0]);
    runtime.run().unwrap();

    let record = &runtime.records[0];
    let mut records = vec![record.clone(), record.clone()];

    // Setup config and chips.
    info!("\n Creating BaseMachine..");
    let config = BabyBearPoseidon2::new();
    let chips = ToyChipType::all_chips();

    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, chips);
    info!("{} created.", simple_machine.name());

    // Setup machine prover, verifier, pk and vk.
    info!("\n Setup machine..");
    let (pk, vk) = simple_machine.setup_keys(&record.program);

    info!("\n Complement records..");
    simple_machine.complement_record(&mut records);

    // Generate the proof.
    info!("\n Generating proof..");
    let proof = simple_machine.prove(&pk, &records);
    info!("{} generated.", proof.name());

    // Verify the proof.
    let result = simple_machine.verify(&vk, &proof);
    info!("\n The proof is verified: {}", result.is_ok());
    assert_eq!(result.is_ok(), true);
}
