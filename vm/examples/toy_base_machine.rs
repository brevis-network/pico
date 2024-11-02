use log::info;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_vm::{
    chips::chips::toys::toy::ToyChip,
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    emulator::{
        opts::EmulatorOpts,
        riscv::{record::EmulationRecord, riscv_emulator::RiscvEmulator},
    },
    instances::configs::riscv_config::StarkConfig as RiscvSC,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        logger::setup_logger,
        machine::BaseMachine,
    },
    primitives::consts::RISCV_NUM_PVS,
};

pub enum ToyChipType<F: Field> {
    Toy(ToyChip<F>),
}

// NOTE: These trait implementations are used to save this `ToyChipType` to `MetaChip`.
// Since MetaChip has a generic parameter which is one type (cannot be two chip types).
// This code is annoyed, we could refactor to use macro later (but less readable).
impl<F: Field> ChipBehavior<F> for ToyChipType<F> {
    type Record = EmulationRecord;
    type Program = Program;

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

    fn is_active(&self, record: &Self::Record) -> bool {
        match self {
            Self::Toy(chip) => chip.is_active(record),
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
    setup_logger();

    info!("\n Creating Program..");
    const ELF: &[u8] = include_bytes!("../src/compiler/test_data/riscv32im-pico-fibonacci-elf");
    let compiler = Compiler::new(SourceType::RiscV, ELF);
    let program = compiler.compile();

    // Create the prover.
    info!("\n Creating Base Machine");
    let config = RiscvSC::new();
    let chips = ToyChipType::all_chips();
    let base_machine = BaseMachine::new(config, chips, RISCV_NUM_PVS);

    // Setup PK and VK.
    info!("\n Setup PK and VK");
    let (pk, vk) = base_machine.setup_keys(&program);

    info!("\n Creating Runtime..");
    let mut runtime = RiscvEmulator::new(program, EmulatorOpts::default());
    runtime.state.input_stream.push(vec![2, 0, 0, 0]);
    runtime.run().unwrap();

    let records = &mut vec![runtime.records[0].clone()];

    info!("\n Generating proof");
    // Generate the proof.
    let proof = base_machine.prove_ensemble(&pk, records);

    // Verify the proof.
    info!("\n Verifying proof");
    let result = base_machine.verify_ensemble(&vk, &proof);
    info!("\n The proof is verified: {}", result.is_ok());
    assert_eq!(result.is_ok(), true);
}
