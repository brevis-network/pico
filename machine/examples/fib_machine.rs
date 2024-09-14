use log::info;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_chips::chips::{
    cpu::CpuChip,
    memory::init_finalize::{MemoryChipType, MemoryInitFinalizeChip},
    program::ProgramChip,
};
use pico_compiler::program::Program;
use pico_configs::bb_poseidon2::BabyBearPoseidon2;
use pico_emulator::{executor::Executor, opts::PicoCoreOpts, record::EmulationRecord};
use pico_machine::{
    chip::{ChipBehavior, ChipBuilder, MetaChip},
    machine::{MachineBehavior, SimpleMachine},
};

pub enum FibChipType<F: Field> {
    Program(ProgramChip<F>),
    Cpu(CpuChip<F>),
    MemoryInit(MemoryInitFinalizeChip<F>),
    MemoryFinalize(MemoryInitFinalizeChip<F>),
}

// NOTE: These trait implementations are used to save this `FibChipType` to `MetaChip`.
// Since MetaChip has a generic parameter which is one type (cannot be two chip types).
// This code is annoyed, we could refactor to use macro later (but less readable).
impl<F: Field> ChipBehavior<F> for FibChipType<F> {
    fn name(&self) -> String {
        match self {
            Self::Program(chip) => chip.name(),
            Self::Cpu(chip) => chip.name(),
            Self::MemoryInit(chip) => chip.name(),
            Self::MemoryFinalize(chip) => chip.name(),
        }
    }

    fn generate_preprocessed(&self, input: &EmulationRecord) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Program(chip) => chip.generate_preprocessed(input),
            Self::Cpu(chip) => chip.generate_preprocessed(input),
            Self::MemoryInit(chip) => chip.generate_preprocessed(input),
            Self::MemoryFinalize(chip) => chip.generate_preprocessed(input),
        }
    }

    fn generate_main(&self, input: &EmulationRecord) -> RowMajorMatrix<F> {
        match self {
            Self::Program(chip) => chip.generate_main(input),
            Self::Cpu(chip) => chip.generate_main(input),
            Self::MemoryInit(chip) => chip.generate_main(input),
            Self::MemoryFinalize(chip) => chip.generate_main(input),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Program(chip) => chip.preprocessed_width(),
            Self::Cpu(chip) => chip.preprocessed_width(),
            Self::MemoryInit(chip) => chip.preprocessed_width(),
            Self::MemoryFinalize(chip) => chip.preprocessed_width(),
        }
    }
}
impl<F: Field> BaseAir<F> for FibChipType<F> {
    fn width(&self) -> usize {
        match self {
            Self::Program(chip) => chip.width(),
            Self::Cpu(chip) => chip.width(),
            Self::MemoryInit(chip) => chip.width(),
            Self::MemoryFinalize(chip) => chip.width(),
        }
    }

    /// todo: this should not be called. all should go to generate_preprocessed.
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Program(chip) => chip.preprocessed_trace(),
            Self::Cpu(chip) => chip.preprocessed_trace(),
            Self::MemoryInit(chip) => chip.preprocessed_trace(),
            Self::MemoryFinalize(chip) => chip.preprocessed_trace(),
        }
    }
}

impl<F, CB> Air<CB> for FibChipType<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, b: &mut CB) {
        match self {
            Self::Program(chip) => chip.eval(b),
            Self::Cpu(chip) => chip.eval(b),
            Self::MemoryInit(chip) => chip.eval(b),
            Self::MemoryFinalize(chip) => chip.eval(b),
        }
    }
}

impl<F: Field> FibChipType<F> {
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::Program(ProgramChip::default())),
            MetaChip::new(Self::Cpu(CpuChip::default())),
            MetaChip::new(Self::MemoryInit(MemoryInitFinalizeChip::new(
                MemoryChipType::Initialize,
            ))),
            MetaChip::new(Self::MemoryFinalize(MemoryInitFinalizeChip::new(
                MemoryChipType::Finalize,
            ))),
        ]
    }
}

fn main() {
    env_logger::init();

    info!("Creating Program..");
    const ELF: &[u8] = include_bytes!("../../compiler/test_data/riscv32im-succinct-zkvm-elf");
    let program = Program::from(ELF).unwrap();

    info!("Creating Runtime..");
    let mut runtime = Executor::new(program, PicoCoreOpts::default());
    runtime.state.input_stream.push(vec![2, 0, 0, 0]);
    runtime.run().unwrap();

    let record = &runtime.records[0];

    // Setup config and chips.
    info!("Creating SimpleMachine..");
    let config = BabyBearPoseidon2::new();
    let chips = FibChipType::all_chips();

    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, chips);
    info!("{} created.", simple_machine.name());

    // Setup machine prover, verifier, pk and vk.
    info!("Setup machine..");
    let (pk, vk) = simple_machine.setup(record);

    // Generate the proof.
    info!("Generating proof..");
    let proof = simple_machine.prove(record, &pk);
    info!("{} generated.", proof.name());

    // Verify the proof.
    let result = simple_machine.verify(&proof, &vk);
    info!("The proof is verified: {}", result.is_ok());
}
