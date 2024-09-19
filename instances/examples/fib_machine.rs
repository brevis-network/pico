use log::info;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_chips::chips::{
    alu::add_sub::AddSubChip,
    byte::ByteChip,
    cpu::CpuChip,
    memory::initialize_finalize::{MemoryChipType, MemoryInitializeFinalizeChip},
    memory_program::MemoryProgramChip,
    program::ProgramChip,
};
use pico_compiler::{
    compiler::{Compilable, Compiler, SourceType},
    program::Program,
};
use pico_configs::bb_poseidon2::BabyBearPoseidon2;
use pico_emulator::{
    opts::PicoCoreOpts,
    riscv::{record::EmulationRecord, riscv_emulator::RiscvEmulator},
};
use pico_instances::simple_machine::SimpleMachine;
use pico_machine::{
    builder::ChipBuilder,
    chip::{ChipBehavior, MetaChip},
    machine::MachineBehavior,
};
use std::path::Path;

pub enum FibChipType<F: Field> {
    Byte(ByteChip<F>),
    Program(ProgramChip<F>),
    Cpu(CpuChip<F>),
    MemoryProgram(MemoryProgramChip<F>),
    MemoryInitialize(MemoryInitializeFinalizeChip<F>),
    MemoryFinalize(MemoryInitializeFinalizeChip<F>),
    AddSub(AddSubChip<F>),
}

// NOTE: These trait implementations are used to save this `FibChipType` to `MetaChip`.
// Since MetaChip has a generic parameter which is one type (cannot be two chip types).
// This code is annoyed, we could refactor to use macro later (but less readable).
impl<F: Field> ChipBehavior<F> for FibChipType<F> {
    type Record = EmulationRecord;

    fn name(&self) -> String {
        match self {
            Self::Byte(chip) => chip.name(),
            Self::Program(chip) => chip.name(),
            Self::Cpu(chip) => chip.name(),
            Self::MemoryProgram(chip) => chip.name(),
            Self::MemoryInitialize(chip) => chip.name(),
            Self::MemoryFinalize(chip) => chip.name(),
            Self::AddSub(chip) => chip.name(),
        }
    }

    fn generate_preprocessed(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Byte(chip) => chip.generate_preprocessed(program),
            Self::Program(chip) => chip.generate_preprocessed(program),
            Self::Cpu(chip) => chip.generate_preprocessed(program),
            Self::MemoryProgram(chip) => chip.generate_preprocessed(program),
            Self::MemoryInitialize(chip) => chip.generate_preprocessed(program),
            Self::MemoryFinalize(chip) => chip.generate_preprocessed(program),
            Self::AddSub(chip) => chip.generate_preprocessed(program),
        }
    }

    fn generate_main(&self, input: &Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::Byte(chip) => chip.generate_main(input),
            Self::Program(chip) => chip.generate_main(input),
            Self::Cpu(chip) => chip.generate_main(input),
            Self::MemoryProgram(chip) => chip.generate_main(input),
            Self::MemoryInitialize(chip) => chip.generate_main(input),
            Self::MemoryFinalize(chip) => chip.generate_main(input),
            Self::AddSub(chip) => chip.generate_main(input),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Byte(chip) => chip.preprocessed_width(),
            Self::Program(chip) => chip.preprocessed_width(),
            Self::Cpu(chip) => chip.preprocessed_width(),
            Self::MemoryProgram(chip) => chip.preprocessed_width(),
            Self::MemoryInitialize(chip) => chip.preprocessed_width(),
            Self::MemoryFinalize(chip) => chip.preprocessed_width(),
            Self::AddSub(chip) => chip.preprocessed_width(),
        }
    }
}
impl<F: Field> BaseAir<F> for FibChipType<F> {
    fn width(&self) -> usize {
        match self {
            Self::Byte(chip) => chip.width(),
            Self::Program(chip) => chip.width(),
            Self::Cpu(chip) => chip.width(),
            Self::MemoryProgram(chip) => chip.width(),
            Self::MemoryInitialize(chip) => chip.width(),
            Self::MemoryFinalize(chip) => chip.width(),
            Self::AddSub(chip) => chip.width(),
        }
    }

    /// todo: this should not be called. all should go to generate_preprocessed.
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Byte(chip) => chip.preprocessed_trace(),
            Self::Program(chip) => chip.preprocessed_trace(),
            Self::Cpu(chip) => chip.preprocessed_trace(),
            Self::MemoryProgram(chip) => chip.preprocessed_trace(),
            Self::MemoryInitialize(chip) => chip.preprocessed_trace(),
            Self::MemoryFinalize(chip) => chip.preprocessed_trace(),
            Self::AddSub(chip) => chip.preprocessed_trace(),
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
            Self::Byte(chip) => chip.eval(b),
            Self::Program(chip) => chip.eval(b),
            Self::Cpu(chip) => chip.eval(b),
            Self::MemoryProgram(chip) => chip.eval(b),
            Self::MemoryInitialize(chip) => chip.eval(b),
            Self::MemoryFinalize(chip) => chip.eval(b),
            Self::AddSub(chip) => chip.eval(b),
        }
    }
}

impl<F: Field> FibChipType<F> {
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::Byte(ByteChip::default())),
            MetaChip::new(Self::Program(ProgramChip::default())),
            MetaChip::new(Self::Cpu(CpuChip::default())),
            MetaChip::new(Self::MemoryProgram(MemoryProgramChip::default())),
            MetaChip::new(Self::MemoryInitialize(MemoryInitializeFinalizeChip::new(
                MemoryChipType::Initialize,
            ))),
            MetaChip::new(Self::MemoryFinalize(MemoryInitializeFinalizeChip::new(
                MemoryChipType::Finalize,
            ))),
            MetaChip::new(Self::AddSub(AddSubChip::default())),
        ]
    }
}

fn main() {
    env_logger::init();

    info!("Creating Program..");
    const ELF: &[u8] = include_bytes!("../../compiler/test_data/riscv32im-succinct-zkvm-elf");

    let compiler = Compiler::new(SourceType::RiscV, ELF);
    let program = compiler.compile();

    info!("Creating Runtime..");
    let mut runtime = RiscvEmulator::new(program, PicoCoreOpts::default());
    runtime.state.input_stream.push(vec![2, 0, 0, 0]);
    runtime.run().unwrap();

    let record = &runtime.records[0];
    let records = vec![record.clone()];

    // Setup config and chips.
    info!("Creating BaseMachine..");
    let config = BabyBearPoseidon2::new();
    let chips = FibChipType::all_chips();

    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, chips);
    info!("{} created.", simple_machine.name());

    // Setup machine prover, verifier, pk and vk.
    info!("Setup machine..");
    let (pk, vk) = simple_machine.setup_keys(&record.program);

    // Generate the proof.
    info!("Generating proof..");
    let proof = simple_machine.prove(&pk, &records);
    info!("{} generated.", proof.name());

    // Verify the proof.
    let result = simple_machine.verify(&vk, &proof);
    info!("The proof is verified: {}", result.is_ok());
    assert_eq!(result.is_ok(), true);
}
