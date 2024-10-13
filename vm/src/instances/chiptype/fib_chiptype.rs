use crate::{
    chips::chips::{
        alu::{add_sub::AddSubChip, bitwise::BitwiseChip, divrem::DivRemChip, mul::MulChip},
        byte::ByteChip,
        lt::LtChip,
        memory_program::MemoryProgramChip,
        riscv_cpu::CpuChip,
        riscv_memory::initialize_finalize::{MemoryChipType, MemoryInitializeFinalizeChip},
        riscv_program::ProgramChip,
        sll::SLLChip,
        sr::traces::ShiftRightChip,
    },
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
    },
};
use p3_air::{Air, BaseAir};
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

pub enum FibChipType<F: Field> {
    Byte(ByteChip<F>),
    Program(ProgramChip<F>),
    Cpu(CpuChip<F>),
    MemoryProgram(MemoryProgramChip<F>),
    MemoryInitialize(MemoryInitializeFinalizeChip<F>),
    MemoryFinalize(MemoryInitializeFinalizeChip<F>),
    AddSub(AddSubChip<F>),
    Bitwise(BitwiseChip<F>),
    DivRem(DivRemChip<F>),
    Mul(MulChip<F>),
    Lt(LtChip<F>),
    SLL(SLLChip<F>),
    SR(ShiftRightChip<F>),
}

// NOTE: These trait implementations are used to save this `TestChipType` to `MetaChip`.
// Since MetaChip has a generic parameter which is one type (cannot be two chip types).
// This code is annoyed, we could refactor to use macro later (but less readable).
impl<F: PrimeField32> ChipBehavior<F> for FibChipType<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        match self {
            Self::Byte(chip) => chip.name(),
            Self::Program(chip) => chip.name(),
            Self::Cpu(chip) => chip.name(),
            Self::MemoryProgram(chip) => chip.name(),
            Self::MemoryInitialize(chip) => chip.name(),
            Self::MemoryFinalize(chip) => chip.name(),
            Self::AddSub(chip) => chip.name(),
            Self::Bitwise(chip) => chip.name(),
            Self::DivRem(chip) => chip.name(),
            Self::Mul(chip) => chip.name(),
            Self::Lt(chip) => chip.name(),
            Self::SLL(chip) => chip.name(),
            Self::SR(chip) => chip.name(),
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
            Self::Bitwise(chip) => chip.generate_preprocessed(program),
            Self::DivRem(chip) => chip.generate_preprocessed(program),
            Self::Mul(chip) => chip.generate_preprocessed(program),
            Self::Lt(chip) => chip.generate_preprocessed(program),
            Self::SLL(chip) => chip.generate_preprocessed(program),
            Self::SR(chip) => chip.generate_preprocessed(program),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::Byte(chip) => chip.generate_main(input, output),
            Self::Program(chip) => chip.generate_main(input, output),
            Self::Cpu(chip) => chip.generate_main(input, output),
            Self::MemoryProgram(chip) => chip.generate_main(input, output),
            Self::MemoryInitialize(chip) => chip.generate_main(input, output),
            Self::MemoryFinalize(chip) => chip.generate_main(input, output),
            Self::AddSub(chip) => chip.generate_main(input, output),
            Self::Bitwise(chip) => chip.generate_main(input, output),
            Self::DivRem(chip) => chip.generate_main(input, output),
            Self::Mul(chip) => chip.generate_main(input, output),
            Self::Lt(chip) => chip.generate_main(input, output),
            Self::SLL(chip) => chip.generate_main(input, output),
            Self::SR(chip) => chip.generate_main(input, output),
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
            Self::Bitwise(chip) => chip.preprocessed_width(),
            Self::DivRem(chip) => chip.preprocessed_width(),
            Self::Mul(chip) => chip.preprocessed_width(),
            Self::Lt(chip) => chip.preprocessed_width(),
            Self::SLL(chip) => chip.preprocessed_width(),
            Self::SR(chip) => chip.preprocessed_width(),
        }
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        match self {
            Self::Byte(chip) => chip.extra_record(input, extra),
            Self::Program(chip) => chip.extra_record(input, extra),
            Self::Cpu(chip) => chip.extra_record(input, extra),
            Self::MemoryProgram(chip) => chip.extra_record(input, extra),
            Self::MemoryInitialize(chip) => chip.extra_record(input, extra),
            Self::MemoryFinalize(chip) => chip.extra_record(input, extra),
            Self::AddSub(chip) => chip.extra_record(input, extra),
            Self::Bitwise(chip) => chip.extra_record(input, extra),
            Self::DivRem(chip) => chip.extra_record(input, extra),
            Self::Mul(chip) => chip.extra_record(input, extra),
            Self::Lt(chip) => chip.extra_record(input, extra),
            Self::SLL(chip) => chip.extra_record(input, extra),
            Self::SR(chip) => chip.extra_record(input, extra),
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        match self {
            Self::Byte(chip) => chip.is_active(record),
            Self::Program(chip) => chip.is_active(record),
            Self::Cpu(chip) => chip.is_active(record),
            Self::MemoryProgram(chip) => chip.is_active(record),
            Self::MemoryInitialize(chip) => chip.is_active(record),
            Self::MemoryFinalize(chip) => chip.is_active(record),
            Self::AddSub(chip) => chip.is_active(record),
            Self::Bitwise(chip) => chip.is_active(record),
            Self::DivRem(chip) => chip.is_active(record),
            Self::Mul(chip) => chip.is_active(record),
            Self::Lt(chip) => chip.is_active(record),
            Self::SLL(chip) => chip.is_active(record),
            Self::SR(chip) => chip.is_active(record),
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
            Self::Bitwise(chip) => chip.width(),
            Self::DivRem(chip) => chip.width(),
            Self::Mul(chip) => chip.width(),
            Self::Lt(chip) => chip.width(),
            Self::SLL(chip) => chip.width(),
            Self::SR(chip) => chip.width(),
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
            Self::Bitwise(chip) => chip.preprocessed_trace(),
            Self::DivRem(chip) => chip.preprocessed_trace(),
            Self::Mul(chip) => chip.preprocessed_trace(),
            Self::Lt(chip) => chip.preprocessed_trace(),
            Self::SLL(chip) => chip.preprocessed_trace(),
            Self::SR(chip) => chip.preprocessed_trace(),
        }
    }
}

impl<F, CB> Air<CB> for FibChipType<F>
where
    F: PrimeField32,
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
            Self::Bitwise(chip) => chip.eval(b),
            Self::DivRem(chip) => chip.eval(b),
            Self::Mul(chip) => chip.eval(b),
            Self::Lt(chip) => chip.eval(b),
            Self::SLL(chip) => chip.eval(b),
            Self::SR(chip) => chip.eval(b),
        }
    }
}

impl<F: PrimeField32> FibChipType<F> {
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::Program(ProgramChip::default())),
            MetaChip::new(Self::MemoryProgram(MemoryProgramChip::default())),
            MetaChip::new(Self::Cpu(CpuChip::default())),
            MetaChip::new(Self::MemoryInitialize(MemoryInitializeFinalizeChip::new(
                MemoryChipType::Initialize,
            ))),
            MetaChip::new(Self::MemoryFinalize(MemoryInitializeFinalizeChip::new(
                MemoryChipType::Finalize,
            ))),
            MetaChip::new(Self::DivRem(DivRemChip::default())),
            MetaChip::new(Self::Mul(MulChip::default())),
            MetaChip::new(Self::Lt(LtChip::default())),
            MetaChip::new(Self::SR(ShiftRightChip::default())),
            MetaChip::new(Self::SLL(SLLChip::default())),
            MetaChip::new(Self::AddSub(AddSubChip::default())),
            MetaChip::new(Self::Bitwise(BitwiseChip::default())),
            MetaChip::new(Self::Byte(ByteChip::default())),
        ]
    }
}
