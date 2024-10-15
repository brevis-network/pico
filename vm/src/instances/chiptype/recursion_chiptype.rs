use crate::{
    chips::chips::{
        fri_fold::FriFoldChip, multi::MultiChip, poseidon2_wide::Poseidon2WideChip,
        recursion_cpu::CpuChip, recursion_memory::MemoryGlobalChip, recursion_program::ProgramChip,
        recursion_range_check::RangeCheckChip,
    },
    compiler::recursion::program::RecursionProgram,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
    },
    primitives::consts::EXTENSION_DEGREE,
    recursion::{exp_reverse_bits::ExpReverseBitsLenChip, runtime::RecursionRecord},
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::marker::PhantomData;

pub enum RecursionChipType<
    F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
    const DEGREE: usize,
> {
    Program(ProgramChip<F>),
    Cpu(CpuChip<F, DEGREE>),
    MemoryGlobal(MemoryGlobalChip<F>),
    Poseidon2Wide(Poseidon2WideChip<DEGREE, F>),
    FriFold(FriFoldChip<DEGREE, F>),
    RangeCheck(RangeCheckChip<F>),
    Multi(MultiChip<DEGREE, F>),
    ExpReverseBitsLen(ExpReverseBitsLenChip<DEGREE, F>),
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>, const DEGREE: usize> ChipBehavior<F>
    for RecursionChipType<F, DEGREE>
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        match self {
            Self::Program(chip) => ChipBehavior::<F>::name(chip),
            Self::Cpu(chip) => chip.name(),
            Self::MemoryGlobal(chip) => ChipBehavior::<F>::name(chip),
            Self::Poseidon2Wide(chip) => ChipBehavior::<F>::name(chip),
            Self::FriFold(chip) => ChipBehavior::<F>::name(chip),
            Self::RangeCheck(chip) => chip.name(),
            Self::Multi(chip) => ChipBehavior::<F>::name(chip),
            Self::ExpReverseBitsLen(chip) => ChipBehavior::<F>::name(chip),
        }
    }

    fn generate_preprocessed(&self, program: &RecursionProgram<F>) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Program(chip) => chip.generate_preprocessed(program),
            Self::Cpu(chip) => chip.generate_preprocessed(program),
            Self::MemoryGlobal(chip) => chip.generate_preprocessed(program),
            Self::Poseidon2Wide(chip) => chip.generate_preprocessed(program),
            Self::FriFold(chip) => chip.generate_preprocessed(program),
            Self::RangeCheck(chip) => chip.generate_preprocessed(program),
            Self::Multi(chip) => chip.generate_preprocessed(program),
            Self::ExpReverseBitsLen(chip) => chip.generate_preprocessed(program),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::Program(chip) => chip.generate_main(input, output),
            Self::Cpu(chip) => chip.generate_main(input, output),
            Self::MemoryGlobal(chip) => chip.generate_main(input, output),
            Self::Poseidon2Wide(chip) => chip.generate_main(input, output),
            Self::FriFold(chip) => chip.generate_main(input, output),
            Self::RangeCheck(chip) => chip.generate_main(input, output),
            Self::Multi(chip) => chip.generate_main(input, output),
            Self::ExpReverseBitsLen(chip) => chip.generate_main(input, output),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Program(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::Cpu(chip) => chip.preprocessed_width(),
            Self::MemoryGlobal(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::Poseidon2Wide(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::FriFold(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::RangeCheck(chip) => chip.preprocessed_width(),
            Self::Multi(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::ExpReverseBitsLen(chip) => ChipBehavior::<F>::preprocessed_width(chip),
        }
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        match self {
            Self::Program(chip) => chip.extra_record(input, extra),
            Self::Cpu(chip) => chip.extra_record(input, extra),
            Self::MemoryGlobal(chip) => chip.extra_record(input, extra),
            Self::Poseidon2Wide(chip) => chip.extra_record(input, extra),
            Self::FriFold(chip) => chip.extra_record(input, extra),
            Self::RangeCheck(chip) => chip.extra_record(input, extra),
            Self::Multi(chip) => chip.extra_record(input, extra),
            Self::ExpReverseBitsLen(chip) => chip.extra_record(input, extra),
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        match self {
            Self::Program(chip) => chip.is_active(record),
            Self::Cpu(chip) => chip.is_active(record),
            Self::MemoryGlobal(chip) => chip.is_active(record),
            Self::Poseidon2Wide(chip) => chip.is_active(record),
            Self::FriFold(chip) => chip.is_active(record),
            Self::RangeCheck(chip) => chip.is_active(record),
            Self::Multi(chip) => chip.is_active(record),
            Self::ExpReverseBitsLen(chip) => chip.is_active(record),
        }
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>, const DEGREE: usize> BaseAir<F>
    for RecursionChipType<F, DEGREE>
{
    fn width(&self) -> usize {
        match self {
            Self::Program(chip) => BaseAir::<F>::width(chip),
            Self::Cpu(chip) => chip.width(),
            Self::MemoryGlobal(chip) => BaseAir::<F>::width(chip),
            Self::Poseidon2Wide(chip) => BaseAir::<F>::width(chip),
            Self::FriFold(chip) => BaseAir::<F>::width(chip),
            Self::RangeCheck(chip) => chip.width(),
            Self::Multi(chip) => BaseAir::<F>::width(chip),
            Self::ExpReverseBitsLen(chip) => BaseAir::<F>::width(chip),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Program(chip) => chip.preprocessed_trace(),
            Self::Cpu(chip) => chip.preprocessed_trace(),
            Self::MemoryGlobal(chip) => chip.preprocessed_trace(),
            Self::Poseidon2Wide(chip) => chip.preprocessed_trace(),
            Self::FriFold(chip) => chip.preprocessed_trace(),
            Self::RangeCheck(chip) => chip.preprocessed_trace(),
            Self::Multi(chip) => chip.preprocessed_trace(),
            Self::ExpReverseBitsLen(chip) => chip.preprocessed_trace(),
        }
    }
}

impl<
        F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
        AB: ChipBuilder<F>,
        const DEGREE: usize,
    > Air<AB> for RecursionChipType<F, DEGREE>
where
    RecursionChipType<F, DEGREE>: BaseAir<<AB as AirBuilder>::F>,
    AB::Var: 'static,
{
    fn eval(&self, b: &mut AB) {
        match self {
            Self::Program(chip) => chip.eval(b),
            Self::Cpu(chip) => chip.eval(b),
            Self::MemoryGlobal(chip) => chip.eval(b),
            Self::Poseidon2Wide(chip) => chip.eval(b),
            Self::FriFold(chip) => chip.eval(b),
            Self::RangeCheck(chip) => chip.eval(b),
            Self::Multi(chip) => chip.eval(b),
            Self::ExpReverseBitsLen(chip) => chip.eval(b),
        }
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>, const DEGREE: usize>
    RecursionChipType<F, DEGREE>
{
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::Program(ProgramChip::default())),
            MetaChip::new(Self::Cpu(CpuChip {
                fixed_log2_rows: None,
                _phantom: PhantomData,
            })),
            MetaChip::new(Self::MemoryGlobal(MemoryGlobalChip {
                fixed_log2_rows: None,
                ..Default::default()
            })),
            MetaChip::new(Self::Poseidon2Wide(Poseidon2WideChip::<DEGREE, F> {
                fixed_log2_rows: None,
                pad: true,
                ..Default::default()
            })),
            MetaChip::new(Self::FriFold(FriFoldChip::<DEGREE, F> {
                fixed_log2_rows: None,
                pad: true,
                ..Default::default()
            })),
            MetaChip::new(Self::RangeCheck(RangeCheckChip::default())),
            // TODO: Seems `MultiChip` is useless, need to confirm.
            // MetaChip::new(Self::Multi(MultiChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(
                ExpReverseBitsLenChip::<DEGREE, F> {
                    fixed_log2_rows: None,
                    pad: true,
                    ..Default::default()
                },
            )),
        ]
    }
}
