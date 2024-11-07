use crate::{
    chips::chips::recursion_memory_v2::{constant::MemoryConstChip, variable::MemoryVarChip},
    compiler::recursion_v2::program::RecursionProgram,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
    },
    primitives::consts::EXTENSION_DEGREE,
    recursion_v2::runtime::RecursionRecord,
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

pub enum RecursionChipType<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>> {
    MemoryConst(MemoryConstChip<F>),
    MemoryVar(MemoryVarChip<F>),
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>> ChipBehavior<F>
    for RecursionChipType<F>
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        match self {
            Self::MemoryConst(chip) => ChipBehavior::<F>::name(chip),
            Self::MemoryVar(chip) => ChipBehavior::<F>::name(chip),
        }
    }

    fn generate_preprocessed(&self, program: &RecursionProgram<F>) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::MemoryConst(chip) => chip.generate_preprocessed(program),
            Self::MemoryVar(chip) => chip.generate_preprocessed(program),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::MemoryConst(chip) => chip.generate_main(input, output),
            Self::MemoryVar(chip) => chip.generate_main(input, output),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::MemoryConst(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::MemoryVar(chip) => ChipBehavior::<F>::preprocessed_width(chip),
        }
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        match self {
            Self::MemoryConst(chip) => chip.extra_record(input, extra),
            Self::MemoryVar(chip) => chip.extra_record(input, extra),
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        match self {
            Self::MemoryConst(chip) => chip.is_active(record),
            Self::MemoryVar(chip) => chip.is_active(record),
        }
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>> BaseAir<F> for RecursionChipType<F> {
    fn width(&self) -> usize {
        match self {
            Self::MemoryConst(chip) => BaseAir::<F>::width(chip),
            Self::MemoryVar(chip) => BaseAir::<F>::width(chip),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::MemoryConst(chip) => chip.preprocessed_trace(),
            Self::MemoryVar(chip) => chip.preprocessed_trace(),
        }
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>, AB: ChipBuilder<F>> Air<AB>
    for RecursionChipType<F>
where
    RecursionChipType<F>: BaseAir<<AB as AirBuilder>::F>,
    AB::Var: 'static,
{
    fn eval(&self, b: &mut AB) {
        match self {
            Self::MemoryConst(chip) => chip.eval(b),
            Self::MemoryVar(chip) => chip.eval(b),
        }
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>> RecursionChipType<F> {
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
        ]
    }

    // TODO: temporarily set to be the same as all_chips since adding Multi will break lookups
    pub fn compress_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
        ]
    }

    // TODO: temporarily set to be the same as all_chips since adding Multi will break lookups
    pub fn embed_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
        ]
    }
}
