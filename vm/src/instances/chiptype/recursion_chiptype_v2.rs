use crate::{
    chips::chips::{
        alu_base::BaseAluChip,
        alu_ext::ExtAluChip,
        exp_reverse_bits_v2::ExpReverseBitsLenChip,
        poseidon2_skinny_v2::Poseidon2SkinnyChip,
        recursion_memory_v2::{constant::MemoryConstChip, variable::MemoryVarChip},
    },
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

pub enum RecursionChipType<
    F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
    const DEGREE: usize,
> {
    MemoryConst(MemoryConstChip<F>),
    MemoryVar(MemoryVarChip<F>),
    ExpReverseBitsLen(ExpReverseBitsLenChip<DEGREE, F>),
    BaseAlu(BaseAluChip<F>),
    ExtAlu(ExtAluChip<F>),
    Poseidon2Skinny(Poseidon2SkinnyChip<DEGREE, F>),
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>, const DEGREE: usize> ChipBehavior<F>
    for RecursionChipType<F, DEGREE>
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        match self {
            Self::MemoryConst(chip) => ChipBehavior::<F>::name(chip),
            Self::MemoryVar(chip) => ChipBehavior::<F>::name(chip),
            Self::ExpReverseBitsLen(chip) => ChipBehavior::<F>::name(chip),
            Self::BaseAlu(chip) => ChipBehavior::<F>::name(chip),
            Self::ExtAlu(chip) => ChipBehavior::<F>::name(chip),
            Self::Poseidon2Skinny(chip) => ChipBehavior::<F>::name(chip),
        }
    }

    fn generate_preprocessed(&self, program: &RecursionProgram<F>) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::MemoryConst(chip) => chip.generate_preprocessed(program),
            Self::MemoryVar(chip) => chip.generate_preprocessed(program),
            Self::ExpReverseBitsLen(chip) => chip.generate_preprocessed(program),
            Self::BaseAlu(chip) => chip.generate_preprocessed(program),
            Self::ExtAlu(chip) => chip.generate_preprocessed(program),
            Self::Poseidon2Skinny(chip) => chip.generate_preprocessed(program),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::MemoryConst(chip) => chip.generate_main(input, output),
            Self::MemoryVar(chip) => chip.generate_main(input, output),
            Self::ExpReverseBitsLen(chip) => chip.generate_main(input, output),
            Self::BaseAlu(chip) => chip.generate_main(input, output),
            Self::ExtAlu(chip) => chip.generate_main(input, output),
            Self::Poseidon2Skinny(chip) => chip.generate_main(input, output),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::MemoryConst(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::MemoryVar(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::ExpReverseBitsLen(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::BaseAlu(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::ExtAlu(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::Poseidon2Skinny(chip) => ChipBehavior::<F>::preprocessed_width(chip),
        }
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        match self {
            Self::MemoryConst(chip) => chip.extra_record(input, extra),
            Self::MemoryVar(chip) => chip.extra_record(input, extra),
            Self::ExpReverseBitsLen(chip) => chip.extra_record(input, extra),
            Self::BaseAlu(chip) => chip.extra_record(input, extra),
            Self::ExtAlu(chip) => chip.extra_record(input, extra),
            Self::Poseidon2Skinny(chip) => chip.extra_record(input, extra),
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        match self {
            Self::MemoryConst(chip) => chip.is_active(record),
            Self::MemoryVar(chip) => chip.is_active(record),
            Self::ExpReverseBitsLen(chip) => chip.is_active(record),
            Self::BaseAlu(chip) => chip.is_active(record),
            Self::ExtAlu(chip) => chip.is_active(record),
            Self::Poseidon2Skinny(chip) => chip.is_active(record),
        }
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>, const DEGREE: usize> BaseAir<F>
    for RecursionChipType<F, DEGREE>
{
    fn width(&self) -> usize {
        match self {
            Self::MemoryConst(chip) => BaseAir::<F>::width(chip),
            Self::MemoryVar(chip) => BaseAir::<F>::width(chip),
            Self::ExpReverseBitsLen(chip) => BaseAir::<F>::width(chip),
            Self::BaseAlu(chip) => BaseAir::<F>::width(chip),
            Self::ExtAlu(chip) => BaseAir::<F>::width(chip),
            Self::Poseidon2Skinny(chip) => BaseAir::<F>::width(chip),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::MemoryConst(chip) => chip.preprocessed_trace(),
            Self::MemoryVar(chip) => chip.preprocessed_trace(),
            Self::ExpReverseBitsLen(chip) => chip.preprocessed_trace(),
            Self::BaseAlu(chip) => chip.preprocessed_trace(),
            Self::ExtAlu(chip) => chip.preprocessed_trace(),
            Self::Poseidon2Skinny(chip) => chip.preprocessed_trace(),
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
            Self::MemoryConst(chip) => chip.eval(b),
            Self::MemoryVar(chip) => chip.eval(b),
            Self::ExpReverseBitsLen(chip) => chip.eval(b),
            Self::BaseAlu(chip) => chip.eval(b),
            Self::ExtAlu(chip) => chip.eval(b),
            Self::Poseidon2Skinny(chip) => chip.eval(b),
        }
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>, const DEGREE: usize>
    RecursionChipType<F, DEGREE>
{
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
        ]
    }

    // TODO: temporarily set to be the same as all_chips since adding Multi will break lookups
    pub fn compress_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
        ]
    }

    // TODO: temporarily set to be the same as all_chips since adding Multi will break lookups
    pub fn embed_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
        ]
    }

    // TODO: temporarily set to be the same as all_chips since adding Multi will break lookups
    // For wrap bn254
    pub fn wrap_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::Poseidon2Skinny(Poseidon2SkinnyChip::default())),
        ]
    }
}
