use crate::{
    chips::chips::{
        alu_base::{columns::NUM_BASE_ALU_ENTRIES_PER_ROW, BaseAluChip},
        alu_ext::{columns::NUM_EXT_ALU_ENTRIES_PER_ROW, ExtAluChip},
        batch_fri::BatchFRIChip,
        exp_reverse_bits_v2::ExpReverseBitsLenChip,
        poseidon2_skinny_v2::Poseidon2SkinnyChip,
        poseidon2_wide_v2::Poseidon2WideChip,
        public_values_v2::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
        recursion_memory_v2::{
            constant::{columns::NUM_CONST_MEM_ENTRIES_PER_ROW, MemoryConstChip},
            variable::{columns::NUM_VAR_MEM_ENTRIES_PER_ROW, MemoryVarChip},
        },
        select::SelectChip,
    },
    compiler::recursion_v2::{
        instruction::{
            HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction,
        },
        program::RecursionProgram,
    },
    instances::compiler_v2::shapes::compress_shape::RecursionPadShape,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        field::{FieldBehavior, FieldType},
        folder::SymbolicConstraintFolder,
    },
    primitives::consts::EXTENSION_DEGREE,
    recursion_v2::{runtime::RecursionRecord, types::ExpReverseBitsInstr},
};
use hashbrown::HashMap;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::ops::{Add, AddAssign};

pub enum RecursionChipType<
    F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
    const DEGREE: usize,
    const W: u32,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> {
    MemoryConst(MemoryConstChip<F>),
    MemoryVar(MemoryVarChip<F>),
    ExpReverseBitsLen(ExpReverseBitsLenChip<DEGREE, F>),
    BaseAlu(BaseAluChip<F>),
    ExtAlu(ExtAluChip<F, W>),
    Select(SelectChip<F>),
    Poseidon2Skinny(Poseidon2SkinnyChip<DEGREE, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, F>),
    Poseidon2Wide(
        Poseidon2WideChip<
            DEGREE,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
            F,
        >,
    ),
    BatchFRI(BatchFRIChip<DEGREE, W, F>),
    PublicValues(PublicValuesChip<F>),
}

impl<
        F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
        const DEGREE: usize,
        const W: u32,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    > ChipBehavior<F>
    for RecursionChipType<
        F,
        DEGREE,
        W,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
    >
where
    Poseidon2SkinnyChip<DEGREE, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, F>:
        ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
    Poseidon2WideChip<
        DEGREE,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
        F,
    >: ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        match self {
            Self::MemoryConst(chip) => ChipBehavior::<F>::name(chip),
            Self::MemoryVar(chip) => ChipBehavior::<F>::name(chip),
            Self::Select(chip) => ChipBehavior::<F>::name(chip),
            Self::ExpReverseBitsLen(chip) => ChipBehavior::<F>::name(chip),
            Self::BaseAlu(chip) => ChipBehavior::<F>::name(chip),
            Self::ExtAlu(chip) => ChipBehavior::<F>::name(chip),
            Self::Poseidon2Skinny(chip) => ChipBehavior::<F>::name(chip),
            Self::Poseidon2Wide(chip) => ChipBehavior::<F>::name(chip),
            Self::BatchFRI(chip) => ChipBehavior::<F>::name(chip),
            Self::PublicValues(chip) => ChipBehavior::<F>::name(chip),
        }
    }

    fn generate_preprocessed(&self, program: &RecursionProgram<F>) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::MemoryConst(chip) => chip.generate_preprocessed(program),
            Self::MemoryVar(chip) => chip.generate_preprocessed(program),
            Self::Select(chip) => chip.generate_preprocessed(program),
            Self::ExpReverseBitsLen(chip) => chip.generate_preprocessed(program),
            Self::BaseAlu(chip) => chip.generate_preprocessed(program),
            Self::ExtAlu(chip) => chip.generate_preprocessed(program),
            Self::Poseidon2Skinny(chip) => chip.generate_preprocessed(program),
            Self::Poseidon2Wide(chip) => chip.generate_preprocessed(program),
            Self::BatchFRI(chip) => chip.generate_preprocessed(program),
            Self::PublicValues(chip) => chip.generate_preprocessed(program),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::MemoryConst(chip) => chip.generate_main(input, output),
            Self::MemoryVar(chip) => chip.generate_main(input, output),
            Self::Select(chip) => chip.generate_main(input, output),
            Self::ExpReverseBitsLen(chip) => chip.generate_main(input, output),
            Self::BaseAlu(chip) => chip.generate_main(input, output),
            Self::ExtAlu(chip) => chip.generate_main(input, output),
            Self::Poseidon2Skinny(chip) => chip.generate_main(input, output),
            Self::Poseidon2Wide(chip) => chip.generate_main(input, output),
            Self::BatchFRI(chip) => chip.generate_main(input, output),
            Self::PublicValues(chip) => chip.generate_main(input, output),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::MemoryConst(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::MemoryVar(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::Select(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::ExpReverseBitsLen(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::BaseAlu(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::ExtAlu(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::Poseidon2Skinny(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::Poseidon2Wide(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::BatchFRI(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::PublicValues(chip) => ChipBehavior::<F>::preprocessed_width(chip),
        }
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        match self {
            Self::MemoryConst(chip) => chip.extra_record(input, extra),
            Self::MemoryVar(chip) => chip.extra_record(input, extra),
            Self::Select(chip) => chip.extra_record(input, extra),
            Self::ExpReverseBitsLen(chip) => chip.extra_record(input, extra),
            Self::BaseAlu(chip) => chip.extra_record(input, extra),
            Self::ExtAlu(chip) => chip.extra_record(input, extra),
            Self::Poseidon2Skinny(chip) => chip.extra_record(input, extra),
            Self::Poseidon2Wide(chip) => chip.extra_record(input, extra),
            Self::BatchFRI(chip) => chip.extra_record(input, extra),
            Self::PublicValues(chip) => chip.extra_record(input, extra),
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        match self {
            Self::MemoryConst(chip) => chip.is_active(record),
            Self::MemoryVar(chip) => chip.is_active(record),
            Self::Select(chip) => chip.is_active(record),
            Self::ExpReverseBitsLen(chip) => chip.is_active(record),
            Self::BaseAlu(chip) => chip.is_active(record),
            Self::ExtAlu(chip) => chip.is_active(record),
            Self::Poseidon2Skinny(chip) => chip.is_active(record),
            Self::Poseidon2Wide(chip) => chip.is_active(record),
            Self::BatchFRI(chip) => chip.is_active(record),
            Self::PublicValues(chip) => chip.is_active(record),
        }
    }
}

impl<
        F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
        const DEGREE: usize,
        const W: u32,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    > BaseAir<F>
    for RecursionChipType<
        F,
        DEGREE,
        W,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
    >
where
    Poseidon2SkinnyChip<DEGREE, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, F>: BaseAir<F>,
    Poseidon2WideChip<
        DEGREE,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
        F,
    >: BaseAir<F>,
{
    fn width(&self) -> usize {
        match self {
            Self::MemoryConst(chip) => BaseAir::<F>::width(chip),
            Self::MemoryVar(chip) => BaseAir::<F>::width(chip),
            Self::Select(chip) => BaseAir::<F>::width(chip),
            Self::ExpReverseBitsLen(chip) => BaseAir::<F>::width(chip),
            Self::BaseAlu(chip) => BaseAir::<F>::width(chip),
            Self::ExtAlu(chip) => BaseAir::<F>::width(chip),
            Self::Poseidon2Skinny(chip) => BaseAir::<F>::width(chip),
            Self::Poseidon2Wide(chip) => BaseAir::<F>::width(chip),
            Self::BatchFRI(chip) => BaseAir::<F>::width(chip),
            Self::PublicValues(chip) => BaseAir::<F>::width(chip),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::MemoryConst(chip) => chip.preprocessed_trace(),
            Self::MemoryVar(chip) => chip.preprocessed_trace(),
            Self::Select(chip) => chip.preprocessed_trace(),
            Self::ExpReverseBitsLen(chip) => chip.preprocessed_trace(),
            Self::BaseAlu(chip) => chip.preprocessed_trace(),
            Self::ExtAlu(chip) => chip.preprocessed_trace(),
            Self::Poseidon2Skinny(chip) => chip.preprocessed_trace(),
            Self::Poseidon2Wide(chip) => chip.preprocessed_trace(),
            Self::BatchFRI(chip) => chip.preprocessed_trace(),
            Self::PublicValues(chip) => chip.preprocessed_trace(),
        }
    }
}

impl<
        F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
        AB: ChipBuilder<F>,
        const DEGREE: usize,
        const W: u32,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    > Air<AB>
    for RecursionChipType<
        F,
        DEGREE,
        W,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
    >
where
    RecursionChipType<
        F,
        DEGREE,
        W,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
    >: BaseAir<<AB as AirBuilder>::F>,
    Poseidon2SkinnyChip<DEGREE, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, F>: Air<AB>,
    Poseidon2WideChip<
        DEGREE,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
        F,
    >: Air<AB>,
    AB::Var: 'static,
{
    fn eval(&self, b: &mut AB) {
        assert_eq!(F::W, F::from_canonical_u32(W));
        match self {
            Self::MemoryConst(chip) => chip.eval(b),
            Self::MemoryVar(chip) => chip.eval(b),
            Self::Select(chip) => chip.eval(b),
            Self::ExpReverseBitsLen(chip) => chip.eval(b),
            Self::BaseAlu(chip) => chip.eval(b),
            Self::ExtAlu(chip) => chip.eval(b),
            Self::Poseidon2Skinny(chip) => chip.eval(b),
            Self::Poseidon2Wide(chip) => chip.eval(b),
            Self::BatchFRI(chip) => chip.eval(b),
            Self::PublicValues(chip) => chip.eval(b),
        }
    }
}

impl<
        F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
        const DEGREE: usize,
        const W: u32,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    >
    RecursionChipType<
        F,
        DEGREE,
        W,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
    >
where
    Poseidon2SkinnyChip<DEGREE, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, F>: Air<SymbolicConstraintFolder<F>>
        + ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
    Poseidon2WideChip<
        DEGREE,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
        F,
    >: Air<SymbolicConstraintFolder<F>>
        + ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
{
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::Select(SelectChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
            MetaChip::new(Self::Poseidon2Wide(Poseidon2WideChip::default())),
            MetaChip::new(Self::BatchFRI(BatchFRIChip::default())),
            MetaChip::new(Self::PublicValues(PublicValuesChip::default())),
        ]
    }

    pub fn convert_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::Select(SelectChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
            MetaChip::new(Self::Poseidon2Wide(Poseidon2WideChip::default())),
            MetaChip::new(Self::BatchFRI(BatchFRIChip::default())),
            MetaChip::new(Self::PublicValues(PublicValuesChip::default())),
        ]
    }

    pub fn combine_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::Select(SelectChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
            MetaChip::new(Self::Poseidon2Wide(Poseidon2WideChip::default())),
            MetaChip::new(Self::BatchFRI(BatchFRIChip::default())),
            MetaChip::new(Self::PublicValues(PublicValuesChip::default())),
        ]
    }

    pub fn compress_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::Select(SelectChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
            MetaChip::new(Self::Poseidon2Wide(Poseidon2WideChip::default())),
            MetaChip::new(Self::BatchFRI(BatchFRIChip::default())),
            MetaChip::new(Self::PublicValues(PublicValuesChip::default())),
        ]
    }

    pub fn embed_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::Select(SelectChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
            MetaChip::new(Self::Poseidon2Wide(Poseidon2WideChip::default())),
            MetaChip::new(Self::BatchFRI(BatchFRIChip::default())),
            MetaChip::new(Self::PublicValues(PublicValuesChip::default())),
        ]
    }

    pub fn chip_heights(program: &RecursionProgram<F>) -> Vec<(String, usize)> {
        let heights = program
            .instructions
            .iter()
            .fold(RecursionEventCount::default(), |heights, instruction| {
                heights + instruction
            });

        [
            (
                Self::MemoryConst(MemoryConstChip::default()),
                heights
                    .mem_const_events
                    .div_ceil(NUM_CONST_MEM_ENTRIES_PER_ROW),
            ),
            (
                Self::MemoryVar(MemoryVarChip::default()),
                heights.mem_var_events.div_ceil(NUM_VAR_MEM_ENTRIES_PER_ROW),
            ),
            (
                Self::BaseAlu(BaseAluChip::default()),
                heights
                    .base_alu_events
                    .div_ceil(NUM_BASE_ALU_ENTRIES_PER_ROW),
            ),
            (
                Self::ExtAlu(ExtAluChip::default()),
                if F::field_type() == FieldType::TypeKoalaBear {
                    heights.ext_alu_events.div_ceil(NUM_EXT_ALU_ENTRIES_PER_ROW)
                } else {
                    0
                },
            ),
            // (
            //     Self::BabyBearPoseidon2Wide(Poseidon2WideChip::<
            //         DEGREE,
            //         BABYBEAR_NUM_EXTERNAL_ROUNDS,
            //         BABYBEAR_NUM_INTERNAL_ROUNDS,
            //         { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
            //         F,
            //     >::default()),
            //     if F::field_type() == FieldType::TypeBabyBear {
            //         heights.poseidon2_wide_events
            //     } else {
            //         0
            //     },
            // ),
            (
                Self::Poseidon2Wide(Poseidon2WideChip::<
                    DEGREE,
                    NUM_EXTERNAL_ROUNDS,
                    NUM_INTERNAL_ROUNDS,
                    NUM_INTERNAL_ROUNDS_MINUS_ONE,
                    F,
                >::default()),
                if F::field_type() == FieldType::TypeKoalaBear {
                    heights.poseidon2_wide_events
                } else {
                    0
                },
            ),
            (
                Self::BatchFRI(BatchFRIChip::<DEGREE, W, F>::default()),
                heights.batch_fri_events,
            ),
            (Self::Select(SelectChip::default()), heights.select_events),
            (
                Self::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE, F>::default()),
                heights.exp_reverse_bits_len_events,
            ),
            (
                Self::PublicValues(PublicValuesChip::default()),
                PUB_VALUES_LOG_HEIGHT,
            ),
        ]
        .map(|(chip, log_height)| (chip.name(), log_height))
        .to_vec()
    }

    // all the compress proof should be padded to this shape
    pub fn compress_shape() -> RecursionPadShape {
        let shape = HashMap::from(
            [
                (Self::MemoryConst(MemoryConstChip::default()), 17),
                (Self::MemoryVar(MemoryVarChip::default()), 18),
                (Self::BaseAlu(BaseAluChip::default()), 15),
                (Self::ExtAlu(ExtAluChip::default()), 15),
                (
                    Self::Poseidon2Wide(Poseidon2WideChip::<
                        DEGREE,
                        NUM_EXTERNAL_ROUNDS,
                        NUM_INTERNAL_ROUNDS,
                        NUM_INTERNAL_ROUNDS_MINUS_ONE,
                        F,
                    >::default()),
                    16,
                ),
                (
                    Self::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE, F>::default()),
                    17,
                ),
                (
                    Self::PublicValues(PublicValuesChip::default()),
                    PUB_VALUES_LOG_HEIGHT,
                ),
                (Self::BatchFRI(BatchFRIChip::<DEGREE, W, F>::default()), 18),
                (Self::Select(SelectChip::default()), 18),
            ]
            .map(|(chip, log_height)| (chip.name(), log_height)),
        );
        RecursionPadShape { inner: shape }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RecursionEventCount {
    pub mem_const_events: usize,
    pub mem_var_events: usize,
    pub base_alu_events: usize,
    pub ext_alu_events: usize,
    pub poseidon2_wide_events: usize,
    pub batch_fri_events: usize,
    pub select_events: usize,
    pub exp_reverse_bits_len_events: usize,
}

impl<F> AddAssign<&Instruction<F>> for RecursionEventCount {
    #[inline]
    fn add_assign(&mut self, rhs: &Instruction<F>) {
        match rhs {
            Instruction::BaseAlu(_) => self.base_alu_events += 1,
            Instruction::ExtAlu(_) => self.ext_alu_events += 1,
            Instruction::Mem(_) => self.mem_const_events += 1,
            Instruction::Select(_) => self.select_events += 1,
            Instruction::Poseidon2(_) => self.poseidon2_wide_events += 1,
            Instruction::ExpReverseBitsLen(ExpReverseBitsInstr { addrs, .. }) => {
                self.exp_reverse_bits_len_events += addrs.exp.len()
            }
            Instruction::Hint(HintInstr { output_addrs_mults })
            | Instruction::HintBits(HintBitsInstr {
                output_addrs_mults,
                input_addr: _, // No receive interaction for the hint operation
            }) => self.mem_var_events += output_addrs_mults.len(),
            Instruction::HintExt2Felts(HintExt2FeltsInstr {
                output_addrs_mults,
                input_addr: _, // No receive interaction for the hint operation
            }) => self.mem_var_events += output_addrs_mults.len(),
            Instruction::HintAddCurve(instr) => {
                let HintAddCurveInstr {
                    output_x_addrs_mults,
                    output_y_addrs_mults,
                    ..
                } = &**instr;
                self.mem_var_events += output_x_addrs_mults.len() + output_y_addrs_mults.len();
            }
            Instruction::CommitPublicValues(_) => {}
            Instruction::Print(_) => {}
            Instruction::BatchFRI(instr) => {
                self.batch_fri_events += instr.base_vec_addrs.p_at_x.len()
            }
        }
    }
}

impl<F> Add<&Instruction<F>> for RecursionEventCount {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Instruction<F>) -> Self::Output {
        self += rhs;
        self
    }
}
