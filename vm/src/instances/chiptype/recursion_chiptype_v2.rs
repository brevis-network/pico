use crate::{
    chips::chips::{
        alu_base::BaseAluChip,
        alu_ext::ExtAluChip,
        batch_fri::BatchFRIChip,
        exp_reverse_bits::ExpReverseBitsLenChip,
        poseidon2_p3::{BabyBearPoseidon2Chip, KoalaBearPoseidon2Chip},
        public_values_v2::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
        recursion_memory_v2::{constant::MemoryConstChip, variable::MemoryVarChip},
        select::SelectChip,
    },
    compiler::recursion_v2::{
        instruction::{
            HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction,
        },
        program::RecursionProgram,
        types::ExpReverseBitsInstr,
    },
    emulator::recursion::emulator::RecursionRecord,
    instances::compiler_v2::shapes::compress_shape::RecursionPadShape,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        field::{same_field, FieldSpecificPoseidon2Config},
        folder::SymbolicConstraintFolder,
    },
    primitives::consts::{
        BASE_ALU_DATAPAR, CONST_MEM_DATAPAR, EXTENSION_DEGREE, EXT_ALU_DATAPAR, POSEIDON2_DATAPAR,
        SELECT_DATAPAR, VAR_MEM_DATAPAR,
    },
};
use hashbrown::HashMap;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::{extension::BinomiallyExtendable, Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use std::ops::{Add, AddAssign};

pub enum RecursionChipType<F: FieldSpecificPoseidon2Config + Field, const DEGREE: usize> {
    MemoryConst(MemoryConstChip<F>),
    MemoryVar(MemoryVarChip<F>),
    ExpReverseBitsLen(ExpReverseBitsLenChip<F>),
    BaseAlu(BaseAluChip<F>),
    ExtAlu(ExtAluChip<F>),
    Select(SelectChip<F>),
    BabyBearPoseidon2(BabyBearPoseidon2Chip<F>),
    KoalaBearPoseidon2(KoalaBearPoseidon2Chip<F>),
    BatchFRI(BatchFRIChip<F>),
    PublicValues(PublicValuesChip<F>),
}

impl<
        F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
        const DEGREE: usize,
    > ChipBehavior<F> for RecursionChipType<F, DEGREE>
where
    BabyBearPoseidon2Chip<F>:
        ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
    KoalaBearPoseidon2Chip<F>:
        ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        match self {
            Self::MemoryConst(chip) => chip.name(),
            Self::MemoryVar(chip) => chip.name(),
            Self::Select(chip) => chip.name(),
            Self::ExpReverseBitsLen(chip) => chip.name(),
            Self::BaseAlu(chip) => chip.name(),
            Self::ExtAlu(chip) => chip.name(),
            Self::BabyBearPoseidon2(chip) => chip.name(),
            Self::KoalaBearPoseidon2(chip) => chip.name(),
            Self::BatchFRI(chip) => chip.name(),
            Self::PublicValues(chip) => chip.name(),
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
            Self::BabyBearPoseidon2(chip) => chip.generate_preprocessed(program),
            Self::KoalaBearPoseidon2(chip) => chip.generate_preprocessed(program),
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
            Self::BabyBearPoseidon2(chip) => chip.generate_main(input, output),
            Self::KoalaBearPoseidon2(chip) => chip.generate_main(input, output),
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
            Self::BabyBearPoseidon2(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::KoalaBearPoseidon2(chip) => ChipBehavior::<F>::preprocessed_width(chip),
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
            Self::BabyBearPoseidon2(chip) => chip.extra_record(input, extra),
            Self::KoalaBearPoseidon2(chip) => chip.extra_record(input, extra),
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
            Self::BabyBearPoseidon2(chip) => chip.is_active(record),
            Self::KoalaBearPoseidon2(chip) => chip.is_active(record),
            Self::BatchFRI(chip) => chip.is_active(record),
            Self::PublicValues(chip) => chip.is_active(record),
        }
    }
}

impl<
        F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
        const DEGREE: usize,
    > BaseAir<F> for RecursionChipType<F, DEGREE>
where
    BabyBearPoseidon2Chip<F>: BaseAir<F>,
    KoalaBearPoseidon2Chip<F>: BaseAir<F>,
{
    fn width(&self) -> usize {
        match self {
            Self::MemoryConst(chip) => chip.width(),
            Self::MemoryVar(chip) => chip.width(),
            Self::Select(chip) => chip.width(),
            Self::ExpReverseBitsLen(chip) => chip.width(),
            Self::BaseAlu(chip) => chip.width(),
            Self::ExtAlu(chip) => chip.width(),
            Self::BabyBearPoseidon2(chip) => chip.width(),
            Self::KoalaBearPoseidon2(chip) => chip.width(),
            Self::BatchFRI(chip) => chip.width(),
            Self::PublicValues(chip) => chip.width(),
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
            Self::BabyBearPoseidon2(chip) => chip.preprocessed_trace(),
            Self::KoalaBearPoseidon2(chip) => chip.preprocessed_trace(),
            Self::BatchFRI(chip) => chip.preprocessed_trace(),
            Self::PublicValues(chip) => chip.preprocessed_trace(),
        }
    }
}

impl<
        F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
        AB: ChipBuilder<F>,
        const DEGREE: usize,
    > Air<AB> for RecursionChipType<F, DEGREE>
where
    RecursionChipType<F, DEGREE>: BaseAir<<AB as AirBuilder>::F>,
    BabyBearPoseidon2Chip<F>: Air<AB>,
    KoalaBearPoseidon2Chip<F>: Air<AB>,
{
    fn eval(&self, b: &mut AB) {
        //assert_eq!(F::W, F::from_canonical_u32(F::W::U32));
        match self {
            Self::MemoryConst(chip) => chip.eval(b),
            Self::MemoryVar(chip) => chip.eval(b),
            Self::Select(chip) => chip.eval(b),
            Self::ExpReverseBitsLen(chip) => chip.eval(b),
            Self::BaseAlu(chip) => chip.eval(b),
            Self::ExtAlu(chip) => chip.eval(b),
            Self::BabyBearPoseidon2(chip) => chip.eval(b),
            Self::KoalaBearPoseidon2(chip) => chip.eval(b),
            Self::BatchFRI(chip) => chip.eval(b),
            Self::PublicValues(chip) => chip.eval(b),
        }
    }
}

impl<
        F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
        const DEGREE: usize,
    > RecursionChipType<F, DEGREE>
where
    BabyBearPoseidon2Chip<F>: Air<SymbolicConstraintFolder<F>>
        + ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
    KoalaBearPoseidon2Chip<F>: Air<SymbolicConstraintFolder<F>>
        + ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
{
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        let mut chips = vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::Select(SelectChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
            MetaChip::new(Self::BatchFRI(BatchFRIChip::default())),
            MetaChip::new(Self::PublicValues(PublicValuesChip::default())),
        ];

        if same_field::<F, BabyBear>() {
            chips.push(MetaChip::new(Self::BabyBearPoseidon2(
                BabyBearPoseidon2Chip::default(),
            )));
        } else if same_field::<F, KoalaBear>() {
            chips.push(MetaChip::new(Self::KoalaBearPoseidon2(
                KoalaBearPoseidon2Chip::default(),
            )));
        } else {
            panic!("Unsupported field type");
        }

        chips
    }

    pub fn convert_chips() -> Vec<MetaChip<F, Self>> {
        let mut chips = vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::Select(SelectChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
            MetaChip::new(Self::BatchFRI(BatchFRIChip::default())),
            MetaChip::new(Self::PublicValues(PublicValuesChip::default())),
        ];

        if same_field::<F, BabyBear>() {
            chips.push(MetaChip::new(Self::BabyBearPoseidon2(
                BabyBearPoseidon2Chip::default(),
            )));
        } else if same_field::<F, KoalaBear>() {
            chips.push(MetaChip::new(Self::KoalaBearPoseidon2(
                KoalaBearPoseidon2Chip::default(),
            )));
        } else {
            panic!("Unsupported field type");
        }

        chips
    }

    pub fn combine_chips() -> Vec<MetaChip<F, Self>> {
        let mut chips = vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::Select(SelectChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
            MetaChip::new(Self::BatchFRI(BatchFRIChip::default())),
            MetaChip::new(Self::PublicValues(PublicValuesChip::default())),
        ];

        if same_field::<F, BabyBear>() {
            chips.push(MetaChip::new(Self::BabyBearPoseidon2(
                BabyBearPoseidon2Chip::default(),
            )));
        } else if same_field::<F, KoalaBear>() {
            chips.push(MetaChip::new(Self::KoalaBearPoseidon2(
                KoalaBearPoseidon2Chip::default(),
            )));
        } else {
            panic!("Unsupported field type");
        }

        chips
    }

    pub fn compress_chips() -> Vec<MetaChip<F, Self>> {
        let mut chips = vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::Select(SelectChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
            MetaChip::new(Self::BatchFRI(BatchFRIChip::default())),
            MetaChip::new(Self::PublicValues(PublicValuesChip::default())),
        ];

        if same_field::<F, BabyBear>() {
            chips.push(MetaChip::new(Self::BabyBearPoseidon2(
                BabyBearPoseidon2Chip::default(),
            )));
        } else if same_field::<F, KoalaBear>() {
            chips.push(MetaChip::new(Self::KoalaBearPoseidon2(
                KoalaBearPoseidon2Chip::default(),
            )));
        } else {
            panic!("Unsupported field type");
        }

        chips
    }

    pub fn embed_chips() -> Vec<MetaChip<F, Self>> {
        let mut chips = vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::Select(SelectChip::default())),
            MetaChip::new(Self::ExpReverseBitsLen(ExpReverseBitsLenChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
            MetaChip::new(Self::BatchFRI(BatchFRIChip::default())),
            MetaChip::new(Self::PublicValues(PublicValuesChip::default())),
        ];

        if same_field::<F, BabyBear>() {
            chips.push(MetaChip::new(Self::BabyBearPoseidon2(
                BabyBearPoseidon2Chip::default(),
            )));
        } else if same_field::<F, KoalaBear>() {
            chips.push(MetaChip::new(Self::KoalaBearPoseidon2(
                KoalaBearPoseidon2Chip::default(),
            )));
        } else {
            panic!("Unsupported field type");
        }

        chips
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
                heights.mem_const_events.div_ceil(CONST_MEM_DATAPAR),
            ),
            (
                Self::MemoryVar(MemoryVarChip::default()),
                heights.mem_var_events.div_ceil(VAR_MEM_DATAPAR),
            ),
            (
                Self::BaseAlu(BaseAluChip::default()),
                heights.base_alu_events.div_ceil(BASE_ALU_DATAPAR),
            ),
            (
                Self::ExtAlu(ExtAluChip::default()),
                heights.ext_alu_events.div_ceil(EXT_ALU_DATAPAR),
            ),
            (
                Self::BabyBearPoseidon2(BabyBearPoseidon2Chip::<F>::default()),
                heights.poseidon2_events.div_ceil(POSEIDON2_DATAPAR),
            ),
            (
                Self::KoalaBearPoseidon2(KoalaBearPoseidon2Chip::<F>::default()),
                heights.poseidon2_events.div_ceil(POSEIDON2_DATAPAR),
            ),
            (
                Self::BatchFRI(BatchFRIChip::default()),
                heights.batch_fri_events,
            ),
            (Self::Select(SelectChip::default()), heights.select_events),
            (
                Self::ExpReverseBitsLen(ExpReverseBitsLenChip::<F>::default()),
                heights.exp_reverse_bits_len_events.div_ceil(SELECT_DATAPAR),
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
                    Self::BabyBearPoseidon2(BabyBearPoseidon2Chip::<F>::default()),
                    16,
                ),
                (
                    Self::KoalaBearPoseidon2(KoalaBearPoseidon2Chip::<F>::default()),
                    16,
                ),
                (
                    Self::ExpReverseBitsLen(ExpReverseBitsLenChip::<F>::default()),
                    17,
                ),
                (
                    Self::PublicValues(PublicValuesChip::default()),
                    PUB_VALUES_LOG_HEIGHT,
                ),
                (Self::BatchFRI(BatchFRIChip::default()), 18),
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
    pub poseidon2_events: usize,
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
            Instruction::Poseidon2(_) => self.poseidon2_events += 1,
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
