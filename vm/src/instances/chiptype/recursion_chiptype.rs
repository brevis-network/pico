use crate::{
    chips::{
        chips::{
            alu_base::BaseAluChip,
            alu_ext::ExtAluChip,
            assert_zero_ext::AssertZeroExtChip,
            batch_fri::BatchFRIChip,
            binary_fold_step::BinaryFoldStepChip,
            digest_select::DigestSelectChip,
            exp_bits_len::ExpBitsLenChip,
            exp_reverse_bits::ExpReverseBitsLenChip,
            ext_dot_product::ExtDotProductChip,
            frac_fold::FracFoldChip,
            gkr_sumcheck_round::GkrSumcheckRoundChip,
            horner_eval::HornerEvalChip,
            lagrange_eval_d2::LagrangeEvalD2Chip,
            mle_open::MleOpenChip,
            pack_block::PackBlockChip,
            poseidon2::{FieldSpecificPoseidon2Chip, POSEIDON2_CHIPNAME},
            poseidon2_packed::FieldSpecificPoseidon2PackedChip,
            public_values::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
            recursion_memory::{constant::MemoryConstChip, variable::MemoryVarChip},
            select::SelectChip,
            univariate_fold::UnivariateFoldChip,
            unpack_block::UnpackBlockChip,
        },
        trace::TraceData,
    },
    compiler::recursion::{
        instruction::{
            HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction,
        },
        program::RecursionProgram,
        types::ExpReverseBitsInstr,
    },
    emulator::recursion::emulator::RecursionRecord,
    instances::compiler::shapes::recursion_shape::RecursionPadShape,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip, PreprocessedRows},
        field::FieldSpecificPoseidon2Config,
    },
    primitives::consts::{
        BASE_ALU_DATAPAR, CONST_MEM_DATAPAR, EXTENSION_DEGREE, EXT_ALU_DATAPAR, POSEIDON2_DATAPAR,
        SELECT_DATAPAR, VAR_MEM_DATAPAR,
    },
};
use hashbrown::HashMap;
use p3_air::{Air, BaseAir};
use p3_field::{extension::BinomiallyExtendable, Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::ops::{Add, AddAssign};

pub enum RecursionChipType<F: FieldSpecificPoseidon2Config + Field> {
    MemoryConst(MemoryConstChip<F>),
    MemoryVar(MemoryVarChip<F>),
    ExpReverseBitsLen(ExpReverseBitsLenChip<F>),
    BaseAlu(BaseAluChip<F>),
    ExtAlu(ExtAluChip<F>),
    Select(SelectChip<F>),
    Poseidon2(FieldSpecificPoseidon2Chip<F>),
    BatchFRI(BatchFRIChip<F>),
    PublicValues(PublicValuesChip<F>),
    // WHIR verifier chips (Convert/Combine/Compress recursion)
    AssertZeroExt(AssertZeroExtChip<F>),
    FracFold(FracFoldChip<F>),
    MleOpen(MleOpenChip<F>),
    UnivariateFold(UnivariateFoldChip<F>),
    LagrangeEvalD2(LagrangeEvalD2Chip<F>),
    GkrSumcheckRound(GkrSumcheckRoundChip<F>),
    ExtDotProduct(ExtDotProductChip<F>),
    HornerEval(HornerEvalChip<F>),
    DigestSelect(DigestSelectChip<F>),
    BinaryFoldStep(BinaryFoldStepChip<F>),
    PackBlock(PackBlockChip<F>),
    UnpackBlock(UnpackBlockChip<F>),
    Poseidon2Packed(FieldSpecificPoseidon2PackedChip<F>),
    ExpBitsLen(ExpBitsLenChip<F>),
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config>
    ChipBehavior<F> for RecursionChipType<F>
{
    type Record = RecursionRecord<F>;
    // NOTE: unnecessary to support additional gpu record in recursion for now
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        match self {
            Self::MemoryConst(chip) => chip.name(),
            Self::MemoryVar(chip) => chip.name(),
            Self::Select(chip) => chip.name(),
            Self::ExpReverseBitsLen(chip) => chip.name(),
            Self::BaseAlu(chip) => chip.name(),
            Self::ExtAlu(chip) => chip.name(),
            Self::Poseidon2(chip) => chip.name(),
            Self::BatchFRI(chip) => chip.name(),
            Self::PublicValues(chip) => chip.name(),
            Self::AssertZeroExt(chip) => chip.name(),
            Self::FracFold(chip) => chip.name(),
            Self::MleOpen(chip) => chip.name(),
            Self::UnivariateFold(chip) => chip.name(),
            Self::LagrangeEvalD2(chip) => chip.name(),
            Self::GkrSumcheckRound(chip) => chip.name(),
            Self::ExtDotProduct(chip) => chip.name(),
            Self::HornerEval(chip) => chip.name(),
            Self::DigestSelect(chip) => chip.name(),
            Self::BinaryFoldStep(chip) => chip.name(),
            Self::PackBlock(chip) => chip.name(),
            Self::UnpackBlock(chip) => chip.name(),
            Self::Poseidon2Packed(chip) => chip.name(),
            Self::ExpBitsLen(chip) => chip.name(),
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
            Self::Poseidon2(chip) => chip.generate_preprocessed(program),
            Self::BatchFRI(chip) => chip.generate_preprocessed(program),
            Self::PublicValues(chip) => chip.generate_preprocessed(program),
            Self::AssertZeroExt(chip) => chip.generate_preprocessed(program),
            Self::FracFold(chip) => chip.generate_preprocessed(program),
            Self::MleOpen(chip) => chip.generate_preprocessed(program),
            Self::UnivariateFold(chip) => chip.generate_preprocessed(program),
            Self::LagrangeEvalD2(chip) => chip.generate_preprocessed(program),
            Self::GkrSumcheckRound(chip) => chip.generate_preprocessed(program),
            Self::ExtDotProduct(chip) => chip.generate_preprocessed(program),
            Self::HornerEval(chip) => chip.generate_preprocessed(program),
            Self::DigestSelect(chip) => chip.generate_preprocessed(program),
            Self::BinaryFoldStep(chip) => chip.generate_preprocessed(program),
            Self::PackBlock(chip) => chip.generate_preprocessed(program),
            Self::UnpackBlock(chip) => chip.generate_preprocessed(program),
            Self::Poseidon2Packed(chip) => chip.generate_preprocessed(program),
            Self::ExpBitsLen(chip) => chip.generate_preprocessed(program),
        }
    }

    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &RecursionProgram<F>,
    ) -> Option<TraceData<'_, F>> {
        match self {
            Self::MemoryConst(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::MemoryVar(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::Select(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::ExpReverseBitsLen(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::BaseAlu(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::ExtAlu(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::Poseidon2(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::BatchFRI(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::PublicValues(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::AssertZeroExt(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::FracFold(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::MleOpen(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::UnivariateFold(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::LagrangeEvalD2(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::GkrSumcheckRound(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::ExtDotProduct(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::HornerEval(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::DigestSelect(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::BinaryFoldStep(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::PackBlock(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::UnpackBlock(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::Poseidon2Packed(chip) => chip.gpu_generate_preprocessed(device_id, program),
            Self::ExpBitsLen(chip) => chip.gpu_generate_preprocessed(device_id, program),
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
            Self::Poseidon2(chip) => chip.generate_main(input, output),
            Self::BatchFRI(chip) => chip.generate_main(input, output),
            Self::PublicValues(chip) => chip.generate_main(input, output),
            Self::AssertZeroExt(chip) => chip.generate_main(input, output),
            Self::FracFold(chip) => chip.generate_main(input, output),
            Self::MleOpen(chip) => chip.generate_main(input, output),
            Self::UnivariateFold(chip) => chip.generate_main(input, output),
            Self::LagrangeEvalD2(chip) => chip.generate_main(input, output),
            Self::GkrSumcheckRound(chip) => chip.generate_main(input, output),
            Self::ExtDotProduct(chip) => chip.generate_main(input, output),
            Self::HornerEval(chip) => chip.generate_main(input, output),
            Self::DigestSelect(chip) => chip.generate_main(input, output),
            Self::BinaryFoldStep(chip) => chip.generate_main(input, output),
            Self::PackBlock(chip) => chip.generate_main(input, output),
            Self::UnpackBlock(chip) => chip.generate_main(input, output),
            Self::Poseidon2Packed(chip) => chip.generate_main(input, output),
            Self::ExpBitsLen(chip) => chip.generate_main(input, output),
        }
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        output: &mut Self::Record,
        gpu_input: Option<&Self::GpuRecord>,
    ) -> TraceData<'_, F> {
        match self {
            Self::MemoryConst(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::MemoryVar(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::Select(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::ExpReverseBitsLen(chip) => {
                chip.gpu_generate_main(device_id, input, output, gpu_input)
            }
            Self::BaseAlu(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::ExtAlu(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::Poseidon2(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::BatchFRI(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::PublicValues(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::AssertZeroExt(chip) => {
                chip.gpu_generate_main(device_id, input, output, gpu_input)
            }
            Self::FracFold(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::MleOpen(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::UnivariateFold(chip) => {
                chip.gpu_generate_main(device_id, input, output, gpu_input)
            }
            Self::LagrangeEvalD2(chip) => {
                chip.gpu_generate_main(device_id, input, output, gpu_input)
            }
            Self::GkrSumcheckRound(chip) => {
                chip.gpu_generate_main(device_id, input, output, gpu_input)
            }
            Self::ExtDotProduct(chip) => {
                chip.gpu_generate_main(device_id, input, output, gpu_input)
            }
            Self::HornerEval(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::DigestSelect(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::BinaryFoldStep(chip) => {
                chip.gpu_generate_main(device_id, input, output, gpu_input)
            }
            Self::PackBlock(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::UnpackBlock(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
            Self::Poseidon2Packed(chip) => {
                chip.gpu_generate_main(device_id, input, output, gpu_input)
            }
            Self::ExpBitsLen(chip) => chip.gpu_generate_main(device_id, input, output, gpu_input),
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
            Self::Poseidon2(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::BatchFRI(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::PublicValues(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::AssertZeroExt(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::FracFold(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::MleOpen(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::UnivariateFold(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::LagrangeEvalD2(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::GkrSumcheckRound(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::ExtDotProduct(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::HornerEval(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::DigestSelect(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::BinaryFoldStep(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::PackBlock(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::UnpackBlock(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::Poseidon2Packed(chip) => ChipBehavior::<F>::preprocessed_width(chip),
            Self::ExpBitsLen(chip) => ChipBehavior::<F>::preprocessed_width(chip),
        }
    }

    /// Forwarded like every other method here: an enum arm that fell through to the trait
    /// default would report "does not declare" for a chip that does, silently sending merged
    /// deferred-commit keygen back to generating the trace.
    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        match self {
            Self::MemoryConst(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::MemoryVar(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::Select(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::ExpReverseBitsLen(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::BaseAlu(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::ExtAlu(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::Poseidon2(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::BatchFRI(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::PublicValues(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::AssertZeroExt(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::FracFold(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::MleOpen(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::UnivariateFold(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::LagrangeEvalD2(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::GkrSumcheckRound(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::ExtDotProduct(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::HornerEval(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::DigestSelect(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::BinaryFoldStep(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::PackBlock(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::UnpackBlock(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::Poseidon2Packed(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
            Self::ExpBitsLen(chip) => ChipBehavior::<F>::preprocessed_rows(chip, program),
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
            Self::Poseidon2(chip) => chip.extra_record(input, extra),
            Self::BatchFRI(chip) => chip.extra_record(input, extra),
            Self::PublicValues(chip) => chip.extra_record(input, extra),
            Self::AssertZeroExt(chip) => chip.extra_record(input, extra),
            Self::FracFold(chip) => chip.extra_record(input, extra),
            Self::MleOpen(chip) => chip.extra_record(input, extra),
            Self::UnivariateFold(chip) => chip.extra_record(input, extra),
            Self::LagrangeEvalD2(chip) => chip.extra_record(input, extra),
            Self::GkrSumcheckRound(chip) => chip.extra_record(input, extra),
            Self::ExtDotProduct(chip) => chip.extra_record(input, extra),
            Self::HornerEval(chip) => chip.extra_record(input, extra),
            Self::DigestSelect(chip) => chip.extra_record(input, extra),
            Self::BinaryFoldStep(chip) => chip.extra_record(input, extra),
            Self::PackBlock(chip) => chip.extra_record(input, extra),
            Self::UnpackBlock(chip) => chip.extra_record(input, extra),
            Self::Poseidon2Packed(chip) => chip.extra_record(input, extra),
            Self::ExpBitsLen(chip) => chip.extra_record(input, extra),
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
            Self::Poseidon2(chip) => chip.is_active(record),
            Self::BatchFRI(chip) => chip.is_active(record),
            Self::PublicValues(chip) => chip.is_active(record),
            Self::AssertZeroExt(chip) => chip.is_active(record),
            Self::FracFold(chip) => chip.is_active(record),
            Self::MleOpen(chip) => chip.is_active(record),
            Self::UnivariateFold(chip) => chip.is_active(record),
            Self::LagrangeEvalD2(chip) => chip.is_active(record),
            Self::GkrSumcheckRound(chip) => chip.is_active(record),
            Self::ExtDotProduct(chip) => chip.is_active(record),
            Self::HornerEval(chip) => chip.is_active(record),
            Self::DigestSelect(chip) => chip.is_active(record),
            Self::BinaryFoldStep(chip) => chip.is_active(record),
            Self::PackBlock(chip) => chip.is_active(record),
            Self::UnpackBlock(chip) => chip.is_active(record),
            Self::Poseidon2Packed(chip) => chip.is_active(record),
            Self::ExpBitsLen(chip) => chip.is_active(record),
        }
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config>
    BaseAir<F> for RecursionChipType<F>
{
    fn width(&self) -> usize {
        match self {
            Self::MemoryConst(chip) => chip.width(),
            Self::MemoryVar(chip) => chip.width(),
            Self::Select(chip) => chip.width(),
            Self::ExpReverseBitsLen(chip) => chip.width(),
            Self::BaseAlu(chip) => chip.width(),
            Self::ExtAlu(chip) => chip.width(),
            Self::Poseidon2(chip) => chip.width(),
            Self::BatchFRI(chip) => chip.width(),
            Self::PublicValues(chip) => chip.width(),
            Self::AssertZeroExt(chip) => chip.width(),
            Self::FracFold(chip) => chip.width(),
            Self::MleOpen(chip) => chip.width(),
            Self::UnivariateFold(chip) => chip.width(),
            Self::LagrangeEvalD2(chip) => chip.width(),
            Self::GkrSumcheckRound(chip) => chip.width(),
            Self::ExtDotProduct(chip) => chip.width(),
            Self::HornerEval(chip) => chip.width(),
            Self::DigestSelect(chip) => chip.width(),
            Self::BinaryFoldStep(chip) => chip.width(),
            Self::PackBlock(chip) => chip.width(),
            Self::UnpackBlock(chip) => chip.width(),
            Self::Poseidon2Packed(chip) => chip.width(),
            Self::ExpBitsLen(chip) => chip.width(),
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
            Self::Poseidon2(chip) => chip.preprocessed_trace(),
            Self::BatchFRI(chip) => chip.preprocessed_trace(),
            Self::PublicValues(chip) => chip.preprocessed_trace(),
            Self::AssertZeroExt(chip) => chip.preprocessed_trace(),
            Self::FracFold(chip) => chip.preprocessed_trace(),
            Self::MleOpen(chip) => chip.preprocessed_trace(),
            Self::UnivariateFold(chip) => chip.preprocessed_trace(),
            Self::LagrangeEvalD2(chip) => chip.preprocessed_trace(),
            Self::GkrSumcheckRound(chip) => chip.preprocessed_trace(),
            Self::ExtDotProduct(chip) => chip.preprocessed_trace(),
            Self::HornerEval(chip) => chip.preprocessed_trace(),
            Self::DigestSelect(chip) => chip.preprocessed_trace(),
            Self::BinaryFoldStep(chip) => chip.preprocessed_trace(),
            Self::PackBlock(chip) => chip.preprocessed_trace(),
            Self::UnpackBlock(chip) => chip.preprocessed_trace(),
            Self::Poseidon2Packed(chip) => chip.preprocessed_trace(),
            Self::ExpBitsLen(chip) => chip.preprocessed_trace(),
        }
    }
}

impl<
        F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
        AB: ChipBuilder<F>,
    > Air<AB> for RecursionChipType<F>
where
    FieldSpecificPoseidon2Chip<F>: Air<AB>,
    FieldSpecificPoseidon2PackedChip<F>: Air<AB>,
{
    fn eval(&self, b: &mut AB) {
        //assert_eq!(F::W, F::from_u32(F::W::U32));
        match self {
            Self::MemoryConst(chip) => chip.eval(b),
            Self::MemoryVar(chip) => chip.eval(b),
            Self::Select(chip) => chip.eval(b),
            Self::ExpReverseBitsLen(chip) => chip.eval(b),
            Self::BaseAlu(chip) => chip.eval(b),
            Self::ExtAlu(chip) => chip.eval(b),
            Self::Poseidon2(chip) => chip.eval(b),
            Self::BatchFRI(chip) => chip.eval(b),
            Self::PublicValues(chip) => chip.eval(b),
            Self::AssertZeroExt(chip) => chip.eval(b),
            Self::FracFold(chip) => chip.eval(b),
            Self::MleOpen(chip) => chip.eval(b),
            Self::UnivariateFold(chip) => chip.eval(b),
            Self::LagrangeEvalD2(chip) => chip.eval(b),
            Self::GkrSumcheckRound(chip) => chip.eval(b),
            Self::ExtDotProduct(chip) => chip.eval(b),
            Self::HornerEval(chip) => chip.eval(b),
            Self::DigestSelect(chip) => chip.eval(b),
            Self::BinaryFoldStep(chip) => chip.eval(b),
            Self::PackBlock(chip) => chip.eval(b),
            Self::UnpackBlock(chip) => chip.eval(b),
            Self::Poseidon2Packed(chip) => chip.eval(b),
            Self::ExpBitsLen(chip) => chip.eval(b),
        }
    }
}

impl RecursionChipType<p3_koala_bear::KoalaBear> {
    /// The 21-chip set for the MLE/WHIR recursion layer (Convert + Combine).
    ///
    /// Differs from the FRI-era recursion chip set: it drops the FRI-only
    /// `ExpReverseBitsLen`/`BatchFRI` and adds the thirteen WHIR verifier chips
    /// (`AssertZeroExt`/`FracFold`/`MleOpen`/`UnivariateFold`/`LagrangeEvalD2`/`GkrSumcheckRound`/`ExtDotProduct`/`HornerEval`/`DigestSelect`/`BinaryFoldStep`/`PackBlock`/`UnpackBlock`/`Poseidon2Packed`).
    /// KoalaBear-only like the MLE engine itself (`mle::machine::riscv::Kb`), whose transcript the
    /// recursion Poseidon2 chips (`recursion::recursion_poseidon2_chip`) re-derive.
    /// Shared by the Convert and Combine recursion provers; split them later if they diverge.
    pub fn mle_recursion_chips() -> Vec<MetaChip<p3_koala_bear::KoalaBear, Self>> {
        vec![
            MetaChip::new(Self::MemoryConst(MemoryConstChip::default())),
            MetaChip::new(Self::MemoryVar(MemoryVarChip::default())),
            MetaChip::new(Self::BaseAlu(BaseAluChip::default())),
            MetaChip::new(Self::ExtAlu(ExtAluChip::default())),
            MetaChip::new(Self::Select(SelectChip::default())),
            MetaChip::new(Self::Poseidon2(
                crate::mle::machine::recursion::recursion_poseidon2_chip(),
            )),
            MetaChip::new(Self::PublicValues(PublicValuesChip::default())),
            MetaChip::new(Self::AssertZeroExt(AssertZeroExtChip::default())),
            MetaChip::new(Self::FracFold(FracFoldChip::default())),
            MetaChip::new(Self::MleOpen(MleOpenChip::default())),
            MetaChip::new(Self::UnivariateFold(UnivariateFoldChip::default())),
            MetaChip::new(Self::LagrangeEvalD2(LagrangeEvalD2Chip::default())),
            MetaChip::new(Self::GkrSumcheckRound(GkrSumcheckRoundChip::default())),
            MetaChip::new(Self::ExtDotProduct(ExtDotProductChip::default())),
            MetaChip::new(Self::HornerEval(HornerEvalChip::default())),
            MetaChip::new(Self::DigestSelect(DigestSelectChip::default())),
            MetaChip::new(Self::BinaryFoldStep(BinaryFoldStepChip::default())),
            MetaChip::new(Self::PackBlock(PackBlockChip::default())),
            MetaChip::new(Self::UnpackBlock(UnpackBlockChip::default())),
            MetaChip::new(Self::Poseidon2Packed(
                crate::mle::machine::recursion::recursion_poseidon2_packed_chip(),
            )),
            MetaChip::new(Self::ExpBitsLen(ExpBitsLenChip::default())),
        ]
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config>
    RecursionChipType<F>
{
    pub fn chip_heights(program: &RecursionProgram<F>) -> Vec<(String, usize)> {
        let heights = program
            .instructions
            .iter()
            .fold(RecursionEventCount::default(), |heights, instruction| {
                heights + instruction
            });

        let mut results = [
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
                Self::BatchFRI(BatchFRIChip::default()),
                heights.batch_fri_events,
            ),
            (
                Self::Select(SelectChip::default()),
                heights.select_events.div_ceil(SELECT_DATAPAR),
            ),
            (
                Self::ExpReverseBitsLen(ExpReverseBitsLenChip::<F>::default()),
                heights.exp_reverse_bits_len_events,
            ),
            (
                Self::PublicValues(PublicValuesChip::default()),
                PUB_VALUES_LOG_HEIGHT,
            ),
        ]
        .map(|(chip, log_height)| (chip.name(), log_height))
        .to_vec();

        results.push((
            POSEIDON2_CHIPNAME.to_string(),
            heights.poseidon2_events.div_ceil(POSEIDON2_DATAPAR),
        ));
        results
    }

    // all the compress proof should be padded to this shape
    pub fn compress_shape() -> RecursionPadShape {
        let mut shape = HashMap::from(
            [
                (Self::MemoryConst(MemoryConstChip::default()), 17),
                (Self::MemoryVar(MemoryVarChip::default()), 17),
                (Self::BaseAlu(BaseAluChip::default()), 16),
                (Self::ExtAlu(ExtAluChip::default()), 15),
                (
                    Self::ExpReverseBitsLen(ExpReverseBitsLenChip::<F>::default()),
                    17,
                ),
                (
                    Self::PublicValues(PublicValuesChip::default()),
                    PUB_VALUES_LOG_HEIGHT,
                ),
                (Self::BatchFRI(BatchFRIChip::default()), 17),
                (Self::Select(SelectChip::default()), 17),
            ]
            .map(|(chip, log_height)| (chip.name(), log_height)),
        );

        shape.insert(POSEIDON2_CHIPNAME.to_string(), 16);
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
            Instruction::AssertZeroExt(_)
            | Instruction::FracFold(_)
            | Instruction::UnivariateFold(_)
            | Instruction::MleOpen(_)
            | Instruction::LagrangeEvalD2(_)
            | Instruction::GkrSumcheckRound(_)
            | Instruction::ExtDotProduct(_)
            | Instruction::HornerEval(_)
            | Instruction::DigestSelect(_)
            | Instruction::BinaryFoldStep(_)
            | Instruction::PackBlock(_)
            | Instruction::UnpackBlock(_)
            | Instruction::Poseidon2Packed(_)
            | Instruction::ExpBitsLen(_) => {}
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
