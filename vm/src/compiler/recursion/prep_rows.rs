//! Unpadded preprocessed row counts for the MLE recursion chip set, tallied in one pass over
//! `instructions` and cached on the program (see `RecursionProgram::prep_row_counts`), so each
//! chip's `ChipBehavior::preprocessed_rows` declaration is a field read instead of its own
//! program-length scan.
//!
//! Separate from [`crate::instances::chiptype::recursion_chiptype::RecursionEventCount`]
//! because that covers only the non-MLE recursion chips and skips every MLE instruction
//! variant.
//!
//! Every field must equal the row count the chip's own `generate_preprocessed` produces before
//! padding; `declared_preprocessed_dims_match_generated` enforces the pairing per chip.

use super::instruction::Instruction;
use crate::{
    chips::chips::exp_bits_len::columns::NUM_BITS_MAX_PLUS_ONE,
    primitives::consts::{
        BASE_ALU_DATAPAR, CONST_MEM_DATAPAR, DIGEST_SELECT_DATAPAR, EXT_ALU_DATAPAR,
        EXT_DOT_PRODUCT_GROUPS, HORNER_EVAL_DATAPAR, PACK_BLOCK_DATAPAR, POSEIDON2_DATAPAR,
        SELECT_DATAPAR, VAR_MEM_DATAPAR,
    },
};

/// Unpadded preprocessed row count per chip in `RecursionChipType::mle_recursion_chips()`.
///
/// `PublicValues` is absent: it declares a fixed height (`PreprocessedRows::FixedLog2`), so no
/// count is needed. The summed fields are why a per-opcode instruction count is not enough.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PrepRowCounts {
    pub(crate) memory_const: usize,
    /// Σ of the Hint variants' output address lists — not an instruction count.
    pub(crate) memory_var: usize,
    pub(crate) base_alu: usize,
    pub(crate) ext_alu: usize,
    pub(crate) select: usize,
    pub(crate) poseidon2: usize,
    pub(crate) assert_zero_ext: usize,
    pub(crate) frac_fold: usize,
    pub(crate) mle_open: usize,
    pub(crate) univariate_fold: usize,
    pub(crate) lagrange_eval_d2: usize,
    pub(crate) gkr_sumcheck_round: usize,
    /// Σ of `val_addrs.len() / EXT_DOT_PRODUCT_GROUPS` per instruction.
    pub(crate) ext_dot_product: usize,
    /// Σ of `coeff_addrs.len() / HORNER_EVAL_DATAPAR` per instruction.
    pub(crate) horner_eval: usize,
    pub(crate) digest_select: usize,
    pub(crate) binary_fold_step: usize,
    pub(crate) pack_block: usize,
    pub(crate) unpack_block: usize,
    pub(crate) poseidon2_packed: usize,
    /// Instruction count × `NUM_BITS_MAX_PLUS_ONE` — the chip emits a fixed block per instruction.
    pub(crate) exp_bits_len: usize,
}

impl PrepRowCounts {
    pub(crate) fn from_instructions<F>(instructions: &[Instruction<F>]) -> Self {
        // Accumulate into the fields directly — no parallel set of locals to keep paired with
        // them, which is how a count silently lands on the wrong chip.
        let mut c = Self::default();

        for instruction in instructions {
            match instruction {
                Instruction::Mem(_) => c.memory_const += 1,
                Instruction::Hint(i) => c.memory_var += i.output_addrs_mults.len(),
                Instruction::HintBits(i) => c.memory_var += i.output_addrs_mults.len(),
                Instruction::HintExt2Felts(i) => c.memory_var += i.output_addrs_mults.len(),
                Instruction::HintAddCurve(i) => {
                    c.memory_var += i.output_x_addrs_mults.len() + i.output_y_addrs_mults.len();
                }
                Instruction::BaseAlu(_) => c.base_alu += 1,
                Instruction::ExtAlu(_) => c.ext_alu += 1,
                Instruction::Select(_) => c.select += 1,
                Instruction::Poseidon2(_) => c.poseidon2 += 1,
                Instruction::AssertZeroExt(_) => c.assert_zero_ext += 1,
                Instruction::FracFold(_) => c.frac_fold += 1,
                Instruction::MleOpen(_) => c.mle_open += 1,
                Instruction::UnivariateFold(_) => c.univariate_fold += 1,
                Instruction::LagrangeEvalD2(_) => c.lagrange_eval_d2 += 1,
                Instruction::GkrSumcheckRound(_) => c.gkr_sumcheck_round += 1,
                // Already whole rows per instruction: the lowering pads both address vectors to a
                // DATAPAR multiple (the generators debug_assert it).
                Instruction::ExtDotProduct(i) => {
                    c.ext_dot_product += i.val_addrs.len() / EXT_DOT_PRODUCT_GROUPS;
                }
                Instruction::HornerEval(i) => {
                    c.horner_eval += i.coeff_addrs.len() / HORNER_EVAL_DATAPAR;
                }
                Instruction::DigestSelect(_) => c.digest_select += 1,
                Instruction::BinaryFoldStep(_) => c.binary_fold_step += 1,
                Instruction::PackBlock(_) => c.pack_block += 1,
                Instruction::UnpackBlock(_) => c.unpack_block += 1,
                Instruction::Poseidon2Packed(_) => c.poseidon2_packed += 1,
                Instruction::ExpBitsLen(_) => c.exp_bits_len += 1,
                // No count kept: `CommitPublicValues` feeds a fixed-height chip,
                // `ExpReverseBitsLen`/`BatchFRI` are FRI-set only, `Print` has no chip. Listed
                // rather than caught by `_` so a new instruction variant fails to compile here
                // instead of silently counting as zero rows for every chip.
                Instruction::CommitPublicValues(_)
                | Instruction::ExpReverseBitsLen(_)
                | Instruction::BatchFRI(_)
                | Instruction::Print(_) => {}
            }
        }

        // Raw tallies above → rows, applied at the end because `div_ceil` of a sum is not the sum
        // of per-instruction `div_ceil` — exactly where the generators divide. Fields absent here
        // are already whole rows per instruction.
        c.memory_const = c.memory_const.div_ceil(CONST_MEM_DATAPAR);
        c.memory_var = c.memory_var.div_ceil(VAR_MEM_DATAPAR);
        c.base_alu = c.base_alu.div_ceil(BASE_ALU_DATAPAR);
        c.ext_alu = c.ext_alu.div_ceil(EXT_ALU_DATAPAR);
        c.select = c.select.div_ceil(SELECT_DATAPAR);
        c.poseidon2 = c.poseidon2.div_ceil(POSEIDON2_DATAPAR);
        c.digest_select = c.digest_select.div_ceil(DIGEST_SELECT_DATAPAR);
        c.pack_block = c.pack_block.div_ceil(PACK_BLOCK_DATAPAR);
        c.exp_bits_len *= NUM_BITS_MAX_PLUS_ONE;

        c
    }
}
