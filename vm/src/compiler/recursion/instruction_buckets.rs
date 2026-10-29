//! Pre-computed instruction buckets for RecursionProgram.
//! Single-pass classification avoids 9 redundant scans in gpu_generate_preprocessed.

use super::{
    instruction::{HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction},
    types::*,
};
use crate::chips::chips::recursion_memory::MemoryAccessCols;
use p3_field::Field;

use serde::{Deserialize, Serialize};

/// Holds per-chip instruction data, computed by a single pass over `program.instructions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionBuckets<F> {
    pub base_alu: Box<[BaseAluInstr<F>]>,
    pub ext_alu: Box<[ExtAluInstr<F>]>,
    pub mem_const: Box<[MemInstrFfi<F>]>,
    /// Pre-computed MemVar accesses in original instruction order.
    pub mem_var_accesses: Box<[MemoryAccessCols<F>]>,
    pub select: Box<[SelectInstr<F>]>,
    pub poseidon2: Box<[Poseidon2Instr<F>]>,
    pub exp_reverse_bits: Box<[ExpReverseBitsInstr<F>]>,
    pub batch_fri: Box<[Box<BatchFRIInstr<F>>]>,
    pub commit_public_values: Box<[Box<CommitPublicValuesInstr<F>>]>,
}

impl<F: Field> InstructionBuckets<F> {
    pub fn from_instructions(instructions: &[Instruction<F>]) -> Self {
        // First pass: count to pre-allocate exact capacity
        let mut n_base_alu = 0usize;
        let mut n_ext_alu = 0usize;
        let mut n_mem_const = 0usize;
        let mut n_mem_var = 0usize;
        let mut n_select = 0usize;
        let mut n_poseidon2 = 0usize;
        let mut n_exp_reverse_bits = 0usize;
        let mut n_batch_fri = 0usize;
        let mut n_commit_pv = 0usize;

        for instr in instructions {
            match instr {
                Instruction::BaseAlu(_) => n_base_alu += 1,
                Instruction::ExtAlu(_) => n_ext_alu += 1,
                Instruction::Mem(_) => n_mem_const += 1,
                Instruction::Select(_) => n_select += 1,
                Instruction::Poseidon2(_) => n_poseidon2 += 1,
                Instruction::ExpReverseBitsLen(_) => n_exp_reverse_bits += 1,
                Instruction::BatchFRI(_) => n_batch_fri += 1,
                Instruction::CommitPublicValues(_) => n_commit_pv += 1,
                Instruction::Hint(HintInstr { output_addrs_mults }) => {
                    n_mem_var += output_addrs_mults.len();
                }
                Instruction::HintBits(HintBitsInstr {
                    output_addrs_mults, ..
                }) => {
                    n_mem_var += output_addrs_mults.len();
                }
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults, ..
                }) => {
                    n_mem_var += output_addrs_mults.len();
                }
                Instruction::HintAddCurve(instr) => {
                    n_mem_var +=
                        instr.output_x_addrs_mults.len() + instr.output_y_addrs_mults.len();
                }
                Instruction::Print(_) => {}
                // MLE recursion instructions (Convert/Combine/Compress) carry no GPU bucket —
                // their chips fall back to CPU trace-gen, so they are skipped here.
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

        let mut base_alu = Vec::with_capacity(n_base_alu);
        let mut ext_alu = Vec::with_capacity(n_ext_alu);
        let mut mem_const = Vec::with_capacity(n_mem_const);
        let mut mem_var_accesses = Vec::with_capacity(n_mem_var);
        let mut select = Vec::with_capacity(n_select);
        let mut poseidon2 = Vec::with_capacity(n_poseidon2);
        let mut exp_reverse_bits = Vec::with_capacity(n_exp_reverse_bits);
        let mut batch_fri = Vec::with_capacity(n_batch_fri);
        let mut commit_pv = Vec::with_capacity(n_commit_pv);

        // Second pass: extract data (preserving original instruction order)
        for instr in instructions {
            match instr {
                Instruction::BaseAlu(x) => base_alu.push(*x),
                Instruction::ExtAlu(x) => ext_alu.push(*x),
                Instruction::Mem(x) => mem_const.push(MemInstrFfi::from(x)),
                Instruction::Select(x) => select.push(*x),
                Instruction::Poseidon2(x) => poseidon2.push(x.as_ref().clone()),
                Instruction::ExpReverseBitsLen(x) => exp_reverse_bits.push(x.clone()),
                Instruction::BatchFRI(x) => batch_fri.push(x.clone()),
                Instruction::CommitPublicValues(x) => commit_pv.push(x.clone()),
                Instruction::Hint(HintInstr { output_addrs_mults }) => {
                    for am in output_addrs_mults {
                        mem_var_accesses.push(MemoryAccessCols::from(am));
                    }
                }
                Instruction::HintBits(HintBitsInstr {
                    output_addrs_mults, ..
                }) => {
                    for am in output_addrs_mults {
                        mem_var_accesses.push(MemoryAccessCols::from(am));
                    }
                }
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults, ..
                }) => {
                    for am in output_addrs_mults {
                        mem_var_accesses.push(MemoryAccessCols::from(am));
                    }
                }
                Instruction::HintAddCurve(instr) => {
                    let HintAddCurveInstr {
                        output_x_addrs_mults,
                        output_y_addrs_mults,
                        ..
                    } = instr.as_ref();
                    for am in output_x_addrs_mults
                        .iter()
                        .chain(output_y_addrs_mults.iter())
                    {
                        mem_var_accesses.push(MemoryAccessCols::from(am));
                    }
                }
                Instruction::Print(_) => {}
                // MLE recursion instructions (Convert/Combine/Compress) carry no GPU bucket —
                // their chips fall back to CPU trace-gen, so they are skipped here.
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

        InstructionBuckets {
            base_alu: base_alu.into(),
            ext_alu: ext_alu.into(),
            mem_const: mem_const.into(),
            mem_var_accesses: mem_var_accesses.into(),
            select: select.into(),
            poseidon2: poseidon2.into(),
            exp_reverse_bits: exp_reverse_bits.into(),
            batch_fri: batch_fri.into(),
            commit_public_values: commit_pv.into(),
        }
    }
}
