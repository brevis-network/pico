//! CFG Analysis for CFG-Aware Chunking
//!
//! This module provides control flow graph analysis to optimize chunk boundaries
//! by minimizing cross-chunk control flow edges. This preserves more direct jumps
//! within chunks, reducing dynamic lookup overhead.

use crate::{
    constants,
    types::{Opcode, ProgramInfo},
};
use std::collections::HashMap;

/// Edge type for weighting control flow edges
#[derive(Debug, Clone, Copy)]
enum EdgeType {
    /// Fallthrough edge (pc + 4)
    Fallthrough,
    /// Branch target edge (taken path)
    BranchTarget,
    /// JAL target edge (unconditional jump/call)
    JalTarget,
}

/// CFG analysis result
pub struct CfgAnalysis {
    /// Cut penalties for each boundary (boundary i is after block i)
    cut_penalties: Vec<u32>,
}

impl CfgAnalysis {
    /// Analyze control flow from the program instructions and block PCs
    pub fn analyze(
        program: &ProgramInfo,
        block_pcs: &[u32],
        _leaders: &std::collections::HashSet<u32>,
    ) -> Self {
        let mut pc_to_idx = HashMap::new();
        for (idx, &pc) in block_pcs.iter().enumerate() {
            pc_to_idx.insert(pc, idx);
        }

        let inst_count = program.instructions.len() as u32;
        let program_end = program.pc_base.wrapping_add(inst_count.saturating_mul(4));
        let inst_idx_for_pc = |pc: u32| -> Option<usize> {
            if pc < program.pc_base || pc >= program_end {
                return None;
            }
            let offset = pc.wrapping_sub(program.pc_base);
            if !offset.is_multiple_of(4) {
                return None;
            }
            let idx = (offset / 4) as usize;
            if idx < program.instructions.len() {
                Some(idx)
            } else {
                None
            }
        };

        // Track which blocks have terminators by finding the last instruction in each block
        let mut has_terminator = vec![false; block_pcs.len()];
        let mut last_inst_pcs = vec![None; block_pcs.len()];
        let mut edges = Vec::new();

        // For each block, find its last instruction and check if it's a terminator
        for (block_idx, _) in block_pcs.iter().enumerate() {
            // Find the last instruction in this block
            // The block ends at the next block's PC (or end of program)
            let next_block_pc = if block_idx + 1 < block_pcs.len() {
                block_pcs[block_idx + 1]
            } else {
                program.pc_base + (program.instructions.len() as u32 * 4)
            };

            // Find the instruction just before the next block (last instruction of this block)
            let start_pc = block_pcs[block_idx];
            let mut cursor = next_block_pc.saturating_sub(4);
            let mut last_inst_pc = None;
            loop {
                if cursor < start_pc {
                    break;
                }
                if inst_idx_for_pc(cursor).is_some() {
                    last_inst_pc = Some(cursor);
                    break;
                }
                if cursor < 4 {
                    break;
                }
                cursor = cursor.saturating_sub(4);
            }

            // Find the instruction index for this PC
            if let Some(last_inst_pc) = last_inst_pc {
                let inst_idx = match inst_idx_for_pc(last_inst_pc) {
                    Some(idx) => idx,
                    None => continue,
                };
                last_inst_pcs[block_idx] = Some(last_inst_pc);
                let inst = &program.instructions[inst_idx];
                match inst.opcode {
                    Opcode::JAL => {
                        has_terminator[block_idx] = true;
                        let (_, imm) = inst.j_type();
                        let target = last_inst_pc.wrapping_add(imm);
                        if let Some(&target_idx) = pc_to_idx.get(&target) {
                            let weight =
                                Self::edge_weight(EdgeType::JalTarget, last_inst_pc, target);
                            edges.push((block_idx, target_idx, weight));
                        }
                    }
                    Opcode::BEQ
                    | Opcode::BNE
                    | Opcode::BLT
                    | Opcode::BGE
                    | Opcode::BLTU
                    | Opcode::BGEU => {
                        has_terminator[block_idx] = true;
                        let (_, _, imm) = inst.b_type();
                        let target = last_inst_pc.wrapping_add(imm);
                        let fallthrough = last_inst_pc.wrapping_add(4);

                        // Branch target
                        if let Some(&target_idx) = pc_to_idx.get(&target) {
                            let weight =
                                Self::edge_weight(EdgeType::BranchTarget, last_inst_pc, target);
                            edges.push((block_idx, target_idx, weight));
                        }
                        // Fallthrough
                        if let Some(&fallthrough_idx) = pc_to_idx.get(&fallthrough) {
                            let weight =
                                Self::edge_weight(EdgeType::Fallthrough, last_inst_pc, fallthrough);
                            edges.push((block_idx, fallthrough_idx, weight));
                        }
                    }
                    Opcode::JALR | Opcode::ECALL | Opcode::EBREAK => {
                        has_terminator[block_idx] = true;
                        // Dynamic targets - no static edges
                    }
                    _ => {
                        // Non-terminator - block falls through
                    }
                }
            }
        }

        // Add fallthrough edges for non-terminated blocks
        // A block falls through if:
        // 1. It doesn't have a terminator
        // 2. The next block in sequence starts at pc + 4
        for i in 0..block_pcs.len().saturating_sub(1) {
            if !has_terminator[i] {
                let next_pc = block_pcs[i + 1];
                if let Some(last_inst_pc) = last_inst_pcs[i] {
                    let expected_fallthrough = last_inst_pc.wrapping_add(4);

                    // Check if next block is the sequential fallthrough
                    if next_pc == expected_fallthrough {
                        // Check if we already have an edge from this block
                        let has_edge = edges.iter().any(|(from, to, _)| *from == i && *to == i + 1);
                        if !has_edge {
                            let weight =
                                Self::edge_weight(EdgeType::Fallthrough, last_inst_pc, next_pc);
                            edges.push((i, i + 1, weight));
                        }
                    }
                }
            }
        }

        // Compute cut penalties using difference array
        let cut_penalties = Self::compute_cut_penalties(block_pcs.len(), &edges);

        Self { cut_penalties }
    }

    /// Compute edge weight based on type and whether it's a back-edge
    fn edge_weight(edge_type: EdgeType, from_pc: u32, to_pc: u32) -> u32 {
        let base_weight = match edge_type {
            EdgeType::Fallthrough => constants::CFG_EDGE_WEIGHT_FALLTHROUGH,
            EdgeType::BranchTarget => constants::CFG_EDGE_WEIGHT_BRANCH_TARGET,
            EdgeType::JalTarget => constants::CFG_EDGE_WEIGHT_JAL_TARGET,
        };

        // Detect back-edges (loops): target PC < source PC
        let is_back_edge = to_pc < from_pc;
        if is_back_edge {
            base_weight * constants::CFG_EDGE_WEIGHT_BACK_EDGE_MULTIPLIER
        } else {
            base_weight
        }
    }

    /// Compute cut penalties for all boundaries using difference array
    fn compute_cut_penalties(num_blocks: usize, edges: &[(usize, usize, u32)]) -> Vec<u32> {
        // Boundary i is after block i (between block i and i+1)
        // We need num_blocks - 1 boundaries
        //
        // IMPORTANT: use signed diff to avoid underflow on subtraction.
        let mut diff = vec![0i64; num_blocks];

        for &(from_idx, to_idx, weight) in edges {
            let min_idx = from_idx.min(to_idx);
            let max_idx = from_idx.max(to_idx);
            let w = weight as i64;

            // Edge crosses all boundaries between min_idx and max_idx
            if min_idx < max_idx {
                diff[min_idx] += w;
                if max_idx < num_blocks {
                    diff[max_idx] -= w;
                }
            }
        }

        // Prefix sum to get cut penalties
        let mut cut_penalties = Vec::with_capacity(num_blocks.saturating_sub(1));
        let mut running_sum = 0i64;
        for value in diff.iter().take(num_blocks.saturating_sub(1)) {
            running_sum += *value;
            // running_sum is non-negative in well-formed input; clamp defensively.
            cut_penalties.push(running_sum.max(0) as u32);
        }

        cut_penalties
    }

    /// Get cut penalty for boundary after block i
    pub fn cut_penalty(&self, boundary_idx: usize) -> u32 {
        if boundary_idx < self.cut_penalties.len() {
            self.cut_penalties[boundary_idx]
        } else {
            0
        }
    }

    /// Get number of boundaries (one less than number of blocks)
    pub fn num_boundaries(&self) -> usize {
        self.cut_penalties.len()
    }
}
