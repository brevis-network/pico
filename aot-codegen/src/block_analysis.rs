//! Block Analysis for AOT Code Generation
//!
//! This module provides analysis of basic blocks in RISC-V programs for
//! ahead-of-time compilation. It identifies block leaders (entry points),
//! analyzes control flow, and generates optimal block layouts.

use crate::types::{Opcode, ProgramInfo};
use std::collections::HashSet;

/// Analyzes basic blocks in a RISC-V program for AOT compilation.
///
/// The `BlockAnalyzer` identifies block leaders (entry points for basic blocks)
/// by analyzing control flow instructions. A basic block is a sequence of
/// instructions with a single entry point and single exit point.
///
/// # Leader Identification
///
/// A program counter (PC) is considered a block leader if it is:
/// - The program start address (`pc_start`)
/// - The program base address (`pc_base`)
/// - The target of a jump instruction (JAL)
/// - The target of a branch instruction (BEQ, BNE, BLT, BGE, BLTU, BGEU)
/// - The instruction following a control flow instruction (fallthrough)
pub struct BlockAnalyzer {
    leaders: HashSet<u32>,
    leader_vec: Vec<u32>,
}

impl BlockAnalyzer {
    /// Creates a new block analyzer for the given program.
    pub fn new(program: &ProgramInfo) -> Self {
        let leaders = Self::compute_leaders(program);
        let mut leader_vec: Vec<u32> = leaders.iter().copied().collect();
        leader_vec.sort_unstable();
        Self {
            leaders,
            leader_vec,
        }
    }

    /// Analyzes the program and returns the set of block leader PCs.
    ///
    /// This performs a single pass over all instructions to identify:
    /// - Entry points (program start and base)
    /// - Control flow targets (jump and branch destinations)
    /// - Fallthrough addresses (instructions following terminators)
    pub fn analyze(&self) -> HashSet<u32> {
        self.leaders.clone()
    }

    fn compute_leaders(program: &ProgramInfo) -> HashSet<u32> {
        let mut leaders = HashSet::new();

        // Add entry points
        leaders.insert(program.pc_start);
        leaders.insert(program.pc_base);

        // Pass 1: Identify block leaders
        for (idx, inst) in program.instructions.iter().enumerate() {
            let pc = program.pc_base + (idx as u32 * 4);

            match inst.opcode {
                Opcode::JAL => {
                    let (_, imm) = inst.j_type();
                    leaders.insert(pc.wrapping_add(imm));
                    leaders.insert(pc.wrapping_add(4));
                }
                Opcode::BEQ
                | Opcode::BNE
                | Opcode::BLT
                | Opcode::BGE
                | Opcode::BLTU
                | Opcode::BGEU => {
                    let (_, _, imm) = inst.b_type();
                    leaders.insert(pc.wrapping_add(imm));
                    leaders.insert(pc.wrapping_add(4));
                }
                Opcode::JALR | Opcode::ECALL | Opcode::EBREAK => {
                    leaders.insert(pc.wrapping_add(4));
                }
                _ => {}
            }
        }

        leaders
    }

    /// Returns an iterator over all block start addresses in program order.
    pub fn block_starts(&self) -> Vec<u32> {
        self.leader_vec.clone()
    }

    /// Checks if the given PC is a block leader.
    pub fn is_leader(&self, pc: u32) -> bool {
        self.leaders.contains(&pc)
    }
}
