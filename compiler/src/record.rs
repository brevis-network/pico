use hashbrown::HashMap;
use itertools::{EitherOrBoth, Itertools};
use p3_field::AbstractField;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{program::Program, Opcode};

use crate::events::{AluEvent, CpuEvent, MemoryInitializeFinalizeEvent, MemoryRecordEnum};

/// A record of the execution of a program.
///
/// The trace of the execution is represented as a list of "events" that occur every cycle.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionRecord {
    /// The program.
    pub program: Arc<Program>,
    /// The nonce lookup.
    pub nonce_lookup: HashMap<u128, u32>,

    pub cpu_events: Vec<CpuEvent>,

    /// A trace of the ADD, and ADDI events.
    pub add_events: Vec<AluEvent>,
    /// A trace of the MUL events.
    pub mul_events: Vec<AluEvent>,
    /// A trace of the SUB events.
    pub sub_events: Vec<AluEvent>,
    /// A trace of the XOR, XORI, OR, ORI, AND, and ANDI events.
    pub bitwise_events: Vec<AluEvent>,
    /// A trace of the SLL and SLLI events.
    pub shift_left_events: Vec<AluEvent>,
    /// A trace of the SRL, SRLI, SRA, and SRAI events.
    pub shift_right_events: Vec<AluEvent>,
    /// A trace of the DIV, DIVU, REM, and REMU events.
    pub divrem_events: Vec<AluEvent>,
    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<AluEvent>,
    /// A trace of the memory initialize events.
    pub memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,
    /// A trace of the memory finalize events.
    pub memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,
}

impl ExecutionRecord {
    /// Create a new [`ExecutionRecord`].
    #[must_use]
    pub fn new(program: Arc<Program>) -> Self {
        Self {
            program,
            ..Default::default()
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct MemoryAccessRecord {
    /// The memory access of the `a` register.
    pub a: Option<MemoryRecordEnum>,
    /// The memory access of the `b` register.
    pub b: Option<MemoryRecordEnum>,
    /// The memory access of the `c` register.
    pub c: Option<MemoryRecordEnum>,
    /// The memory access of the `memory` register.
    pub memory: Option<MemoryRecordEnum>,
}
