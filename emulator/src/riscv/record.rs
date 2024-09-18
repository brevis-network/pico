use hashbrown::HashMap;
use std::sync::Arc;

use crate::riscv::events::{AluEvent, ByteLookupEvent, CpuEvent, MemoryInitializeFinalizeEvent, MemoryRecordEnum};
use pico_compiler::program::Program;
use serde::{Deserialize, Serialize};
use crate::record::RecordBehavior;

/// A record of the emulation of a program.
///
/// The trace of the emulation is represented as a list of "events" that occur every cycle.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct EmulationRecord {
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
    /// A trace of the byte lookups that are needed.
    pub byte_lookups: HashMap<u32, HashMap<ByteLookupEvent, usize>>,
    /// A trace of the memory initialize events.
    pub memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,
    /// A trace of the memory finalize events.
    pub memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,
}

impl EmulationRecord {
    #[must_use]
    pub fn new(program: Arc<Program>) -> Self {
        Self {
            program,
            ..Default::default()
        }
    }
}

impl RecordBehavior for EmulationRecord {
    fn name(&self) -> String {
        "RiscvEmulationRecord".to_string()
    }

    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("Cpu Events".to_string(), self.cpu_events.len());
        stats.insert("Add Events".to_string(), self.add_events.len());
        stats.insert("Mul Events".to_string(), self.mul_events.len());
        stats.insert("Sub Events".to_string(), self.sub_events.len());
        stats.insert("Bitwise Events".to_string(), self.bitwise_events.len());
        stats.insert("Shift Left Events".to_string(), self.shift_left_events.len());
        stats.insert("Shift Right Events".to_string(), self.shift_right_events.len());
        stats.insert("Divrem Events".to_string(), self.divrem_events.len());
        stats.insert("Lt Events".to_string(), self.lt_events.len());
        stats.insert("Memory Initialize Events".to_string(), self.memory_initialize_events.len());
        stats.insert("Memory Finalize Events".to_string(), self.memory_finalize_events.len());

        // Filter out the empty events.
        stats.retain(|_, v| *v != 0);
        stats
    }

    fn append(&mut self, extra: &mut EmulationRecord) {
        self.cpu_events.append(&mut extra.cpu_events);
        self.add_events.append(&mut extra.add_events);
        self.mul_events.append(&mut extra.mul_events);
        self.sub_events.append(&mut extra.sub_events);
        self.bitwise_events.append(&mut extra.bitwise_events);
        self.shift_left_events.append(&mut extra.shift_left_events);
        self.shift_right_events.append(&mut extra.shift_right_events);
        self.divrem_events.append(&mut extra.divrem_events);
        self.lt_events.append(&mut extra.lt_events);
        self.memory_initialize_events.append(&mut extra.memory_initialize_events);
        self.memory_finalize_events.append(&mut extra.memory_finalize_events);
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
