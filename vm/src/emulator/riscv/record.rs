use crate::{
    chips::chips::{
        alu::event::AluEvent,
        byte::event::{add_chunked_byte_lookup_events, ByteLookupEvent, ByteRecordBehavior},
        rangecheck::event::{
            add_chunked_range_lookup_events, RangeLookupEvent, RangeRecordBehavior,
        },
        riscv_cpu::event::CpuEvent,
        riscv_memory::event::{MemoryInitializeFinalizeEvent, MemoryRecordEnum},
    },
    compiler::riscv::{opcode::Opcode, program::Program},
    emulator::{record::RecordBehavior, riscv::public_values::PublicValues},
};
use hashbrown::HashMap;
use p3_field::AbstractField;
use serde::{Deserialize, Serialize};
use std::{iter, sync::Arc};

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
    /// A trace of the range lookups that are needed.
    pub range_lookups: HashMap<u32, HashMap<RangeLookupEvent, usize>>,
    /// A trace of the memory initialize events.
    pub memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,
    /// A trace of the memory finalize events.
    pub memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,

    /// Public values
    pub public_values: PublicValues<u32, u32>,
}

impl EmulationRecord {
    #[must_use]
    pub fn new(program: Arc<Program>) -> Self {
        Self {
            program,
            ..Default::default()
        }
    }

    /// Add a mul event to the execution record.
    pub fn add_mul_event(&mut self, mul_event: AluEvent) {
        self.mul_events.push(mul_event);
    }

    /// Add a lt event to the execution record.
    pub fn add_lt_event(&mut self, lt_event: AluEvent) {
        self.lt_events.push(lt_event);
    }

    /// Add a batch of alu events to the execution record.
    pub fn add_alu_events(&mut self, mut alu_events: HashMap<Opcode, Vec<AluEvent>>) {
        for (opcode, value) in &mut alu_events {
            match opcode {
                Opcode::ADD => {
                    self.add_events.append(value);
                }
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => {
                    self.mul_events.append(value);
                }
                Opcode::SUB => {
                    self.sub_events.append(value);
                }
                Opcode::XOR | Opcode::OR | Opcode::AND => {
                    self.bitwise_events.append(value);
                }
                Opcode::SLL => {
                    self.shift_left_events.append(value);
                }
                Opcode::SRL | Opcode::SRA => {
                    self.shift_right_events.append(value);
                }
                Opcode::SLT | Opcode::SLTU => {
                    self.lt_events.append(value);
                }
                _ => {
                    panic!("Invalid opcode: {opcode:?}");
                }
            }
        }
    }

    pub fn add_rangecheck_lookup_events(
        &mut self,
        events: impl IntoIterator<Item = HashMap<RangeLookupEvent, usize>>,
    ) {
        events.into_iter().for_each(|events| {
            for (event, multi) in events.into_iter() {
                *self
                    .range_lookups
                    .entry(event.chunk.unwrap_or_default())
                    .or_default()
                    .entry(event)
                    .or_default() += multi;
            }
        });
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
        stats.insert(
            "Shift Left Events".to_string(),
            self.shift_left_events.len(),
        );
        stats.insert(
            "Shift Right Events".to_string(),
            self.shift_right_events.len(),
        );
        stats.insert("Divrem Events".to_string(), self.divrem_events.len());
        stats.insert("Lt Events".to_string(), self.lt_events.len());
        stats.insert(
            "Memory Initialize Events".to_string(),
            self.memory_initialize_events.len(),
        );
        stats.insert(
            "Memory Finalize Events".to_string(),
            self.memory_finalize_events.len(),
        );
        if !self.cpu_events.is_empty() {
            let chunk = self.cpu_events[0].chunk;
            stats.insert(
                "byte_lookups".to_string(),
                self.byte_lookups
                    .get(&chunk)
                    .map_or(0, hashbrown::HashMap::len),
            );
        }
        stats.insert("Range lookups".to_string(), self.range_lookups.len());

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
        self.shift_right_events
            .append(&mut extra.shift_right_events);
        self.divrem_events.append(&mut extra.divrem_events);
        self.lt_events.append(&mut extra.lt_events);
        self.memory_initialize_events
            .append(&mut extra.memory_initialize_events);
        self.memory_finalize_events
            .append(&mut extra.memory_finalize_events);
        if self.byte_lookups.is_empty() {
            self.byte_lookups = std::mem::take(&mut extra.byte_lookups);
        } else {
            self.add_chunked_byte_lookup_events(vec![&extra.byte_lookups]);
        }
        if self.range_lookups.is_empty() {
            self.range_lookups = std::mem::take(&mut extra.range_lookups);
        } else {
            add_chunked_range_lookup_events(&mut self.range_lookups, vec![&extra.range_lookups]);
        }
    }

    fn register_nonces(&mut self) {
        self.add_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        });

        self.sub_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup
                .insert(event.lookup_id, (self.add_events.len() + i) as u32);
        });

        self.mul_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        });

        self.bitwise_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.shift_left_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.shift_right_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.divrem_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.lt_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        });
    }

    fn public_values<F: AbstractField>(&self) -> Vec<F> {
        self.public_values.to_vec()
    }

    fn chunk_index(&self) -> usize {
        self.public_values.chunk as usize
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

impl ByteRecordBehavior for EmulationRecord {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        *self
            .byte_lookups
            .entry(blu_event.chunk)
            .or_default()
            .entry(blu_event)
            .or_insert(0) += 1;
    }

    #[inline]
    fn add_chunked_byte_lookup_events(
        &mut self,
        new_events: Vec<&HashMap<u32, HashMap<ByteLookupEvent, usize>>>,
    ) {
        add_chunked_byte_lookup_events(&mut self.byte_lookups, new_events);
    }
}

impl RangeRecordBehavior for EmulationRecord {
    fn add_range_lookup_event(&mut self, event: RangeLookupEvent) {
        *self
            .range_lookups
            .entry(event.chunk.unwrap_or_default())
            .or_default()
            .entry(event)
            .or_insert(0) += 1;
    }

    fn range_lookup_events(
        &self,
        chunk: Option<u32>,
    ) -> Box<dyn Iterator<Item = (RangeLookupEvent, usize)> + '_> {
        assert!(chunk.is_some());

        self.range_lookups.get(&chunk.unwrap()).map_or_else(
            || Box::new(iter::empty()) as Box<dyn Iterator<Item = (RangeLookupEvent, usize)>>,
            |chunk_events| Box::new(chunk_events.iter().map(|(k, v)| (*k, *v))),
        )
    }
}
