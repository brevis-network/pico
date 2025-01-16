use super::syscalls::precompiles::{PrecompileEvent, PrecompileEvents};
use crate::{
    chips::chips::{
        alu::event::AluEvent,
        byte::event::{add_chunked_byte_lookup_events, ByteLookupEvent, ByteRecordBehavior},
        riscv_cpu::event::CpuEvent,
        riscv_memory::event::{MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryRecordEnum},
    },
    compiler::riscv::{opcode::Opcode, program::Program},
    emulator::{
        opts::SplitOpts,
        record::RecordBehavior,
        riscv::{
            public_values::PublicValues,
            syscalls::{SyscallCode, SyscallEvent},
        },
    },
    instances::compiler_v2::shapes::riscv_shape::RiscvPadShape,
};
use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::FieldAlgebra;
use serde::{Deserialize, Serialize};
use std::{mem::take, sync::Arc};

/// A record of the emulation of a program.
///
/// The trace of the emulation is represented as a list of "events" that occur every cycle.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct EmulationRecord {
    /// The program.
    pub program: Arc<Program>,
    pub unconstrained: bool,

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
    /// A trace of all the chunk's local memory events.
    pub cpu_local_memory_access: Vec<MemoryLocalEvent>,
    /// Public values
    pub public_values: PublicValues<u32, u32>,
    /// A trace of the precompile events.
    pub precompile_events: PrecompileEvents,
    /// A trace of all the syscall events.
    pub syscall_events: Vec<SyscallEvent>,
    /// The shape of the proof.
    pub shape: Option<RiscvPadShape>,
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

    #[inline]
    /// Add a precompile event to the execution record.
    pub fn add_precompile_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        self.precompile_events
            .add_event(syscall_code, syscall_event, event);
    }

    /// Get all the precompile events for a syscall code.
    #[inline]
    #[must_use]
    pub fn get_precompile_events(
        &self,
        syscall_code: SyscallCode,
    ) -> &Vec<(SyscallEvent, PrecompileEvent)> {
        self.precompile_events
            .get_events(syscall_code)
            .expect("Precompile events not found")
    }

    /// Get all the local memory events.
    #[inline]
    pub fn get_local_mem_events(&self) -> impl Iterator<Item = &MemoryLocalEvent> {
        let precompile_local_mem_events = self.precompile_events.get_local_mem_events();
        precompile_local_mem_events.chain(self.cpu_local_memory_access.iter())
    }

    /// Return the number of rows needed for a chip, according to the proof shape specified in the
    /// struct.
    pub fn shape_chip_size(&self, chip_name: &String) -> Option<usize> {
        self.shape
            .as_ref()
            .map(|shape| {
                shape
                    .inner
                    .get(chip_name)
                    .unwrap_or_else(|| panic!("Chip {} not found in specified shape", chip_name))
            })
            .copied()
    }

    /// Take out events from the [`EmulationRecord`] that should be deferred to a separate chunk.
    ///
    /// Note: we usually defer events that would increase the recursion cost significantly if
    /// included in every chunk.
    #[must_use]
    pub fn defer(&mut self) -> EmulationRecord {
        let mut emulation_record = EmulationRecord::new(self.program.clone());
        emulation_record.precompile_events = take(&mut self.precompile_events);
        // emulation_record.uint256_mul_events = take(&mut self.uint256_mul_events);
        // emulation_record.memory_initialize_events =
        //     std::mem::take(&mut self.memory_initialize_events);
        // emulation_record.memory_finalize_events =
        //     std::mem::take(&mut self.memory_finalize_events);
        emulation_record
    }

    /// Splits the deferred [`EmulationRecord`] into multiple [`EmulationRecord`]s, each which
    /// contain a "reasonable" number of deferred events.
    pub fn split(&mut self, last: bool, opts: SplitOpts) -> Vec<EmulationRecord> {
        let mut chunk_records = Vec::new();

        let precompile_events = take(&mut self.precompile_events);

        for (syscall_code, events) in precompile_events.into_iter() {
            let threshold = match syscall_code {
                SyscallCode::KECCAK_PERMUTE => opts.keccak,
                SyscallCode::SHA_EXTEND => opts.sha_extend,
                SyscallCode::SHA_COMPRESS => opts.sha_compress,
                _ => opts.deferred,
            };

            let precompile_event_chunks = events.chunks_exact(threshold);
            if last {
                let remainder = precompile_event_chunks.remainder().to_vec();
                if !remainder.is_empty() {
                    let mut emulation_record = EmulationRecord::new(self.program.clone());
                    emulation_record
                        .precompile_events
                        .insert(syscall_code, remainder);
                    chunk_records.push(emulation_record);
                }
            } else {
                self.precompile_events
                    .insert(syscall_code, precompile_event_chunks.remainder().to_vec());
            }
            let mut records = precompile_event_chunks
                .map(|event_chunk| {
                    let mut emulation_record = EmulationRecord::new(self.program.clone());
                    emulation_record
                        .precompile_events
                        .insert(syscall_code, event_chunk.to_vec());
                    emulation_record
                })
                .collect::<Vec<_>>();
            chunk_records.append(&mut records);
        }

        // TODO: should we split last memory initialize / finalize chunk?

        chunk_records
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
        stats.insert(
            "local_memory_access_events".to_string(),
            self.cpu_local_memory_access.len(),
        );
        if !self.cpu_events.is_empty() {
            let chunk = self.cpu_events[0].chunk;
            stats.insert(
                "byte_lookups".to_string(),
                self.byte_lookups
                    .get(&chunk)
                    .map_or(0, hashbrown::HashMap::len),
            );
            stats.insert(
                "memory_read_write Events".to_string(),
                self.cpu_events
                    .iter()
                    .filter(|e| e.instruction.is_memory_instruction())
                    .collect_vec()
                    .len(),
            );
        }
        // stats.insert("Range lookups".to_string(), self.range_lookups.len());

        for (syscall_code, events) in self.precompile_events.iter() {
            stats.insert(format!("syscall {syscall_code:?}"), events.len());
        }

        // stats.insert(
        //     "Keccak Permute lookups".to_string(),
        //     self.keccak_permute_events.len(),
        // );
        // stats.insert("ED Add lookups".to_string(), self.ed_add_events.len());
        // stats.insert(
        //     "ED Decompress lookups".to_string(),
        //     self.ed_decompress_events.len(),
        // );

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
        self.cpu_local_memory_access
            .append(&mut extra.cpu_local_memory_access);
        // self.keccak_permute_events
        //     .append(&mut extra.keccak_permute_events);
        // self.ed_add_events.append(&mut extra.ed_add_events);
        // self.ed_decompress_events
        //     .append(&mut extra.ed_decompress_events);
        self.syscall_events.append(&mut extra.syscall_events);
        self.precompile_events.append(&mut extra.precompile_events);
        if self.byte_lookups.is_empty() {
            self.byte_lookups = std::mem::take(&mut extra.byte_lookups);
        } else {
            self.add_chunked_byte_lookup_events(vec![&extra.byte_lookups]);
        }
    }

    fn public_values<F: FieldAlgebra>(&self) -> Vec<F> {
        self.public_values.to_vec()
    }

    fn chunk_index(&self) -> usize {
        self.public_values.chunk as usize
    }

    fn unconstrained(&self) -> bool {
        self.unconstrained
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
