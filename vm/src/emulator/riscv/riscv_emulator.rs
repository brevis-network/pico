use crate::{
    chips::{
        chips::{
            alu::event::AluEvent,
            riscv_cpu::event::CpuEvent,
            riscv_memory::event::{
                MemoryAccessPosition, MemoryInitializeFinalizeEvent, MemoryReadRecord,
                MemoryRecord, MemoryWriteRecord,
            },
        },
        utils::{create_alu_lookup_id, create_alu_lookups},
    },
    compiler::riscv::{
        instruction::Instruction, opcode::Opcode, program::Program, register::Register,
    },
    emulator::{
        context::EmulatorContext,
        opts::EmulatorOpts,
        riscv::{
            public_values::PublicValues,
            record::{EmulationRecord, MemoryAccessRecord},
            state::RiscvEmulationState,
            stdin::EmulatorStdin,
            syscalls::{
                default_syscall_map, syscall_context::SyscallContext, Syscall, SyscallCode,
            },
        },
    },
};
use hashbrown::{hash_map::Entry, HashMap};
use log::{debug, info};
use nohash_hasher::BuildNoHashHasher;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Instant};
use thiserror::Error;

pub const NUM_BYTE_LOOKUP_CHANNELS: u8 = 16;

/// An emulator for the Pico RISC-V zkVM.
///
/// The exeuctor is responsible for executing a user program and tracing important events which
/// occur during emulation (i.e., memory reads, alu operations, etc).
pub struct RiscvEmulator {
    /// The program.
    pub program: Arc<Program>,

    /// The options for the runtime.
    pub opts: EmulatorOpts,

    /// The maximum number of cpu cycles to use for emulation.
    pub max_cycles: Option<u64>,

    pub emulator_mode: EmulatorMode,

    /// The state of the emulation.
    pub state: RiscvEmulationState,

    /// The current trace of the emulation that is being collected.
    pub record: EmulationRecord,

    /// The collected batch_chunk_size records last executed
    pub batch_records: Vec<EmulationRecord>,

    /// Current batch number
    pub current_batch: u32,

    pub last_batch_next_pc: u32,

    pub last_batch_exit_code: u32,

    pub public_values_buffer: PublicValues<u32, u32>,

    /// The collected records, split by cpu cycles.
    pub records: Vec<EmulationRecord>,

    /// The maximum size of each chunk.
    pub chunk_size: u32,

    /// The maximimum number of chunks to emulate at once.
    pub chunk_batch_size: u32,

    /// The mapping between syscall codes and their implementations.
    pub syscall_map: HashMap<SyscallCode, Arc<dyn Syscall>>,

    /// The memory accesses for the current cycle.
    pub memory_accesses: MemoryAccessRecord,

    /// Memory addresses that were touched in this batch of chunks. Used to minimize the size of
    /// checkpoints.
    pub memory_checkpoint: HashMap<u32, Option<MemoryRecord>, BuildNoHashHasher<u32>>,

    /// The maximum number of cycles for a syscall.
    pub max_syscall_cycles: u32,
}

/// The different modes the emulator can run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmulatorMode {
    /// Run the emulation with no tracing or checkpointing.
    Simple,
    /// Run the emulation with checkpoints for memory.
    Checkpoint,
    /// Run the emulation with full tracing of events.
    Trace,
}

/// Errors that the [``Emulator``] can throw.
#[derive(Error, Debug, Serialize, Deserialize)]
pub enum EmulationError {
    /// The emulation failed with a non-zero exit code.
    #[error("emulation failed with exit code {0}")]
    HaltWithNonZeroExitCode(u32),

    /// The emulation failed with an invalid memory access.
    #[error("invalid memory access for opcode {0} and address {1}")]
    InvalidMemoryAccess(Opcode, u32),

    /// The emulation failed with an unimplemented syscall.
    #[error("unimplemented syscall {0}")]
    UnsupportedSyscall(u32),

    /// The emulation failed with a breakpoint.
    #[error("breakpoint encountered")]
    Breakpoint(),

    /// The emulation failed with an exceeded cycle limit.
    #[error("exceeded cycle limit of {0}")]
    ExceededCycleLimit(u64),

    /// The emulation failed because the syscall was called in unconstrained mode.
    #[error("syscall called in unconstrained mode")]
    InvalidSyscallUsage(u64),

    /// The emulation failed with an unimplemented feature.
    #[error("got unimplemented as opcode")]
    Unimplemented(),
}

macro_rules! assert_valid_memory_access {
    ($addr:expr, $position:expr) => {
        #[cfg(not(debug_assertions))]
        {}
    };
}

impl RiscvEmulator {
    #[must_use]
    pub fn new(program: Program, opts: EmulatorOpts) -> Self {
        Self::with_context(program, opts, EmulatorContext::default())
    }

    fn initialize(&mut self) {
        self.state.clk = 0;
        self.state.channel = 0;
        tracing::debug!("loading memory image");
        for (addr, value) in &self.program.memory_image {
            self.state.memory.insert(
                *addr,
                MemoryRecord {
                    value: *value,
                    chunk: 0,
                    timestamp: 0,
                },
            );
        }
    }

    /// Create a new runtime from a program, options, and a context.
    ///
    /// # Panics
    ///
    /// This function may panic if it fails to create the trace file if `TRACE_FILE` is set.
    #[must_use]
    pub fn with_context(program: Program, opts: EmulatorOpts, context: EmulatorContext) -> Self {
        // Create a shared reference to the program.
        let program = Arc::new(program);

        let record = EmulationRecord {
            program: program.clone(),
            ..Default::default()
        };

        // Determine the maximum number of cycles for any syscall.
        let syscall_map = default_syscall_map();
        let max_syscall_cycles = syscall_map
            .values()
            .map(|syscall| syscall.num_extra_cycles())
            .max()
            .unwrap_or(0);

        Self {
            syscall_map,
            memory_accesses: MemoryAccessRecord::default(),
            chunk_size: opts.chunk_size as u32,
            chunk_batch_size: opts.chunk_batch_size as u32,
            record,
            batch_records: vec![],
            current_batch: 0,
            last_batch_next_pc: 0,
            last_batch_exit_code: 0,
            public_values_buffer: PublicValues::<u32, u32>::default(),
            records: vec![],
            state: RiscvEmulationState::new(program.pc_start),
            program,
            opts,
            max_cycles: context.max_cycles,
            emulator_mode: EmulatorMode::Simple,
            memory_checkpoint: HashMap::default(),
            max_syscall_cycles,
        }
    }

    fn fetch(&self) -> Instruction {
        let idx = ((self.state.pc - self.program.pc_base) / 4) as usize;
        self.program.instructions[idx]
    }

    /// Emulates one cycle of the program, returning whether the program has finished.
    #[inline]
    fn emulate_cycle(&mut self) -> Result<bool, EmulationError> {
        // Fetch the instruction at the current program counter.
        let instruction = self.fetch();

        // Emulate the instruction.
        self.emulate_instruction(&instruction)?;

        // Increment the clock.
        self.state.global_clk += 1;

        // Check if there's enough cycles or move to the next chunk.
        if self.state.clk + self.max_syscall_cycles >= self.chunk_size * 4 {
            self.state.current_chunk += 1;
            self.state.clk = 0;
            self.state.channel = 0;

            self.bump_record();
        }

        if let Some(max_cycles) = self.max_cycles {
            if self.state.global_clk >= max_cycles {
                panic!("exceeded cycle limit of {}", max_cycles);
            }
        }

        // TODO: check if pc is 0 at the end
        let done = self.state.pc == 0
            || self.state.pc.wrapping_sub(self.program.pc_base)
                >= (self.program.instructions.len() * 4) as u32;

        Ok(done)
    }

    #[inline]
    fn emulate_cycle_to_batch(&mut self) -> Result<bool, EmulationError> {
        // Fetch the instruction at the current program counter.
        let instruction = self.fetch();

        // Emulate the instruction.
        self.emulate_instruction(&instruction)?;

        // Increment the clock.
        self.state.global_clk += 1;

        // Check if there's enough cycles or move to the next chunk.
        if self.state.clk + self.max_syscall_cycles >= self.chunk_size * 4 {
            // update chunk and execution chunk
            self.state.current_chunk += 1;
            if !self.record.cpu_events.is_empty() {
                self.state.current_execution_chunk += 1;
            }
            // reset clk and channel
            self.state.clk = 0;
            self.state.channel = 0;

            self.bump_record_to_batch();
        }

        if let Some(max_cycles) = self.max_cycles {
            if self.state.global_clk >= max_cycles {
                panic!("exceeded cycle limit of {}", max_cycles);
            }
        }

        // TODO: check if pc is 0 at the end
        let done = self.state.pc == 0
            || self.state.pc.wrapping_sub(self.program.pc_base)
                >= (self.program.instructions.len() * 4) as u32;

        Ok(done)
    }

    pub fn run_fast(&mut self) -> Result<(), EmulationError> {
        self.emulator_mode = EmulatorMode::Simple;
        while !self.emulate()? {}
        Ok(())
    }

    /// Emulates the program and prints the emulation report.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program emulation fails.
    pub fn run(&mut self) -> Result<(), EmulationError> {
        self.emulator_mode = EmulatorMode::Trace;
        while !self.emulate()? {}
        Ok(())
    }

    // todo: refactor
    pub fn run_with_stdin(&mut self, stdin: EmulatorStdin<Vec<u8>>) -> Result<(), EmulationError> {
        self.emulator_mode = EmulatorMode::Trace;
        for input in &stdin.buffer {
            self.state.input_stream.push(input.clone());
        }
        self.run()
    }

    // todo: refactor
    fn emulate(&mut self) -> Result<bool, EmulationError> {
        // Get the current chunk.
        info!("emulate - BEGIN");
        let begin = Instant::now();
        let start_chunk = self.state.current_chunk; // needed for public input
        debug!("start_chunk: {}", start_chunk);

        // If it's the first cycle, initialize the program.
        if self.state.global_clk == 0 {
            self.initialize();
        }

        // Loop until we've emulated `self.chunk_batch_size` chunks if `self.chunk_batch_size` is
        // set.
        debug!(
            "emulate - current chunk {}, batch size {}",
            self.state.current_chunk, self.chunk_batch_size
        );
        let mut done = false;
        let mut current_chunk = self.state.current_chunk;
        let mut num_chunks_emulated = 0;
        loop {
            if self.emulate_cycle()? {
                done = true;
                break;
            }

            if self.chunk_batch_size > 0 && current_chunk != self.state.current_chunk {
                num_chunks_emulated += 1;
                current_chunk = self.state.current_chunk;
                if num_chunks_emulated == self.chunk_batch_size {
                    break;
                }
            }
        }
        debug!("emulate - global clk {}", self.state.global_clk);

        // Get the final public values.
        let public_values = self.record.public_values;

        if !self.record.cpu_events.is_empty() {
            self.bump_record();
        }

        if done {
            self.postprocess();
            // Push the remaining emulation record with memory initialize & finalize events.
            self.bump_record();
        }

        // Set the global public values for all chunks.
        let mut last_next_pc = 0;
        let mut last_exit_code = 0;
        println!("# records to be processed: {}", self.records.len());
        for (i, record) in self.records.iter_mut().enumerate() {
            record.public_values = public_values;
            record.public_values.committed_value_digest = public_values.committed_value_digest;
            record.public_values.deferred_proofs_digest = public_values.deferred_proofs_digest;
            record.public_values.execution_chunk = start_chunk + i as u32;
            record.public_values.chunk = start_chunk + i as u32;
            if record.cpu_events.is_empty() {
                record.public_values.start_pc = last_next_pc;
                record.public_values.next_pc = last_next_pc;
                record.public_values.exit_code = last_exit_code;
            } else {
                record.public_values.start_pc = record.cpu_events[0].pc;
                record.public_values.next_pc = record.cpu_events.last().unwrap().next_pc;
                record.public_values.exit_code = record.cpu_events.last().unwrap().exit_code;
                last_next_pc = record.public_values.next_pc;
                last_exit_code = record.public_values.exit_code;
            }
        }
        info!("emulate - END in {:?}", begin.elapsed());
        Ok(done)
    }

    /// Emulate chunk_batch_size cycles and bump to self.batch_records.
    pub fn emulate_to_batch(&mut self) -> Result<bool, EmulationError> {
        self.batch_records.clear();

        // let begin = Instant::now();

        // Get the current chunk.
        // let start_chunk = self.state.current_chunk; // needed for public input
        // let start_execution_chunk = self.state.current_execution_chunk;

        // If it's the first cycle, initialize the program.
        if self.state.global_clk == 0 {
            self.initialize();
        }

        // Loop until we've emulated `self.chunk_batch_size` chunks if `self.chunk_batch_size` is
        // set.

        let mut done = false;
        let mut current_chunk = self.state.current_chunk;
        let mut num_chunks_emulated = 0;
        loop {
            if self.emulate_cycle_to_batch()? {
                done = true;
                break;
            }

            if self.chunk_batch_size > 0 && current_chunk != self.state.current_chunk {
                num_chunks_emulated += 1;
                current_chunk = self.state.current_chunk;
                if num_chunks_emulated == self.chunk_batch_size {
                    break;
                }
            }
        }
        debug!("emulate - global clk {}", self.state.global_clk);

        // Get the final public values.
        // let public_values = self.record.public_values;

        if !self.record.cpu_events.is_empty() {
            self.bump_record_to_batch();
        }

        if done {
            self.postprocess();
            // Push the remaining emulation record with memory initialize & finalize events.
            self.bump_record_to_batch();
        } else {
            self.current_batch += 1;
        }

        // Set the global public values for all chunks.
        // println!("# batch records to be processed: {}", self.batch_records.len());
        let mut current_execution_chunk = 0;
        let mut flag_extra = true;
        for (i, record) in self.batch_records.iter_mut().enumerate() {
            self.public_values_buffer.chunk += 1;
            if !record.cpu_events.is_empty() {
                self.public_values_buffer.execution_chunk += 1;
                current_execution_chunk = self.public_values_buffer.execution_chunk;
                self.public_values_buffer.start_pc = record.cpu_events[0].pc;
                self.public_values_buffer.next_pc = record.cpu_events.last().unwrap().next_pc;
                self.public_values_buffer.exit_code = record.cpu_events.last().unwrap().exit_code;
                self.public_values_buffer.committed_value_digest =
                    record.public_values.committed_value_digest;
            } else {
                // hack to make execution chunk consistent
                if flag_extra {
                    current_execution_chunk += 1;
                    flag_extra = false;
                }
                self.public_values_buffer.execution_chunk = current_execution_chunk;

                self.public_values_buffer.start_pc = self.public_values_buffer.next_pc;
                self.public_values_buffer.previous_initialize_addr_bits =
                    record.public_values.previous_initialize_addr_bits;
                self.public_values_buffer.last_initialize_addr_bits =
                    record.public_values.last_initialize_addr_bits;
                self.public_values_buffer.previous_finalize_addr_bits =
                    record.public_values.previous_finalize_addr_bits;
                self.public_values_buffer.last_finalize_addr_bits =
                    record.public_values.last_finalize_addr_bits;
            }
            record.public_values = self.public_values_buffer.clone();
        }

        Ok(done)
    }

    /// Emulate the given instruction over the current state of the runtime.
    #[allow(clippy::too_many_lines)]
    fn emulate_instruction(&mut self, instruction: &Instruction) -> Result<(), EmulationError> {
        let mut pc = self.state.pc;
        let mut clk = self.state.clk;
        let mut exit_code = 0u32;

        let mut next_pc = self.state.pc.wrapping_add(4);

        let rd: Register;
        let (a, b, c): (u32, u32, u32);
        let (addr, memory_read_value): (u32, u32);
        let mut memory_store_value: Option<u32> = None;

        if self.emulator_mode != EmulatorMode::Simple {
            self.memory_accesses = MemoryAccessRecord::default();
        }
        let lookup_id = if self.emulator_mode == EmulatorMode::Simple {
            0
        } else {
            create_alu_lookup_id()
        };
        let syscall_lookup_id = if self.emulator_mode == EmulatorMode::Simple {
            0
        } else {
            create_alu_lookup_id()
        };

        match instruction.opcode {
            // Arithmetic instructions.
            Opcode::ADD => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_add(c);
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SUB => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_sub(c);
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::XOR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b ^ c;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::OR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b | c;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::AND => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b & c;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SLL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shl(c);
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SRL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shr(c);
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SRA => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (b as i32).wrapping_shr(c) as u32;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SLT => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SLTU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if b < c { 1 } else { 0 };
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }

            // Load instructions.
            Opcode::LB => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                let value = (memory_read_value).to_le_bytes()[(addr % 4) as usize];
                a = ((value as i8) as i32) as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LH => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::LH, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => memory_read_value & 0x0000_FFFF,
                    1 => (memory_read_value & 0xFFFF_0000) >> 16,
                    _ => unreachable!(),
                };
                a = ((value as i16) as i32) as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LW => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::LW, addr));
                }
                a = memory_read_value;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LBU => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                let value = (memory_read_value).to_le_bytes()[(addr % 4) as usize];
                a = value as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LHU => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::LHU, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => memory_read_value & 0x0000_FFFF,
                    1 => (memory_read_value & 0xFFFF_0000) >> 16,
                    _ => unreachable!(),
                };
                a = (value as u16) as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }

            // Store instructions.
            Opcode::SB => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                let value = match addr % 4 {
                    0 => (a & 0x0000_00FF) + (memory_read_value & 0xFFFF_FF00),
                    1 => ((a & 0x0000_00FF) << 8) + (memory_read_value & 0xFFFF_00FF),
                    2 => ((a & 0x0000_00FF) << 16) + (memory_read_value & 0xFF00_FFFF),
                    3 => ((a & 0x0000_00FF) << 24) + (memory_read_value & 0x00FF_FFFF),
                    _ => unreachable!(),
                };
                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SH => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::SH, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => (a & 0x0000_FFFF) + (memory_read_value & 0xFFFF_0000),
                    1 => ((a & 0x0000_FFFF) << 16) + (memory_read_value & 0x0000_FFFF),
                    _ => unreachable!(),
                };
                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SW => {
                (a, b, c, addr, _) = self.store_rr(instruction);
                if addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::SW, addr));
                }
                let value = a;
                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }

            // B-type instructions.
            Opcode::BEQ => {
                (a, b, c) = self.branch_rr(instruction);
                if a == b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BNE => {
                (a, b, c) = self.branch_rr(instruction);
                if a != b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BLT => {
                (a, b, c) = self.branch_rr(instruction);
                if (a as i32) < (b as i32) {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BGE => {
                (a, b, c) = self.branch_rr(instruction);
                if (a as i32) >= (b as i32) {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BLTU => {
                (a, b, c) = self.branch_rr(instruction);
                if a < b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BGEU => {
                (a, b, c) = self.branch_rr(instruction);
                if a >= b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                (b, c) = (imm, 0);
                a = self.state.pc + 4;
                self.rw(rd, a);
                next_pc = self.state.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1, MemoryAccessPosition::B), imm);
                a = self.state.pc + 4;
                self.rw(rd, a);
                next_pc = b.wrapping_add(c);
            }

            // Upper immediate instructions.
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, imm);
                a = self.state.pc.wrapping_add(b);
                self.rw(rd, a);
            }

            // System instructions.
            Opcode::ECALL => {
                // We peek at register x5 to get the syscall id. The reason we don't `self.rr` this
                // register is that we write to it later.
                let t0 = Register::X5;
                let syscall_id = self.register(t0);
                c = self.rr(Register::X11, MemoryAccessPosition::C);
                b = self.rr(Register::X10, MemoryAccessPosition::B);
                let syscall = SyscallCode::from_u32(syscall_id);

                // `hint_slice` is allowed in unconstrained mode since it is used to write the hint.
                // Other syscalls are not allowed because they can lead to non-deterministic
                // behavior, especially since many syscalls modify memory in place,
                // which is not permitted in unconstrained mode. This will result in
                // non-zero memory interactions when generating a proof.

                let syscall_impl = self.get_syscall(syscall).cloned();
                let mut precompile_rt = SyscallContext::new(self);
                precompile_rt.syscall_lookup_id = syscall_lookup_id;
                let (precompile_next_pc, precompile_cycles, returned_exit_code) =
                    if let Some(syscall_impl) = syscall_impl {
                        // Executing a syscall optionally returns a value to write to the t0
                        // register. If it returns None, we just keep the
                        // syscall_id in t0.
                        let res = syscall_impl.emulate(&mut precompile_rt, b, c);
                        if let Some(val) = res {
                            a = val;
                        } else {
                            a = syscall_id;
                        }

                        // If the syscall is `HALT` and the exit code is non-zero, return an error.
                        if syscall == SyscallCode::HALT && precompile_rt.exit_code != 0 {
                            return Err(EmulationError::HaltWithNonZeroExitCode(
                                precompile_rt.exit_code,
                            ));
                        }

                        (
                            precompile_rt.next_pc,
                            syscall_impl.num_extra_cycles(),
                            precompile_rt.exit_code,
                        )
                    } else {
                        return Err(EmulationError::UnsupportedSyscall(syscall_id));
                    };

                // Allow the syscall impl to modify state.clk/pc (exit unconstrained does this)
                clk = self.state.clk;
                pc = self.state.pc;

                self.rw(t0, a);
                next_pc = precompile_next_pc;
                self.state.clk += precompile_cycles;
                exit_code = returned_exit_code;

                // TODO: handle syscall counts
                let syscall_for_count = syscall.count_map();
                let syscall_count = self
                    .state
                    .syscall_counts
                    .entry(syscall_for_count)
                    .or_insert(0);
                let (threshold, multiplier) = match syscall_for_count {
                    _ => (self.opts.split_opts.deferred, 1),
                };
                let nonce = (((*syscall_count as usize) % threshold) * multiplier) as u32;
                self.record.nonce_lookup.insert(syscall_lookup_id, nonce);
                *syscall_count += 1;
            }
            Opcode::EBREAK => {
                return Err(EmulationError::Breakpoint());
            }

            // Multiply instructions.
            Opcode::MUL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_mul(c);
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::MULH => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul((c as i32) as i64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::MULHU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = ((b as u64).wrapping_mul(c as u64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::MULHSU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::DIV => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = (b as i32).wrapping_div(c as i32) as u32;
                }
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::DIVU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = b.wrapping_div(c);
                }
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::REM => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = (b as i32).wrapping_rem(c as i32) as u32;
                }
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::REMU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = b.wrapping_rem(c);
                }
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }

            // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#instruction-aliases
            Opcode::UNIMP => {
                return Err(EmulationError::Unimplemented());
            }
        }

        // Update the program counter.
        self.state.pc = next_pc;

        // Update the clk to the next cycle.
        self.state.clk += 4;

        let channel = self.channel();

        // Update the channel to the next cycle.
        self.state.channel = (self.state.channel + 1) % NUM_BYTE_LOOKUP_CHANNELS;

        // Emit the CPU event for this cycle.
        if self.emulator_mode == EmulatorMode::Trace {
            self.emit_cpu(
                self.chunk(),
                channel,
                clk,
                pc,
                next_pc,
                *instruction,
                a,
                b,
                c,
                memory_store_value,
                self.memory_accesses,
                exit_code,
                lookup_id,
                syscall_lookup_id,
            );
        };
        Ok(())
    }

    /// Get the current value of a byte.
    #[must_use]
    pub fn byte(&mut self, addr: u32) -> u8 {
        let word = self.word(addr - addr % 4);
        (word >> ((addr % 4) * 8)) as u8
    }

    /// Get the current timestamp for a given memory access position.
    #[must_use]
    pub const fn timestamp(&self, position: &MemoryAccessPosition) -> u32 {
        self.state.clk + *position as u32
    }

    /// Get the current chunk.
    #[must_use]
    #[inline]
    pub fn chunk(&self) -> u32 {
        self.state.current_chunk
    }

    /// Get the current channel.
    #[must_use]
    #[inline]
    pub fn channel(&self) -> u8 {
        self.state.channel
    }

    /// Read a word from memory and create an access record.
    pub fn mr(&mut self, addr: u32, chunk: u32, timestamp: u32) -> MemoryReadRecord {
        // Get the memory record entry.
        let entry = self.state.memory.entry(addr);
        if self.emulator_mode != EmulatorMode::Simple {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint
                        .entry(addr)
                        .or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.entry(addr).or_insert(None);
                }
            }
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.get(&addr).unwrap_or(&0);
                entry.insert(MemoryRecord {
                    value: *value,
                    chunk: 0,
                    timestamp: 0,
                })
            }
        };
        let value = record.value;
        let prev_chunk = record.chunk;
        let prev_timestamp = record.timestamp;
        record.chunk = chunk;
        record.timestamp = timestamp;

        // Construct the memory read record.
        MemoryReadRecord::new(value, chunk, timestamp, prev_chunk, prev_timestamp)
    }

    /// Write a word to memory and create an access record.
    pub fn mw(&mut self, addr: u32, value: u32, chunk: u32, timestamp: u32) -> MemoryWriteRecord {
        // Get the memory record entry.
        let entry = self.state.memory.entry(addr);
        if self.emulator_mode != EmulatorMode::Simple {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint
                        .entry(addr)
                        .or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.entry(addr).or_insert(None);
                }
            }
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.get(&addr).unwrap_or(&0);

                entry.insert(MemoryRecord {
                    value: *value,
                    chunk: 0,
                    timestamp: 0,
                })
            }
        };
        let prev_value = record.value;
        let prev_chunk = record.chunk;
        let prev_timestamp = record.timestamp;
        record.value = value;
        record.chunk = chunk;
        record.timestamp = timestamp;

        // Construct the memory write record.
        MemoryWriteRecord::new(
            value,
            chunk,
            timestamp,
            prev_value,
            prev_chunk,
            prev_timestamp,
        )
    }

    /// Read from memory, assuming that all addresses are aligned.
    pub fn mr_cpu(&mut self, addr: u32, position: MemoryAccessPosition) -> u32 {
        // Assert that the address is aligned.
        assert_valid_memory_access!(addr, position);

        // Read the address from memory and create a memory read record.
        let record = self.mr(addr, self.chunk(), self.timestamp(&position));

        // If we're not in unconstrained mode, record the access for the current cycle.
        if self.emulator_mode == EmulatorMode::Trace {
            match position {
                MemoryAccessPosition::A => self.memory_accesses.a = Some(record.into()),
                MemoryAccessPosition::B => self.memory_accesses.b = Some(record.into()),
                MemoryAccessPosition::C => self.memory_accesses.c = Some(record.into()),
                MemoryAccessPosition::Memory => self.memory_accesses.memory = Some(record.into()),
            }
        }
        record.value
    }

    /// Write to memory.
    ///
    /// # Panics
    ///
    /// This function will panic if the address is not aligned or if the memory accesses are already
    /// initialized.
    pub fn mw_cpu(&mut self, addr: u32, value: u32, position: MemoryAccessPosition) {
        // Assert that the address is aligned.
        assert_valid_memory_access!(addr, position);

        // Read the address from memory and create a memory read record.
        let record = self.mw(addr, value, self.chunk(), self.timestamp(&position));

        // If we're not in unconstrained mode, record the access for the current cycle.
        if self.emulator_mode == EmulatorMode::Trace {
            match position {
                MemoryAccessPosition::A => {
                    assert!(self.memory_accesses.a.is_none());
                    self.memory_accesses.a = Some(record.into());
                }
                MemoryAccessPosition::B => {
                    assert!(self.memory_accesses.b.is_none());
                    self.memory_accesses.b = Some(record.into());
                }
                MemoryAccessPosition::C => {
                    assert!(self.memory_accesses.c.is_none());
                    self.memory_accesses.c = Some(record.into());
                }
                MemoryAccessPosition::Memory => {
                    assert!(self.memory_accesses.memory.is_none());
                    self.memory_accesses.memory = Some(record.into());
                }
            }
        }
    }

    /// Read from a register.
    pub fn rr(&mut self, register: Register, position: MemoryAccessPosition) -> u32 {
        self.mr_cpu(register as u32, position)
    }

    /// Write to a register.
    pub fn rw(&mut self, register: Register, value: u32) {
        // The only time we are writing to a register is when it is in operand A.
        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the RISC-V spec. We always write 0 to %x0.
        if register == Register::X0 {
            self.mw_cpu(register as u32, 0, MemoryAccessPosition::A);
        } else {
            self.mw_cpu(register as u32, value, MemoryAccessPosition::A);
        }
    }

    /// Emit a CPU event.
    #[allow(clippy::too_many_arguments)]
    fn emit_cpu(
        &mut self,
        chunk: u32,
        channel: u8,
        clk: u32,
        pc: u32,
        next_pc: u32,
        instruction: Instruction,
        a: u32,
        b: u32,
        c: u32,
        memory_store_value: Option<u32>,
        record: MemoryAccessRecord,
        exit_code: u32,
        lookup_id: u128,
        syscall_lookup_id: u128,
    ) {
        let cpu_event = CpuEvent {
            chunk,
            channel,
            clk,
            pc,
            next_pc,
            instruction,
            a,
            a_record: record.a,
            b,
            b_record: record.b,
            c,
            c_record: record.c,
            memory: memory_store_value,
            memory_record: record.memory,
            exit_code,
            alu_lookup_id: lookup_id,
            syscall_lookup_id,
            memory_add_lookup_id: create_alu_lookup_id(),
            memory_sub_lookup_id: create_alu_lookup_id(),
            branch_lt_lookup_id: create_alu_lookup_id(),
            branch_gt_lookup_id: create_alu_lookup_id(),
            branch_add_lookup_id: create_alu_lookup_id(),
            jump_jal_lookup_id: create_alu_lookup_id(),
            jump_jalr_lookup_id: create_alu_lookup_id(),
            auipc_lookup_id: create_alu_lookup_id(),
        };

        self.record.cpu_events.push(cpu_event);
    }

    /// Emit an ALU event.
    fn emit_alu(&mut self, clk: u32, opcode: Opcode, a: u32, b: u32, c: u32, lookup_id: u128) {
        let event = AluEvent {
            lookup_id,
            chunk: self.chunk(),
            clk,
            channel: self.channel(),
            opcode,
            a,
            b,
            c,
            sub_lookups: create_alu_lookups(),
        };
        match opcode {
            Opcode::ADD => {
                self.record.add_events.push(event);
            }
            Opcode::SUB => {
                self.record.sub_events.push(event);
            }
            Opcode::XOR | Opcode::OR | Opcode::AND => {
                self.record.bitwise_events.push(event);
            }
            Opcode::SLL => {
                self.record.shift_left_events.push(event);
            }
            Opcode::SRL | Opcode::SRA => {
                self.record.shift_right_events.push(event);
            }
            Opcode::SLT | Opcode::SLTU => {
                self.record.lt_events.push(event);
            }
            Opcode::MUL | Opcode::MULHU | Opcode::MULHSU | Opcode::MULH => {
                self.record.mul_events.push(event);
            }
            Opcode::DIVU | Opcode::REMU | Opcode::DIV | Opcode::REM => {
                self.record.divrem_events.push(event);
            }
            _ => {}
        }
    }

    /// Fetch the destination register and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: &Instruction) -> (Register, u32, u32) {
        if !instruction.imm_c {
            let (rd, rs1, rs2) = instruction.r_type();
            let c = self.rr(rs2, MemoryAccessPosition::C);
            let b = self.rr(rs1, MemoryAccessPosition::B);
            (rd, b, c)
        } else if !instruction.imm_b && instruction.imm_c {
            let (rd, rs1, imm) = instruction.i_type();
            let (rd, b, c) = (rd, self.rr(rs1, MemoryAccessPosition::B), imm);
            (rd, b, c)
        } else {
            assert!(instruction.imm_b && instruction.imm_c);
            let (rd, b, c) = (
                Register::from_u32(instruction.op_a),
                instruction.op_b,
                instruction.op_c,
            );
            (rd, b, c)
        }
    }

    /// Set the destination register with the result and emit an ALU event.
    fn alu_rw(
        &mut self,
        instruction: &Instruction,
        rd: Register,
        a: u32,
        b: u32,
        c: u32,
        lookup_id: u128,
    ) {
        self.rw(rd, a);
        if self.emulator_mode == EmulatorMode::Trace {
            self.emit_alu(self.state.clk, instruction.opcode, a, b, c, lookup_id);
        }
    }

    /// Fetch the input operand values for a load instruction.
    fn load_rr(&mut self, instruction: &Instruction) -> (Register, u32, u32, u32, u32) {
        let (rd, rs1, imm) = instruction.i_type();
        let (b, c) = (self.rr(rs1, MemoryAccessPosition::B), imm);
        let addr = b.wrapping_add(c);
        let memory_value = self.mr_cpu(align(addr), MemoryAccessPosition::Memory);
        (rd, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a store instruction.
    fn store_rr(&mut self, instruction: &Instruction) -> (u32, u32, u32, u32, u32) {
        let (rs1, rs2, imm) = instruction.s_type();
        let c = imm;
        let b = self.rr(rs2, MemoryAccessPosition::B);
        let a = self.rr(rs1, MemoryAccessPosition::A);
        let addr = b.wrapping_add(c);
        let memory_value = self.word(align(addr));
        (a, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (rs1, rs2, imm) = instruction.b_type();
        let c = imm;
        let b = self.rr(rs2, MemoryAccessPosition::B);
        let a = self.rr(rs1, MemoryAccessPosition::A);
        (a, b, c)
    }

    fn get_syscall(&mut self, code: SyscallCode) -> Option<&Arc<dyn Syscall>> {
        self.syscall_map.get(&code)
    }

    /// Recover runtime state from a program and existing emulation state.
    #[must_use]
    pub fn recover(program: Program, state: RiscvEmulationState, opts: EmulatorOpts) -> Self {
        let mut runtime = Self::new(program, opts);
        runtime.state = state;
        runtime
    }

    /// Get the current values of the registers.
    #[allow(clippy::single_match_else)]
    #[must_use]
    pub fn registers(&mut self) -> [u32; 32] {
        let mut registers = [0; 32];
        for i in 0..32 {
            let addr = Register::from_u32(i as u32) as u32;
            let record = self.state.memory.get(&addr);

            if self.emulator_mode != EmulatorMode::Simple {
                match record {
                    Some(record) => {
                        self.memory_checkpoint
                            .entry(addr)
                            .or_insert_with(|| Some(*record));
                    }
                    None => {
                        self.memory_checkpoint.entry(addr).or_insert(None);
                    }
                }
            }

            registers[i] = match record {
                Some(record) => record.value,
                None => 0,
            };
        }
        registers
    }

    /// Get the current value of a register.
    #[must_use]
    pub fn register(&mut self, register: Register) -> u32 {
        let addr = register as u32;
        let record = self.state.memory.get(&addr);

        if self.emulator_mode != EmulatorMode::Simple {
            match record {
                Some(record) => {
                    self.memory_checkpoint
                        .entry(addr)
                        .or_insert_with(|| Some(*record));
                }
                None => {
                    self.memory_checkpoint.entry(addr).or_insert(None);
                }
            }
        }

        match record {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// Get the current value of a word.
    #[must_use]
    pub fn word(&mut self, addr: u32) -> u32 {
        #[allow(clippy::single_match_else)]
        let record = self.state.memory.get(&addr);

        if self.emulator_mode != EmulatorMode::Simple {
            match record {
                Some(record) => {
                    self.memory_checkpoint
                        .entry(addr)
                        .or_insert_with(|| Some(*record));
                }
                None => {
                    self.memory_checkpoint.entry(addr).or_insert(None);
                }
            }
        }

        match record {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// Bump the record.
    pub fn bump_record(&mut self) {
        let removed_record =
            std::mem::replace(&mut self.record, EmulationRecord::new(self.program.clone()));
        let public_values = removed_record.public_values;
        self.record.public_values = public_values;
        self.records.push(removed_record);
    }

    /// Bump the records to self.batch_records.
    pub fn bump_record_to_batch(&mut self) {
        let removed_record =
            std::mem::replace(&mut self.record, EmulationRecord::new(self.program.clone()));
        let public_values = removed_record.public_values;
        self.record.public_values = public_values;
        self.batch_records.push(removed_record);
    }

    fn postprocess(&mut self) {
        // Ensure that all proofs and input bytes were read, otherwise warn the user.
        // if self.state.proof_stream_ptr != self.state.proof_stream.len() {
        //     panic!(
        //         "Not all proofs were read. Proving will fail during field_config. Did you pass too
        // many proofs in or forget to call verify_sp1_proof?"     );
        // }
        if self.state.input_stream_ptr != self.state.input_stream.len() {
            tracing::warn!("Not all input bytes were read.");
        }

        // SECTION: Set up all MemoryInitializeFinalizeEvents needed for memory argument.
        let memory_finalize_events = &mut self.record.memory_finalize_events;

        // We handle the addr = 0 case separately, as we constrain it to be 0 in the first row
        // of the memory finalize table so it must be first in the array of events.
        let addr_0_record = self.state.memory.get(&0u32);

        let addr_0_final_record = match addr_0_record {
            Some(record) => record,
            None => &MemoryRecord {
                value: 0,
                chunk: 0,
                timestamp: 1,
            },
        };
        memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
            0,
            addr_0_final_record,
        ));

        let memory_initialize_events = &mut self.record.memory_initialize_events;
        let addr_0_initialize_event =
            MemoryInitializeFinalizeEvent::initialize(0, 0, addr_0_record.is_some());
        memory_initialize_events.push(addr_0_initialize_event);

        for addr in self.state.memory.keys() {
            if addr == &0 {
                // Handled above.
                continue;
            }

            // Program memory is initialized in the MemoryProgram chip and doesn't require any
            // events, so we only send init events for other memory addresses.
            if !self.record.program.memory_image.contains_key(addr) {
                let initial_value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                memory_initialize_events.push(MemoryInitializeFinalizeEvent::initialize(
                    *addr,
                    *initial_value,
                    true,
                ));
            }

            let record = *self.state.memory.get(addr).unwrap();
            memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
                *addr, &record,
            ));
        }
    }
}

// TODO: FIX
/// Aligns an address to the nearest word below or equal to it.
#[must_use]
pub const fn align(addr: u32) -> u32 {
    addr - addr % 4
}

impl Default for EmulatorMode {
    fn default() -> Self {
        Self::Simple
    }
}

mod tests {
    use super::{Program, RiscvEmulator};
    use crate::{
        compiler::riscv::compiler::{Compiler, SourceType},
        emulator::{opts::EmulatorOpts, riscv::stdin::EmulatorStdin},
    };

    #[allow(dead_code)]
    const FIBONACCI_ELF: &[u8] =
        include_bytes!("../../compiler/test_data/riscv32im-pico-fibonacci-elf");

    #[allow(dead_code)]
    const KECCAK_ELF: &[u8] = include_bytes!("../../compiler/test_data/riscv32im-pico-keccak-elf");

    #[must_use]
    #[allow(clippy::unreadable_literal)]
    #[allow(dead_code)]
    pub fn simple_fibo_program() -> Program {
        let compiler = Compiler::new(SourceType::RiscV, FIBONACCI_ELF);

        compiler.compile()
    }

    #[must_use]
    #[allow(clippy::unreadable_literal)]
    #[allow(dead_code)]
    pub fn simple_keccak_program() -> Program {
        let compiler = Compiler::new(SourceType::RiscV, KECCAK_ELF);

        compiler.compile()
    }

    fn _assert_send<T: Send>() {}

    /// Runtime needs to be Send so we can use it across async calls.
    fn _assert_runtime_is_send() {
        _assert_send::<RiscvEmulator>();
    }

    #[allow(dead_code)]
    const MAX_FIBONACCI_NUM_IN_ONE_CHUNK: u32 = 836789u32;

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn test_simple_fib() {
        // just run a simple elf file in the compiler folder(test_data)
        let program = simple_fibo_program();
        let mut stdin = EmulatorStdin::default();
        stdin.write(&MAX_FIBONACCI_NUM_IN_ONE_CHUNK);
        let mut emulator = RiscvEmulator::new(program, EmulatorOpts::default());
        emulator.run_with_stdin(stdin).unwrap();
        // println!("{:x?}", emulator.state.public_values_stream)
    }

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn test_simple_keccak() {
        let program = simple_keccak_program();
        let n = "a"; // do keccak(b"abcdefg")
        let mut stdin = EmulatorStdin::default();
        stdin.write(&n);
        let mut emulator = RiscvEmulator::new(program, EmulatorOpts::default());
        emulator.run_with_stdin(stdin).unwrap();
        // println!("{:x?}", emulator.state.public_values_stream)
    }
}
