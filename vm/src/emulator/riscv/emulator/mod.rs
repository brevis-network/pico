pub mod error;
pub mod instruction;
pub mod mode;
pub mod unconstrained;
pub mod util;

use crate::{
    chips::chips::events::{
        MemoryAccessPosition, MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryReadRecord,
        MemoryRecord, MemoryWriteRecord,
    },
    compiler::riscv::{instruction::Instruction, program::Program, register::Register},
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            hook::{default_hook_map, Hook},
            public_values::PublicValues,
            record::{EmulationRecord, MemoryAccessRecord},
            state::RiscvEmulationState,
            syscalls::{default_syscall_map, Syscall, SyscallCode},
        },
    },
    primitives::Poseidon2Init,
};
use alloc::sync::Arc;
use hashbrown::{hash_map::Entry, HashMap};
use p3_field::PrimeField32;
use p3_symmetric::Permutation;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, instrument};

pub use error::EmulationError;
pub use mode::RiscvEmulatorMode;
pub use unconstrained::UnconstrainedState;
pub use util::align;

/// An emulator for the Pico RISC-V zkVM.
///
/// The executor is responsible for executing a user program and tracing important events which
/// occur during emulation (i.e., memory reads, alu operations, etc).
pub struct RiscvEmulator {
    /// The current running mode of RiscV emulator.
    pub mode: RiscvEmulatorMode,

    /// The program.
    pub program: Arc<Program>,

    /// The options for the emulator.
    pub opts: EmulatorOpts,

    /// The state of the emulation.
    pub state: RiscvEmulationState,

    /// The current trace of the emulation that is being collected.
    pub record: EmulationRecord,

    pub public_values_buffer: PublicValues<u32, u32>,

    /// The mapping between syscall codes and their implementations.
    pub syscall_map: HashMap<SyscallCode, Arc<dyn Syscall>>,

    /// The mapping between hook fds and their implementation
    pub hook_map: HashMap<u32, Hook>,

    /// The memory accesses for the current cycle.
    pub memory_accesses: MemoryAccessRecord,

    /// The maximum number of cycles for a syscall.
    pub max_syscall_cycles: u32,

    /// Local memory access events.
    pub local_memory_access: HashMap<u32, MemoryLocalEvent>,

    /// Collects precompile and memory init/finalize events across batches
    pub deferred_record: EmulationRecord,

    flag_active: bool,

    /// whether or not to log syscalls
    log_syscalls: bool,
}

/// The different modes the emulator can run in.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmulatorMode {
    /// Run the emulation with no tracing or checkpointing.
    #[default]
    Simple,
    /// Run the emulation with full tracing of events.
    Trace,
}

impl RiscvEmulator {
    #[must_use]
    pub fn new<F>(program: Arc<Program>, opts: EmulatorOpts) -> Self
    where
        F: PrimeField32 + Poseidon2Init,
        F::Poseidon2: Permutation<[F; 16]>,
    {
        let record = EmulationRecord::new(program.clone());
        let deferred_record = record.clone();

        // Determine the maximum number of cycles for any syscall.
        let syscall_map = default_syscall_map::<F>();
        let max_syscall_cycles = syscall_map
            .values()
            .map(|syscall| syscall.num_extra_cycles())
            .max()
            .unwrap_or_default();

        let hook_map = default_hook_map();

        let log_syscalls = std::env::var_os("LOG_SYSCALLS").is_some();

        Self {
            syscall_map,
            hook_map,
            memory_accesses: Default::default(),
            record,
            public_values_buffer: Default::default(),
            state: RiscvEmulationState::new(program.pc_start),
            program,
            opts,
            max_syscall_cycles,
            local_memory_access: Default::default(),
            deferred_record,
            mode: RiscvEmulatorMode::Trace,
            flag_active: true,
            log_syscalls,
        }
    }

    /// If it's the first cycle, initialize the program.
    #[inline(always)]
    fn initialize_if_needed(&mut self) {
        if self.state.global_clk == 0 {
            self.state.clk = 0;
            tracing::debug!("loading memory image");
            for (addr, value) in self.program.memory_image.iter() {
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
    }

    /// Emulates one cycle of the program, returning whether the program has finished.
    #[inline]
    fn emulate_cycle(
        &mut self,
        batch_records: &mut Vec<EmulationRecord>,
    ) -> Result<bool, EmulationError> {
        // Fetch the instruction at the current program counter.
        let instruction = self.program.fetch(self.state.pc);

        // Emulate the instruction.
        self.emulate_instruction(&instruction)?;

        // Increment the clock.
        self.state.global_clk += 1;

        if !self.is_unconstrained() {
            // Check if there's enough cycles or move to the next chunk.
            if self.state.clk + self.max_syscall_cycles >= self.opts.chunk_size * 4 {
                self.state.current_chunk += 1;
                self.state.clk = 0;

                self.bump_record(batch_records);
            }
        }

        if let Some(max_cycles) = self.opts.max_cycles {
            if self.state.global_clk >= max_cycles {
                panic!("exceeded cycle limit of {}", max_cycles);
            }
        }

        let done = self.state.pc == 0
            || self.state.pc.wrapping_sub(self.program.pc_base)
                >= (self.program.instructions.len() * 4) as u32;
        if done && self.is_unconstrained() {
            error!(
                "program ended in unconstrained mode at clk {}",
                self.state.global_clk
            );
            return Err(EmulationError::UnconstrainedEnd);
        }

        Ok(done)
    }

    /// Emulate chunk_batch_size cycles and bump to self.batch_records.
    #[instrument(name = "emulate_batch_records", level = "debug", skip_all)]
    pub fn emulate_batch(&mut self) -> Result<(Vec<EmulationRecord>, bool), EmulationError> {
        let mut batch_records = Vec::with_capacity(self.opts.chunk_batch_size as usize);

        let start_chunk = self.state.current_chunk; // needed for public input
        debug!("start_chunk: {}", start_chunk);

        self.initialize_if_needed();

        // Loop until we've emulated `self.chunk_batch_size` chunks if `self.chunk_batch_size` is
        // set.
        debug!(
            "emulate - current chunk {}, batch size {}",
            self.state.current_chunk, self.opts.chunk_batch_size
        );
        let mut done = false;
        let mut current_chunk = self.state.current_chunk;
        let mut num_chunks_emulated = 0;
        loop {
            if self.emulate_cycle(&mut batch_records)? {
                done = true;
                break;
            }

            if self.opts.chunk_batch_size > 0 && current_chunk != self.state.current_chunk {
                num_chunks_emulated += 1;
                current_chunk = self.state.current_chunk;
                if num_chunks_emulated == self.opts.chunk_batch_size {
                    break;
                }
            }
        }
        debug!("emulate - global clk {}", self.state.global_clk);

        if !self.record.cpu_events.is_empty() {
            self.bump_record(&mut batch_records);
        }

        if done {
            self.postprocess();
            // Push the remaining emulation record with memory initialize & finalize events.
            self.bump_record(&mut batch_records);
        } else {
            self.state.current_batch += 1;
        }

        for record in batch_records.iter_mut() {
            self.deferred_record.append(&mut record.defer());
        }

        // remove empty memory init/finalize chunk
        if done {
            batch_records.pop();
        }

        let deferred = self.deferred_record.split(done, self.opts.split_opts);
        debug!("split-chunks len: {:?}", deferred.len());

        batch_records.reserve(deferred.len() + done as usize);
        batch_records.extend(deferred);

        debug!("batch record capacity: {}", batch_records.capacity());

        debug!(
            "Final batch record len after postprocess and split: {}",
            batch_records.len()
        );

        // Set the global public values for all chunks.
        // println!("# batch records to be processed: {}", self.batch_records.len());
        let mut current_execution_chunk = 0;
        for record in batch_records.iter_mut() {
            self.public_values_buffer.chunk += 1;
            if !record.cpu_events.is_empty() {
                if !self.flag_active {
                    self.flag_active = true;
                } else {
                    self.public_values_buffer.execution_chunk += 1;
                }
                current_execution_chunk = self.public_values_buffer.execution_chunk;
                self.public_values_buffer.start_pc = record.cpu_events[0].pc;
                self.public_values_buffer.next_pc = record.cpu_events.last().unwrap().next_pc;
                self.public_values_buffer.exit_code = record.cpu_events.last().unwrap().exit_code;
                self.public_values_buffer.committed_value_digest =
                    record.public_values.committed_value_digest;
            } else {
                // hack to make execution chunk consistent
                if (self.flag_active) & (!done) {
                    current_execution_chunk += 1;
                    self.flag_active = false;
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
            record.public_values = self.public_values_buffer;
        }

        Ok((batch_records, done))
    }

    /// Read a word from memory and create an access record.
    pub fn mr(
        &mut self,
        addr: u32,
        chunk: u32,
        timestamp: u32,
        local_memory_access: Option<&mut HashMap<u32, MemoryLocalEvent>>,
    ) -> MemoryReadRecord {
        // Get the memory record entry.
        let entry = self.state.memory.entry(addr);

        self.mode.add_unconstrained_memory_record(addr, &entry);

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

        let prev_record = *record;
        record.chunk = chunk;
        record.timestamp = timestamp;

        self.mode.add_memory_local_event(
            addr,
            *record,
            prev_record,
            local_memory_access.unwrap_or(&mut self.local_memory_access),
        );

        // Construct the memory read record.
        MemoryReadRecord::new(value, chunk, timestamp, prev_chunk, prev_timestamp)
    }

    /// Write a word to memory and create an access record.
    pub fn mw(
        &mut self,
        addr: u32,
        value: u32,
        chunk: u32,
        timestamp: u32,
        local_memory_access: Option<&mut HashMap<u32, MemoryLocalEvent>>,
    ) -> MemoryWriteRecord {
        // Get the memory record entry.
        let entry = self.state.memory.entry(addr);

        self.mode.add_unconstrained_memory_record(addr, &entry);

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

        let prev_record = *record;
        record.value = value;
        record.chunk = chunk;
        record.timestamp = timestamp;

        self.mode.add_memory_local_event(
            addr,
            *record,
            prev_record,
            local_memory_access.unwrap_or(&mut self.local_memory_access),
        );

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
        // Read the address from memory and create a memory read record.
        let record = self.mr(addr, self.chunk(), self.timestamp(&position), None);

        // If we're not in unconstrained mode, record the access for the current cycle.
        self.mode
            .set_memory_access(position, record.into(), &mut self.memory_accesses);

        record.value
    }

    /// Write to memory.
    ///
    /// # Panics
    ///
    /// This function will panic if the address is not aligned or if the memory accesses are already
    /// initialized.
    pub fn mw_cpu(&mut self, addr: u32, value: u32, position: MemoryAccessPosition) {
        // Read the address from memory and create a memory read record.
        let record = self.mw(addr, value, self.chunk(), self.timestamp(&position), None);

        // If we're not in unconstrained mode, record the access for the current cycle.
        self.mode
            .set_memory_access(position, record.into(), &mut self.memory_accesses);
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
    #[inline]
    fn alu_rw(&mut self, rd: Register, a: u32) {
        self.rw(rd, a);
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

    /// Recover emulator state from a program and existing emulation state.
    #[must_use]
    pub fn recover<F>(program: Arc<Program>, state: RiscvEmulationState, opts: EmulatorOpts) -> Self
    where
        F: PrimeField32 + Poseidon2Init,
        F::Poseidon2: Permutation<[F; 16]>,
    {
        let mut runtime = Self::new::<F>(program, opts);
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

        match record {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// Bump the record.
    pub fn bump_record(&mut self, batch_records: &mut Vec<EmulationRecord>) {
        // Copy all of the existing local memory accesses to the record's local_memory_access vec.
        self.mode.copy_local_memory_events(
            &mut self.local_memory_access,
            &mut self.record.cpu_local_memory_access,
        );

        let removed_record =
            std::mem::replace(&mut self.record, EmulationRecord::new(self.program.clone()));
        let public_values = removed_record.public_values;
        self.record.public_values = public_values;
        batch_records.push(removed_record);
    }

    fn postprocess(&mut self) {
        // Ensure that all proofs and input bytes were read, otherwise warn the user.
        // if self.state.proof_stream_ptr != self.state.proof_stream.len() {
        //     panic!(
        //         "Not all proofs were read. Proving will fail during recursion. Did you pass too
        // many proofs in or forget to call verify_pico_proof?"     );
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

#[cfg(test)]
mod tests {
    use super::{Program, RiscvEmulator};
    use crate::{
        compiler::riscv::compiler::{Compiler, SourceType},
        emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
    };
    use alloc::sync::Arc;
    use p3_baby_bear::BabyBear;

    #[allow(dead_code)]
    const FIBONACCI_ELF: &[u8] =
        include_bytes!("../../../compiler/test_elf/riscv32im-pico-fibonacci-elf");

    #[allow(dead_code)]
    const KECCAK_ELF: &[u8] =
        include_bytes!("../../../compiler/test_elf/riscv32im-pico-keccak-elf");

    pub fn simple_fibo_program() -> Arc<Program> {
        let compiler = Compiler::new(SourceType::RISCV, FIBONACCI_ELF);

        compiler.compile()
    }

    pub fn simple_keccak_program() -> Arc<Program> {
        let compiler = Compiler::new(SourceType::RISCV, KECCAK_ELF);

        compiler.compile()
    }

    const MAX_FIBONACCI_NUM_IN_ONE_CHUNK: u32 = 836789u32;

    #[test]
    fn test_simple_fib() {
        // just run a simple elf file in the compiler folder(test_elf)
        let program = simple_fibo_program();
        let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder();
        stdin.write(&MAX_FIBONACCI_NUM_IN_ONE_CHUNK);
        let mut emulator = RiscvEmulator::new::<BabyBear>(program, EmulatorOpts::default());
        emulator.run(Some(stdin.finalize())).unwrap();
        // println!("{:x?}", emulator.state.public_values_stream)
    }

    #[test]
    fn test_simple_keccak() {
        let program = simple_keccak_program();
        let n = "a"; // do keccak(b"abcdefg")
        let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder();
        stdin.write(&n);
        let mut emulator = RiscvEmulator::new::<BabyBear>(program, EmulatorOpts::default());
        emulator.run(Some(stdin.finalize())).unwrap();
        // println!("{:x?}", emulator.state.public_values_stream)
    }
}
