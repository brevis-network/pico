use crate::{
    chips::chips::riscv_memory::event::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
    compiler::riscv::register::Register,
    emulator::riscv::{record::EmulationRecord, riscv_emulator::RiscvEmulator},
};
use hashbrown::HashMap;

/// A runtime for syscalls that is protected so that developers cannot arbitrarily modify the
/// runtime.
#[allow(dead_code)]
pub struct SyscallContext<'a: 'a> {
    /// The current chunk.
    pub current_chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The exit code.
    pub exit_code: u32,
    /// The runtime.
    pub rt: &'a mut RiscvEmulator,
    /// The syscall lookup id.
    pub syscall_lookup_id: u128,
    /// The local memory access events for the syscall.
    pub local_memory_access: HashMap<u32, MemoryLocalEvent>,
}

impl<'a> SyscallContext<'a> {
    /// Create a new [`SyscallContext`].
    pub fn new(runtime: &'a mut RiscvEmulator) -> Self {
        let current_chunk = runtime.chunk();
        let clk = runtime.state.clk;
        Self {
            current_chunk,
            clk,
            next_pc: runtime.state.pc.wrapping_add(4),
            exit_code: 0,
            rt: runtime,
            syscall_lookup_id: 0,
            local_memory_access: HashMap::new(),
        }
    }

    /// Get a mutable reference to the emulation record.
    pub fn record_mut(&mut self) -> &mut EmulationRecord {
        &mut self.rt.record
    }

    /// Get the current chunk.
    #[must_use]
    pub fn current_chunk(&self) -> u32 {
        self.rt.state.current_chunk
    }

    /// Read a word from memory.
    pub fn mr(&mut self, addr: u32) -> (MemoryReadRecord, u32) {
        let record = self.rt.mr(
            addr,
            self.current_chunk,
            self.clk,
            Some(&mut self.local_memory_access),
        );
        (record, record.value)
    }

    /// Read a slice of words from memory.
    pub fn mr_slice(&mut self, addr: u32, len: usize) -> (Vec<MemoryReadRecord>, Vec<u32>) {
        let mut records = Vec::new();
        let mut values = Vec::new();
        for i in 0..len {
            let (record, value) = self.mr(addr + i as u32 * 4);
            records.push(record);
            values.push(value);
        }
        (records, values)
    }

    /// Write a word to memory.
    pub fn mw(&mut self, addr: u32, value: u32) -> MemoryWriteRecord {
        self.rt.mw(
            addr,
            value,
            self.current_chunk,
            self.clk,
            Some(&mut self.local_memory_access),
        )
    }

    /// Write a slice of words to memory.
    pub fn mw_slice(&mut self, addr: u32, values: &[u32]) -> Vec<MemoryWriteRecord> {
        let mut records = Vec::new();
        for i in 0..values.len() {
            let record = self.mw(addr + i as u32 * 4, values[i]);
            records.push(record);
        }
        records
    }

    /// Postprocess the syscall.  Specifically will process the syscall's memory local events.
    pub fn postprocess(&mut self) -> Vec<MemoryLocalEvent> {
        let mut syscall_local_mem_events = Vec::new();

        if !self.rt.is_unconstrained() {
            // Will need to transfer the existing memory local events in the emulator to it's record,
            // and return all the syscall memory local events.  This is similar to what
            // `bump_record` does.
            for (addr, event) in self.local_memory_access.drain() {
                let local_mem_access = self.rt.local_memory_access.remove(&addr);

                if let Some(local_mem_access) = local_mem_access {
                    self.rt
                        .record
                        .cpu_local_memory_access
                        .push(local_mem_access);
                }

                syscall_local_mem_events.push(event);
            }
        }

        syscall_local_mem_events
    }

    /// Get the current value of a register, but doesn't use a memory record.
    /// This is generally unconstrained, so you must be careful using it.
    #[must_use]
    pub fn register_unsafe(&mut self, register: Register) -> u32 {
        self.rt.register(register)
    }

    /// Get the current value of a byte, but doesn't use a memory record.
    #[must_use]
    pub fn byte_unsafe(&mut self, addr: u32) -> u8 {
        self.rt.byte(addr)
    }

    /// Get the current value of a word, but doesn't use a memory record.
    #[must_use]
    pub fn word_unsafe(&mut self, addr: u32) -> u32 {
        self.rt.word(addr)
    }

    /// Get a slice of words, but doesn't use a memory record.
    #[must_use]
    pub fn slice_unsafe(&mut self, addr: u32, len: usize) -> Vec<u32> {
        let mut values = Vec::with_capacity(len);
        for i in 0..len {
            values.push(self.rt.word(addr + i as u32 * 4));
        }
        values
    }

    /// Set the next program counter.
    pub fn set_next_pc(&mut self, next_pc: u32) {
        self.next_pc = next_pc;
    }

    /// Set the exit code.
    pub fn set_exit_code(&mut self, exit_code: u32) {
        self.exit_code = exit_code;
    }
}
