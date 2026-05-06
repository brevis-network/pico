use crate::{
    chips::chips::riscv_memory::event::{
        MemoryLocalEvent, MemoryReadRecord, MemoryRecord, MemoryWriteRecord,
    },
    compiler::riscv::register::Register,
    emulator::riscv::{
        emulator::util::{align_u64, dword_half},
        event_types::{RvAddr, RvChunk, RvClk, RvTimestamp, RvValue},
        record::EmulationRecord,
        riscv_emulator::{RiscvEmulator, MIN_MAIN_MEMORY_ADDR},
    },
};
use hashbrown::HashMap;

/// A emulator for syscalls that is protected so that developers cannot arbitrarily modify the
/// emulator.
#[allow(dead_code)]
pub struct SyscallContext<'a: 'a> {
    /// The current chunk.
    pub current_chunk: RvChunk,
    /// The clock cycle.
    pub clk: RvClk,
    /// The next program counter.
    pub next_pc: RvAddr,
    /// The exit code.
    pub exit_code: u32,
    /// The emulator.
    pub rt: &'a mut RiscvEmulator,
    /// The syscall lookup id.
    pub syscall_lookup_id: u128,
    /// The local memory access events for the syscall.
    pub local_memory_access: HashMap<u64, MemoryLocalEvent>,
}

impl<'a> SyscallContext<'a> {
    #[inline(always)]
    fn timestamp(&self) -> RvTimestamp {
        u32::try_from(self.clk).unwrap_or_else(|_| {
            panic!(
                "syscall-local timestamp {} exceeds u32::MAX; increase timestamp width or reduce chunk budget",
                self.clk
            )
        })
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

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
    pub fn current_chunk(&self) -> RvChunk {
        self.rt.state.current_chunk
    }

    #[inline(always)]
    fn validate_main_memory_addr(&self, addr: RvAddr) {
        assert!(
            addr >= MIN_MAIN_MEMORY_ADDR,
            "syscall memory access below floor 0x{MIN_MAIN_MEMORY_ADDR:08x}: 0x{addr:08x}"
        );
    }

    #[inline(always)]
    pub fn assert_dword_aligned_precompile(addr: RvAddr, context: &str) {
        assert!(
            addr.is_multiple_of(8),
            "{context} must be 8-byte aligned, got 0x{addr:08x}"
        );
    }

    // TODO: remove this after poseidon2 precompile upgrade
    // ── Canonical RV64 memory API ───────────────────────────────────────
    // Memory is now 8-byte granular. Syscalls operate at 4-byte word level,
    // so we align to 8, read/write the full dword, and extract/insert the
    // correct 4-byte half.
    //
    // IMPORTANT: Two consecutive 4-byte accesses that fall within the same
    // 8-byte dword must share a single `rt.mr()`/`rt.mw()` call, because
    // the memory metadata (chunk, timestamp) is tracked per dword.  Calling
    // `rt.mr()` twice on the same dword at the same clock tick violates the
    // timestamp-monotonicity invariant.  The `_slice` helpers below handle
    // this by iterating in dword-aligned pairs: one real memory op per
    // dword, with both 4-byte halves extracted / merged from that single op.

    /// Read a 4-byte word from memory, returning the full dword record and
    /// the extracted 4-byte value (as u64 with upper bits zero).
    ///
    /// If the 8-byte-aligned dword has already been accessed at the current
    /// clock tick (tracked via `local_memory_access`), the existing metadata
    /// is reused instead of calling `rt.mr()` again, avoiding a
    /// timestamp-monotonicity violation.
    pub fn mr(&mut self, addr: RvAddr) -> (MemoryReadRecord, RvValue) {
        self.validate_main_memory_addr(addr);
        let aligned = align_u64(addr);

        let record = if let Some(local_event) = self.local_memory_access.get(&aligned) {
            // This dword was already accessed in this syscall invocation.
            // Reuse the existing metadata instead of calling rt.mr() again
            // (which would fail the timestamp monotonicity check).
            //
            // Chunk splitting still needs to see the repeated syscall-local
            // access. AOT counts every syscall memory access even when it hits
            // the same dword multiple times within one syscall invocation.
            self.rt.chunk_split_state.add_syscall_memory_events(1);
            let value = self.rt.state.memory.peek_dword(aligned);
            let initial = &local_event.initial_mem_access;
            MemoryReadRecord {
                value,
                chunk: self.current_chunk,
                timestamp: self.timestamp(),
                prev_chunk: initial.chunk,
                prev_timestamp: initial.timestamp,
            }
        } else {
            self.rt.mr(
                aligned,
                self.current_chunk,
                self.timestamp(),
                Some(&mut self.local_memory_access),
            )
        };

        let half = dword_half(addr);
        let value = if half == 0 {
            record.value & 0xFFFF_FFFF
        } else {
            record.value >> 32
        };
        (record, value)
    }

    /// Read a slice of 4-byte words from memory.
    pub fn mr_slice(&mut self, addr: RvAddr, len: usize) -> (Vec<MemoryReadRecord>, Vec<RvValue>) {
        let mut records = Vec::with_capacity(len);
        let mut values = Vec::with_capacity(len);
        for i in 0..len {
            let word_addr = addr.wrapping_add((i as u64) * 4);
            let (record, value) = self.mr(word_addr);
            records.push(record);
            values.push(value);
        }
        (records, values)
    }

    // TODO: remove this after poseidon2 precompile upgrade
    /// Write a 4-byte word to memory (read-modify-write within 8-byte dword).
    ///
    /// If the dword was already accessed at the current clock tick, the value
    /// is merged directly into memory without calling `rt.mw()` again, to
    /// preserve timestamp-monotonicity.
    pub fn mw(&mut self, addr: RvAddr, value: RvValue) -> MemoryWriteRecord {
        self.validate_main_memory_addr(addr);
        let aligned = align_u64(addr);
        let existing = self.rt.state.memory.peek_dword(aligned);
        let half = dword_half(addr);
        let merged = if half == 0 {
            (existing & 0xFFFF_FFFF_0000_0000) | (value & 0xFFFF_FFFF)
        } else {
            (existing & 0x0000_0000_FFFF_FFFF) | ((value & 0xFFFF_FFFF) << 32)
        };

        let timestamp = self.timestamp();
        if let Some(local_event) = self.local_memory_access.get_mut(&aligned) {
            // This dword was already accessed in this syscall invocation.
            // Write directly to memory and update the local event's final state,
            // without calling rt.mw() (which would fail the monotonicity check).
            //
            // Keep chunk-split accounting aligned with AOT: repeated accesses
            // to the same dword inside a syscall still contribute syscall
            // memory events even though the metadata update is coalesced here.
            self.rt.chunk_split_state.add_syscall_memory_events(1);
            let prev_value = existing;
            self.rt
                .state
                .memory
                .write_dword(aligned, merged, self.current_chunk, timestamp);
            local_event.final_mem_access = MemoryRecord {
                value: merged,
                chunk: self.current_chunk,
                timestamp,
            };
            let initial = &local_event.initial_mem_access;
            MemoryWriteRecord {
                value: merged,
                chunk: self.current_chunk,
                timestamp,
                prev_value,
                prev_chunk: initial.chunk,
                prev_timestamp: initial.timestamp,
            }
        } else {
            self.rt.mw(
                aligned,
                merged,
                self.current_chunk,
                self.timestamp(),
                Some(&mut self.local_memory_access),
            )
        }
    }

    /// Write a slice of 4-byte words to memory.
    pub fn mw_slice(&mut self, addr: RvAddr, values: &[RvValue]) -> Vec<MemoryWriteRecord> {
        let mut records = Vec::with_capacity(values.len());
        for i in 0..values.len() {
            let word_addr = addr.wrapping_add((i as u64) * 4);
            let record = self.mw(word_addr, values[i]);
            records.push(record);
        }
        records
    }

    /// Get the current value of a register (unconstrained).
    #[must_use]
    pub fn register_unsafe(&mut self, register: Register) -> RvValue {
        self.rt.register(register)
    }

    /// Get the current value of a byte (unconstrained).
    #[must_use]
    pub fn byte_unsafe(&mut self, addr: RvAddr) -> u8 {
        self.validate_main_memory_addr(addr);
        self.rt.byte(addr)
    }

    /// Get the current value of a 4-byte word (unconstrained).
    #[must_use]
    pub fn word_unsafe(&mut self, addr: RvAddr) -> RvValue {
        self.validate_main_memory_addr(addr);
        let dword = self.rt.dword(align_u64(addr));
        let half = dword_half(addr);
        if half == 0 {
            dword & 0xFFFF_FFFF
        } else {
            dword >> 32
        }
    }

    /// Get a slice of 4-byte words (unconstrained).
    #[must_use]
    pub fn slice_unsafe(&mut self, addr: RvAddr, len: usize) -> Vec<RvValue> {
        let mut values = Vec::with_capacity(len);
        for i in 0..len {
            let word_addr = addr.wrapping_add((i as u64) * 4);
            values.push(self.word_unsafe(word_addr));
        }
        values
    }

    // ── Native dword API ────────────────────────────────────────────────
    // Direct 8-byte dword access — one memory op per dword, no half
    // extraction. Use when the precompile naturally operates on u64 values
    // (e.g. keccak state lanes).

    /// Read an 8-byte dword from memory (no half extraction).
    pub fn mr_dword(&mut self, addr: RvAddr) -> (MemoryReadRecord, RvValue) {
        self.validate_main_memory_addr(addr);
        debug_assert_eq!(addr & 7, 0, "mr_dword requires 8-byte-aligned address");
        let record = self.rt.mr(
            addr,
            self.current_chunk,
            self.timestamp(),
            Some(&mut self.local_memory_access),
        );
        (record, record.value)
    }

    /// Read N consecutive 8-byte dwords.
    pub fn mr_dword_slice(
        &mut self,
        addr: RvAddr,
        len: usize,
    ) -> (Vec<MemoryReadRecord>, Vec<RvValue>) {
        let mut records = Vec::with_capacity(len);
        let mut values = Vec::with_capacity(len);
        for i in 0..len {
            let dword_addr = addr.wrapping_add((i as u64) * 8);
            let (record, value) = self.mr_dword(dword_addr);
            records.push(record);
            values.push(value);
        }
        (records, values)
    }

    /// Write an 8-byte dword to memory.
    pub fn mw_dword(&mut self, addr: RvAddr, value: RvValue) -> MemoryWriteRecord {
        self.validate_main_memory_addr(addr);
        debug_assert_eq!(addr & 7, 0, "mw_dword requires 8-byte-aligned address");
        self.rt.mw(
            addr,
            value,
            self.current_chunk,
            self.timestamp(),
            Some(&mut self.local_memory_access),
        )
    }

    /// Write N consecutive 8-byte dwords.
    pub fn mw_dword_slice(&mut self, addr: RvAddr, values: &[RvValue]) -> Vec<MemoryWriteRecord> {
        let mut records = Vec::with_capacity(values.len());
        for (i, &value) in values.iter().enumerate() {
            let dword_addr = addr.wrapping_add((i as u64) * 8);
            records.push(self.mw_dword(dword_addr, value));
        }
        records
    }

    /// Read N consecutive dwords (unconstrained).
    #[must_use]
    pub fn dword_slice_unsafe(&mut self, addr: RvAddr, len: usize) -> Vec<RvValue> {
        self.validate_main_memory_addr(addr);
        debug_assert_eq!(
            addr & 7,
            0,
            "dword_slice_unsafe requires 8-byte-aligned address"
        );
        let mut values = Vec::with_capacity(len);
        for i in 0..len {
            let dword_addr = addr.wrapping_add((i as u64) * 8);
            values.push(self.rt.dword(dword_addr));
        }
        values
    }

    // ── Postprocess + setters ───────────────────────────────────────────

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

    /// Set the next program counter.
    pub fn set_next_pc(&mut self, next_pc: RvAddr) {
        self.next_pc = next_pc;
    }

    /// Set the exit code.
    pub fn set_exit_code(&mut self, exit_code: u32) {
        self.exit_code = exit_code;
    }
}

#[cfg(test)]
mod tests {
    use super::SyscallContext;
    use crate::{
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        emulator::{opts::EmulatorOpts, riscv::riscv_emulator::RiscvEmulator},
    };
    use alloc::sync::Arc;
    use p3_baby_bear::BabyBear;

    fn tiny_program() -> Arc<Program> {
        Arc::new(Program::new(
            vec![Instruction::new(Opcode::ADD, 0, 0, 0, false, false)],
            0x1000,
            0x1000,
        ))
    }

    #[test]
    fn dword_alignment_helper_accepts_eight_byte_alignment() {
        SyscallContext::assert_dword_aligned_precompile(0x1000, "test");
    }

    #[test]
    #[should_panic(expected = "must be 8-byte aligned")]
    fn dword_alignment_helper_rejects_four_byte_alignment() {
        SyscallContext::assert_dword_aligned_precompile(0x1004, "test");
    }

    #[test]
    fn repeated_syscall_word_reads_still_count_chunk_split_events() {
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(tiny_program(), EmulatorOpts::default(), None);
        emulator.chunk_split_state.enter_syscall();

        let mut ctx = SyscallContext::new(&mut emulator);
        let _ = ctx.mr(0x10000);
        let _ = ctx.mr(0x10004);

        assert_eq!(ctx.rt.chunk_split_state.num_syscall_memory_events, 2);
        assert_eq!(ctx.rt.chunk_split_state.num_global_lookup_base, 3);
        ctx.rt.chunk_split_state.exit_syscall();
    }

    #[test]
    fn repeated_syscall_word_writes_still_count_chunk_split_events() {
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(tiny_program(), EmulatorOpts::default(), None);
        emulator.chunk_split_state.enter_syscall();

        let mut ctx = SyscallContext::new(&mut emulator);
        let _ = ctx.mw(0x10000, 1);
        let _ = ctx.mw(0x10004, 2);

        assert_eq!(ctx.rt.chunk_split_state.num_syscall_memory_events, 2);
        assert_eq!(ctx.rt.chunk_split_state.num_global_lookup_base, 3);
        ctx.rt.chunk_split_state.exit_syscall();
    }
}
