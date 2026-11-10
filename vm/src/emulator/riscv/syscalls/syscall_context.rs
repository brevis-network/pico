use super::{host::SyscallHost, SyscallEvent};
use crate::{
    chips::chips::riscv_memory::event::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
    compiler::riscv::opcode::Opcode,
    emulator::riscv::{
        emulator::{
            error::{AbnormalTermination, EmulationError},
            guard::access_fault,
        },
        event_types::{RvAddr, RvChunk, RvClk, RvTimestamp, RvValue},
        record::EmulationRecord,
        riscv_emulator::RiscvEmulator,
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
    /// Set by a syscall that cannot proceed; the ECALL dispatcher turns it into the emulation's
    /// `Err`. A syscall returns `Option<RvValue>` and so has no error channel of its own, and
    /// aborting is not available to a library whose caller must be able to handle bad input.
    error: Option<EmulationError>,
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
            error: None,
        }
    }

    /// Fail this syscall. The dispatcher checks [`Self::take_error`] the moment `emulate` returns,
    /// so whatever the syscall returns afterwards is discarded; the first failure wins.
    pub fn fail(&mut self, error: EmulationError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    /// The failure a syscall recorded, if any.
    pub fn take_error(&mut self) -> Option<EmulationError> {
        self.error.take()
    }

    /// Get a mutable reference to the emulation record.
    pub fn record_mut(&mut self) -> &mut EmulationRecord {
        self.rt.sink.record_mut()
    }

    /// Get the current chunk.
    #[must_use]
    pub fn current_chunk(&self) -> RvChunk {
        self.rt.state.current_chunk
    }

    /// Whether the syscall's `width`-byte access at `addr` may happen. One that lands
    /// where no guest access may fails the syscall with that fault and does not happen: its
    /// accessor hands back zero, and the dispatcher ends the run when the syscall returns.
    #[inline(always)]
    pub(crate) fn allowed(&mut self, addr: RvAddr, width: u64, store: bool) -> bool {
        match access_fault(Opcode::ECALL, addr, width, store, self.rt.code()) {
            None => true,
            Some(reason) => {
                self.fail(AbnormalTermination::fault(reason).into());
                false
            }
        }
    }

    // ── Dword API ───────────────────────────────────────────────────────
    // One memory op per 8-byte dword, the unit every precompile reads and writes.

    /// Read an 8-byte dword from memory.
    pub fn mr_dword(&mut self, addr: RvAddr) -> (MemoryReadRecord, RvValue) {
        if !self.allowed(addr, 8, false) {
            return (MemoryReadRecord::default(), 0);
        }
        debug_assert_eq!(addr & 7, 0, "mr_dword requires 8-byte-aligned address");
        let record = self.rt.mr(
            addr,
            self.current_chunk,
            self.timestamp(),
            Some(&mut self.local_memory_access),
        );
        (record, record.value)
    }

    /// Write an 8-byte dword to memory.
    pub fn mw_dword(&mut self, addr: RvAddr, value: RvValue) -> MemoryWriteRecord {
        if !self.allowed(addr, 8, true) {
            return MemoryWriteRecord::default();
        }
        debug_assert_eq!(addr & 7, 0, "mw_dword requires 8-byte-aligned address");
        self.rt.mw(
            addr,
            value,
            self.current_chunk,
            self.timestamp(),
            Some(&mut self.local_memory_access),
        )
    }

    /// Read N consecutive dwords (unconstrained).
    #[must_use]
    pub fn dword_slice_unsafe(&mut self, addr: RvAddr, len: usize) -> Vec<RvValue> {
        if len > 0 && !self.allowed(addr, 8 * len as u64, false) {
            return vec![0; len];
        }
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
            // `ExecutionSink::cut_chunk` does.
            for (addr, event) in self.local_memory_access.drain() {
                let local_mem_access = self.rt.sink.local_memory_access_mut().remove(&addr);

                if let Some(local_mem_access) = local_mem_access {
                    self.rt
                        .sink
                        .record_mut()
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

// Forwards to the inherent methods, which resolve first and which the ECALL dispatcher and the
// host-side syscalls call directly; the slices are the trait's own.
impl SyscallHost for SyscallContext<'_> {
    fn current_chunk(&self) -> RvChunk {
        Self::current_chunk(self)
    }

    fn clk(&self) -> RvClk {
        self.clk
    }

    fn advance_clk(&mut self, cycles: RvClk) {
        self.clk += cycles;
    }

    fn mr_dword(&mut self, addr: RvAddr) -> (MemoryReadRecord, RvValue) {
        Self::mr_dword(self, addr)
    }

    fn mw_dword(&mut self, addr: RvAddr, value: RvValue) -> MemoryWriteRecord {
        Self::mw_dword(self, addr, value)
    }

    fn dword_slice_unsafe(&mut self, addr: RvAddr, len: usize) -> Vec<RvValue> {
        Self::dword_slice_unsafe(self, addr, len)
    }

    fn add_syscall_memory_events(&mut self, count: usize) {
        self.rt.chunk_split_state.add_syscall_memory_events(count);
    }

    fn record_mut(&mut self) -> &mut EmulationRecord {
        Self::record_mut(self)
    }

    fn postprocess(&mut self) -> Vec<MemoryLocalEvent> {
        Self::postprocess(self)
    }

    fn syscall_event(
        &self,
        clk: RvClk,
        syscall_id: u32,
        arg1: RvValue,
        arg2: RvValue,
    ) -> SyscallEvent {
        self.rt.syscall_event(clk, syscall_id, arg1, arg2)
    }
}
