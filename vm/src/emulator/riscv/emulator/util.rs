use super::{EmulationError, RiscvEmulator, RiscvEmulatorMode};
use crate::{
    chips::chips::riscv_memory::event::MemoryAccessPosition,
    compiler::riscv::program::Program,
    emulator::{
        riscv::{
            event_types::{RvAddr, RvChunk, RvClk, RvTimestamp, RvValue},
            record::EmulationRecord,
            syscalls::{Syscall, SyscallCode, SyscallEvent},
        },
        stdin::EmulatorStdin,
    },
    machine::report::EmulationReport,
};
use alloc::sync::Arc;

type Stdin = EmulatorStdin<Program, Vec<u8>>;

impl RiscvEmulator {
    pub fn write_stdin(&mut self, stdin: &Stdin) {
        for input in &*stdin.inputs {
            self.state.input_stream.push(input.clone());
        }
    }

    /// Run without tracing
    pub fn run_fast(
        &mut self,
        stdin: Option<Stdin>,
    ) -> Result<(Vec<EmulationRecord>, Vec<EmulationReport>), EmulationError> {
        if let Some(stdin) = stdin {
            self.write_stdin(&stdin);
        }
        self.mode = RiscvEmulatorMode::Simple;
        let mut all_records = vec![];
        let mut all_reports = vec![];
        loop {
            let report = self.emulate_batch(&mut |record| all_records.push(record))?;
            let done = report.done;
            all_reports.push(report);
            if done {
                return Ok((all_records, all_reports));
            }
        }
    }

    /// Emulates the program and prints the emulation report.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program emulation fails.
    pub fn run(
        &mut self,
        stdin: Option<Stdin>,
    ) -> Result<(Vec<EmulationRecord>, Vec<EmulationReport>), EmulationError> {
        if let Some(stdin) = stdin {
            self.write_stdin(&stdin);
        }
        let mut all_records = vec![];
        let mut all_reports = vec![];
        loop {
            let report = self.emulate_batch(&mut |record| all_records.push(record))?;
            let done = report.done;
            all_reports.push(report);
            if done {
                return Ok((all_records, all_reports));
            }
        }
    }

    #[inline]
    pub fn is_unconstrained(&self) -> bool {
        self.mode.is_unconstrained()
    }

    pub(crate) fn get_syscall(&mut self, code: SyscallCode) -> Option<&Arc<dyn Syscall>> {
        self.syscall_map.get(&code)
    }

    /// Get the current value of a byte.
    #[inline(always)]
    pub fn byte(&mut self, addr: RvAddr) -> u8 {
        self.validate_main_memory_addr(addr);
        let dword = self.dword(align_u64(addr));
        dword.to_le_bytes()[(addr % 8) as usize]
    }

    /// Get the current timestamp for a given memory access position.
    #[inline(always)]
    pub fn timestamp(&self, position: &MemoryAccessPosition) -> RvTimestamp {
        let timestamp = self.state.clk + *position as u64;
        u32::try_from(timestamp).unwrap_or_else(|_| {
            panic!(
                "chunk-local timestamp {} exceeds u32::MAX; increase timestamp width or reduce chunk budget",
                timestamp
            )
        })
    }

    /// Get the current chunk.
    #[inline(always)]
    pub fn chunk(&self) -> RvChunk {
        self.state.current_chunk
    }

    #[inline]
    pub(crate) fn syscall_event(
        &self,
        clk: RvClk,
        syscall_id: u32,
        arg1: RvValue,
        arg2: RvValue,
    ) -> SyscallEvent {
        SyscallEvent {
            chunk: self.chunk(),
            clk,
            syscall_id,
            arg1,
            arg2,
        }
    }

    pub(crate) fn emit_syscall(
        &mut self,
        clk: RvClk,
        syscall_id: u32,
        arg1: RvValue,
        arg2: RvValue,
    ) {
        self.chunk_split_state.num_syscall_events += 1;

        let syscall_event = self.syscall_event(clk, syscall_id, arg1, arg2);

        self.record.syscall_events.push(syscall_event);
    }
}

#[inline(always)]
pub const fn align_u64(addr: RvAddr) -> RvAddr {
    addr & (!7)
}

/// Returns 0 if addr is in the lower 4-byte half of the dword, 1 if upper.
#[inline(always)]
pub const fn dword_half(addr: RvAddr) -> u32 {
    ((addr >> 2) & 1) as u32
}
