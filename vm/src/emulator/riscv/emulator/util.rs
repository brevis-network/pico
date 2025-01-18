use super::{EmulationError, EmulatorMode, RiscvEmulator};
use crate::{
    chips::chips::riscv_memory::event::MemoryAccessPosition,
    compiler::riscv::program::Program,
    emulator::riscv::{
        record::EmulationRecord,
        stdin::EmulatorStdin,
        syscalls::{Syscall, SyscallCode, SyscallEvent},
    },
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
    ) -> Result<Vec<EmulationRecord>, EmulationError> {
        if let Some(stdin) = stdin {
            self.write_stdin(&stdin);
        }
        self.emulator_mode = EmulatorMode::Simple;
        loop {
            let (batch, done) = self.emulate_batch()?;
            if done {
                return Ok(batch);
            }
        }
    }

    /// Emulates the program and prints the emulation report.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program emulation fails.
    pub fn run(&mut self, stdin: Option<Stdin>) -> Result<Vec<EmulationRecord>, EmulationError> {
        if let Some(stdin) = stdin {
            self.write_stdin(&stdin);
        }
        self.emulator_mode = EmulatorMode::Trace;
        loop {
            let (batch, done) = self.emulate_batch()?;
            if done {
                return Ok(batch);
            }
        }
    }

    pub fn is_unconstrained(&self) -> bool {
        self.unconstrained.is_some()
    }

    pub(crate) fn get_syscall(&mut self, code: SyscallCode) -> Option<&Arc<dyn Syscall>> {
        self.syscall_map.get(&code)
    }

    /// Get the current value of a byte.
    #[inline(always)]
    pub fn byte(&mut self, addr: u32) -> u8 {
        let word = self.word(align(addr));
        word.to_le_bytes()[(addr % 4) as usize]
    }

    /// Get the current timestamp for a given memory access position.
    #[inline(always)]
    pub const fn timestamp(&self, position: &MemoryAccessPosition) -> u32 {
        self.state.clk + *position as u32
    }

    /// Get the current chunk.
    #[inline(always)]
    pub fn chunk(&self) -> u32 {
        self.state.current_chunk
    }

    #[inline]
    pub(crate) fn syscall_event(
        &self,
        clk: u32,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
    ) -> SyscallEvent {
        SyscallEvent {
            chunk: self.chunk(),
            clk,
            syscall_id,
            arg1,
            arg2,
        }
    }

    pub(crate) fn emit_syscall(&mut self, clk: u32, syscall_id: u32, arg1: u32, arg2: u32) {
        let syscall_event = self.syscall_event(clk, syscall_id, arg1, arg2);

        self.record.syscall_events.push(syscall_event);
    }
}

/// Aligns an address to the nearest word below or equal to it.
#[inline(always)]
pub const fn align(addr: u32) -> u32 {
    addr & (!3)
}
