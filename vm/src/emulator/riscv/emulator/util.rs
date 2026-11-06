use super::{EmulationError, RiscvEmulator};
use crate::{
    chips::chips::riscv_memory::event::MemoryAccessPosition,
    compiler::riscv::program::Program,
    emulator::{
        riscv::{
            event_types::{RvAddr, RvChunk, RvClk, RvTimestamp, RvValue},
            record::EmulationRecord,
            sink::ExecutionSink,
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

    /// Emits the event only: the ECALL arm already counted the syscall for the chunk split, as the
    /// simple interpreter does.
    pub(crate) fn emit_syscall(
        &mut self,
        clk: RvClk,
        syscall_id: u32,
        arg1: RvValue,
        arg2: RvValue,
    ) {
        let syscall_event = self.syscall_event(clk, syscall_id, arg1, arg2);

        // Ungated: an unconstrained block's syscall events go with the record it discards.
        self.sink.syscall(syscall_event);
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

#[cfg(test)]
mod tests {
    use super::RiscvEmulator;
    use crate::{
        compiler::riscv::{
            instruction::Instruction, opcode::Opcode, program::Program, register::Register,
        },
        emulator::{
            opts::EmulatorOpts,
            riscv::{
                emulator::RiscvEmulatorMode, public_values::RecordFinalPvsState,
                state::RuntimeRegisterRecord, syscalls::SyscallCode,
            },
        },
    };
    use alloc::sync::Arc;
    use p3_koala_bear::KoalaBear;

    fn ecall() -> Instruction {
        Instruction::new(
            Opcode::ECALL,
            Register::X5 as u8,
            Register::X10 as u64,
            Register::X11 as u64,
            false,
            false,
        )
    }

    /// An emulator in `mode` about to run a `POSEIDON2_PERMUTE` in place at 0x2000, a syscall the
    /// syscall chip receives.
    fn about_to_permute(mode: RiscvEmulatorMode) -> RiscvEmulator {
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            Arc::new(Program::new(vec![ecall()], 0x1000, 0x1000)),
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        emulator.mode = mode;
        emulator.update_mode_deps();
        for (register, value) in [
            (Register::X5, SyscallCode::POSEIDON2_PERMUTE as u64),
            (Register::X10, 0x2000),
            (Register::X11, 0x2000),
        ] {
            emulator.state.registers[register as usize] = RuntimeRegisterRecord {
                value,
                chunk: 0,
                timestamp: 0,
            };
        }
        emulator
    }

    /// The leaf estimate charges the syscall chip by `num_syscall_events`, so the tracing
    /// interpreter, which cuts the serial path's chunks, must count as the simple one, which cuts
    /// the pipeline's.
    #[test]
    fn a_sent_syscall_counts_once_in_the_chunk_split_state() {
        let mut trace = about_to_permute(RiscvEmulatorMode::Trace);
        trace
            .emulate_instruction(&ecall())
            .expect("the tracing interpreter's permute");
        let mut simple = about_to_permute(RiscvEmulatorMode::Simple);
        simple
            .emulate_instruction_simple(&ecall())
            .expect("the simple interpreter's permute");

        assert_eq!(trace.chunk_split_state.num_syscall_events, 1);
        assert_eq!(
            format!("{:?}", trace.chunk_split_state),
            format!("{:?}", simple.chunk_split_state),
            "the tracing interpreter's chunk-split state, then the simple one's"
        );
        assert_eq!(
            trace.chunk_split_state.marked_dwords(),
            simple.chunk_split_state.marked_dwords(),
            "the dwords the tracing interpreter's chunk-split bitmaps mark, then the simple one's"
        );
    }
}
