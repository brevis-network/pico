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

/// The `width` bytes of `dword` from byte `offset` on, in the low bytes of the result. Needs
/// `offset + width <= 8`.
#[inline(always)]
pub const fn dword_bytes(dword: u64, offset: u64, width: u64) -> u64 {
    let shifted = dword >> (8 * offset);
    if width == 8 {
        shifted
    } else {
        shifted & ((1u64 << (8 * width)) - 1)
    }
}

/// The `width` bytes from byte `offset` of `dword` on, running into the doubleword after it,
/// `next`, in the low bytes of the result: a misaligned access that crosses a doubleword boundary.
/// Needs `offset + width > 8`.
#[inline(always)]
pub const fn straddling_bytes(dword: u64, next: u64, offset: u64, width: u64) -> u64 {
    dword_bytes(
        (dword >> (8 * offset)) | (next << (8 * (8 - offset))),
        0,
        width,
    )
}

/// `dword` with its `width` bytes from byte `offset` on replaced by the low `width` bytes of
/// `value`. Needs `offset + width <= 8`.
#[inline(always)]
pub const fn splice_dword(dword: u64, offset: u64, width: u64, value: u64) -> u64 {
    let field = if width == 8 {
        u64::MAX
    } else {
        (1u64 << (8 * width)) - 1
    };
    let mask = field << (8 * offset);
    (dword & !mask) | ((value << (8 * offset)) & mask)
}

#[cfg(test)]
mod tests {
    use super::{dword_bytes, splice_dword, straddling_bytes, RiscvEmulator};
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

    /// Each helper against bytes taken one at a time, at every offset and width it is used with.
    #[test]
    fn the_byte_helpers_take_the_bytes_they_name() {
        let (dword, next) = (0x8877_6655_4433_2211_u64, 0xffee_ddcc_bbaa_9900_u64);
        let bytes: Vec<u8> = dword
            .to_le_bytes()
            .into_iter()
            .chain(next.to_le_bytes())
            .collect();
        let value = 0x0123_4567_89ab_cdef_u64;
        let take = |from: usize, width: usize| {
            bytes[from..from + width]
                .iter()
                .rev()
                .fold(0, |acc, &byte| (acc << 8) | u64::from(byte))
        };
        for width in [1_u64, 2, 4, 8] {
            for offset in 0..8_u64 {
                let (from, n) = (offset as usize, width as usize);
                if offset + width > 8 {
                    assert_eq!(straddling_bytes(dword, next, offset, width), take(from, n));
                    continue;
                }
                assert_eq!(dword_bytes(dword, offset, width), take(from, n));
                let mut spliced = dword.to_le_bytes();
                spliced[from..from + n].copy_from_slice(&value.to_le_bytes()[..n]);
                assert_eq!(
                    splice_dword(dword, offset, width, value),
                    u64::from_le_bytes(spliced),
                    "width {width}, offset {offset}"
                );
            }
        }
    }

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

    /// An emulator in `mode` about to run a `POSEIDON2_PERMUTE` in place at 0x2_0000, a syscall the
    /// syscall chip receives.
    fn about_to_permute(mode: RiscvEmulatorMode) -> RiscvEmulator {
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            Arc::new(Program::new(vec![ecall()], 0x1_0000, 0x1_0000)),
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        emulator.mode = mode;
        emulator.update_mode_deps();
        for (register, value) in [
            (Register::X5, SyscallCode::POSEIDON2_PERMUTE as u64),
            (Register::X10, 0x2_0000),
            (Register::X11, 0x2_0000),
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
