use super::{EmulatorMode, UnconstrainedState};
use crate::{
    chips::chips::{
        events::{MemoryAccessPosition, MemoryLocalEvent, MemoryRecord},
        riscv_memory::event::MemoryRecordEnum,
    },
    compiler::riscv::{instruction::Instruction, opcode::Opcode},
    emulator::riscv::{
        emulator::EmulationError,
        event_types::{RvAddr, RvChunk, RvClk, RvValue},
        sink::ExecutionSink,
        state::RuntimeRegisterRecord,
        syscalls::SyscallCode,
    },
};
use hashbrown::HashMap;

/// RiscV emulator running mode
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RiscvEmulatorMode {
    /// Simple mode for only executing the instructions without trace generation
    Simple,
    /// Normal trace mode for executing with trace generation
    Trace,
    /// Syscall unconstrained mode
    Unconstrained(UnconstrainedState),
}

impl PartialEq for RiscvEmulatorMode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unconstrained(_), Self::Unconstrained(_)) => false,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl RiscvEmulatorMode {
    /// Identify if the mode should emit records.
    #[inline]
    pub fn is_recording(&self) -> bool {
        matches!(self, Self::Trace)
    }

    /// Identify if it's the unconstrained mode.
    #[inline]
    pub fn is_unconstrained(&self) -> bool {
        matches!(self, Self::Unconstrained(_))
    }

    /// Exit the unconstrained mode and reset to the previous one.
    /// Return the UnconstrainedState.
    pub fn exit_unconstrained(&mut self) -> Option<UnconstrainedState> {
        if let Self::Unconstrained(state) = self {
            let mode_to_restore = match state.prev_mode {
                EmulatorMode::Trace => Self::Trace,
                EmulatorMode::Simple => Self::Simple,
            };

            if let RiscvEmulatorMode::Unconstrained(state) =
                core::mem::replace(self, mode_to_restore)
            {
                Some(state)
            } else {
                unreachable!();
            }
        } else {
            None
        }
    }

    /// Emit a CPU event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn emit_cpu(
        &self,
        chunk: RvChunk,
        clk: RvClk,
        pc: RvAddr,
        next_pc: RvAddr,
        exit_code: u32,
        a: RvValue,
        b: RvValue,
        c: RvValue,
        instruction: Instruction,
        memory_store_value: Option<RvValue>,
        sink: &mut impl ExecutionSink,
    ) {
        // TODO: Remove Self::Simple
        if matches!(self, Self::Trace | Self::Simple) {
            sink.end_cycle(
                chunk,
                clk,
                pc,
                next_pc,
                exit_code,
                a,
                b,
                c,
                instruction,
                memory_store_value,
            );
        }
    }

    /// Emit a ALU event.
    #[inline]
    ///
    /// `op_a` is the destination register index. When it is `x0` the result is discarded
    /// by the register file, and the CPU AIR correspondingly does **not** dispatch an ALU
    /// lookup for the row (`riscv_cpu/constraints.rs`, gated on `1 - op_a_0`). Emitting an
    /// event here anyway would leave the ALU chip supplying a row nobody looks up
    /// => regional cumulative sum != 0 => `verifier.rs:391`.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_alu(
        &self,
        op_a: u8,
        clk: RvClk,
        a: RvValue,
        b: RvValue,
        c: RvValue,
        opcode: Opcode,
        is_imm: bool,
        sink: &mut impl ExecutionSink,
    ) {
        if op_a == 0 {
            return;
        }
        if let Self::Trace = self {
            sink.alu(clk, opcode, a, b, c, is_imm);
        }
    }

    /// Add a memory local event.
    #[inline]
    pub fn add_memory_local_event(
        &self,
        addr: u64,
        record: MemoryRecord,
        prev_record: MemoryRecord,
        events: &mut HashMap<u64, MemoryLocalEvent>,
    ) {
        // Self::Simple matching only for syscall emulate in simple mode
        if matches!(self, Self::Trace | Self::Simple) {
            events
                .entry(addr)
                .and_modify(|e| {
                    e.final_mem_access = record;
                })
                .or_insert_with(|| MemoryLocalEvent {
                    addr,
                    initial_mem_access: prev_record,
                    final_mem_access: record,
                });
        }
    }

    /// Init the specified memory access.
    #[inline]
    pub fn init_memory_access(&self, sink: &mut impl ExecutionSink) {
        if let Self::Trace = self {
            sink.begin_cycle();
        }
    }

    /// Set the specified memory access.
    #[inline]
    pub fn set_memory_access(
        &self,
        position: MemoryAccessPosition,
        input: MemoryRecordEnum,
        sink: &mut impl ExecutionSink,
    ) {
        if let Self::Trace = self {
            sink.access(position, input);
        }
    }

    /// Add an unconstrained memory record.
    pub fn add_unconstrained_memory_record(&mut self, addr: RvAddr, record: Option<&MemoryRecord>) {
        if let Self::Unconstrained(state) = self {
            state.memory_diff.entry(addr).or_insert(record.copied());
        }
    }

    /// Add an unconstrained register record.
    pub fn add_unconstrained_register_record(
        &mut self,
        register: u8,
        record: Option<&RuntimeRegisterRecord>,
    ) {
        if let Self::Unconstrained(state) = self {
            state
                .register_diff
                .entry(register)
                .or_insert(record.copied());
        }
    }

    /// Check the syscall in unconstrained block.
    pub fn check_unconstrained_syscall(&self, syscall: SyscallCode) -> Result<(), EmulationError> {
        if let Self::Unconstrained(_) = self {
            // `hint_slice` is allowed in unconstrained mode since it is used to write the hint.
            // Other syscalls are not allowed because they can lead to non-deterministic
            // behavior, especially since many syscalls modify memory in place,
            // which is not permitted in unconstrained mode. This will result in
            // non-zero memory interactions when generating a proof.
            if syscall == SyscallCode::EXIT_UNCONSTRAINED || syscall == SyscallCode::WRITE {
                Ok(())
            } else {
                Err(EmulationError::InvalidSyscallUsage(
                    syscall.syscall_id() as u64
                ))
            }
        } else {
            Ok(())
        }
    }
}
