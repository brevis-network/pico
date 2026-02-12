use super::{EmulatorMode, UnconstrainedState};
use crate::{
    chips::chips::{
        events::{AluEvent, CpuEvent, MemoryAccessPosition, MemoryLocalEvent, MemoryRecord},
        riscv_memory::event::MemoryRecordEnum,
    },
    compiler::riscv::{instruction::Instruction, opcode::Opcode},
    emulator::riscv::{
        emulator::EmulationError, record::MemoryAccessRecord, syscalls::SyscallCode,
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
    /// Identify if it's the unconstrained mode.
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
    #[allow(clippy::too_many_arguments)]
    pub fn emit_cpu(
        &self,
        chunk: u32,
        clk: u32,
        pc: u32,
        next_pc: u32,
        exit_code: u32,
        a: u32,
        b: u32,
        c: u32,
        instruction: Instruction,
        memory_record: MemoryAccessRecord,
        memory_store_value: Option<u32>,
        events: &mut Vec<CpuEvent>,
        mem_read_write: &mut Vec<usize>,
    ) {
        // TODO: Remove Self::Simple
        if matches!(self, Self::Trace | Self::Simple) {
            let event = CpuEvent::new(
                chunk,
                clk,
                pc,
                next_pc,
                instruction,
                a,
                b,
                c,
                memory_store_value,
                memory_record,
                exit_code,
            );

            if instruction.is_memory_instruction() {
                mem_read_write.push(events.len());
            }
            events.push(event);
        }
    }

    /// Emit a ALU event.
    pub fn emit_alu(
        &self,
        clk: u32,
        a: u32,
        b: u32,
        c: u32,
        opcode: Opcode,
        events: &mut Vec<AluEvent>,
    ) {
        if let Self::Trace = self {
            let event = AluEvent {
                clk,
                opcode,
                a,
                b,
                c,
            };
            events.push(event);
        }
    }

    /// Add a memory local event.
    pub fn add_memory_local_event(
        &self,
        addr: u32,
        record: MemoryRecord,
        prev_record: MemoryRecord,
        events: &mut HashMap<u32, MemoryLocalEvent>,
    ) {
        // Self::Simple matching only for syscall emulate in simple mode
        if matches!(self, Self::Trace | Self::Simple) {
            events
                .entry(addr)
                .and_modify(|e| {
                    e.final_mem_access = record;
                })
                .or_insert(MemoryLocalEvent {
                    addr,
                    initial_mem_access: prev_record,
                    final_mem_access: record,
                });
        }
    }

    /// Copy the local memory events.
    ///
    /// After exiting unconstrained mode, we need to restore the correct memory events.
    /// Since the previous mode could be either `Trace` or `Simple`, both cases must be handled here.
    pub fn copy_local_memory_events(
        &self,
        from: &mut HashMap<u32, MemoryLocalEvent>,
        to: &mut Vec<MemoryLocalEvent>,
    ) {
        if matches!(self, Self::Trace | Self::Simple) {
            for (_, event) in from.drain() {
                to.push(event);
            }
        }
    }

    /// Init the specified memory access.
    pub fn init_memory_access(&self, output: &mut MemoryAccessRecord) {
        if let Self::Trace = self {
            *output = MemoryAccessRecord::default();
        }
    }

    /// Set the specified memory access.
    pub fn set_memory_access(
        &self,
        position: MemoryAccessPosition,
        input: MemoryRecordEnum,
        output: &mut MemoryAccessRecord,
    ) {
        if let Self::Trace = self {
            match position {
                MemoryAccessPosition::A => output.a = Some(input),
                MemoryAccessPosition::B => output.b = Some(input),
                MemoryAccessPosition::C => output.c = Some(input),
                MemoryAccessPosition::Memory => output.memory = Some(input),
            };
        }
    }

    /// Add an unconstrained memory record.
    pub fn add_unconstrained_memory_record(&mut self, addr: u32, record: Option<&MemoryRecord>) {
        if let Self::Unconstrained(state) = self {
            state.memory_diff.entry(addr).or_insert(record.copied());
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
