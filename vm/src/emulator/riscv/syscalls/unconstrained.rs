use tracing::debug;

use super::{Syscall, SyscallCode, SyscallContext};
use crate::emulator::riscv::{
    emulator::{RiscvEmulatorMode, UnconstrainedState},
    event_types::RvValue,
    state::RuntimeRegisterRecord,
};

pub(crate) struct EnterUnconstrainedSyscall;

impl Syscall for EnterUnconstrainedSyscall {
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        _: RvValue,
        _: RvValue,
    ) -> Option<RvValue> {
        // Panic if the previous mode is wrong.
        let state = UnconstrainedState::new(ctx.rt);
        debug!(
            "[Unconstrained] Entering at PC={} clk={} global_clk={}",
            ctx.rt.state.pc, ctx.rt.state.clk, ctx.rt.state.global_clk
        );
        ctx.rt.mode = RiscvEmulatorMode::Unconstrained(state);
        ctx.rt.update_mode_deps();

        Some(1)
    }
}

pub(crate) struct ExitUnconstrainedSyscall;

impl Syscall for ExitUnconstrainedSyscall {
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        _: RvValue,
        _: RvValue,
    ) -> Option<RvValue> {
        // The emulator state is restored in this function if the previous mode is unconstrained.
        let state = ctx.rt.mode.exit_unconstrained();
        ctx.rt.update_mode_deps();

        // Reset the state of the emulator.
        if let Some(mut state) = state {
            ctx.rt.state.global_clk = state.global_clk;
            ctx.rt.state.clk = state.clk;
            ctx.rt.state.pc = state.pc;
            ctx.next_pc = state.pc.wrapping_add(4);
            for (reg_idx, value) in state.register_diff.drain() {
                let record = value.unwrap_or_default();
                ctx.rt.state.registers[usize::from(reg_idx)] = RuntimeRegisterRecord {
                    value: record.value,
                    chunk: record.chunk,
                    timestamp: record.timestamp,
                };
            }

            for (addr, value) in state.memory_diff.drain() {
                let record = value.unwrap_or_default();
                ctx.rt.state.memory.insert_u64(addr, record);
            }
            ctx.rt.record = core::mem::take(&mut state.record);
            ctx.rt.memory_accesses = core::mem::take(&mut state.op_record);
        }
        Some(0)
    }
}
