use super::{Syscall, SyscallCode, SyscallContext};
use crate::emulator::riscv::emulator::{RiscvEmulatorMode, UnconstrainedState};

pub(crate) struct EnterUnconstrainedSyscall;

impl Syscall for EnterUnconstrainedSyscall {
    fn emulate(&self, ctx: &mut SyscallContext, _: SyscallCode, _: u32, _: u32) -> Option<u32> {
        // Panic if the previous mode is wrong.
        let state = UnconstrainedState::new(ctx.rt);
        ctx.rt.mode = RiscvEmulatorMode::Unconstrained(state);
        ctx.rt.update_mode_deps();

        Some(1)
    }
}

pub(crate) struct ExitUnconstrainedSyscall;

impl Syscall for ExitUnconstrainedSyscall {
    fn emulate(&self, ctx: &mut SyscallContext, _: SyscallCode, _: u32, _: u32) -> Option<u32> {
        // The emulator state is restored in this function if the previous mode is unconstrained.
        let state = ctx.rt.mode.exit_unconstrained();
        ctx.rt.update_mode_deps();

        // Reset the state of the emulator.
        if let Some(mut state) = state {
            ctx.rt.state.global_clk = state.global_clk;
            ctx.rt.state.clk = state.clk;
            ctx.rt.state.pc = state.pc;
            ctx.next_pc = state.pc.wrapping_add(4);
            for (addr, value) in state.memory_diff.drain() {
                match value {
                    Some(value) => {
                        ctx.rt.state.memory.insert(addr, value);
                    }
                    None => {
                        ctx.rt.state.memory.remove(addr);
                    }
                }
            }
            ctx.rt.record = core::mem::take(&mut state.record);
            ctx.rt.memory_accesses = core::mem::take(&mut state.op_record);
        }
        Some(0)
    }
}
