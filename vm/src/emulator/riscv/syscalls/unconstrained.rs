use hashbrown::HashMap;

use super::{Syscall, SyscallCode, SyscallContext};
use crate::emulator::riscv::riscv_emulator::{EmulatorMode, UnconstrainedState};

pub(crate) struct EnterUnconstrainedSyscall;

impl Syscall for EnterUnconstrainedSyscall {
    fn emulate(&self, ctx: &mut SyscallContext, _: SyscallCode, _: u32, _: u32) -> Option<u32> {
        if let Some(_) = ctx.rt.unconstrained {
            panic!("Unconstrained block is already active.");
        } else {
            let program = ctx.rt.record.program.clone();
            ctx.rt.unconstrained = Some(UnconstrainedState {
                global_clk: ctx.rt.state.global_clk,
                clk: ctx.rt.state.clk,
                pc: ctx.rt.state.pc,
                memory_diff: HashMap::default(),
                record: core::mem::take(&mut ctx.rt.record),
                op_record: core::mem::take(&mut ctx.rt.memory_accesses),
                emulator_mode: ctx.rt.emulator_mode,
            });
            ctx.rt.emulator_mode = EmulatorMode::Simple;
            ctx.rt.record.unconstrained = true;
            ctx.rt.record.program = program;
            Some(1)
        }
    }
}

pub(crate) struct ExitUnconstrainedSyscall;

impl Syscall for ExitUnconstrainedSyscall {
    fn emulate(&self, ctx: &mut SyscallContext, _: SyscallCode, _: u32, _: u32) -> Option<u32> {
        let state = core::mem::take(&mut ctx.rt.unconstrained);

        // Reset the state of the runtime.
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
                        ctx.rt.state.memory.remove(&addr);
                    }
                }
            }
            ctx.rt.record = core::mem::take(&mut state.record);
            ctx.rt.memory_accesses = core::mem::take(&mut state.op_record);
            ctx.rt.emulator_mode = state.emulator_mode;
            assert!(ctx.rt.record.unconstrained == false);
        }
        Some(0)
    }
}
