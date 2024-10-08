use super::{Syscall, SyscallContext};

pub(crate) struct HaltSyscall;

impl Syscall for HaltSyscall {
    fn emulate(&self, ctx: &mut SyscallContext, exit_code: u32, _: u32) -> Option<u32> {
        ctx.set_next_pc(0);
        ctx.set_exit_code(exit_code);
        None
    }
}
