use super::{Syscall, SyscallCode, SyscallContext};
use crate::emulator::riscv::{event_types::RvValue, syscalls::abi::decode_u32_abi_word};

pub(crate) struct HaltSyscall;

impl Syscall for HaltSyscall {
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        exit_code: RvValue,
        _: RvValue,
    ) -> Option<RvValue> {
        ctx.set_next_pc(0);
        ctx.set_exit_code(decode_u32_abi_word(exit_code, "halt exit_code"));
        None
    }
}
