use super::{Syscall, SyscallCode, SyscallContext};
use crate::emulator::riscv::{
    emulator::AbnormalTermination, event_types::RvValue, syscalls::abi::decode_u32_abi_word,
};

pub(crate) struct HaltSyscall;

impl Syscall for HaltSyscall {
    /// `exit_code` in `a0`; in `a1`, the reason tag the runtime passes with a non-zero code
    /// (`error::halt_reason`).
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        exit_code: RvValue,
        reason_tag: RvValue,
    ) -> Option<RvValue> {
        let exit_code = decode_u32_abi_word(exit_code, "halt exit_code");
        ctx.set_next_pc(0);
        ctx.set_exit_code(exit_code);
        if exit_code != 0 {
            ctx.fail(AbnormalTermination::halt(exit_code, reason_tag).into());
        }
        None
    }
}
