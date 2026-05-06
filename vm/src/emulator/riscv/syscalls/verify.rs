use super::{Syscall, SyscallCode, SyscallContext};
use crate::emulator::riscv::event_types::RvValue;

pub(crate) struct VerifySyscall;

impl Syscall for VerifySyscall {
    #[allow(clippy::mut_mut)]
    fn emulate(
        &self,
        _ctx: &mut SyscallContext,
        _: SyscallCode,
        _vk_digest_ptr: RvValue,
        _pv_digest_ptr: RvValue,
    ) -> Option<RvValue> {
        // Note: no need to do anything, pico proofs attached will be verified in convert phase
        None
    }
}
