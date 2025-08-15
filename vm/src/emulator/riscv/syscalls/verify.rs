use super::{Syscall, SyscallCode, SyscallContext};

pub(crate) struct VerifySyscall;

impl Syscall for VerifySyscall {
    #[allow(clippy::mut_mut)]
    fn emulate(
        &self,
        _ctx: &mut SyscallContext,
        _: SyscallCode,
        _vk_digest_ptr: u32,
        _pv_digest_ptr: u32,
    ) -> Option<u32> {
        // Note: no need to do anything, pico proofs attached will be verified in convert phase
        None
    }
}
