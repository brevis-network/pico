use super::{Syscall, SyscallCode, SyscallContext};
use crate::{
    emulator::riscv::{
        event_types::RvValue,
        syscalls::abi::{decode_u32_abi_index, decode_u32_abi_word},
    },
    primitives::consts::DIGEST_SIZE,
};

pub(crate) struct CommitDeferredSyscall;

impl Syscall for CommitDeferredSyscall {
    #[allow(clippy::mut_mut)]
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let word_idx = decode_u32_abi_index(arg1, DIGEST_SIZE, "deferred word_idx");
        // Digest words are 32-bit ABI values transported via RV64 registers.
        // Accept both zero-extended and sign-extended 32-bit encodings.
        let word = decode_u32_abi_word(arg2, "deferred digest word");
        let rt = &mut ctx.rt;
        rt.record.public_values.deferred_proofs_digest[word_idx] = word;
        None
    }
}
