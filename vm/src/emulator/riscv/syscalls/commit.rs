use super::{Syscall, SyscallCode, SyscallContext};
use crate::{
    emulator::riscv::{
        event_types::RvValue,
        syscalls::abi::{decode_u32_abi_index, decode_u32_abi_word},
    },
    primitives::consts::PV_DIGEST_NUM_WORDS,
};

pub(crate) struct CommitSyscall;

impl Syscall for CommitSyscall {
    #[allow(clippy::mut_mut)]
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let word_idx = decode_u32_abi_index(arg1, PV_DIGEST_NUM_WORDS, "commit word_idx");
        // Digest words are 32-bit ABI values transported via RV64 registers.
        // Accept both zero-extended and sign-extended 32-bit encodings.
        let public_values_digest_word = decode_u32_abi_word(arg2, "commit digest word");
        let rt = &mut ctx.rt;

        rt.record.public_values.committed_value_digest[word_idx] = public_values_digest_word;

        None
    }
}
