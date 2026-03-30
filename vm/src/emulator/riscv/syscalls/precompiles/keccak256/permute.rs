use crate::emulator::riscv::{
    event_types::RvValue,
    syscalls::{
        precompiles::{KeccakPermuteEvent, PrecompileEvent},
        syscall_context::SyscallContext,
        Syscall, SyscallCode,
    },
};
use tiny_keccak::keccakf;

pub(crate) const STATE_SIZE: usize = 25;

// The permutation state is 25 u64's.  Our word size is 64 bits, so it is 25 words.
pub const STATE_NUM_WORDS: usize = STATE_SIZE;

pub(crate) struct Keccak256PermuteSyscall;

impl Syscall for Keccak256PermuteSyscall {
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let start_clk = ctx.clk;
        let state_ptr = arg1;
        if arg2 != 0 {
            panic!("Expected arg2 to be 0, got {arg2}");
        }

        let (state_read_records, state_values) = ctx.mr_dword_slice(state_ptr, STATE_SIZE);

        let saved_state = state_values.clone();

        let mut state: [u64; STATE_SIZE] = state_values.try_into().unwrap();
        keccakf(&mut state);

        // Increment the clk by 1 before writing because we read from memory at start_clk.
        ctx.clk += 1;
        let state_write_records = ctx.mw_dword_slice(state_ptr, &state);

        // Push the Keccak permute event.
        let chunk = ctx.current_chunk();
        let event = PrecompileEvent::KeccakPermute(KeccakPermuteEvent {
            chunk,
            clk: start_clk,
            pre_state: saved_state.as_slice().try_into().unwrap(),
            post_state: state,
            state_read_records,
            state_write_records,
            state_addr: arg1,
            local_mem_access: ctx.postprocess(),
        });
        let syscall_event = ctx
            .rt
            .syscall_event(start_clk, syscall_code.syscall_id(), arg1, arg2);
        ctx.record_mut()
            .add_precompile_event(syscall_code, syscall_event, event);
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
