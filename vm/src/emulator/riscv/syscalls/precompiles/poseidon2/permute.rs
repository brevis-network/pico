use super::event::Poseidon2PermuteEvent;
use crate::{
    emulator::riscv::syscalls::{
        precompiles::PrecompileEvent, syscall_context::SyscallContext, Syscall, SyscallCode,
    },
    primitives::{consts::PERMUTATION_WIDTH, Poseidon2Init},
};
use p3_field::PrimeField32;
use p3_symmetric::Permutation;
use std::marker::PhantomData;

#[allow(clippy::type_complexity)]
pub(crate) struct Poseidon2PermuteSyscall<F>(pub(crate) PhantomData<fn(F) -> F>);

impl<F> Syscall for Poseidon2PermuteSyscall<F>
where
    F: PrimeField32 + Poseidon2Init,
    F::Poseidon2: Permutation<[F; 16]>,
{
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let clk_init = ctx.clk;
        let input_memory_ptr = arg1;
        let output_memory_ptr = arg2;

        let mut state_read_records = Vec::new();
        let mut state_write_records = Vec::new();

        let (state_records, state_values) = ctx.mr_slice(input_memory_ptr, PERMUTATION_WIDTH);
        state_read_records.extend_from_slice(&state_records);

        let state: [F; PERMUTATION_WIDTH] = state_values
            .clone()
            .into_iter()
            .map(F::from_canonical_u32)
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();

        let state = F::init().permute(state);

        // Increment the clk by 1 before writing because we read from memory at start_clk.
        ctx.clk += 1;

        let write_records = ctx.mw_slice(output_memory_ptr, &state.map(|f| f.as_canonical_u32()));
        state_write_records.extend_from_slice(&write_records);

        let chunk = ctx.current_chunk();
        let event = Poseidon2PermuteEvent {
            chunk,
            clk: clk_init,
            state_values,
            input_memory_ptr,
            output_memory_ptr,
            state_read_records,
            state_write_records,
            local_mem_access: ctx.postprocess(),
        };

        let syscall_event = ctx
            .rt
            .syscall_event(clk_init, syscall_code.syscall_id(), arg1, arg2);
        ctx.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Poseidon2Permute(event),
        );

        None
    }
}
