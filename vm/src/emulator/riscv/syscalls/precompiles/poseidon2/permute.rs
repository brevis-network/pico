use p3_field::PrimeField32;
use std::marker::PhantomData;

use super::event::Poseidon2PermuteEvent;
use crate::{
    chips::gadgets::poseidon2::utils::{external_linear_layer, internal_linear_layer},
    configs::config::Poseidon2Config,
    emulator::riscv::syscalls::{
        precompiles::PrecompileEvent, syscall_context::SyscallContext, Syscall, SyscallCode,
    },
    primitives::{consts::PERMUTATION_WIDTH, RC_16_30_U32},
};
use typenum::Unsigned;

#[allow(clippy::type_complexity)]
pub(crate) struct Poseidon2PermuteSyscall<F, Config>(
    pub(crate) PhantomData<fn(F, Config) -> (F, Config)>,
);

impl<F: PrimeField32, Config: Poseidon2Config> Poseidon2PermuteSyscall<F, Config> {
    const NUM_INTERNAL_ROUNDS: usize = Config::InternalRounds::USIZE;
    const HALF_EXTERNAL_ROUNDS: usize = Config::HalfExternalRounds::USIZE;

    pub fn full_round(
        state: &mut [F; PERMUTATION_WIDTH],
        round_constants: &[F; PERMUTATION_WIDTH],
    ) {
        for (s, r) in state.iter_mut().zip(round_constants.iter()) {
            *s += *r;
            Self::sbox(s);
        }
        external_linear_layer(state);
    }

    pub fn partial_round(state: &mut [F; PERMUTATION_WIDTH], round_constant: &F) {
        state[0] += *round_constant;
        Self::sbox(&mut state[0]);
        internal_linear_layer::<F, _>(state);
    }

    #[inline]
    pub fn sbox(x: &mut F) {
        *x = x.exp_const_u64::<7>();
    }
}

impl<F: PrimeField32, Config: Poseidon2Config> Syscall for Poseidon2PermuteSyscall<F, Config> {
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

        let mut state: [F; PERMUTATION_WIDTH] = state_values
            .clone()
            .into_iter()
            .map(F::from_wrapped_u32)
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();

        // Perform permutation on the state
        external_linear_layer(&mut state);

        for round in 0..Self::HALF_EXTERNAL_ROUNDS {
            Self::full_round(&mut state, &RC_16_30_U32[round].map(F::from_wrapped_u32));
        }

        for round in 0..Self::NUM_INTERNAL_ROUNDS {
            Self::partial_round(
                &mut state,
                &RC_16_30_U32[round + Self::HALF_EXTERNAL_ROUNDS].map(F::from_wrapped_u32)[0],
            );
        }

        for round in 0..Self::HALF_EXTERNAL_ROUNDS {
            Self::full_round(
                &mut state,
                &RC_16_30_U32[round + Self::NUM_INTERNAL_ROUNDS + Self::HALF_EXTERNAL_ROUNDS]
                    .map(F::from_wrapped_u32),
            );
        }

        // Increment the clk by 1 before writing because we read from memory at start_clk.
        ctx.clk += 1;

        let write_records = ctx.mw_slice(
            output_memory_ptr,
            state
                .into_iter()
                .map(|f| f.as_canonical_u32())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        state_write_records.extend_from_slice(&write_records);

        // Push the SHA extend event.
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
