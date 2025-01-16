use std::borrow::Borrow;

use p3_air::Air;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::Matrix;

use super::{
    columns::{FullRound, PartialRound, Poseidon2Cols},
    Poseidon2PermuteChip,
};
use crate::{
    chips::chips::{
        poseidon2::utils::{external_linear_layer, internal_linear_layer},
        riscv_memory::read_write::columns::MemoryCols,
    },
    configs::config::Poseidon2Config,
    emulator::riscv::syscalls::SyscallCode,
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        lookup::LookupScope,
    },
    primitives::{consts::PERMUTATION_WIDTH, RC_16_30_U32},
};

impl<F: PrimeField32, Config: Poseidon2Config, CB: ChipBuilder<F>> Air<CB>
    for Poseidon2PermuteChip<F, Config>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2Cols<CB::Var, Config> = (*local).borrow();

        // Load from memory to the state
        for (i, word) in local.input_memory.iter().enumerate() {
            builder.assert_eq(local.inputs[i], word.value().reduce::<CB>());
        }

        let mut state: [CB::Expr; PERMUTATION_WIDTH] = local.inputs.map(|x| x.into());

        // Perform permutation on the state
        external_linear_layer::<CB::Expr>(&mut state);
        builder.assert_all_eq(state, local.state_linear_layer.map(|x| x.into()));

        state = local.state_linear_layer.map(|x| x.into());

        for round in 0..Self::HALF_EXTERNAL_ROUNDS {
            Self::eval_full_round(
                &state,
                &local.beginning_full_rounds[round],
                &RC_16_30_U32[round].map(CB::F::from_wrapped_u32),
                builder,
            );
            state = local.beginning_full_rounds[round].post.map(|x| x.into());
        }

        for round in 0..Self::NUM_INTERNAL_ROUNDS {
            Self::eval_partial_round(
                &state,
                &local.partial_rounds[round],
                &RC_16_30_U32[round + Self::HALF_EXTERNAL_ROUNDS].map(CB::F::from_wrapped_u32)[0],
                builder,
            );
            state = local.partial_rounds[round].post.map(|x| x.into());
        }

        for round in 0..Self::HALF_EXTERNAL_ROUNDS {
            Self::eval_full_round(
                &state,
                &local.ending_full_rounds[round],
                &RC_16_30_U32[round + Self::NUM_INTERNAL_ROUNDS + Self::HALF_EXTERNAL_ROUNDS]
                    .map(CB::F::from_wrapped_u32),
                builder,
            );
            state = local.ending_full_rounds[round].post.map(|x| x.into());
        }

        // Assert that the permuted state is being written to input_memory.
        builder.assert_all_eq(
            state.into_iter().collect::<Vec<CB::Expr>>(),
            local
                .output_memory
                .into_iter()
                .map(|f| f.value().reduce::<CB>())
                .collect::<Vec<CB::Expr>>(),
        );

        // Read input_memory.
        builder.eval_memory_access_slice(
            local.chunk,
            local.clk.into(),
            local.input_memory_ptr,
            &local.input_memory,
            local.is_real,
        );

        // Write output_memory.
        builder.eval_memory_access_slice(
            local.chunk,
            local.clk.into() + CB::Expr::ONE,
            local.output_memory_ptr,
            &local.output_memory,
            local.is_real,
        );

        builder.looked_syscall(
            local.chunk,
            local.clk,
            CB::F::from_canonical_u32(SyscallCode::POSEIDON2_PERMUTE.syscall_id()),
            local.input_memory_ptr,
            local.output_memory_ptr,
            local.is_real,
            LookupScope::Regional,
        );

        // Assert that is_real is a boolean.
        builder.assert_bool(local.is_real);
    }
}

impl<F: PrimeField32, Config: Poseidon2Config> Poseidon2PermuteChip<F, Config> {
    pub fn eval_full_round<CB>(
        state: &[CB::Expr; PERMUTATION_WIDTH],
        full_round: &FullRound<CB::Var>,
        round_constants: &[CB::F; PERMUTATION_WIDTH],
        builder: &mut CB,
    ) where
        CB: ChipBuilder<F>,
    {
        for (i, (s, r)) in state.iter().zip(round_constants.iter()).enumerate() {
            Self::eval_sbox(
                &full_round.sbox_x3[i],
                &full_round.sbox_x7[i],
                &(s.clone() + *r),
                builder,
            );
        }
        let mut committed_sbox_x7 = full_round.sbox_x7.map(|x| x.into());
        external_linear_layer::<CB::Expr>(&mut committed_sbox_x7);
        builder.assert_all_eq(committed_sbox_x7, full_round.post);
    }

    pub fn eval_partial_round<CB>(
        state: &[CB::Expr; PERMUTATION_WIDTH],
        partial_round: &PartialRound<CB::Var>,
        round_constant: &CB::F,
        builder: &mut CB,
    ) where
        CB: ChipBuilder<F>,
    {
        Self::eval_sbox(
            &partial_round.sbox_x3,
            &partial_round.sbox_x7,
            &(state[0].clone() + *round_constant),
            builder,
        );
        let mut committed_state = state.clone();
        committed_state[0] = partial_round.sbox_x7.into();
        internal_linear_layer::<F, CB::Expr>(&mut committed_state);
        builder.assert_all_eq(committed_state, partial_round.post.map(|x| x.into()));
    }

    #[inline]
    pub fn eval_sbox<CB>(sbox_x3: &CB::Var, sbox_x7: &CB::Var, x: &CB::Expr, builder: &mut CB)
    where
        CB: ChipBuilder<F>,
    {
        let committed_x3: CB::Expr = (*sbox_x3).into();
        let committed_x7: CB::Expr = (*sbox_x7).into();
        builder.assert_eq(committed_x7.clone(), committed_x3.square() * x.clone());
    }
}
