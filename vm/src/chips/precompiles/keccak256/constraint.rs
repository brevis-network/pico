use core::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS, U64_LIMBS};
use p3_matrix::Matrix;

use super::{columns::KeccakMemCols, KeccakPermuteChip, STATE_NUM_WORDS, STATE_SIZE};
use crate::{
    chips::chips::riscv_memory::read_write::columns::MemoryCols,
    emulator::riscv::syscalls::SyscallCode,
    machine::builder::{
        ChipBuilder, ChipLookupBuilder, ChipRangeBuilder, ChipWordBuilder, RiscVMemoryBuilder,
        SubAirBuilder,
    },
};

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for KeccakPermuteChip<F> {
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();

        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &KeccakMemCols<CB::Var> = (*local).borrow();
        let next: &KeccakMemCols<CB::Var> = (*next).borrow();

        let first_step = local.keccak.step_flags[0];
        let final_step = local.keccak.step_flags[NUM_ROUNDS - 1];
        let not_final_step = CB::Expr::ONE - final_step;

        // Constrain memory in the first and last cycles.
        builder.assert_eq(
            (first_step + final_step) * local.is_real,
            local.do_memory_check,
        );

        // Constrain memory
        for i in 0..STATE_NUM_WORDS as u32 {
            // At the first cycle, verify that the memory has not changed since it's a memory read.
            builder
                .when(local.keccak.step_flags[0] * local.is_real)
                .assert_word_eq(
                    *local.state_mem[i as usize].value(),
                    *local.state_mem[i as usize].prev_value(),
                );

            builder.eval_memory_access(
                local.chunk,
                local.clk + final_step, // The clk increments by 1 after a final step
                local.state_addr + CB::Expr::from_canonical_u32(i * 4),
                &local.state_mem[i as usize],
                local.do_memory_check,
            );
        }

        // Receive the syscall in the first row of each 24-cycle
        builder.assert_eq(local.receive_ecall, first_step * local.is_real);

        builder.looked_syscall(
            local.clk,
            CB::F::from_canonical_u32(SyscallCode::KECCAK_PERMUTE.syscall_id()),
            local.state_addr,
            CB::Expr::ZERO,
            local.receive_ecall,
        );

        // Constrain that the inputs stay the same throughout the 24 rows of each cycle
        let mut transition_builder = builder.when_transition();
        let mut transition_not_final_builder = transition_builder.when(not_final_step);
        transition_not_final_builder.assert_eq(local.chunk, next.chunk);
        transition_not_final_builder.assert_eq(local.clk, next.clk);
        transition_not_final_builder.assert_eq(local.state_addr, next.state_addr);
        transition_not_final_builder.assert_eq(local.is_real, next.is_real);

        // The last row must be nonreal because NUM_ROUNDS is not a power of 2. This constraint
        // ensures that the table does not end abruptly.
        builder.when_last_row().assert_zero(local.is_real);

        // Verify that local.a values are equal to the memory values in the 0 and 23rd rows of each
        // cycle Memory values are 32 bit values (encoded as 4 8-bit columns).
        // local.a values are 64 bit values (encoded as 4 16-bit columns).
        let expr_2_pow_8 = CB::Expr::from_canonical_u32(2u32.pow(8));
        for i in 0..STATE_SIZE as u32 {
            // Interpret u32 memory words as u16 limbs
            let least_sig_word = local.state_mem[(i * 2) as usize].value();
            let most_sig_word = local.state_mem[(i * 2 + 1) as usize].value();
            let memory_limbs = [
                least_sig_word[0] + least_sig_word[1] * expr_2_pow_8.clone(),
                least_sig_word[2] + least_sig_word[3] * expr_2_pow_8.clone(),
                most_sig_word[0] + most_sig_word[1] * expr_2_pow_8.clone(),
                most_sig_word[2] + most_sig_word[3] * expr_2_pow_8.clone(),
            ];

            let y_idx = i / 5;
            let x_idx = i % 5;

            // On a first step row, verify memory matches with local.p3_keccak_cols.a
            let a_value_limbs = local.keccak.a[y_idx as usize][x_idx as usize];
            for i in 0..U64_LIMBS {
                builder
                    .when(first_step * local.is_real)
                    .assert_eq(memory_limbs[i].clone(), a_value_limbs[i]);
            }

            // On a final step row, verify memory matches with
            // local.p3_keccak_cols.a_prime_prime_prime
            for i in 0..U64_LIMBS {
                builder.when(final_step * local.is_real).assert_eq(
                    memory_limbs[i].clone(),
                    local
                        .keccak
                        .a_prime_prime_prime(y_idx as usize, x_idx as usize, i),
                )
            }
        }

        // Range check all the values in `state_mem` to be bytes.
        for i in 0..STATE_NUM_WORDS {
            builder.slice_range_check_u8(&local.state_mem[i].value().0, local.do_memory_check);
        }

        let mut sub_builder =
            SubAirBuilder::<CB, KeccakAir, CB::Var>::new(builder, 0..NUM_KECCAK_COLS);

        // Eval the plonky3 keccak air
        self.p3_keccak.eval(&mut sub_builder);
    }
}
