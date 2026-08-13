use core::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS, U64_LIMBS};
use p3_matrix::Matrix;

use super::{columns::KeccakMemCols, KeccakPermuteChip, STATE_NUM_WORDS, STATE_SIZE};
use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::MemoryCols,
        gadgets::{addr_add::AddrAddGadget, syscall_addr::SyscallAddrGadget},
    },
    compiler::word::Word,
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

        // Address alignment constraints.
        let state_addr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            200, // 25 words × 8 bytes
            local.state_addr,
            local.is_real.into(),
        );

        for i in 0..STATE_NUM_WORDS {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    state_addr[0].into(),
                    state_addr[1].into(),
                    state_addr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                local.state_addrs[i],
                local.do_memory_check.into(),
            );
        }

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
                local.state_addrs[i as usize].value.map(Into::into),
                &local.state_mem[i as usize],
                local.do_memory_check,
            );
        }

        // Receive the syscall in the first row of each 24-cycle
        builder.assert_eq(local.receive_ecall, first_step * local.is_real);

        builder.looked_syscall(
            local.chunk,
            local.clk,
            CB::F::from_canonical_u32(SyscallCode::KECCAK_PERMUTE.syscall_id()),
            state_addr.map(Into::into),
            [CB::F::ZERO, CB::F::ZERO, CB::F::ZERO],
            local.receive_ecall,
        );

        // Constrain that the inputs stay the same throughout the 24 rows of each cycle
        let mut transition_builder = builder.when_transition();
        let mut transition_not_final_builder = transition_builder.when(not_final_step);
        transition_not_final_builder.assert_eq(local.chunk, next.chunk);
        transition_not_final_builder.assert_eq(local.clk, next.clk);
        transition_not_final_builder.assert_eq(local.state_addr.addr[0], next.state_addr.addr[0]);
        transition_not_final_builder.assert_eq(local.state_addr.addr[1], next.state_addr.addr[1]);
        transition_not_final_builder.assert_eq(local.state_addr.addr[2], next.state_addr.addr[2]);
        transition_not_final_builder.assert_eq(local.is_real, next.is_real);

        // The last row must be nonreal because NUM_ROUNDS is not a power of 2. This constraint
        // ensures that the table does not end abruptly.
        builder.when_last_row().assert_zero(local.is_real);

        // Verify that local.a values are equal to the memory values in the 0 and 23rd rows of each
        // cycle. Memory values are 64-bit words (4 u16 limbs), which directly match
        // the keccak state's 4 u16 limbs per u64 element.
        for i in 0..STATE_SIZE as u32 {
            // Word is 4×u16 limbs, directly matching keccak.a's u16 limbs
            let memory_limbs = local.state_mem[i as usize].value();

            let y_idx = i / 5;
            let x_idx = i % 5;

            // On a first step row, verify memory matches with local.p3_keccak_cols.a
            let a_value_limbs = local.keccak.a[y_idx as usize][x_idx as usize];
            for j in 0..U64_LIMBS {
                builder
                    .when(first_step * local.is_real)
                    .assert_eq(memory_limbs[j], a_value_limbs[j]);
            }

            // On a final step row, verify memory matches with
            // local.p3_keccak_cols.a_prime_prime_prime
            for j in 0..U64_LIMBS {
                builder.when(final_step * local.is_real).assert_eq(
                    memory_limbs[j],
                    local
                        .keccak
                        .a_prime_prime_prime(y_idx as usize, x_idx as usize, j),
                )
            }
        }

        // Range check all the values in `state_mem` to be u16 limbs.
        for i in 0..STATE_NUM_WORDS {
            builder.slice_range_check_u16(&local.state_mem[i].value().0, local.do_memory_check);
        }

        let mut sub_builder =
            SubAirBuilder::<CB, KeccakAir, CB::Var>::new(builder, 0..NUM_KECCAK_COLS);

        // Eval the plonky3 keccak air
        self.p3_keccak.eval(&mut sub_builder);
    }
}
