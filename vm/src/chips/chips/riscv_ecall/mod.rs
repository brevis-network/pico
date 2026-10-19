//! Dedicated ECALL chip.
//!
//! One row per ECALL instruction (vs one row per instruction on the Cpu chip). Receives a fat
//! lookup message from the Cpu chip — [chunk, clk, op_a_prev(4), op_a_val(4), op_b_val(4),
//! op_c_val(4), num_extra_clk, is_halt] — re-derives the syscall decode from the syscall code
//! word (op_a prev_value), certifies the Cpu-committed `num_extra_clk`/`is_halt` scalars, sends
//! the syscall-table lookup and owns the ecall-driven public-value constraints (exit_code at
//! halt, commit / deferred-proofs digests).

pub mod columns;
pub mod constraints;
pub mod traces;

use crate::compiler::word::Word;
use std::{iter::once, marker::PhantomData};

#[derive(Default)]
pub struct EcallChip<F>(PhantomData<F>);

/// Bit width the Ecall chip caps `num_extra_clk` at (`BitRange(NUM_EXTRA_CLK_BITS)`). The Cpu
/// row chain steps by `4 + num_extra_clk` and bounds clk as an integer with no range check of
/// its own (`riscv_cpu/chunk_clk/constraints.rs`, `CLK_BOUND_FITS`), so this cap is part of that
/// bound. Honest values are 0, 1 and 48 (`SyscallCode::num_cycles`), checked against this cap by
/// `syscalls/code.rs` tests.
pub const NUM_EXTRA_CLK_BITS: u8 = 6;

/// Canonical field order of the Cpu→Ecall bus message (20 elements):
/// `[chunk, clk, op_a_prev(4), op_a_val(4), op_b_val(4), op_c_val(4), num_extra_clk, is_halt]`.
/// Both the Cpu looking side (`CpuChip::eval_ecall`) and the Ecall looked side (`EcallChip::eval`)
/// build the message through this one fn, so the 20-element layout has a single source of truth.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ecall_message<T, E>(
    chunk: T,
    clk: T,
    op_a_prev: Word<T>,
    op_a_val: Word<T>,
    op_b_val: Word<T>,
    op_c_val: Word<T>,
    num_extra_clk: T,
    is_halt: T,
) -> Vec<E>
where
    T: Into<E>,
{
    once(chunk)
        .chain(once(clk))
        .chain(op_a_prev)
        .chain(op_a_val)
        .chain(op_b_val)
        .chain(op_c_val)
        .chain(once(num_extra_clk))
        .chain(once(is_halt))
        .map(Into::into)
        .collect()
}

#[cfg(test)]
mod interaction_pins {
    use super::EcallChip;
    use crate::primitives::consts::MAX_NUM_PVS;
    use p3_air::BaseAir;
    use p3_koala_bear::KoalaBear;
    use pico_mle_core::{
        air::symbolic::get_symbolic_builder_with_public_values, keygen::types::TraceWidth,
    };

    type F = KoalaBear;

    /// Pins the Ecall chip's interaction count (14: the nine of the syscall decode, table send
    /// and operand / digest checks, plus the four U16 lookups on HINT_LEN's `op_a_value` and the
    /// BitRange(NUM_EXTRA_CLK_BITS) lookup on `num_extra_clk`), its constraint degree and its
    /// width (60, including the `hint_len_mul` gate column and the three deferred-commit tally
    /// columns).
    #[test]
    fn ecall_interaction_count_pin() {
        let chip = EcallChip::<F>::default();
        let common_main = BaseAir::<F>::width(&chip);
        assert_eq!(common_main, 60);
        let width = TraceWidth {
            preprocessed: None,
            cached_mains: vec![],
            common_main,
        };
        let builder = get_symbolic_builder_with_public_values::<F, _>(&chip, &width, MAX_NUM_PVS);
        let constraints = builder.constraints();
        assert_eq!(constraints.max_constraint_degree(), 3);
        assert_eq!(constraints.interactions.len(), 14);
    }
}
