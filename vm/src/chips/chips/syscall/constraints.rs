use crate::{
    chips::{
        chips::syscall::{columns::SyscallCols, SyscallChip, SyscallChunkKind, NUM_SYSCALL_COLS},
        gadgets::{
            global_accumulation::GlobalAccumulationOperation,
            global_interaction::GlobalInteractionOperation,
        },
    },
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use p3_air::{Air, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field, CB> Air<CB> for SyscallChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SyscallCols<CB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &SyscallCols<CB::Var> = (*next).borrow();

        // dummy constraints to normalize degree
        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        match self.chunk_kind {
            SyscallChunkKind::Riscv => {
                builder.looked_syscall(
                    local.clk_16 + local.clk_8 * CB::Expr::from_canonical_u32(1 << 16),
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                );

                // Send the call to the global bus to/from the precompile chips.
                GlobalInteractionOperation::<CB::F>::eval_single_digest_syscall(
                    builder,
                    local.chunk.into(),
                    local.clk_16.into(),
                    local.clk_8.into(),
                    local.syscall_id.into(),
                    local.arg1.into(),
                    local.arg2.into(),
                    local.global_interaction_cols,
                    false,
                    local.is_real,
                );
            }
            SyscallChunkKind::Precompile => {
                builder.looking_syscall(
                    local.clk_16 + local.clk_8 * CB::Expr::from_canonical_u32(1 << 16),
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                );

                GlobalInteractionOperation::<CB::F>::eval_single_digest_syscall(
                    builder,
                    local.chunk.into(),
                    local.clk_16.into(),
                    local.clk_8.into(),
                    local.syscall_id.into(),
                    local.arg1.into(),
                    local.arg2.into(),
                    local.global_interaction_cols,
                    true,
                    local.is_real,
                );
            }
        }

        GlobalAccumulationOperation::<CB::F, 1>::eval_accumulation(
            builder,
            [local.global_interaction_cols],
            [local.is_real],
            [next.is_real],
            local.global_accumulation_cols,
            next.global_accumulation_cols,
        );
    }
}

impl<F: Field> BaseAir<F> for SyscallChip<F> {
    fn width(&self) -> usize {
        NUM_SYSCALL_COLS
    }
}
