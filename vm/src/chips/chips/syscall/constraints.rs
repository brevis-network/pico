use crate::{
    chips::chips::syscall::{
        columns::SyscallCols, SyscallChip, SyscallChunkKind, NUM_SYSCALL_COLS,
    },
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder},
        lookup::LookupScope,
    },
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
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

        // dummy constraints to normalize degree
        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        match self.chunk_kind {
            SyscallChunkKind::Riscv => {
                builder.looked_syscall(
                    local.chunk,
                    local.clk,
                    local.nonce,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    LookupScope::Regional,
                );

                // Send the call to the global bus to/from the precompile chips.
                builder.looking_syscall(
                    local.chunk,
                    local.clk,
                    local.nonce,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    LookupScope::Global,
                );
            }
            SyscallChunkKind::Precompile => {
                builder.looking_syscall(
                    local.chunk,
                    local.clk,
                    local.nonce,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    LookupScope::Regional,
                );

                // Send the call to the global bus to/from the precompile chips.
                builder.looked_syscall(
                    local.chunk,
                    local.clk,
                    local.nonce,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                    LookupScope::Global,
                );
            }
        }
    }
}

impl<F: Field> BaseAir<F> for SyscallChip<F> {
    fn width(&self) -> usize {
        NUM_SYSCALL_COLS
    }
}
