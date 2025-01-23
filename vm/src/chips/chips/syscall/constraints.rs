use crate::{
    chips::chips::syscall::{
        columns::SyscallCols, SyscallChip, SyscallChunkKind, NUM_SYSCALL_COLS,
    },
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
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

        // dummy constraints to normalize degree
        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        match self.chunk_kind {
            SyscallChunkKind::Riscv => {
                builder.looked_syscall(
                    local.clk,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                );

                // Send the "send interaction" to the global table.
                builder.looking(SymbolicLookup::new(
                    vec![
                        local.chunk.into(),
                        local.clk.into(),
                        local.syscall_id.into(),
                        local.arg1.into(),
                        local.arg2.into(),
                        CB::Expr::ZERO,
                        CB::Expr::ZERO,
                        CB::Expr::ONE,
                        CB::Expr::ZERO,
                        CB::Expr::from_canonical_u8(LookupType::Syscall as u8),
                    ],
                    local.is_real.into(),
                    LookupType::Global,
                    LookupScope::Regional,
                ));
            }
            SyscallChunkKind::Precompile => {
                builder.looking_syscall(
                    local.clk,
                    local.syscall_id,
                    local.arg1,
                    local.arg2,
                    local.is_real,
                );

                // Send the "receive interaction" to the global table.
                builder.looking(SymbolicLookup::new(
                    vec![
                        local.chunk.into(),
                        local.clk.into(),
                        local.syscall_id.into(),
                        local.arg1.into(),
                        local.arg2.into(),
                        CB::Expr::ZERO,
                        CB::Expr::ZERO,
                        CB::Expr::ZERO,
                        CB::Expr::ONE,
                        CB::Expr::from_canonical_u8(LookupType::Syscall as u8),
                    ],
                    local.is_real.into(),
                    LookupType::Global,
                    LookupScope::Regional,
                ));
            }
        }
    }
}

impl<F: Field> BaseAir<F> for SyscallChip<F> {
    fn width(&self) -> usize {
        NUM_SYSCALL_COLS
    }
}
