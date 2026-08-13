use crate::{
    chips::chips::syscall::{
        columns::SyscallCols, SyscallChip, SyscallChunkKind, NUM_SYSCALL_COLS,
    },
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder},
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

        // ensure is_real is boolean
        builder.assert_bool(local.is_real);

        // Constrain syscall_id ∈ [0, 255] (u8 range).
        builder.slice_range_check_u8(&[local.syscall_id.into()], local.is_real);
        // Constrain arg1[0] ∈ [0, 65535] (u16 range).
        builder.slice_range_check_u16(&[local.arg1[0].into()], local.is_real);

        // Degree-3 padding constraint for AIR quotient polynomial degree alignment.
        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        // On both global messages below, `message[7]` carries `chunk`.
        //
        // It used to be a zero pad ("Pico uses single clk"). The local syscall bus now carries
        // `chunk` too, which makes each side internally consistent -- the CPU agrees with
        // SyscallRiscv, and the precompile agrees with SyscallPrecompile. But that alone does not
        // make the precompile run in the chunk the CPU asked for: the two sides live in different
        // chunk proofs and meet only here, on the global bus. Carrying `chunk` in the message is
        // what forces SyscallRiscv's chunk to equal SyscallPrecompile's, and so pins the
        // precompile's memory effects to the point in time the syscall was actually issued.
        match self.chunk_kind {
            SyscallChunkKind::Riscv => {
                // arg1 and arg2 are now Addr<T> = [T; 3]
                let arg1: [_; 3] = [local.arg1[0], local.arg1[1], local.arg1[2]];
                let arg2: [_; 3] = [local.arg2[0], local.arg2[1], local.arg2[2]];
                builder.looked_syscall(
                    local.chunk,
                    local.clk,
                    local.syscall_id,
                    arg1,
                    arg2,
                    local.is_real,
                );

                // Send the "send interaction" to the global table.
                // Format: [msg[0..7], is_send, is_receive, kind] — 11 elements matching GlobalChip.
                builder.looking(SymbolicLookup::new(
                    vec![
                        local.clk.into(),
                        local.syscall_id.into()
                            + local.arg1[0].into() * CB::Expr::from_canonical_u32(1 << 8),
                        local.arg1[1].into(),
                        local.arg1[2].into(),
                        local.arg2[0].into(),
                        local.arg2[1].into(),
                        local.arg2[2].into(),
                        local.chunk.into(), // message[7]: chunk -- see below
                        CB::Expr::ONE,      // is_send = 1
                        CB::Expr::ZERO,     // is_receive = 0
                        CB::Expr::from_canonical_u8(LookupType::Syscall as u8), // kind
                    ],
                    local.is_real.into(),
                    LookupType::Global,
                    LookupScope::Regional,
                ));
            }
            SyscallChunkKind::Precompile => {
                // arg1 and arg2 are now Addr<T> = [T; 3], pass as arrays
                let arg1: [_; 3] = [local.arg1[0], local.arg1[1], local.arg1[2]];
                let arg2: [_; 3] = [local.arg2[0], local.arg2[1], local.arg2[2]];
                builder.looking_syscall(
                    local.chunk,
                    local.clk,
                    local.syscall_id,
                    arg1,
                    arg2,
                    local.is_real,
                );

                // Send the "receive interaction" to the global table.
                // Format: [msg[0..7], is_send, is_receive, kind] — 11 elements matching GlobalChip.
                builder.looking(SymbolicLookup::new(
                    vec![
                        local.clk.into(),
                        local.syscall_id.into()
                            + local.arg1[0].into() * CB::Expr::from_canonical_u32(1 << 8),
                        local.arg1[1].into(),
                        local.arg1[2].into(),
                        local.arg2[0].into(),
                        local.arg2[1].into(),
                        local.arg2[2].into(),
                        local.chunk.into(), // message[7]: chunk -- see below
                        CB::Expr::ZERO,     // is_send = 0
                        CB::Expr::ONE,      // is_receive = 1
                        CB::Expr::from_canonical_u8(LookupType::Syscall as u8), // kind
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
