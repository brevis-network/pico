use super::{
    columns::{MemoryLocalCols, NUM_MEMORY_LOCAL_INIT_COLS},
    MemoryLocalChip,
};
use crate::machine::{
    builder::{ChipBuilder, ChipRangeBuilder},
    lookup::{LookupScope, LookupType, SymbolicLookup},
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field> BaseAir<F> for MemoryLocalChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_LOCAL_INIT_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for MemoryLocalChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryLocalCols<CB::Var> = (*local).borrow();

        for local in local.memory_local_entries.iter() {
            builder.assert_bool(local.is_real);
            builder.assert_eq(
                local.is_real * local.is_real * local.is_real,
                local.is_real * local.is_real * local.is_real,
            );

            // Regional lookup: 9 elements [chunk, clk, addr[0], addr[1], addr[2], v0, v1, v2, v3]
            let initial_regional = vec![
                local.initial_chunk.into(),
                local.initial_clk.into(),
                local.addr[0].into(),
                local.addr[1].into(),
                local.addr[2].into(),
                local.initial_value[0].into(),
                local.initial_value[1].into(),
                local.initial_value[2].into(),
                local.initial_value[3].into(),
            ];
            // Looked initial values for Regional scope.
            builder.looked(SymbolicLookup::new(
                initial_regional,
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Regional,
            ));

            // v2 packing constraints: value[2] = value_lower + value_upper * 256
            builder.when(local.is_real).assert_eq(
                local.initial_value[2],
                CB::Expr::from_canonical_u32(256) * local.initial_value_upper
                    + local.initial_value_lower,
            );
            builder.when(local.is_real).assert_eq(
                local.final_value[2],
                CB::Expr::from_canonical_u32(256) * local.final_value_upper
                    + local.final_value_lower,
            );

            // Range checks for soundness.
            // v2 packing columns must be u8.
            builder.slice_range_check_u8(
                &[local.initial_value_lower, local.initial_value_upper],
                local.is_real,
            );
            builder.slice_range_check_u8(
                &[local.final_value_lower, local.final_value_upper],
                local.is_real,
            );
            // Value limbs must be u16.
            builder.slice_range_check_u16(&local.initial_value.0, local.is_real);
            builder.slice_range_check_u16(&local.final_value.0, local.is_real);
            // Addr limbs must be u16.
            // TODO: is the range check for local.addr necessary?
            builder.slice_range_check_u16(&local.addr, local.is_real);

            // Global lookup: 11 elements [chunk, clk, addr[0..2], v0+v2_lower<<16, v1+v2_upper<<16, v3, is_send, is_receive, kind]
            // Send the "receive interaction" to the global table (initial values).
            builder.looking(SymbolicLookup::new(
                vec![
                    local.initial_chunk.into(),
                    local.initial_clk.into(),
                    local.addr[0].into(),
                    local.addr[1].into(),
                    local.addr[2].into(),
                    local.initial_value[0].into()
                        + CB::Expr::from_canonical_u32(1 << 16) * local.initial_value_lower,
                    local.initial_value[1].into()
                        + CB::Expr::from_canonical_u32(1 << 16) * local.initial_value_upper,
                    local.initial_value[3].into(),
                    CB::Expr::ZERO,
                    CB::Expr::ONE,
                    CB::Expr::from_canonical_u8(LookupType::Memory as u8),
                ],
                local.is_real.into(),
                LookupType::Global,
                LookupScope::Regional,
            ));

            // Send the "send interaction" to the global table (final values).
            builder.looking(SymbolicLookup::new(
                vec![
                    local.final_chunk.into(),
                    local.final_clk.into(),
                    local.addr[0].into(),
                    local.addr[1].into(),
                    local.addr[2].into(),
                    local.final_value[0].into()
                        + CB::Expr::from_canonical_u32(1 << 16) * local.final_value_lower,
                    local.final_value[1].into()
                        + CB::Expr::from_canonical_u32(1 << 16) * local.final_value_upper,
                    local.final_value[3].into(),
                    CB::Expr::ONE,
                    CB::Expr::ZERO,
                    CB::Expr::from_canonical_u8(LookupType::Memory as u8),
                ],
                local.is_real.into(),
                LookupType::Global,
                LookupScope::Regional,
            ));

            // Looking final values for Regional scope.
            let final_regional = vec![
                local.final_chunk.into(),
                local.final_clk.into(),
                local.addr[0].into(),
                local.addr[1].into(),
                local.addr[2].into(),
                local.final_value[0].into(),
                local.final_value[1].into(),
                local.final_value[2].into(),
                local.final_value[3].into(),
            ];
            builder.looking(SymbolicLookup::new(
                final_regional,
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Regional,
            ));
        }
    }
}
