use super::{
    columns::{MemoryLocalCols, NUM_MEMORY_LOCAL_INIT_COLS},
    MemoryLocalChip,
};
use crate::{
    chips::gadgets::{
        global_accumulation::GlobalAccumulationOperation,
        global_interaction::GlobalInteractionOperation,
    },
    machine::{
        builder::ChipBuilder,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
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
        let next = main.row_slice(1);
        let next: &MemoryLocalCols<CB::Var> = (*next).borrow();

        let mut global_interaction_cols = Vec::with_capacity(8);
        let mut local_is_reals = Vec::with_capacity(8);
        let mut next_is_reals = Vec::with_capacity(8);

        for local in local.memory_local_entries.iter() {
            builder.assert_eq(
                local.is_real * local.is_real * local.is_real,
                local.is_real * local.is_real * local.is_real,
            );

            let mut values = vec![
                local.initial_chunk.into(),
                local.initial_clk.into(),
                local.addr.into(),
            ];
            values.extend(local.initial_value.map(Into::into));
            // Looked initial values and looking final values for Regional scope.
            builder.looked(SymbolicLookup::new(
                values,
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Regional,
            ));

            GlobalInteractionOperation::<CB::F>::eval_single_digest_memory(
                builder,
                local.initial_chunk.into(),
                local.initial_clk.into(),
                local.addr.into(),
                local.initial_value.map(Into::into).0,
                local.initial_global_interaction_cols,
                true,
                local.is_real,
            );

            global_interaction_cols.push(local.initial_global_interaction_cols);
            local_is_reals.push(local.is_real);

            let mut values = vec![
                local.final_chunk.into(),
                local.final_clk.into(),
                local.addr.into(),
            ];
            values.extend(local.final_value.map(Into::into));
            builder.looking(SymbolicLookup::new(
                values,
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Regional,
            ));

            GlobalInteractionOperation::<CB::F>::eval_single_digest_memory(
                builder,
                local.final_chunk.into(),
                local.final_clk.into(),
                local.addr.into(),
                local.final_value.map(Into::into).0,
                local.final_global_interaction_cols,
                false,
                local.is_real,
            );

            global_interaction_cols.push(local.final_global_interaction_cols);
            local_is_reals.push(local.is_real);
        }

        for next in next.memory_local_entries.iter() {
            next_is_reals.push(next.is_real);
            next_is_reals.push(next.is_real);
        }

        GlobalAccumulationOperation::<CB::F, 8>::eval_accumulation(
            builder,
            global_interaction_cols
                .try_into()
                .unwrap_or_else(|_| panic!("There should be 8 interactions")),
            local_is_reals
                .try_into()
                .unwrap_or_else(|_| panic!("There should be 8 interactions")),
            next_is_reals
                .try_into()
                .unwrap_or_else(|_| panic!("There should be 8 interactions")),
            local.global_accumulation_cols,
            next.global_accumulation_cols,
        );
    }
}
