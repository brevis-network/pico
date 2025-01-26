use super::{
    columns::{GlobalCols, NUM_GLOBAL_COLS},
    GlobalChip,
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
use std::{any::Any, borrow::Borrow};

impl<F: Field> BaseAir<F> for GlobalChip<F> {
    fn width(&self) -> usize {
        NUM_GLOBAL_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for GlobalChip<F>
where
    CB::Var: Sized,
    CB::Expr: Any,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &GlobalCols<CB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &GlobalCols<CB::Var> = (*next).borrow();

        // Receive the arguments, which consists of 7 message columns, `is_send`, `is_receive`, and `kind`.
        // In MemoryGlobal, MemoryLocal, Syscall chips, `is_send`, `is_receive`, `kind` are sent with correct constant values.
        // For a global send interaction, `is_send = 1` and `is_receive = 0` are used.
        // For a global receive interaction, `is_send = 0` and `is_receive = 1` are used.
        // For a memory global interaction, `kind = InteractionKind::Memory` is used.
        // For a syscall global interaction, `kind = InteractionKind::Syscall` is used.
        // Therefore, `is_send`, `is_receive` are already known to be boolean, and `kind` is also known to be a `u8` value.
        // Note that `local.is_real` is constrained to be boolean in `eval_single_digest`.
        builder.looked(SymbolicLookup::new(
            vec![
                local.message[0].into(),
                local.message[1].into(),
                local.message[2].into(),
                local.message[3].into(),
                local.message[4].into(),
                local.message[5].into(),
                local.message[6].into(),
                local.is_send.into(),
                local.is_receive.into(),
                local.kind.into(),
            ],
            local.is_real.into(),
            LookupType::Global,
            LookupScope::Regional,
        ));

        // Evaluate the interaction.
        GlobalInteractionOperation::<CB::F>::eval_single_digest(
            builder,
            local.message.map(Into::into),
            local.interaction,
            local.is_receive.into(),
            local.is_send.into(),
            local.is_real,
            local.kind,
        );

        // Evaluate the accumulation.
        GlobalAccumulationOperation::<CB::F, 1>::eval_accumulation(
            builder,
            [local.interaction],
            [local.is_real],
            [next.is_real],
            local.accumulation,
            next.accumulation,
        );
    }
}
