use crate::{
    chips::chips::unpack_block::{
        columns::{UnpackBlockCols, UnpackBlockPreprocessedCols},
        UnpackBlockChip,
    },
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::consts::EXTENSION_DEGREE,
};
use p3_air::{Air, WindowAccess};
use p3_field::Field;
use std::borrow::Borrow;

impl<F: Field, CB> Air<CB> for UnpackBlockChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &UnpackBlockCols<CB::Var> = (*local).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &UnpackBlockPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        // Memory read of the input Block.
        builder.looked_block(prepr_local.in_addr, local.val, prepr_local.is_real);
        // Memory writes of the single lanes (values forwarded as-is).
        for i in 0..EXTENSION_DEGREE {
            builder.looking_single(
                prepr_local.out[i].addr,
                local.val.0[i],
                prepr_local.out[i].mult,
            );
        }
    }
}
