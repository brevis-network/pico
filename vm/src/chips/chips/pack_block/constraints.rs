use crate::{
    chips::chips::pack_block::{
        columns::{PackBlockCols, PackBlockPreprocessedCols},
        PackBlockChip,
    },
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::consts::{PACK_BLOCK_DATAPAR, PACK_LANES},
};
use p3_air::{Air, WindowAccess};
use p3_field::Field;
use std::borrow::Borrow;

impl<F: Field, CB> Air<CB> for PackBlockChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &PackBlockCols<CB::Var> = (*local).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &PackBlockPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        for k in 0..PACK_BLOCK_DATAPAR {
            let group = &prepr_local.values[k];
            let lanes = &local.values[k];
            // Read the PACK_LANES single-F inputs; forward them as one packed block.
            for i in 0..PACK_LANES {
                builder.looked_single(group.in_addrs[i], lanes[i], group.is_real);
            }
            builder.looking_packed(group.out_addr, *lanes, group.mult);
        }
    }
}
