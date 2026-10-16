use crate::{
    chips::chips::pack_block::{
        columns::{PackBlockCols, PackBlockPreprocessedCols},
        PackBlockChip,
    },
    compiler::recursion::ir::Block,
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::consts::PACK_BLOCK_DATAPAR,
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
            // Read the 4 single-F inputs; forward them as one packed block.
            for i in 0..4 {
                builder.looked_single(group.in_addrs[i], lanes[i], group.is_real);
            }
            builder.looking_block(
                group.out_addr,
                Block([lanes[0], lanes[1], lanes[2], lanes[3]]),
                group.mult,
            );
        }
    }
}
