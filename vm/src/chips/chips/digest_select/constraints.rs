use crate::{
    chips::chips::digest_select::{
        columns::{DigestSelectCols, DigestSelectPreprocessedCols},
        DigestSelectChip,
    },
    compiler::recursion::ir::Block,
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::consts::DIGEST_SELECT_DATAPAR,
};
use p3_air::{Air, AirBuilder, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use std::borrow::Borrow;

impl<F: Field, CB> Air<CB> for DigestSelectChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &DigestSelectCols<CB::Var> = (*local).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &DigestSelectPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        for k in 0..DIGEST_SELECT_DATAPAR {
            let group = &prepr_local.values[k];
            let vals = &local.values[k];
            builder.looked_single(group.bit_addr, vals.bit, group.is_real);
            for j in 0..2 {
                let blk =
                    |v: &[CB::Var; 8]| Block([v[4 * j], v[4 * j + 1], v[4 * j + 2], v[4 * j + 3]]);
                builder.looked_block(group.in1_addrs[j], blk(&vals.in1), group.is_real);
                builder.looked_block(group.in2_addrs[j], blk(&vals.in2), group.is_real);
                builder.looking_block(group.out_addrs[j], blk(&vals.out), group.mults[j]);
            }
            // Soundness fix (belt-and-suspenders): constrain `bit` boolean on real rows.
            // Selection is only well-defined for bit in {0,1} (a non-boolean bit yields an affine
            // blend). The WHIR query index bits that drive Merkle-path selection are also bound to
            // the transcript's canonical (boolean) decomposition upstream; this is a local guard.
            builder.when(group.is_real).assert_bool(vals.bit);
            for i in 0..8 {
                // out[i] = bit * in2[i] + (1 - bit) * in1[i] (SelectChip's out1 algebra;
                // holds trivially on all-zero padding rows).
                builder.assert_eq(
                    vals.out[i],
                    vals.bit * vals.in2[i] + (CB::Expr::ONE - vals.bit) * vals.in1[i],
                );
            }
        }
    }
}
