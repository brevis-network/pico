use crate::{
    chips::chips::mle_open::{
        columns::{MleOpenCols, MleOpenPreprocessedCols},
        MleOpenChip,
    },
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::consts::EXTENSION_DEGREE,
};
use p3_air::{Air, WindowAccess};
use p3_field::{extension::BinomiallyExtendable, Field};
use std::borrow::Borrow;

impl<F: Field + BinomiallyExtendable<EXTENSION_DEGREE>, CB> Air<CB> for MleOpenChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &MleOpenCols<CB::Var> = (*local).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &MleOpenPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        let is_real = prepr_local.is_real;

        // Memory-bus read of the opening value at `opening_value_addr`.
        //
        // NOTE: this chip does NOT by itself enforce MLE-opening consistency. The property
        // "the opening used by the constraint check == the value the PCS actually opened" is
        // enforced by the stacking sumcheck + WHIR PCS path
        // (t_claim_addrs -> stk_s0 -> stk_claim -> stk_open), independently of this read —
        // which is therefore currently redundant.
        //
        // `col_ref` (air_id << 16 | col_id) is an UNWIRED hook: it is written to the trace but
        // consumed by no bus, so it constrains nothing today. It is reserved for a possible
        // future global MLE-opening consistency argument; wiring it would mean pushing
        // (col_ref, opening_value) onto a dedicated bus with a matching consumer.
        builder.looked_block(prepr_local.opening_value_addr, local.opening_value, is_real);
    }
}
