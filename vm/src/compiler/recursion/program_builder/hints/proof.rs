use crate::{
    configs::config::StarkGenericConfig,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        proof::BaseProof,
    },
};
use alloc::sync::Arc;
use p3_air::Air;

pub struct BaseProofHint<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub chips: Arc<[MetaChip<SC::Val, C>]>,
    pub proof: &'a BaseProof<SC>,
}

impl<'a, SC, C> BaseProofHint<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub fn new(chips: Arc<[MetaChip<SC::Val, C>]>, proof: &'a BaseProof<SC>) -> Self {
        Self {
            chips: chips.clone(),
            proof,
        }
    }
}
