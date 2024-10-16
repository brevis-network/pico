use crate::{
    configs::config::StarkGenericConfig,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
    },
};
use p3_air::Air;

pub struct VerifyingKeyHint<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub chips: &'a [MetaChip<SC::Val, C>],
    pub preprocessed_chip_ids: Vec<usize>,
    pub vk: &'a BaseVerifyingKey<SC>,
}

impl<'a, SC, C> VerifyingKeyHint<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub const fn new(
        chips: &'a [MetaChip<SC::Val, C>],
        preprocessed_chip_ids: Vec<usize>,
        vk: &'a BaseVerifyingKey<SC>,
    ) -> Self {
        Self {
            chips,
            preprocessed_chip_ids,
            vk,
        }
    }
}
