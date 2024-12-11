use crate::{
    configs::config::StarkGenericConfig,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
    },
};
use alloc::sync::Arc;
use p3_air::Air;

pub struct VerifyingKeyHint<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    pub chips: Arc<[MetaChip<SC::Val, C>]>,
    pub preprocessed_chip_ids: Vec<usize>,
    pub vk: BaseVerifyingKey<SC>,
}

impl<SC, C> VerifyingKeyHint<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    pub const fn new(
        chips: Arc<[MetaChip<SC::Val, C>]>,
        preprocessed_chip_ids: Vec<usize>,
        vk: BaseVerifyingKey<SC>,
    ) -> Self {
        Self {
            chips,
            preprocessed_chip_ids,
            vk,
        }
    }
}
