mod combine;
mod combine_vk;
mod compress;
mod compress_vk;
mod convert;
mod embed;
mod embed_vk;
mod riscv;

use crate::{
    configs::config::{StarkGenericConfig, Val},
    machine::{chip::ChipBehavior, keys::HashableKey, machine::BaseMachine, proof::MetaProof},
};

// re-exports
pub use combine::CombineProver;
pub use combine_vk::CombineVkProver;
pub use compress::CompressProver;
pub use compress_vk::CompressVkProver;
pub use convert::ConvertProver;
pub use embed::EmbedProver;
pub use embed_vk::EmbedVkProver;
pub use riscv::RiscvProver;

/// Trait to assist with inline proving
pub trait ProverChain<PrevSC, PrevC, SC>
where
    PrevSC: StarkGenericConfig,
{
    type Opts;
    type ShapeConfig;
    fn new_with_prev(
        prev_prover: &impl MachineProver<PrevSC, Chips = PrevC>,
        opts: Self::Opts,
        shape_config: Option<Self::ShapeConfig>,
    ) -> Self;
}

/// Trait to assist with inline proving
pub trait InitialProverSetup {
    type Input<'a>;
    type Opts;
    type ShapeConfig;
    fn new_initial_prover(
        input: Self::Input<'_>,
        opts: Self::Opts,
        shape_config: Option<Self::ShapeConfig>,
    ) -> Self;
}

/// Trait to assist with inline proving
pub trait MachineProver<SC>
where
    SC: StarkGenericConfig,
{
    type Witness;
    type Chips: ChipBehavior<Val<SC>>;

    fn machine(&self) -> &BaseMachine<SC, Self::Chips>;
    fn prove(&self, witness: Self::Witness) -> MetaProof<SC>;
    fn verify(&self, proof: &MetaProof<SC>, riscv_vk: &dyn HashableKey<SC::Val>) -> bool;
}
