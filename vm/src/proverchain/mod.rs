mod combine;
mod compress;
mod convert;
mod embed;
mod riscv;

use crate::{
    configs::config::{StarkGenericConfig, Val},
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        machine::BaseMachine,
        proof::MetaProof,
    },
};
use p3_air::Air;

// re-exports
pub use combine::CombineProver;
pub use compress::CompressProver;
pub use convert::ConvertProver;
pub use embed::EmbedProver;
pub use riscv::RiscvProver;

/// Trait to assist with inline proving
pub trait ProverChain<PrevSC, PrevC, SC>
where
    PrevSC: StarkGenericConfig,
{
    fn new_with_prev(prev_prover: &impl MachineProver<PrevSC, Chips = PrevC>) -> Self;
}

/// Trait to assist with inline proving
pub trait InitialProverSetup {
    type Input<'a>;
    fn new_initial_prover(input: Self::Input<'_>) -> Self;
}

/// Trait to assist with inline proving
pub trait MachineProver<SC>
where
    SC: StarkGenericConfig,
{
    type Witness;
    type Chips: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>;

    fn machine(&self) -> &BaseMachine<SC, Self::Chips>;
    fn prove(&self, witness: Self::Witness) -> MetaProof<SC>;
    fn verify(&self, proof: &MetaProof<SC>) -> bool;
}
