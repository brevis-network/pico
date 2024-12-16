use crate::{
    compiler::{
        recursion_v2::{
            circuit::{
                challenger::DuplexChallengerVariable,
                config::{BabyBearFriConfigVariable, CircuitConfig},
                hash::FieldHasherVariable,
                stark::BaseProofVariable,
                types,
                types::BaseVerifyingKeyVariable,
                witness::{witnessable::Witnessable, WitnessWriter},
            },
            prelude::*,
        },
        riscv::program::Program,
    },
    configs::{
        config::{Com, FieldGenericConfig, PcsProof, StarkGenericConfig, Val},
        stark_config::bb_poseidon2::{BabyBearPoseidon2, SC_Challenge, SC_Val},
    },
    instances::compiler_v2::witness,
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::BaseMachine,
        proof::BaseProof,
    },
    primitives::consts::DIGEST_SIZE,
    recursion::air::Block,
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, DuplexChallenger};
use p3_field::FieldAlgebra;
use pico_derive::DslVariable;

#[derive(Clone)]
pub struct RecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub machine: &'a BaseMachine<SC, C>,
    pub vks_and_proofs: Vec<(BaseVerifyingKey<SC>, BaseProof<SC>)>,
    pub flag_complete: bool,
    pub vk_root: [SC::Val; DIGEST_SIZE],
}

pub struct RecursionStdinVariable<
    CC: CircuitConfig<F = BabyBear>,
    SC: BabyBearFriConfigVariable<CC>,
> {
    pub vks_and_proofs: Vec<(BaseVerifyingKeyVariable<CC, SC>, BaseProofVariable<CC, SC>)>,
    pub flag_complete: Felt<CC::F>,
    pub vk_root: [Felt<CC::F>; DIGEST_SIZE],
}

impl<'a, SC, C> RecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub fn new(
        machine: &'a BaseMachine<SC, C>,
        vks_and_proofs: Vec<(BaseVerifyingKey<SC>, BaseProof<SC>)>,
        flag_complete: bool,
        vk_root: [SC::Val; DIGEST_SIZE],
    ) -> Self {
        Self {
            machine,
            vks_and_proofs,
            flag_complete,
            vk_root,
        }
    }
}

impl<'a, CC, C> Witnessable<CC> for RecursionStdin<'a, BabyBearPoseidon2, C>
where
    CC: CircuitConfig<F = SC_Val, EF = SC_Challenge, Bit = Felt<BabyBear>>,
    C: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    type WitnessVariable = RecursionStdinVariable<CC, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let vks_and_proofs = self.vks_and_proofs.read(builder);
        let flag_complete = SC_Val::from_bool(self.flag_complete).read(builder);
        let vk_root = self.vk_root.read(builder);

        RecursionStdinVariable {
            vks_and_proofs,
            flag_complete,
            vk_root,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.vks_and_proofs.write(witness);
        self.flag_complete.write(witness);
        self.vk_root.write(witness);
    }
}
