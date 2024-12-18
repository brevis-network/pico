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
    recursion_v2::air::Block,
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, DuplexChallenger};
use p3_field::FieldAlgebra;
use pico_derive::DslVariable;

#[derive(Clone)]
pub struct ConvertStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub machine: &'a BaseMachine<SC, C>,
    pub riscv_vk: &'a BaseVerifyingKey<SC>,
    pub proofs: Vec<BaseProof<SC>>,
    pub base_challenger: SC::Challenger,
    pub reconstruct_challenger: SC::Challenger,
    pub flag_complete: bool,
    pub flag_first_chunk: bool,
    pub vk_root: [SC::Val; DIGEST_SIZE],
}

pub struct ConvertStdinVariable<CC: CircuitConfig<F = BabyBear>, SC: BabyBearFriConfigVariable<CC>>
{
    pub riscv_vk: BaseVerifyingKeyVariable<CC, SC>,
    pub proofs: Vec<BaseProofVariable<CC, SC>>,
    pub base_challenger: SC::FriChallengerVariable,
    pub reconstruct_challenger: DuplexChallengerVariable<CC>,
    pub flag_complete: Felt<CC::F>,
    pub flag_first_chunk: Felt<CC::F>,
    pub vk_root: [Felt<CC::F>; DIGEST_SIZE],
}

impl<'a, SC, C> ConvertStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub fn new(
        machine: &'a BaseMachine<SC, C>,
        riscv_vk: &'a BaseVerifyingKey<SC>,
        proofs: Vec<BaseProof<SC>>,
        base_challenger: SC::Challenger,
        reconstruct_challenger: SC::Challenger,
        flag_complete: bool,
        flag_first_chunk: bool,
        vk_root: [SC::Val; DIGEST_SIZE],
    ) -> Self {
        Self {
            machine,
            riscv_vk,
            proofs,
            base_challenger,
            reconstruct_challenger,
            flag_complete,
            flag_first_chunk,
            vk_root,
        }
    }
}

impl<'a, CC, C> Witnessable<CC> for ConvertStdin<'a, BabyBearPoseidon2, C>
where
    CC: CircuitConfig<F = SC_Val, EF = SC_Challenge, Bit = Felt<BabyBear>>,
    C: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    type WitnessVariable = ConvertStdinVariable<CC, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let riscv_vk = self.riscv_vk.read(builder);
        let proofs = self.proofs.read(builder);
        let base_challenger = self.base_challenger.read(builder);
        let reconstruct_challenger = self.reconstruct_challenger.read(builder);
        let flag_complete = SC_Val::from_bool(self.flag_complete).read(builder);
        let flag_first_chunk = SC_Val::from_bool(self.flag_first_chunk).read(builder);
        let vk_root = self.vk_root.read(builder);

        ConvertStdinVariable {
            riscv_vk,
            proofs,
            base_challenger,
            reconstruct_challenger,
            flag_complete,
            flag_first_chunk,
            vk_root,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.riscv_vk.write(witness);
        self.proofs.write(witness);
        self.base_challenger.write(witness);
        self.reconstruct_challenger.write(witness);
        self.flag_complete.write(witness);
        self.flag_first_chunk.write(witness);
        self.vk_root.write(witness);
    }
}
