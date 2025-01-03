use crate::{
    compiler::recursion_v2::{
        circuit::{
            config::{BabyBearFriConfigVariable, CircuitConfig},
            stark::BaseProofVariable,
            types::BaseVerifyingKeyVariable,
            witness::{witnessable::Witnessable, WitnessWriter},
        },
        prelude::*,
    },
    configs::{
        config::{StarkGenericConfig, Val},
        stark_config::bb_poseidon2::{BabyBearPoseidon2, SC_Challenge, SC_Val},
    },
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::{
            riscv_circuit::stdin::dummy_vk_and_chunk_proof, shapes::compress_shape::RecursionShape,
        },
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::BaseMachine,
        proof::BaseProof,
    },
    primitives::consts::{COMBINE_DEGREE, DIGEST_SIZE},
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;

#[derive(Clone)]
pub struct RecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub machine: &'a BaseMachine<SC, C>,
    pub vks: Arc<[BaseVerifyingKey<SC>]>,
    pub proofs: Arc<[BaseProof<SC>]>,
    pub flag_complete: bool,
    pub vk_root: [SC::Val; DIGEST_SIZE],
}

pub struct RecursionStdinVariable<
    CC: CircuitConfig<F = BabyBear>,
    SC: BabyBearFriConfigVariable<CC>,
> {
    pub vks: Vec<BaseVerifyingKeyVariable<CC, SC>>,
    pub proofs: Vec<BaseProofVariable<CC, SC>>,
    pub flag_complete: Felt<CC::F>,
    pub vk_root: [Felt<CC::F>; DIGEST_SIZE],
}

impl<'a> RecursionStdin<'a, BabyBearPoseidon2, RecursionChipType<BabyBear, COMBINE_DEGREE>> {
    pub fn dummy(
        machine: &'a BaseMachine<BabyBearPoseidon2, RecursionChipType<BabyBear, COMBINE_DEGREE>>,
        shape: &RecursionShape,
    ) -> Self {
        let vks_and_proofs: Vec<_> = shape
            .proof_shapes
            .iter()
            .map(|proof_shape| {
                let (vk, proof) = dummy_vk_and_chunk_proof(machine, proof_shape);
                (vk, proof)
            })
            .collect();

        let (vks, proofs): (Vec<_>, Vec<_>) = vks_and_proofs.into_iter().unzip();

        let vks = Arc::from(vks.into_boxed_slice());
        let proofs = Arc::from(proofs.into_boxed_slice());

        Self {
            machine,
            vks,
            proofs,
            flag_complete: false,
            vk_root: [BabyBear::ZERO; DIGEST_SIZE],
        }
    }
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
        vks: Arc<[BaseVerifyingKey<SC>]>,
        proofs: Arc<[BaseProof<SC>]>,
        flag_complete: bool,
        vk_root: [SC::Val; DIGEST_SIZE],
    ) -> Self {
        Self {
            machine,
            vks,
            proofs,
            flag_complete,
            vk_root,
        }
    }
}

impl<CC, C> Witnessable<CC> for RecursionStdin<'_, BabyBearPoseidon2, C>
where
    CC: CircuitConfig<F = SC_Val, EF = SC_Challenge, Bit = Felt<BabyBear>>,
    C: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    type WitnessVariable = RecursionStdinVariable<CC, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let vks = self.vks.as_ref().read(builder);
        let proofs = self.proofs.as_ref().read(builder);
        let flag_complete = SC_Val::from_bool(self.flag_complete).read(builder);
        let vk_root = self.vk_root.read(builder);

        RecursionStdinVariable {
            vks,
            proofs,
            flag_complete,
            vk_root,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.vks.as_ref().write(witness);
        self.proofs.as_ref().write(witness);
        self.flag_complete.write(witness);
        self.vk_root.write(witness);
    }
}
