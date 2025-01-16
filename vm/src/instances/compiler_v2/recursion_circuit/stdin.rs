use crate::{
    compiler::recursion_v2::{
        circuit::{
            config::{CircuitConfig, FieldFriConfigVariable},
            stark::BaseProofVariable,
            types::{BaseVerifyingKeyVariable, FriProofVariable},
            witness::{witnessable::Witnessable, WitnessWriter},
        },
        prelude::*,
    },
    configs::{
        config::{Com, PcsProof, StarkGenericConfig, Val},
        stark_config::bb_poseidon2::BabyBearPoseidon2,
    },
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::{
            riscv_circuit::stdin::dummy_vk_and_chunk_proof, shapes::compress_shape::RecursionShape,
        },
    },
    machine::{chip::ChipBehavior, keys::BaseVerifyingKey, machine::BaseMachine, proof::BaseProof},
    primitives::consts::{COMBINE_DEGREE, DIGEST_SIZE},
};
use alloc::sync::Arc;
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{FieldAlgebra, TwoAdicField};

#[derive(Clone)]
pub struct RecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub machine: &'a BaseMachine<SC, C>,
    pub vks: Arc<[BaseVerifyingKey<SC>]>,
    pub proofs: Arc<[BaseProof<SC>]>,
    pub flag_complete: bool,
    pub vk_root: [SC::Val; DIGEST_SIZE],
}

pub struct RecursionStdinVariable<CC, SC>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,
{
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
    C: ChipBehavior<SC::Val>,
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

impl<CC, SC, C> Witnessable<CC> for RecursionStdin<'_, SC, C>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
        CC,
        Val = CC::F,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<CC::F>,
    >,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    C: ChipBehavior<CC::F>,
{
    type WitnessVariable = RecursionStdinVariable<CC, SC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let vks = self.vks.as_ref().read(builder);
        let proofs = self.proofs.as_ref().read(builder);
        let flag_complete = CC::F::from_bool(self.flag_complete).read(builder);
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
