use crate::{
    compiler::recursion::{
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
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            riscv_circuit::stdin::{dummy_vk_and_chunk_proof, dummy_vk_and_chunk_proof_kb},
            shapes::recursion_shape::RecursionShape,
        },
    },
    machine::{chip::ChipBehavior, keys::BaseVerifyingKey, machine::BaseMachine, proof::BaseProof},
    primitives::consts::DIGEST_SIZE,
};
use alloc::sync::Arc;
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{FieldAlgebra, TwoAdicField};
use p3_koala_bear::KoalaBear;

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

macro_rules! impl_recursion_stdin_dummy {
    ($poseidon_type:ty, $field_type:ty, $dummy_vk_fn:ident) => {
        impl<'a> RecursionStdin<'a, $poseidon_type, RecursionChipType<$field_type>> {
            pub fn dummy(
                machine: &'a BaseMachine<$poseidon_type, RecursionChipType<$field_type>>,
                shape: &RecursionShape,
            ) -> Self {
                let vks_and_proofs = shape.proof_shapes.iter().map(|proof_shape| {
                    let (vk, proof) = $dummy_vk_fn(machine, proof_shape);
                    (vk, proof)
                });

                let num_shapes = shape.proof_shapes.len();
                let mut vks = Arc::new_uninit_slice(num_shapes);
                let mut proofs = Arc::new_uninit_slice(num_shapes);
                let vk_writer = Arc::get_mut(&mut vks).unwrap();
                let proof_writer = Arc::get_mut(&mut proofs).unwrap();

                for (i, (vk, proof)) in vks_and_proofs.enumerate() {
                    vk_writer[i].write(vk);
                    proof_writer[i].write(proof);
                }

                // SAFETY: we've written num_shapes values so the Arc slices have been initialized
                let vks = unsafe { vks.assume_init() };
                let proofs = unsafe { proofs.assume_init() };

                Self {
                    machine,
                    vks,
                    proofs,
                    flag_complete: false,
                    vk_root: [<$field_type>::ZERO; DIGEST_SIZE],
                }
            }
        }
    };
}

impl_recursion_stdin_dummy!(BabyBearPoseidon2, BabyBear, dummy_vk_and_chunk_proof);
impl_recursion_stdin_dummy!(KoalaBearPoseidon2, KoalaBear, dummy_vk_and_chunk_proof_kb);

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
