use crate::{
    compiler::recursion::{
        circuit::{
            config::{CircuitConfig, FieldFriConfigVariable},
            hash::{FieldHasher, FieldHasherVariable},
            merkle_tree::MerkleProof,
            stark::MerkleProofVariable,
            types::FriProofVariable,
            witness::{WitnessWriter, Witnessable},
        },
        ir::{Ext, Felt},
        prelude::Builder,
    },
    configs::{
        config::{Com, PcsProof, StarkGenericConfig, Val},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            recursion_circuit::stdin::{RecursionStdin, RecursionStdinVariable},
            shapes::recursion_shape::RecursionVkShape,
        },
    },
    machine::{chip::ChipBehavior, machine::BaseMachine},
    primitives::consts::DIGEST_SIZE,
};
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{FieldAlgebra, TwoAdicField};
use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SC::Digest: Serialize"))]
#[serde(bound(deserialize = "SC::Digest: Deserialize<'de>"))]
pub struct MerkleProofStdin<SC: StarkGenericConfig + FieldHasher<Val<SC>>> {
    pub vk_merkle_proofs: Vec<MerkleProof<Val<SC>, SC>>,
    pub vk_values: Vec<SC::Digest>,
    pub merkle_root: SC::Digest,
}

/// An input layout for the merkle proof verifier.
pub struct MerkleProofStdinVariable<CC, SC>
where
    CC: CircuitConfig,
    SC: FieldHasherVariable<CC> + FieldFriConfigVariable<CC, Val = CC::F>,
{
    /// The merkle proofs to verify.
    pub vk_merkle_proofs: Vec<MerkleProofVariable<CC, SC>>,
    // TODO: we can remove the vk_values here
    pub vk_values: Vec<SC::DigestVariable>,
    pub merkle_root: SC::DigestVariable,
}

impl<CC, SC> Witnessable<CC> for MerkleProofStdin<SC>
where
    SC: FieldFriConfigVariable<CC, Val = CC::F> + FieldHasher<CC::F>,
    SC::Digest: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    CC: CircuitConfig,
{
    type WitnessVariable = MerkleProofStdinVariable<CC, SC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        MerkleProofStdinVariable {
            vk_merkle_proofs: self.vk_merkle_proofs.read(builder),
            vk_values: self.vk_values.read(builder),
            merkle_root: self.merkle_root.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.vk_merkle_proofs.write(witness);
        self.vk_values.write(witness);
        self.merkle_root.write(witness);
    }
}

impl<CC: CircuitConfig, HV: FieldHasherVariable<CC>> Witnessable<CC> for MerkleProof<CC::F, HV>
where
    HV::Digest: Witnessable<CC, WitnessVariable = HV::DigestVariable>,
{
    type WitnessVariable = MerkleProofVariable<CC, HV>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let mut bits = vec![];
        let mut index = self.index;
        for _ in 0..self.path.len() {
            bits.push(index % 2 == 1);
            index >>= 1;
        }
        let index_bits = bits.read(builder);
        let path = self.path.read(builder);

        MerkleProofVariable {
            index: index_bits,
            path,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        let mut index = self.index;
        for _ in 0..self.path.len() {
            (index % 2 == 1).write(witness);
            index >>= 1;
        }
        self.path.write(witness);
    }
}

impl<SC: StarkGenericConfig + FieldHasher<Val<SC>, Digest = [Val<SC>; DIGEST_SIZE]>>
    MerkleProofStdin<SC>
{
    pub fn dummy(num_proofs: usize, height: usize) -> Self {
        let dummy_digest = [Val::<SC>::ZERO; DIGEST_SIZE];
        let vk_merkle_proofs = vec![
            MerkleProof {
                index: 0,
                path: vec![dummy_digest; height]
            };
            num_proofs
        ];
        let vk_values = vec![dummy_digest; num_proofs];

        Self {
            vk_merkle_proofs,
            vk_values,
            merkle_root: dummy_digest,
        }
    }
}

#[derive(Clone)]
pub enum RecursionStdinVariant<'a, SC, C>
where
    SC: StarkGenericConfig + FieldHasher<Val<SC>>,
    C: ChipBehavior<Val<SC>>,
{
    NoVk(RecursionStdin<'a, SC, C>),
    WithVk(RecursionVkStdin<'a, SC, C>),
}

#[derive(Clone)]
pub struct RecursionVkStdin<'a, SC, C>
where
    SC: StarkGenericConfig + FieldHasher<Val<SC>>,
    C: ChipBehavior<Val<SC>>,
{
    pub merkle_proof_stdin: MerkleProofStdin<SC>,
    pub recursion_stdin: RecursionStdin<'a, SC, C>,
}

pub enum RecursionStdinVariantVariable<CC, SC>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,
{
    NoVk(RecursionStdinVariable<CC, SC>),
    WithVk(RecursionVkStdinVariable<CC, SC>),
}

pub struct RecursionVkStdinVariable<CC, SC>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,
{
    pub recursion_stdin_var: RecursionStdinVariable<CC, SC>,
    pub merkle_proof_var: MerkleProofStdinVariable<CC, SC>,
}

impl<CC, SC, C> Witnessable<CC> for RecursionVkStdin<'_, SC, C>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
            CC,
            Val = CC::F,
            Challenge = CC::EF,
            Domain = TwoAdicMultiplicativeCoset<CC::F>,
        > + FieldHasher<CC::F>,
    SC::Digest: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    C: ChipBehavior<CC::F>,
{
    type WitnessVariable = RecursionVkStdinVariable<CC, SC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        RecursionVkStdinVariable {
            recursion_stdin_var: self.recursion_stdin.read(builder),
            merkle_proof_var: self.merkle_proof_stdin.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.recursion_stdin.write(witness);
        self.merkle_proof_stdin.write(witness);
    }
}

impl<CC, SC, C> Witnessable<CC> for RecursionStdinVariant<'_, SC, C>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
            CC,
            Val = CC::F,
            Challenge = CC::EF,
            Domain = TwoAdicMultiplicativeCoset<CC::F>,
        > + FieldHasher<CC::F>,
    SC::Digest: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    C: ChipBehavior<CC::F>,
{
    type WitnessVariable = RecursionStdinVariantVariable<CC, SC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        match self {
            RecursionStdinVariant::NoVk(stdin) => {
                RecursionStdinVariantVariable::NoVk(stdin.read(builder))
            }
            RecursionStdinVariant::WithVk(stdin) => {
                RecursionStdinVariantVariable::WithVk(stdin.read(builder))
            }
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        match self {
            RecursionStdinVariant::NoVk(stdin) => stdin.write(witness),
            RecursionStdinVariant::WithVk(stdin) => stdin.write(witness),
        }
    }
}

macro_rules! impl_recursion_vk_stdin_dummy {
    ($poseidon_type:ty, $field_type:ty) => {
        impl<'a> RecursionVkStdin<'a, $poseidon_type, RecursionChipType<$field_type>> {
            pub fn dummy(
                machine: &'a BaseMachine<$poseidon_type, RecursionChipType<$field_type>>,
                shape: &RecursionVkShape,
            ) -> Self {
                let recursion_stdin = RecursionStdin::<
                    'a,
                    $poseidon_type,
                    RecursionChipType<$field_type>,
                >::dummy(machine, &shape.recursion_shape);
                let num_proofs = recursion_stdin.proofs.len();
                let merkle_proof_stdin =
                    MerkleProofStdin::dummy(num_proofs, shape.merkle_tree_height);
                Self {
                    merkle_proof_stdin,
                    recursion_stdin,
                }
            }
        }
    };
}

impl_recursion_vk_stdin_dummy!(BabyBearPoseidon2, BabyBear);
impl_recursion_vk_stdin_dummy!(KoalaBearPoseidon2, KoalaBear);
