use crate::{
    compiler::recursion_v2::{
        circuit::{
            config::{BabyBearFriConfigVariable, CircuitConfig},
            hash::{FieldHasher, FieldHasherVariable},
            merkle_tree::MerkleProof,
            stark::MerkleProofVariable,
            witness::{WitnessWriter, Witnessable},
        },
        ir::Felt,
        prelude::Builder,
    },
    configs::{
        config::{StarkGenericConfig, Val},
        stark_config::bb_poseidon2::{BabyBearPoseidon2, SC_Challenge, SC_Val},
    },
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::{
            recursion_circuit::stdin::{RecursionStdin, RecursionStdinVariable},
            shapes::compress_shape::RecursionVkShape,
        },
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        machine::BaseMachine,
    },
    primitives::consts::{COMBINE_DEGREE, DIGEST_SIZE},
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SC::Digest: Serialize"))]
#[serde(bound(deserialize = "SC::Digest: Deserialize<'de>"))]
pub struct MerkleProofStdin<SC: FieldHasher<BabyBear>> {
    pub vk_merkle_proofs: Vec<MerkleProof<BabyBear, SC>>,
    pub vk_values: Vec<SC::Digest>,
    pub merkle_root: SC::Digest,
}

/// An input layout for the merkle proof verifier.
pub struct MerkleProofStdinVariable<
    CC: CircuitConfig<F = BabyBear>,
    SC: FieldHasherVariable<CC> + BabyBearFriConfigVariable<CC>,
> {
    /// The merkle proofs to verify.
    pub vk_merkle_proofs: Vec<MerkleProofVariable<CC, SC>>,
    // TODO: we can remove the vk_values here
    pub vk_values: Vec<SC::DigestVariable>,
    pub merkle_root: SC::DigestVariable,
}

impl<CC: CircuitConfig<F = BabyBear>, SC: BabyBearFriConfigVariable<CC>> Witnessable<CC>
    for MerkleProofStdin<SC>
where
    SC: FieldHasher<BabyBear>,
    <SC as FieldHasher<BabyBear>>::Digest: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
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

impl MerkleProofStdin<BabyBearPoseidon2> {
    pub fn dummy(num_proofs: usize, height: usize) -> Self {
        let dummy_digest = [BabyBear::ZERO; DIGEST_SIZE];
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
pub struct RecursionVkStdin<'a, SC, C>
where
    SC: FieldHasher<BabyBear> + StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub merkle_proof_stdin: MerkleProofStdin<SC>,
    pub recursion_stdin: RecursionStdin<'a, SC, C>,
}

pub struct RecursionVkStdinVariable<
    CC: CircuitConfig<F = BabyBear>,
    SC: BabyBearFriConfigVariable<CC>,
> {
    pub resursion_stdin_var: RecursionStdinVariable<CC, SC>,
    pub merkle_proof_var: MerkleProofStdinVariable<CC, SC>,
}

impl<'a, CC, C> Witnessable<CC> for RecursionVkStdin<'a, BabyBearPoseidon2, C>
where
    CC: CircuitConfig<F = SC_Val, EF = SC_Challenge, Bit = Felt<BabyBear>>,
    C: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    type WitnessVariable = RecursionVkStdinVariable<CC, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        RecursionVkStdinVariable {
            resursion_stdin_var: self.recursion_stdin.read(builder),
            merkle_proof_var: self.merkle_proof_stdin.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.recursion_stdin.write(witness);
        self.merkle_proof_stdin.write(witness);
    }
}

impl<'a> RecursionVkStdin<'a, BabyBearPoseidon2, RecursionChipType<BabyBear, 3>> {
    pub fn dummy(
        machine: &'a BaseMachine<BabyBearPoseidon2, RecursionChipType<BabyBear, COMBINE_DEGREE>>,
        shape: &RecursionVkShape,
    ) -> Self {
        let recursion_stdin = RecursionStdin::dummy(machine, &shape.recursion_shape);
        let num_proofs = recursion_stdin.proofs.len();
        let merkle_proof_stdin = MerkleProofStdin::dummy(num_proofs, shape.merkle_tree_height);
        Self {
            merkle_proof_stdin,
            recursion_stdin,
        }
    }
}
