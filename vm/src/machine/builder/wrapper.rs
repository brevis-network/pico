use crate::{
    compiler::recursion_v2::{
        circuit::config::EmbedConfig,
        constraints::{Constraint, ConstraintCompiler},
        ir::{Builder, Var, Witness},
    },
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        configs::embed_config::StarkConfig as EmbedSC,
    },
    machine::{
        keys::BaseVerifyingKey,
        proof::{BaseProof, MetaProof},
    },
};
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use std::borrow::Borrow;

use crate::{
    compiler::recursion_v2::circuit::{
        hash::FieldHasherVariable,
        utils::{babybear_bytes_to_bn254, babybears_to_bn254, words_to_bytes},
        witness::{embed::EmbedWitnessValues, Witnessable},
    },
    configs::{config::OuterConfig, stark_config::bb_bn254_poseidon2::BbBn254Poseidon2},
    instances::machine::embed::EmbedMachine,
    primitives::consts::{EMBED_DEGREE, RECURSION_NUM_PVS_V2},
    recursion_v2::air::RecursionPublicValues,
};

#[allow(unused)]
pub fn build_constraints_and_witness(
    template_vk: &BaseVerifyingKey<BbBn254Poseidon2>,
    template_proof: &BaseProof<BbBn254Poseidon2>,
) -> (Vec<Constraint>, Witness<OuterConfig>) {
    tracing::info!("building verifier constraints");
    let template_input = EmbedWitnessValues {
        vks_and_proofs: vec![(template_vk.clone(), template_proof.clone())],
        is_complete: true,
    };
    let constraints =
        tracing::info_span!("wrap circuit").in_scope(|| build_outer_circuit(&template_input));

    // TODO, better method? // let pv: &RecursionPublicValues<BabyBear> = template_proof.public_values.as_slice().borrow();
    let binding = template_proof.public_values.to_vec();
    let pv: &RecursionPublicValues<BabyBear> = binding.as_slice().borrow();
    let vkey_hash = babybears_to_bn254(&pv.riscv_vk_digest);
    let committed_values_digest_bytes: [BabyBear; 32] = words_to_bytes(&pv.committed_value_digest)
        .try_into()
        .unwrap();
    let committed_values_digest = babybear_bytes_to_bn254(&committed_values_digest_bytes);

    tracing::info!("building template witness");
    let mut witness = Witness::default();
    template_input.write(&mut witness);
    witness.write_committed_values_digest(committed_values_digest);
    witness.write_vkey_hash(vkey_hash);

    (constraints, witness)
}

#[allow(unused)]
fn build_outer_circuit(template_input: &EmbedWitnessValues) -> Vec<Constraint> {
    let embed_machine = EmbedMachine::<_, _, Vec<u8>>::new(
        EmbedSC::new(),
        RecursionChipType::<BabyBear, EMBED_DEGREE>::embed_chips(),
        RECURSION_NUM_PVS_V2,
    );
    let mut builder = Builder::<OuterConfig>::default();

    let template_vk = template_input.vks_and_proofs.first().unwrap().0.clone();
    let input = template_input.read(&mut builder);
    let vk = input.vks_and_proofs.first().unwrap().0.clone();

    let expected_commitment: [_; 1] = template_vk.commit.into();
    let expected_commitment: [Var<Bn254Fr>; 1] = expected_commitment.map(|x| builder.eval(x));

    BbBn254Poseidon2::assert_digest_eq(&mut builder, expected_commitment, vk.commit);

    builder.assert_felt_eq(vk.pc_start, template_vk.pc_start);

    // TODO, add embed proof variable verifier here

    let mut backend = ConstraintCompiler::<OuterConfig>::default();
    backend.emit(builder.into_operations())
}
