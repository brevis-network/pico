use crate::{
    compiler::recursion_v2::{
        circuit::{
            challenger::CanObserveVariable,
            config::BabyBearFriConfigVariable,
            hash::FieldHasherVariable,
            stark::StarkVerifier,
            utils::{babybear_bytes_to_bn254, babybears_to_bn254, words_to_bytes},
            witness::{
                embed::{EmbedWitnessValues, EmbedWitnessVariable},
                Witnessable,
            },
        },
        constraints::{Constraint, ConstraintCompiler},
        ir::{Builder, Ext, Var, Witness},
    },
    configs::config::FieldGenericConfig,
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        configs::{
            embed_config::{FieldConfig as EmbedFC, StarkConfig as EmbedSC},
            recur_config::StarkConfig as RecurSC,
        },
        machine::embed::EmbedMachine,
    },
    machine::{
        keys::BaseVerifyingKey,
        machine::{BaseMachine, MachineBehavior},
        proof::BaseProof,
    },
    primitives::consts::{EMBED_DEGREE, RECURSION_NUM_PVS_V2},
    recursion_v2::air::{
        assert_embed_public_values_valid, assert_recursion_public_values_valid,
        RecursionPublicValues,
    },
};
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::{FieldAlgebra, FieldExtensionAlgebra, PrimeField};
use serde::{Deserialize, Serialize};
use std::{
    borrow::{Borrow, BorrowMut},
    fs::File,
    io::Write,
    path::PathBuf,
};

/// A witness that can be used to initialize values for witness generation inside Gnark.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GnarkWitness {
    pub vars: Vec<String>,
    pub felts: Vec<String>,
    pub exts: Vec<Vec<String>>,
    pub vkey_hash: String,
    pub committed_values_digest: String,
}

impl GnarkWitness {
    /// Creates a new witness from a given [Witness].
    pub fn new(mut witness: Witness<EmbedFC>) -> Self {
        witness
            .vars
            .push(<EmbedFC as FieldGenericConfig>::N::from_canonical_usize(
                999,
            ));
        witness
            .felts
            .push(<EmbedFC as FieldGenericConfig>::F::from_canonical_usize(
                999,
            ));
        witness
            .exts
            .push(<EmbedFC as FieldGenericConfig>::EF::from_canonical_usize(
                999,
            ));
        GnarkWitness {
            vars: witness
                .vars
                .into_iter()
                .map(|w| w.as_canonical_biguint().to_string())
                .collect(),
            felts: witness
                .felts
                .into_iter()
                .map(|w| w.as_canonical_biguint().to_string())
                .collect(),
            exts: witness
                .exts
                .into_iter()
                .map(|w| {
                    w.as_base_slice()
                        .iter()
                        .map(|x: &BabyBear| x.as_canonical_biguint().to_string())
                        .collect()
                })
                .collect(),
            vkey_hash: witness.vkey_hash.as_canonical_biguint().to_string(),
            committed_values_digest: witness
                .committed_values_digest
                .as_canonical_biguint()
                .to_string(),
        }
    }

    /// Saves the witness to a given path.
    #[allow(unused)]
    pub fn save(&self, path: &str) {
        let serialized = serde_json::to_string(self).unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();
    }
}

#[allow(unused)]
pub fn build_constraints_and_witness(
    template_vk: &BaseVerifyingKey<EmbedSC>,
    template_proof: &BaseProof<EmbedSC>,
) -> (Vec<Constraint>, Witness<EmbedFC>) {
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
fn build_outer_circuit(template_input: &EmbedWitnessValues<EmbedSC>) -> Vec<Constraint> {
    let embed_machine = EmbedMachine::<_, _, Vec<u8>>::new(
        EmbedSC::new(),
        RecursionChipType::<BabyBear, EMBED_DEGREE>::embed_chips(),
        RECURSION_NUM_PVS_V2,
    );
    let mut builder = Builder::<EmbedFC>::default();

    let template_vk = template_input.vks_and_proofs.first().unwrap().0.clone();
    let input = template_input.read(&mut builder);
    let vk = input.vks_and_proofs.first().unwrap().0.clone();

    let expected_commitment: [_; 1] = template_vk.commit.into();
    let expected_commitment: [Var<Bn254Fr>; 1] = expected_commitment.map(|x| builder.eval(x));

    EmbedSC::assert_digest_eq(&mut builder, expected_commitment, vk.commit);

    builder.assert_felt_eq(vk.pc_start, template_vk.pc_start);

    let base_machine = embed_machine.base_machine();
    verify_embed(&mut builder, base_machine, &input);

    let mut backend = ConstraintCompiler::<EmbedFC>::default();
    backend.emit(builder.into_operations())
}

pub fn verify_embed(
    builder: &mut Builder<EmbedFC>,
    machine: &BaseMachine<EmbedSC, RecursionChipType<BabyBear, EMBED_DEGREE>>,
    input: &EmbedWitnessVariable<EmbedFC, EmbedSC>,
) {
    // Assert that there is only one proof, and get the verification key and proof.
    let vk = input.vks_and_proofs.first().unwrap().clone().0;
    let proof = input.vks_and_proofs.first().unwrap().clone().1;

    let zero_ext: Ext<<EmbedFC as FieldGenericConfig>::F, <EmbedFC as FieldGenericConfig>::EF> =
        builder.eval(<EmbedFC as FieldGenericConfig>::F::ZERO);

    /*
    Verify chunk proof
     */
    {
        // Prepare a challenger.
        let mut challenger = machine.config().challenger_variable(builder);

        vk.observed_by(builder, &mut challenger);

        // Observe the main commitment and public values.
        challenger.observe_slice(
            builder,
            proof.public_values[0..machine.num_public_values()]
                .iter()
                .copied(),
        );

        StarkVerifier::verify_chunk(
            builder,
            &vk,
            machine,
            &mut challenger,
            &proof,
            &[zero_ext, zero_ext],
        );
    }

    // Get the public values, and assert that they are valid.
    let embed_public_values = proof.public_values.as_slice().borrow();
    // let embed_public_values: &mut RecursionPublicValues<_> =
    //     embed_public_values_stream.as_mut_slice().borrow_mut();

    assert_embed_public_values_valid::<EmbedFC, EmbedSC>(builder, embed_public_values);

    // Reflect the public values to the next level.
    EmbedSC::commit_recursion_public_values(builder, *embed_public_values);
}

#[allow(unused)]
pub fn build_gnark_config(
    constraints: Vec<Constraint>,
    witness: Witness<EmbedFC>,
    build_dir: PathBuf,
) {
    let serialized = serde_json::to_string(&constraints).unwrap();

    // Write constraints.
    let constraints_path = build_dir.join("constraints.json");
    let mut file = File::create(constraints_path).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();

    // Write witness.
    let witness_path = build_dir.join("groth16_witness.json");
    let gnark_witness = GnarkWitness::new(witness);
    let mut file = File::create(witness_path).unwrap();
    let serialized = serde_json::to_string(&gnark_witness).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();
}
