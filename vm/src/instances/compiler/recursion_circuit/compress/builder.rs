use crate::{
    compiler::recursion::{
        ir::{Builder, Felt},
        program::RecursionProgram,
        program_builder::{
            hints::hintable::Hintable,
            p3::{
                challenger::{CanObserveVariable, DuplexChallengerVariable},
                fri::TwoAdicFriPcsVariable,
            },
            stark::StarkVerifier,
            utils::{const_fri_config, hash_vkey},
        },
    },
    configs::config::{FieldGenericConfig, StarkGenericConfig, Val},
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            recursion_circuit::stdin::{RecursionStdin, RecursionStdinVariable},
            utils::{commit_public_values, verify_public_values_hash},
        },
        configs::recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
    },
    machine::machine::BaseMachine,
    primitives::{
        consts::{COMBINE_DEGREE, RECURSION_NUM_PVS},
        types::RecursionProgramType,
    },
    recursion::air::RecursionPublicValues,
};
use p3_field::FieldAlgebra;
use std::{borrow::Borrow, marker::PhantomData};

#[derive(Debug, Clone, Copy)]
pub struct RecursionCompressVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig> {
    _phantom: PhantomData<(FC, SC)>,
}

impl RecursionCompressVerifierCircuit<RecursionFC, RecursionSC> {
    pub fn build(
        machine: &BaseMachine<RecursionSC, RecursionChipType<Val<RecursionSC>, COMBINE_DEGREE>>,
    ) -> RecursionProgram<Val<RecursionSC>> {
        let mut builder = Builder::<RecursionFC>::new(RecursionProgramType::Compress);

        let stdin: RecursionStdinVariable<_> = builder.uninit();
        RecursionStdin::<RecursionSC, RecursionChipType<Val<RecursionSC>, COMBINE_DEGREE>>::witness(
            &stdin,
            &mut builder,
        );

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, machine.config().fri_config()),
        };

        Self::build_verifier(&mut builder, &pcs, machine, stdin);
        builder.halt();
        builder.compile_program()
    }

    pub fn build_verifier(
        builder: &mut Builder<RecursionFC>,
        pcs: &TwoAdicFriPcsVariable<RecursionFC>,
        machine: &BaseMachine<RecursionSC, RecursionChipType<Val<RecursionSC>, COMBINE_DEGREE>>,
        stdin: RecursionStdinVariable<RecursionFC>,
    ) {
        let RecursionStdinVariable {
            vk,
            proofs,
            flag_complete: _,
        } = stdin;

        /*
        assert only one proof
        */
        builder.assert_usize_eq(proofs.len(), 1);
        let proof = builder.get(&proofs, 0);

        /*
        verify the proof
         */
        let mut challenger = DuplexChallengerVariable::new(builder);

        // observe vk and start pc
        challenger.observe(builder, vk.commitment.clone());
        challenger.observe(builder, vk.pc_start);

        // commitment and pv
        challenger.observe(builder, proof.commitment.main_commit.clone());
        for j in 0..RECURSION_NUM_PVS {
            let pv = builder.get(&proof.public_values, j);
            challenger.observe(builder, pv);
        }

        // verify proof
        StarkVerifier::<RecursionFC, RecursionSC>::verify_chunk(
            builder,
            &vk,
            pcs,
            &machine.chips(),
            &machine.preprocessed_chip_ids(),
            &mut challenger,
            &proof,
            true,
        );

        /*
        Extract public values
         */
        let mut public_values_stream = Vec::new();
        for j in 0..RECURSION_NUM_PVS {
            public_values_stream.push(builder.get(&proof.public_values, j));
        }
        let public_values: &RecursionPublicValues<Felt<<RecursionFC as FieldGenericConfig>::F>> =
            public_values_stream.as_slice().borrow();

        // todo: Check that the public values digest is correct.
        verify_public_values_hash(builder, public_values);

        builder.assert_felt_eq(public_values.flag_complete, <Val<RecursionSC>>::ONE);

        let recursion_vk_digest = hash_vkey(builder, &vk);
        for (i, digest_value) in public_values.recursion_vk_digest.iter().enumerate() {
            let vk_digest_elem = builder.get(&recursion_vk_digest, i);
            builder.assert_felt_eq(vk_digest_elem, *digest_value);
        }

        commit_public_values(builder, public_values);
    }
}
