use super::super::stdin::{RecursionStdin, RecursionStdinVariable};
use crate::{
    chips::chips::riscv_cpu::MAX_CPU_LOG_DEGREE,
    compiler::{
        recursion_v2::{
            circuit::{
                challenger::{
                    CanObserveVariable, DuplexChallengerVariable, FieldChallengerVariable,
                },
                config::{BabyBearFriConfig, BabyBearFriConfigVariable, CircuitConfig},
                stark::StarkVerifier,
                utils::uninit_challenger_pv,
                witness::Witnessable,
                CircuitV2Builder,
            },
            instruction::commit_public_values,
            ir::{compiler, compiler::DslIrCompiler},
            prelude::*,
            program::RecursionProgram,
        },
        word::Word,
    },
    configs::{
        config::{Com, FieldGenericConfig, StarkGenericConfig, Val},
        stark_config::bb_poseidon2::{BabyBearPoseidon2, SC_Challenge, SC_Val, SC_ValMmcs},
    },
    emulator::riscv::public_values::PublicValues,
    instances::{
        chiptype::{recursion_chiptype_v2::RecursionChipType, riscv_chiptype::RiscvChipType},
        configs::{
            recur_config::{
                FieldConfig as RiscvFC, FieldConfig as RecursionFC, StarkConfig as RecursionSC,
            },
            riscv_config::StarkConfig as RiscvSC,
        },
    },
    machine::{chip::ChipBehavior, machine::BaseMachine},
    primitives::{
        consts::{
            ADDR_NUM_BITS, COMPRESS_DEGREE, DIGEST_SIZE, EMPTY, MAX_LOG_CHUNK_SIZE,
            MAX_LOG_NUMBER_OF_CHUNKS, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS,
            RISCV_COMPRESS_DEGREE,
        },
        consts_v2::RECURSION_NUM_PVS_V2,
    },
    recursion_v2::air::{
        assert_recursion_public_values_valid, embed_public_values_digest,
        recursion_public_values_digest, ChallengerPublicValues, RecursionPublicValues,
    },
};
use itertools::{izip, Itertools};
use p3_baby_bear::BabyBear;
use p3_commit::{Mmcs, TwoAdicMultiplicativeCoset};
use p3_field::{FieldAlgebra, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::MaybeUninit,
};

#[derive(Debug, Clone, Copy)]
pub struct RecursionEmbedVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig>(
    PhantomData<(FC, SC)>,
);

impl RecursionEmbedVerifierCircuit<RecursionFC, RecursionSC> {
    pub fn build(
        machine: &BaseMachine<RecursionSC, RecursionChipType<Val<RecursionSC>, COMPRESS_DEGREE>>,
        input: &RecursionStdin<RecursionSC, RecursionChipType<Val<RecursionSC>, COMPRESS_DEGREE>>,
    ) -> RecursionProgram<Val<RecursionSC>> {
        // Construct the builder.
        let mut builder = Builder::<RecursionFC>::new();
        let input = input.read(&mut builder);
        Self::build_verifier(&mut builder, machine, input);

        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<RiscvFC>::default();
        compiler.compile(operations)
    }
}

impl<CC, SC> RecursionEmbedVerifierCircuit<CC, SC>
where
    SC: BabyBearFriConfigVariable<CC>,
    CC: CircuitConfig<F = SC::Val, EF = SC::Challenge>,
{
    pub fn build_verifier(
        builder: &mut Builder<CC>,
        machine: &BaseMachine<SC, RecursionChipType<SC::Val, COMPRESS_DEGREE>>,
        input: RecursionStdinVariable<CC, SC>,
    ) {
        // Read input.
        let RecursionStdinVariable {
            mut vks_and_proofs,
            flag_complete,
            ..
        } = input;

        // Must only have one proof.
        assert_eq!(vks_and_proofs.len(), 1);
        let (vk, chunk_proof) = vks_and_proofs.pop().unwrap();

        let one: Felt<_> = builder.eval(CC::F::ONE);
        let zero: Felt<_> = builder.eval(CC::F::ZERO);
        let zero_ext: Ext<CC::F, CC::EF> = builder.eval(zero);

        // Flag must be complete.
        builder.assert_felt_eq(flag_complete, one);

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
                chunk_proof.public_values[0..machine.num_public_values()]
                    .iter()
                    .copied(),
            );

            StarkVerifier::verify_chunk(
                builder,
                &vk,
                machine,
                &mut challenger,
                &chunk_proof,
                &[zero_ext, zero_ext],
            );
        }

        /*
        Update public values
         */
        let mut compress_public_values_stream = chunk_proof.public_values;
        let compress_public_values: &mut RecursionPublicValues<_> =
            compress_public_values_stream.as_mut_slice().borrow_mut();

        // validate digest
        assert_recursion_public_values_valid::<CC, SC>(builder, compress_public_values);

        compress_public_values.digest =
            embed_public_values_digest::<CC, SC>(builder, compress_public_values);

        /*
        Commit public values
         */
        SC::commit_recursion_public_values(builder, *compress_public_values);
    }
}
