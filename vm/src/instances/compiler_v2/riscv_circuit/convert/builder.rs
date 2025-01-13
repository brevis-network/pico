use super::super::stdin::{ConvertStdin, ConvertStdinVariable};
use crate::{
    chips::chips::riscv_cpu::MAX_CPU_LOG_DEGREE,
    compiler::{
        recursion_v2::{
            circuit::{
                challenger::{CanObserveVariable, DuplexChallengerVariable},
                config::{CircuitConfig, FieldFriConfig, FieldFriConfigVariable},
                constraints::RecursiveVerifierConstraintFolder,
                stark::StarkVerifier,
                types::FriProofVariable,
                witness::Witnessable,
                CircuitV2Builder,
            },
            ir::compiler::DslIrCompiler,
            prelude::*,
            program::RecursionProgram,
        },
        word::Word,
    },
    configs::config::{Challenger, Com, PcsProof, Val},
    emulator::riscv::public_values::PublicValues,
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        lookup::LookupScope,
        machine::BaseMachine,
    },
    primitives::consts::{
        ADDR_NUM_BITS, DIGEST_SIZE, MAX_LOG_NUMBER_OF_CHUNKS, RECURSION_NUM_PVS_V2,
    },
    recursion_v2::air::{recursion_public_values_digest, RecursionPublicValues},
};
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{FieldAlgebra, PrimeField32, TwoAdicField};
use std::{
    borrow::{Borrow, BorrowMut},
    fmt::Debug,
    marker::PhantomData,
};

/// Circuit that verifies a single riscv proof and checks constraints
#[derive(Debug, Clone, Copy)]
pub struct ConvertVerifierCircuit<
    CC: CircuitConfig,
    SC: FieldFriConfig,
    const HALF_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
> {
    _phantom: PhantomData<(CC, SC)>,
}

impl<F, CC, SC, const HALF_EXTERNAL_ROUNDS: usize, const NUM_INTERNAL_ROUNDS: usize>
    ConvertVerifierCircuit<CC, SC, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>
where
    F: TwoAdicField + PrimeField32 + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC: CircuitConfig<N = F, F = F, Bit = Felt<F>> + Debug,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
        CC,
        Val = F,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<F>,
        FriChallengerVariable = DuplexChallengerVariable<CC>,
        DigestVariable = [Felt<F>; DIGEST_SIZE],
    >,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    Challenger<SC>: Witnessable<CC, WitnessVariable = SC::FriChallengerVariable>,

    RiscvChipType<Val<SC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<RecursiveVerifierConstraintFolder<'a, CC>>,
{
    pub fn build(
        machine: &BaseMachine<
            SC,
            RiscvChipType<Val<SC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>,
        >,
        input: &ConvertStdin<SC, RiscvChipType<Val<SC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>>,
    ) -> RecursionProgram<Val<SC>> {
        // Construct the builder.
        let mut builder = Builder::<CC>::new();
        let input = input.read(&mut builder);
        Self::build_verifier(&mut builder, machine, input);

        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<CC>::default();
        compiler.compile(operations)
    }
}

impl<CC, SC, const HALF_EXTERNAL_ROUNDS: usize, const NUM_INTERNAL_ROUNDS: usize>
    ConvertVerifierCircuit<CC, SC, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField + PrimeField32,
    SC: FieldFriConfigVariable<
        CC,
        Val = CC::F,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<CC::F>,
        FriChallengerVariable = DuplexChallengerVariable<CC>,
        DigestVariable = [Felt<CC::F>; DIGEST_SIZE],
    >,

    RiscvChipType<Val<SC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<RecursiveVerifierConstraintFolder<'a, CC>>,
{
    pub fn build_verifier(
        builder: &mut Builder<CC>,
        machine: &BaseMachine<
            SC,
            RiscvChipType<SC::Val, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>,
        >,
        input: ConvertStdinVariable<CC, SC>,
    ) {
        // Read input.
        let ConvertStdinVariable {
            riscv_vk,
            proofs,
            flag_complete,
            flag_first_chunk,
            vk_root,
        } = input;

        // Assert that the number of proofs is one.
        assert_eq!(proofs.len(), 1);

        /*
        Extract public values
         */
        let public_values: &PublicValues<Word<Felt<_>>, Felt<_>> =
            proofs[0].public_values.as_slice().borrow();

        /*
        Initializations
        */
        // chunk numbers
        let mut current_chunk = public_values.chunk;
        let mut current_execution_chunk = public_values.execution_chunk;

        // flags
        let flag_cpu = proofs[0].contains_cpu();
        let flag_memory_initialize = proofs[0].contains_memory_initialize();
        let flag_memory_finalize = proofs[0].contains_memory_finalize();

        /*
        Verify chunk proof
         */

        // Prepare a challenger.
        let mut challenger = {
            let mut challenger = machine.config().challenger_variable(builder);
            riscv_vk.observed_by(builder, &mut challenger);

            challenger.observe_slice(
                builder,
                proofs[0].public_values[0..machine.num_public_values()]
                    .iter()
                    .copied(),
            );

            challenger
        };

        StarkVerifier::verify_chunk(builder, &riscv_vk, machine, &mut challenger, &proofs[0]);

        /*
        Beginning constraints
         */
        {
            // boolean assertion
            builder.assert_felt_eq(
                flag_first_chunk * (flag_first_chunk - CC::F::ONE),
                CC::F::ZERO,
            );

            // Chunk index assertion
            builder.assert_felt_eq(
                flag_first_chunk * (public_values.chunk - CC::F::ONE),
                CC::F::ZERO,
            );
            builder.assert_felt_ne(
                (SymbolicFelt::ONE - flag_first_chunk) * public_values.chunk,
                CC::F::ONE,
            );

            // `start_pc` equals `vk.pc_start`.
            builder.assert_felt_eq(
                flag_first_chunk * (public_values.start_pc - riscv_vk.pc_start),
                CC::F::ZERO,
            );

            // Assert that previous `init_addr_bits` and `finalize_addr_bits` are zeros
            for bit in public_values.previous_initialize_addr_bits.iter() {
                builder.assert_felt_eq(flag_first_chunk * *bit, CC::F::ZERO);
            }
            for bit in public_values.previous_finalize_addr_bits.iter() {
                builder.assert_felt_eq(flag_first_chunk * *bit, CC::F::ZERO);
            }
        }

        /*
        Chunk number constraints and updates
         */
        {
            // range check
            CC::range_check_felt(builder, public_values.chunk, MAX_LOG_NUMBER_OF_CHUNKS);

            // current chunk is incremented by 1
            current_chunk = builder.eval(current_chunk + CC::F::ONE);

            // If the chunk has a "CPU" chip, then the execution chunk should be incremented by 1.
            if flag_cpu {
                current_execution_chunk = builder.eval(current_execution_chunk + CC::F::ONE);
            }
        }

        /*
        CPU constraints
         */

        {
            if !flag_cpu {
                builder.assert_felt_ne(current_chunk, CC::F::ONE);

                builder.assert_felt_eq(public_values.start_pc, public_values.next_pc);
            }
            if flag_cpu {
                let log_degree_cpu = proofs[0].log_degree_cpu();
                assert!(log_degree_cpu <= MAX_CPU_LOG_DEGREE);

                builder.assert_felt_ne(public_values.start_pc, CC::F::ZERO);
            }
        }

        /*
        Memory constraints
         */
        {
            if !flag_memory_initialize {
                for i in 0..ADDR_NUM_BITS {
                    builder.assert_felt_eq(
                        public_values.previous_initialize_addr_bits[i],
                        public_values.last_initialize_addr_bits[i],
                    );
                }
            }

            if !flag_memory_finalize {
                for i in 0..ADDR_NUM_BITS {
                    builder.assert_felt_eq(
                        public_values.previous_finalize_addr_bits[i],
                        public_values.last_finalize_addr_bits[i],
                    );
                }
            }
        }

        /*
        Completeness constraints
         */
        {
            // Assert that the last exit code is zero.
            builder.assert_felt_eq(public_values.exit_code, CC::F::ZERO);
        }

        // cumulative sum
        let mut global_cumulative_sums = Vec::new();
        global_cumulative_sums.push(builder.select_global_cumulative_sum(
            flag_first_chunk,
            riscv_vk.initial_global_cumulative_sum,
        ));
        let chips = machine
            .chunk_ordered_chips(&proofs[0].main_chip_ordering)
            .collect::<Vec<_>>();
        for (chip, values) in chips
            .iter()
            .zip(proofs[0].opened_values.chips_opened_values.iter())
        {
            if chip.lookup_scope() == LookupScope::Global {
                global_cumulative_sums.push(values.global_cumulative_sum);
            }
        }
        let global_cumulative_sum = builder.sum_digest_v2(global_cumulative_sums);

        /*
        Update public values and commit
        */
        {
            // Compute the vk digest.
            let vk_digest = riscv_vk.hash_field(builder);

            let zero: Felt<_> = builder.eval(CC::F::ZERO);

            // Initialize the public values we will commit to.
            let mut recursion_public_values_stream = [zero; RECURSION_NUM_PVS_V2];
            let recursion_public_values: &mut RecursionPublicValues<_> =
                recursion_public_values_stream.as_mut_slice().borrow_mut();

            // Update recursion public values
            recursion_public_values.committed_value_digest = public_values.committed_value_digest;
            recursion_public_values.start_pc = public_values.start_pc;
            recursion_public_values.next_pc = public_values.next_pc;
            recursion_public_values.start_chunk = public_values.chunk;
            recursion_public_values.next_chunk = current_chunk;
            recursion_public_values.start_execution_chunk = public_values.execution_chunk;
            recursion_public_values.next_execution_chunk = current_execution_chunk;
            recursion_public_values.contains_execution_chunk =
                builder.eval(CC::F::from_bool(flag_cpu));

            recursion_public_values.previous_initialize_addr_bits =
                public_values.previous_initialize_addr_bits;
            recursion_public_values.last_initialize_addr_bits =
                public_values.last_initialize_addr_bits;
            recursion_public_values.previous_finalize_addr_bits =
                public_values.previous_finalize_addr_bits;
            recursion_public_values.last_finalize_addr_bits = public_values.last_finalize_addr_bits;

            recursion_public_values.riscv_vk_digest = vk_digest;
            recursion_public_values.vk_root = vk_root;

            recursion_public_values.global_cumulative_sum = global_cumulative_sum;
            recursion_public_values.exit_code = public_values.exit_code;
            recursion_public_values.flag_complete = flag_complete;

            // Calculate the digest and set it in the public values.
            recursion_public_values.digest =
                recursion_public_values_digest::<CC, SC>(builder, recursion_public_values);

            SC::commit_recursion_public_values(builder, *recursion_public_values);
        }
    }
}
