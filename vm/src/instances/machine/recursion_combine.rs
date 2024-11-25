use crate::{
    compiler::recursion::program::RecursionProgram,
    configs::config::{StarkGenericConfig, Val},
    emulator::{emulator::MetaEmulator, record::RecordBehavior, riscv::stdin::EmulatorStdin},
    instances::{
        compiler::recursion_circuit::stdin::RecursionStdin,
        configs::recur_config::StarkConfig as RecursionSC,
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::COMBINE_SIZE,
    recursion::{air::RecursionPublicValues, runtime::RecursionRecord},
};
use anyhow::Result;
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::AbstractField;
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{info, instrument, trace};

pub struct RecursionCombineMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    // vk: BaseVerifyingKey<RiscvSC>, // this is for the riscv pk
    base_machine: BaseMachine<SC, C>,
}

impl<'a, C> MachineBehavior<RecursionSC, C, RecursionStdin<'a, RecursionSC, C>>
    for RecursionCombineMachine<RecursionSC, C>
where
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("Combine Recursion Machine <{}>", type_name::<RecursionSC>())
    }

    /// Get the base machine.
    fn base_machine(&self) -> &BaseMachine<RecursionSC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    #[instrument(name = "combine_prove", level = "debug", skip_all)]
    fn prove(
        &self,
        pk: &BaseProvingKey<RecursionSC>,
        witness: &ProvingWitness<RecursionSC, C, RecursionStdin<RecursionSC, C>>,
    ) -> MetaProof<RecursionSC>
    where
        C: for<'c> Air<
            DebugConstraintFolder<
                'c,
                <RecursionSC as StarkGenericConfig>::Val,
                <RecursionSC as StarkGenericConfig>::Challenge,
            >,
        >,
    {
        info!("PERF-machine=combine");
        let begin = Instant::now();

        // First
        // Generate batch records and commit to challenger

        let mut recursion_stdin;
        let mut recursion_witness;
        let mut recursion_emulator = MetaEmulator::setup_recursion(witness, COMBINE_SIZE);

        let mut chunk_index = 1;
        let mut layer_index = 1;
        let mut all_proofs = vec![];
        let mut flag_complete = false;

        // used for collect all records for debugging
        #[cfg(feature = "debug")]
        let mut all_records = Vec::new();

        loop {
            loop {
                info!("layer {}, chunk {}", layer_index, chunk_index);
                // generate record
                let (record, done) = recursion_emulator.next();
                let mut records = vec![record];

                self.complement_record(&mut records);

                #[cfg(feature = "debug")]
                {
                    tracing::debug!("record stats");
                    let stats = records[0].stats();
                    for (key, value) in &stats {
                        tracing::debug!("{:<25}: {}", key, value);
                    }
                    if flag_complete {
                        all_records.extend_from_slice(&records);
                    }
                }

                // commit main
                let commitment = self.base_machine.commit(&records[0]);

                // setup challenger
                let mut challenger = self.config().challenger();
                pk.observed_by(&mut challenger);
                challenger.observe(commitment.commitment);
                challenger.observe_slice(&commitment.public_values[..self.num_public_values()]);

                let proof = self.base_machine.prove_plain(
                    pk,
                    &mut challenger.clone(),
                    commitment,
                    records[0].chunk_index(),
                );

                // extend all_proofs to include batch_proofs
                all_proofs.push(proof);

                if done {
                    break;
                }

                chunk_index += 1;
            }

            if flag_complete {
                info!("combine finished");
                break;
            }
            flag_complete = all_proofs.len() <= COMBINE_SIZE;

            layer_index += 1;
            chunk_index = 1;

            // more than one proofs, need to combine another round
            recursion_stdin = EmulatorStdin::setup_for_combine(
                witness.vk.unwrap(),
                self.base_machine(),
                &all_proofs,
                COMBINE_SIZE,
                all_proofs.len() <= COMBINE_SIZE,
            );

            recursion_witness = ProvingWitness::setup_for_recursion(
                witness.program.clone(),
                &recursion_stdin,
                self.config(),
                witness.vk.unwrap(),
            );

            recursion_emulator = MetaEmulator::setup_recursion(&recursion_witness, COMBINE_SIZE);

            all_proofs.clear();
        }

        info!("PERF-step=prove-user_time={}", begin.elapsed().as_millis(),);

        // construct meta proof
        let proof = MetaProof::new(all_proofs);
        let proof_size = bincode::serialize(&proof).unwrap().len();
        info!("PERF-step=proof_size-{}", proof_size);

        #[cfg(feature = "debug")]
        {
            assert_eq!(all_records.len(), 1);
            use crate::machine::debug::constraints::debug_all_constraints;
            let mut debug_challenger = self.config().challenger();
            debug_all_constraints(self.chips(), pk, &all_records, &mut debug_challenger);
        }

        #[cfg(feature = "debug-lookups")]
        {
            use crate::machine::debug::lookups::DebugLookup;
            DebugLookup::debug_all_lookups(self.chips(), pk, &all_records, None);
        }

        proof
    }

    /// Verify the proof.
    fn verify(
        &self,
        combine_vk: &BaseVerifyingKey<RecursionSC>, // note that this is the vk of riscv machine
        proof: &MetaProof<RecursionSC>,
    ) -> Result<()> {
        info!("PERF-machine=combine");
        let begin = Instant::now();

        assert_eq!(proof.proofs().len(), 1);

        let public_values: &RecursionPublicValues<_> =
            proof.proofs[0].public_values.as_slice().borrow();
        trace!("public values: {:?}", public_values);

        // assert completion
        if public_values.flag_complete != <Val<RecursionSC>>::one() {
            panic!("flag_complete is not 1");
        }

        // verify
        self.base_machine
            .verify_ensemble(combine_vk, proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis());

        Ok(())
    }
}

impl<SC, C> RecursionCombineMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>, num_public_values: usize) -> Self {
        info!("PERF-machine=combine");
        Self {
            // vk,
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
