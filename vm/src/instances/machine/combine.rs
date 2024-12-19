use crate::{
    compiler::recursion_v2::{
        circuit::constraints::RecursiveVerifierConstraintFolder, program::RecursionProgram,
    },
    configs::config::{Com, PcsProverData, StarkGenericConfig, Val},
    emulator::{emulator_v2::MetaEmulator, record::RecordBehavior, riscv::stdin::EmulatorStdin},
    instances::{
        compiler_v2::recursion_circuit::stdin::RecursionStdin,
        configs::recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey, HashableKey},
        lookup::LookupScope,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::COMBINE_SIZE,
    recursion_v2::{air::RecursionPublicValues, runtime::RecursionRecord},
};
use anyhow::Result;
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::FieldAlgebra;
use p3_maybe_rayon::prelude::*;
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{debug, info, instrument, trace};

pub struct CombineMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    base_machine: BaseMachine<SC, C>,
}

impl<C> MachineBehavior<RecursionSC, C, RecursionStdin<'_, RecursionSC, C>>
    for CombineMachine<RecursionSC, C>
where
    C: Send
        + ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<RecursiveVerifierConstraintFolder<'b, RecursionFC>>,
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
        proving_witness: &ProvingWitness<RecursionSC, C, RecursionStdin<RecursionSC, C>>,
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
        let mut recursion_emulator =
            MetaEmulator::setup_combine(proving_witness, self.base_machine());
        let mut recursion_witness;
        let mut recursion_stdin;

        let mut all_proofs = vec![];
        let mut all_vks = vec![];

        let mut chunk_index = 1;
        let mut layer_index = 1;
        let mut flag_complete = false;

        loop {
            loop {
                let (mut batch_records, batch_pks, batch_vks, done) =
                    recursion_emulator.next_record_keys_batch();

                self.complement_record(batch_records.as_mut_slice());

                info!(
                    "recursion combine layer {}, chunk {}-{}",
                    layer_index,
                    chunk_index,
                    chunk_index + batch_records.len() as u32 - 1
                );

                // set index for each record
                for record in batch_records.as_mut_slice() {
                    record.index = chunk_index;
                    chunk_index += 1;
                    debug!(
                        "riscv recursion record stats: chunk {}",
                        record.chunk_index()
                    );
                    let stats = record.stats();
                    for (key, value) in &stats {
                        debug!("   |- {:<28}: {}", key, value);
                    }
                }

                // prove records in parallel
                // todo optimize: check parallelism is proper
                let batch_proofs = batch_records
                    .par_iter()
                    .zip(batch_pks.par_iter())
                    .flat_map(|(record, pk)| {
                        self.base_machine
                            .prove_ensemble(pk, std::slice::from_ref(record))
                    })
                    .collect::<Vec<_>>();

                all_proofs.extend(batch_proofs);
                all_vks.extend(batch_vks);

                if done {
                    break;
                }
            }

            if flag_complete {
                info!("recursion combine finished");
                break;
            }

            flag_complete = all_proofs.len() <= COMBINE_SIZE;

            layer_index += 1;
            chunk_index = 1;

            // more than one proofs, need to combine another round
            recursion_stdin = EmulatorStdin::setup_for_combine(
                proving_witness.vk_root.unwrap(),
                &all_vks,
                &all_proofs,
                self.base_machine(),
                COMBINE_SIZE,
                flag_complete,
            );

            recursion_witness = ProvingWitness::setup_for_recursion(
                proving_witness.vk_root.unwrap(),
                recursion_stdin,
                self.config(),
                proving_witness.opts.unwrap(),
            );

            recursion_emulator =
                MetaEmulator::setup_combine(&recursion_witness, self.base_machine());

            all_proofs.clear();
            all_vks.clear();
        }

        // construct meta proof
        MetaProof::new(all_proofs.into(), all_vks.into())
    }

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<RecursionSC>) -> Result<()> {
        info!("PERF-machine=combine");
        let begin = Instant::now();

        assert_eq!(proof.proofs().len(), 1);

        // assert completion

        let public_values: &RecursionPublicValues<_> =
            proof.proofs[0].public_values.as_ref().borrow();

        if public_values.flag_complete != <Val<RecursionSC>>::ONE {
            panic!("flag_complete is not 1");
        }

        // verify
        self.base_machine
            .verify_ensemble(proof.vks().first().unwrap(), proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis());

        Ok(())
    }
}

impl<SC, C> CombineMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>, num_public_values: usize) -> Self {
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
