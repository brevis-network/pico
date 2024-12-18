// #[cfg(feature = "debug")]
// use crate::machine::debug::constraints::IncrementalConstraintDebugger;
// #[cfg(feature = "debug-lookups")]
// use crate::machine::debug::lookups::IncrementalLookupDebugger;
use crate::{
    compiler::recursion_v2::program::RecursionProgram,
    configs::config::{Com, PcsProverData, StarkGenericConfig, Val},
    emulator::{emulator_v2::MetaEmulator, record::RecordBehavior},
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        compiler_v2::riscv_circuit::stdin::ConvertStdin,
        configs::{recur_config::StarkConfig as RecursionSC, riscv_config::StarkConfig as RiscvSC},
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        lookup::LookupScope,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    recursion_v2::{air::RecursionPublicValues, runtime::RecursionRecord},
};
use anyhow::Result;
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::Field;
use p3_maybe_rayon::prelude::*;
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{debug, info, instrument, trace};

pub struct ConvertMachine<SC, C>
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

impl<C> MachineBehavior<RecursionSC, C, ConvertStdin<'_, RiscvSC, RiscvChipType<Val<RiscvSC>>>>
    for ConvertMachine<RecursionSC, C>
where
    C: Send
        + ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'a> Air<ProverConstraintFolder<'a, RecursionSC>>
        + for<'a> Air<VerifierConstraintFolder<'a, RecursionSC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("Riscv Compress Machine <{}>", type_name::<RecursionSC>())
    }

    /// Get the base machine.
    fn base_machine(&self) -> &BaseMachine<RecursionSC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    #[instrument(name = "riscv_recursion", level = "debug", skip_all)]
    fn prove(
        &self,
        proving_witness: &ProvingWitness<
            RecursionSC,
            C,
            ConvertStdin<RiscvSC, RiscvChipType<Val<RiscvSC>>>,
        >,
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
        // setup
        let mut emulator = MetaEmulator::setup_convert(proving_witness, self.base_machine());
        let mut all_proofs = vec![];
        let mut all_vks = vec![];

        let mut chunk_index = 1;
        loop {
            let (mut batch_records, batch_pks, batch_vks, done) = emulator.next_record_keys_batch();

            self.complement_record(batch_records.as_mut_slice());

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

        // construct meta proof
        MetaProof::new(all_proofs.into(), all_vks.into())
    }

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<RecursionSC>) -> Result<()> {
        info!("PERF-machine=recursion");
        let begin = Instant::now();

        proof
            .proofs()
            .par_iter()
            .zip(proof.vks().par_iter())
            .try_for_each(|(p, vk)| {
                self.base_machine
                    .verify_ensemble(vk, std::slice::from_ref(p))
            })?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis());

        Ok(())
    }
}

impl<SC, C> ConvertMachine<SC, C>
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
