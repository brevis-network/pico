use crate::{
    compiler::recursion_v2::{
        circuit::constraints::RecursiveVerifierConstraintFolder, program::RecursionProgram,
    },
    configs::config::{Com, PcsProverData, StarkGenericConfig, Val},
    emulator::{emulator_v2::MetaEmulator, record::RecordBehavior, riscv::stdin::EmulatorStdin},
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::{
            shapes::compress_shape::RecursionShapeConfig,
            vk_merkle::{stdin::RecursionVkStdin, VkMerkleManager},
        },
        configs::recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{COMBINE_DEGREE, COMBINE_SIZE},
    recursion_v2::{air::RecursionPublicValues, runtime::RecursionRecord},
};
use anyhow::Result;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use p3_maybe_rayon::prelude::*;
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{info, instrument};

pub struct CombineVkMachine<SC, C>
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

impl<C> MachineBehavior<RecursionSC, C, RecursionVkStdin<'_, RecursionSC, C>>
    for CombineVkMachine<RecursionSC, C>
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
        format!(
            "CombineVk Recursion Machine <{}>",
            type_name::<RecursionSC>()
        )
    }

    /// Get the base machine.
    fn base_machine(&self) -> &BaseMachine<RecursionSC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    #[instrument(name = "combine_prove", level = "debug", skip_all)]
    fn prove(
        &self,
        proving_witness: &ProvingWitness<RecursionSC, C, RecursionVkStdin<RecursionSC, C>>,
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
            MetaEmulator::setup_combine_vk(proving_witness, self.base_machine());
        let mut recursion_witness;
        let mut recursion_stdin;

        let mut all_proofs = vec![];
        let mut all_vks = vec![];
        let mut last_vk = proving_witness.vk.clone();
        let mut last_proof = proving_witness.proof.clone();

        let mut chunk_index = 1;
        let mut layer_index = 1;
        // TODO: vk_manager as a input parameters or static value
        let vk_manager = VkMerkleManager::new_from_file("vk_map.bin").unwrap();
        let recursion_shape_config =
            RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear, COMBINE_DEGREE>>::default(
            );

        loop {
            let mut batch_num = 1;
            let start_layer = Instant::now();
            loop {
                let start_batch = Instant::now();
                if proving_witness.flag_empty_stdin {
                    break;
                }

                let (mut batch_records, batch_pks, batch_vks, done) =
                    recursion_emulator.next_record_keys_batch();

                self.complement_record(batch_records.as_mut_slice());

                info!(
                    "--- Generate combine records for layer {}, batch {}, chunk {}-{} in {:?}",
                    layer_index,
                    batch_num,
                    chunk_index,
                    chunk_index + batch_records.len() as u32 - 1,
                    start_batch.elapsed()
                );

                // set index for each record
                for record in batch_records.as_mut_slice() {
                    record.index = chunk_index;
                    chunk_index += 1;
                    let stats = record.stats();
                    info!("COMBINE record stats: chunk {}", record.chunk_index());
                    for (key, value) in &stats {
                        info!("   |- {:<28}: {}", key, value);
                    }
                }

                // prove records in parallel
                let batch_proofs = batch_records
                    .par_iter()
                    .zip(batch_pks.par_iter())
                    .flat_map(|(record, pk)| {
                        let start_chunk = Instant::now();
                        let proof = self
                            .base_machine
                            .prove_ensemble(pk, std::slice::from_ref(record));
                        info!(
                            "--- Prove combine layer {} chunk {} in {:?}",
                            layer_index,
                            record.chunk_index(),
                            start_chunk.elapsed()
                        );
                        proof
                    })
                    .collect::<Vec<_>>();

                all_proofs.extend(batch_proofs);
                all_vks.extend(batch_vks);

                info!(
                    "--- Finish combine batch {} of layer {} in {:?}",
                    batch_num,
                    layer_index,
                    start_batch.elapsed()
                );

                batch_num += 1;
                if done {
                    break;
                }
            }

            info!(
                "--- Finish combine layer {} in {:?}",
                layer_index,
                start_layer.elapsed()
            );

            if last_proof.is_some() {
                all_vks.push(last_vk.unwrap());
                all_proofs.push(last_proof.unwrap());
            }

            if all_proofs.len() == 1 {
                info!("recursion combine finished");
                break;
            }

            layer_index += 1;
            chunk_index = 1;

            // more than one proofs, need to combine another round
            (recursion_stdin, last_vk, last_proof) = EmulatorStdin::setup_for_combine_vk(
                proving_witness.vk_root.unwrap(),
                &all_vks,
                &all_proofs,
                self.base_machine(),
                COMBINE_SIZE,
                all_proofs.len() <= COMBINE_SIZE,
                &vk_manager,
                &recursion_shape_config,
            );

            recursion_witness = ProvingWitness::setup_for_recursion_vk(
                proving_witness.vk_root.unwrap(),
                recursion_stdin,
                last_vk,
                last_proof,
                self.config(),
                proving_witness.opts.unwrap(),
            );

            recursion_emulator =
                MetaEmulator::setup_combine_vk(&recursion_witness, self.base_machine());

            last_proof = recursion_witness.proof.clone();
            last_vk = recursion_witness.vk.clone();

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
            .verify_ensemble(proof.vks().first().unwrap(), &proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis());

        Ok(())
    }
}

impl<SC, C> CombineVkMachine<SC, C>
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
