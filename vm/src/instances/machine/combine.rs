use crate::{
    compiler::recursion_v2::{
        circuit::constraints::RecursiveVerifierConstraintFolder, program::RecursionProgram,
    },
    configs::{
        config::{StarkGenericConfig, Val},
        field_config::{bb_simple::BabyBearSimple, kb_simple::KoalaBearSimple},
        stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    },
    emulator::{
        emulator_v2::{BabyBearMetaEmulator, KoalaBearMetaEmulator},
        record::RecordBehavior,
        riscv::stdin::EmulatorStdin,
    },
    instances::compiler_v2::recursion_circuit::stdin::RecursionStdin,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::COMBINE_SIZE,
    recursion_v2::{air::RecursionPublicValues, runtime::RecursionRecord},
};
use anyhow::Result;
use p3_air::Air;
use p3_field::FieldAlgebra;
use p3_maybe_rayon::prelude::*;
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{info, instrument};

pub struct CombineMachine<SC, C>
where
    SC: StarkGenericConfig,
{
    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> CombineMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
        Val<SC>,
        Program = RecursionProgram<Val<SC>>,
        Record = RecursionRecord<Val<SC>>,
    >,
{
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>, num_public_values: usize) -> Self {
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}

macro_rules! impl_combine_machine {
    ($emul_name:ident, $recur_cc:ident, $recur_sc:ident) => {
        impl<C> MachineBehavior<$recur_sc, C, RecursionStdin<'_, $recur_sc, C>>
            for CombineMachine<$recur_sc, C>
        where
            C: ChipBehavior<
                    Val<$recur_sc>,
                    Program = RecursionProgram<Val<$recur_sc>>,
                    Record = RecursionRecord<Val<$recur_sc>>,
                > + for<'b> Air<ProverConstraintFolder<'b, $recur_sc>>
                + for<'b> Air<VerifierConstraintFolder<'b, $recur_sc>>
                + for<'b> Air<RecursiveVerifierConstraintFolder<'b, $recur_cc>>
                + Send
                + Sync,
        {
            /// Get the name of the machine.
            fn name(&self) -> String {
                format!("Combine Recursion Machine <{}>", type_name::<$recur_sc>())
            }

            /// Get the base machine.
            fn base_machine(&self) -> &BaseMachine<$recur_sc, C> {
                &self.base_machine
            }

            /// Get the prover of the machine.
            #[instrument(name = "combine_prove", level = "debug", skip_all)]
            fn prove(
                &self,
                proving_witness: &ProvingWitness<$recur_sc, C, RecursionStdin<$recur_sc, C>>,
            ) -> MetaProof<$recur_sc>
            where
                C: for<'c> Air<
                    DebugConstraintFolder<
                        'c,
                        <$recur_sc as StarkGenericConfig>::Val,
                        <$recur_sc as StarkGenericConfig>::Challenge,
                    >,
                >,
            {
                let mut recursion_emulator =
                    $emul_name::setup_combine(proving_witness, self.base_machine());
                let mut recursion_witness;
                let mut recursion_stdin;

                let mut all_proofs = vec![];
                let mut all_vks = vec![];
                let mut last_vk = proving_witness.vk.clone();
                let mut last_proof = proving_witness.proof.clone();

                let mut chunk_index = 1;
                let mut layer_index = 1;

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
                            info!("COMBINE record stats: chunk {}", record.chunk_index());
                            let stats = record.stats();
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
                    (recursion_stdin, last_vk, last_proof)  = EmulatorStdin::<
                        RecursionProgram<Val<$recur_sc>>,
                        RecursionStdin<$recur_sc, C>,
                    >::setup_for_combine::<Val<$recur_sc>, $recur_cc>(
                        proving_witness.vk_root.unwrap(),
                        &all_vks,
                        &all_proofs,
                        self.base_machine(),
                        COMBINE_SIZE,
                        all_proofs.len() <= COMBINE_SIZE,
                    );

                    recursion_witness = ProvingWitness::setup_for_recursion(
                        proving_witness.vk_root.unwrap(),
                        recursion_stdin,
                        last_vk,
                        last_proof,
                        self.config(),
                        proving_witness.opts.unwrap(),
                    );

                    recursion_emulator =
                        $emul_name::<_, _, _, _>::setup_combine(&recursion_witness, self.base_machine());

                    last_proof = recursion_witness.proof.clone();
                    last_vk = recursion_witness.vk.clone();

                    all_proofs.clear();
                    all_vks.clear();
                }

                // construct meta proof
                MetaProof::new(all_proofs.into(), all_vks.into(), None)
            }

            /// Verify the proof.
            fn verify(&self, proof: &MetaProof<$recur_sc>) -> Result<()> {
                info!("PERF-machine=combine");
                let begin = Instant::now();

                assert_eq!(proof.proofs().len(), 1);

                // assert completion

                let public_values: &RecursionPublicValues<_> =
                    proof.proofs[0].public_values.as_ref().borrow();

                if public_values.flag_complete != <Val<$recur_sc>>::ONE {
                    panic!("flag_complete is not 1");
                }

                // todo: assert public values digest

                // verify
                self.base_machine
                    .verify_ensemble(proof.vks().first().unwrap(), &proof.proofs())?;

                info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis());

                Ok(())
            }
        }
    };
}

impl_combine_machine!(BabyBearMetaEmulator, BabyBearSimple, BabyBearPoseidon2);
impl_combine_machine!(KoalaBearMetaEmulator, KoalaBearSimple, KoalaBearPoseidon2);
