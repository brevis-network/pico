use crate::{
    compiler::recursion_v2::program::RecursionProgram,
    configs::{
        config::{StarkGenericConfig, Val},
        stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    },
    emulator::{
        emulator_v2::{BabyBearMetaEmulator, KoalaBearMetaEmulator},
        record::RecordBehavior,
        recursion::emulator::RecursionRecord,
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType, compiler_v2::riscv_circuit::stdin::ConvertStdin,
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
};
use anyhow::Result;
use p3_air::Air;
use p3_maybe_rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::{any::type_name, time::Instant};
use tracing::{info, instrument};

pub struct ConvertMachine<SC, C>
where
    SC: StarkGenericConfig,
{
    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> ConvertMachine<SC, C>
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

macro_rules! impl_convert_machine {
    ($emul_name:ident, $riscv_sc:ident, $recur_cc:ident, $recur_sc:ident) => {
        impl<C>
            MachineBehavior<$recur_sc, C, ConvertStdin<$riscv_sc, RiscvChipType<Val<$riscv_sc>>>>
            for ConvertMachine<$recur_sc, C>
        where
            C: Send
                + ChipBehavior<
                    Val<$recur_sc>,
                    Program = RecursionProgram<Val<$recur_sc>>,
                    Record = RecursionRecord<Val<$recur_sc>>,
                >,
        {
            /// Get the name of the machine.
            fn name(&self) -> String {
                format!("Riscv Compress Machine <{}>", type_name::<$recur_sc>())
            }

            /// Get the base machine.
            fn base_machine(&self) -> &BaseMachine<$recur_sc, C> {
                &self.base_machine
            }

            /// Get the prover of the machine.
            #[instrument(name = "riscv_recursion", level = "debug", skip_all)]
            fn prove(
                &self,
                proving_witness: &ProvingWitness<
                    $recur_sc,
                    C,
                    ConvertStdin<$riscv_sc, RiscvChipType<Val<$riscv_sc>>>,
                >,
            ) -> MetaProof<$recur_sc>
            where
                C: for<'a> Air<
                        DebugConstraintFolder<
                            'a,
                            <$recur_sc as StarkGenericConfig>::Val,
                            <$recur_sc as StarkGenericConfig>::Challenge,
                        >,
                    > + for<'a> Air<ProverConstraintFolder<'a, $recur_sc>>,
            {
                // setup
                let mut emulator = $emul_name::setup_convert(proving_witness, self.base_machine());
                let mut all_proofs = vec![];
                let mut all_vks = vec![];

                let mut batch_num = 1;
                let mut chunk_index = 1;
                loop {
                    let start = Instant::now();
                    let (mut batch_records, batch_pks, batch_vks, done) =
                        emulator.next_record_keys_batch();

                    self.complement_record(batch_records.as_mut_slice());

                    info!(
                        "--- Generate convert records for batch {}, chunk {}-{} in {:?}",
                        batch_num,
                        chunk_index,
                        chunk_index + batch_records.len() as u32 - 1,
                        start.elapsed()
                    );

                    // set index for each record
                    for record in batch_records.as_mut_slice() {
                        record.index = chunk_index;
                        chunk_index += 1;
                        info!("CONVERT record stats: chunk {}", record.chunk_index());
                        let stats = record.stats();
                        for (key, value) in &stats {
                            info!("   |- {:<28}: {}", key, value);
                        }
                    }

                    let batch_proofs = batch_records
                        .par_iter()
                        .zip(batch_pks.par_iter())
                        .flat_map(|(record, pk)| {
                            let start_chunk = Instant::now();
                            let proof = self
                                .base_machine
                                .prove_ensemble(pk, std::slice::from_ref(record));
                            info!(
                                "--- Prove convert chunk {} in {:?}",
                                record.chunk_index(),
                                start_chunk.elapsed()
                            );
                            proof
                        })
                        .collect::<Vec<_>>();

                    all_proofs.extend(batch_proofs);
                    all_vks.extend(batch_vks);

                    info!(
                        "--- Finish convert batch {} in {:?}",
                        batch_num,
                        start.elapsed()
                    );
                    batch_num += 1;

                    if done {
                        break;
                    }
                }

                // construct meta proof
                info!("CONVERT chip log degrees:");
                all_proofs.iter().enumerate().for_each(|(i, proof)| {
                    info!("Proof {}", i);
                    proof
                        .main_chip_ordering
                        .iter()
                        .for_each(|(chip_name, idx)| {
                            info!(
                                "   |- {:<20} main: {:<8}",
                                chip_name,
                                proof.opened_values.chips_opened_values[*idx].log_main_degree,
                            );
                        });
                });

                MetaProof::new(all_proofs.into(), all_vks.into(), None)
            }

            /// Verify the proof.
            fn verify(&self, proof: &MetaProof<$recur_sc>) -> Result<()>
            where
                C: for<'a> Air<VerifierConstraintFolder<'a, $recur_sc>>,
            {
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
    };
}

impl_convert_machine!(
    BabyBearMetaEmulator,
    BabyBearPoseidon2,
    BabyBearSimple,
    BabyBearPoseidon2
);
impl_convert_machine!(
    KoalaBearMetaEmulator,
    KoalaBearPoseidon2,
    KoalaBearSimple,
    KoalaBearPoseidon2
);
