use crate::{
    compiler::recursion::program::RecursionProgram,
    configs::{
        config::{StarkGenericConfig, Val},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    cuda_adaptor::setup_keys_gm::BaseProvingKeyCuda,
    emulator::{
        emulator::{BabyBearMetaEmulator, KoalaBearMetaEmulator},
        record::RecordBehavior,
        recursion::{emulator::RecursionRecord, public_values::RecursionPublicValues},
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType, compiler::riscv_circuit::stdin::ConvertStdin,
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::HashableKey,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        utils::{assert_recursion_public_values_valid, assert_riscv_vk_digest},
        witness::ProvingWitness,
    },
};
use anyhow::Result;
use cudart::{memory_pools::CudaMemPool, stream::CudaStream};
use p3_air::Air;
use p3_maybe_rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{debug, debug_span, info, instrument};

pub struct ConvertMachine<SC, C>
where
    SC: StarkGenericConfig,
{
    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> ConvertMachine<SC, C>
where
    SC: StarkGenericConfig + 'static,
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
                format!("Convert Machine <{}>", type_name::<$recur_sc>())
            }

            /// Get the base machine.
            fn base_machine(&self) -> &BaseMachine<$recur_sc, C> {
                &self.base_machine
            }

            /// Get the prover of the machine.
            #[instrument(name = "CONVERT MACHINE PROVE", level = "debug", skip_all)]
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
                    > + Air<ProverConstraintFolder<$recur_sc>>,
            {
                // setup
                let mut emulator = $emul_name::setup_convert(proving_witness, self.base_machine());
                let mut all_proofs = vec![];
                let mut all_vks = vec![];

                let mut batch_num = 1;
                let mut chunk_index = 1;
                loop {
                    let loop_span = debug_span!(parent: &tracing::Span::current(), "convert batch prove loop", batch_num).entered();
                    let start = Instant::now();
                    let (mut batch_records, batch_pks, batch_vks, done) =
                    debug_span!("emulate_batch_records").in_scope(|| {emulator.next_record_keys_batch()});

                    debug_span!("complement_record").in_scope(|| {self.complement_record(batch_records.as_mut_slice())});

                    debug!(
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
                        debug!("CONVERT record stats: chunk {}", record.chunk_index());
                        let stats = record.stats();
                        for (key, value) in &stats {
                            debug!("   |- {:<28}: {}", key, value);
                        }
                    }

                    let batch_proofs = batch_records
                        .par_iter()
                        .zip(batch_pks.par_iter())
                        .flat_map(|(record, pk)| {
                            let start_chunk = Instant::now();
                            let proof = debug_span!(parent: &loop_span, "prove_ensemble", chunk_index = record.chunk_index()).in_scope(||{
                                self
                                .base_machine
                                .prove_ensemble(pk, std::slice::from_ref(record))
                            });
                            debug!(
                                "--- Prove convert chunk {} in {:?}",
                                record.chunk_index(),
                                start_chunk.elapsed()
                            );
                            proof
                        })
                        .collect::<Vec<_>>();

                    all_proofs.extend(batch_proofs);
                    all_vks.extend(batch_vks);

                    debug!(
                        "--- Finish convert batch {} in {:?}",
                        batch_num,
                        start.elapsed()
                    );
                    batch_num += 1;

                    if done {
                        break;
                    }

                    loop_span.exit();
                }

                // construct meta proof
                debug!("CONVERT chip log degrees:");
                all_proofs.iter().enumerate().for_each(|(i, proof)| {
                    debug!("Proof {}", i);
                    proof
                        .main_chip_ordering
                        .iter()
                        .for_each(|(chip_name, idx)| {
                            debug!(
                                "   |- {:<20} main: {:<8}",
                                chip_name,
                                proof.opened_values.chips_opened_values[*idx].log_main_degree,
                            );
                        });
                });

                MetaProof::new(all_proofs.into(), all_vks.into(), None)
            }

            fn prove_cuda(
                &self,
                proving_witness: &ProvingWitness<
                    $recur_sc,
                    C,
                    ConvertStdin<$riscv_sc, RiscvChipType<Val<$riscv_sc>>>,
                >,
                _pk_cuda: Option<&BaseProvingKeyCuda<$recur_sc>>,
                stream: &'static CudaStream,
                mem_pool: & CudaMemPool,
                dev_id: usize,
            ) -> MetaProof<$recur_sc>
            where
                C: for<'a> Air<
                        DebugConstraintFolder<
                            'a,
                            <$recur_sc as StarkGenericConfig>::Val,
                            <$recur_sc as StarkGenericConfig>::Challenge,
                        >,
                    > + Air<ProverConstraintFolder<$recur_sc>>,
            {
                // setup
                let mut emulator = $emul_name::setup_convert(proving_witness, self.base_machine());
                let mut all_proofs = vec![];
                let mut all_vks = vec![];

                let mut batch_num = 1;
                let mut chunk_index = 1;
                loop {
                    let loop_span = debug_span!(parent: &tracing::Span::current(), "convert batch prove loop", batch_num).entered();
                    let start = Instant::now();
                    let (mut batch_records, batch_vks, done, batch_pks_cuda) =
                    debug_span!("emulate_batch_records").in_scope(|| {emulator.next_record_keys_batch_cuda(stream, mem_pool, dev_id)});

                    debug_span!("complement_record").in_scope(|| {self.complement_record(batch_records.as_mut_slice())});

                    debug!(
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
                        debug!("CONVERT record stats: chunk {}", record.chunk_index());
                        let stats = record.stats();
                        for (key, value) in &stats {
                            debug!("   |- {:<28}: {}", key, value);
                        }
                    }

                    let start = Instant::now();
                    let batch_proofs = batch_records
                        .iter()
                        .zip(batch_pks_cuda.iter())
                        .flat_map(|(record, pk_cuda)| {
                            let start_chunk = Instant::now();
                            let proof = debug_span!(parent: &loop_span, "prove_ensemble", chunk_index = record.chunk_index()).in_scope(||{
                                self
                                .base_machine
                                .prove_ensemble_cuda(std::slice::from_ref(record), pk_cuda, stream, mem_pool, dev_id)
                            });
                            debug!(
                                "--- Prove convert chunk {} in {:?}",
                                record.chunk_index(),
                                start_chunk.elapsed()
                            );
                            proof
                        })
                        .collect::<Vec<_>>();
                    println!("self.base_machine.prove_ensemble_cuda: {:?}", start.elapsed());

                    all_proofs.extend(batch_proofs);
                    all_vks.extend(batch_vks);

                    debug!(
                        "--- Finish convert batch {} in {:?}",
                        batch_num,
                        start.elapsed()
                    );
                    batch_num += 1;

                    if done {
                        break;
                    }

                    loop_span.exit();
                }

                // construct meta proof
                debug!("CONVERT chip log degrees:");
                all_proofs.iter().enumerate().for_each(|(i, proof)| {
                    debug!("Proof {}", i);
                    proof
                        .main_chip_ordering
                        .iter()
                        .for_each(|(chip_name, idx)| {
                            debug!(
                                "   |- {:<20} main: {:<8}",
                                chip_name,
                                proof.opened_values.chips_opened_values[*idx].log_main_degree,
                            );
                        });
                });

                MetaProof::new(all_proofs.into(), all_vks.into(), None)
            }

            /// Verify the proof.
            fn verify(
                &self,
                proof: &MetaProof<$recur_sc>,
                riscv_vk: &dyn HashableKey<Val<$recur_sc>>,
            ) -> Result<()>
            where
                C: for<'a> Air<VerifierConstraintFolder<'a, $recur_sc>>,
            {
                assert_riscv_vk_digest(proof, riscv_vk);

                proof
                    .proofs()
                    .par_iter()
                    .zip(proof.vks().par_iter())
                    .try_for_each(|(p, vk)| {
                        let public_values: &RecursionPublicValues<_> =
                            p.public_values.as_ref().borrow();
                        assert_recursion_public_values_valid(self.config().as_ref(), public_values);

                        self.base_machine
                            .verify_ensemble(vk, std::slice::from_ref(p))
                    })?;

                Ok(())
            }
        }
    };
}

macro_rules! impl_indexed_convert_machine {
    ($emul_name:ident, $riscv_sc:ident, $recur_cc:ident, $recur_sc:ident) => {
        impl<C> ConvertMachine<$recur_sc, C>
        where
            C: Send
                + ChipBehavior<
                    Val<$recur_sc>,
                    Program = RecursionProgram<Val<$recur_sc>>,
                    Record = RecursionRecord<Val<$recur_sc>>,
                >,
        {
             /// Get the prover of the machine.
            #[instrument(name = "CONVERT MACHINE PROVE", level = "debug", skip_all)]
            pub fn prove_with_index(
                &self,
                chunk_index: u32,
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
                    > + Air<ProverConstraintFolder<$recur_sc>>,
            {
                // setup
                let mut emulator = $emul_name::setup_convert(proving_witness, self.base_machine());
                let mut all_proofs = vec![];
                let mut all_vks = vec![];

                let mut chunk_index = chunk_index + 1;
                info!("chunk_index in prove_with_index: {}", chunk_index);

                let convert_span = debug_span!(parent: &tracing::Span::current(), "convert prove").entered();
                let start = Instant::now();

                let (mut batch_records, batch_pks, batch_vks, done) =
                    debug_span!("emulate_batch_records").in_scope(|| {emulator.next_record_keys_batch()});

                assert_eq!(batch_records.len(), 1);
                assert_eq!(batch_pks.len(), 1);
                assert_eq!(batch_vks.len(), 1);
                assert_eq!(done, true);

                debug_span!("complement_record").in_scope(|| {self.complement_record(batch_records.as_mut_slice())});

                info!(
                        "--- Generate convert records, chunk {}-{} in {:?}",
                        chunk_index,
                        chunk_index + batch_records.len() as u32 - 1,
                        start.elapsed()
                    );

                // set index for each record
                for record in batch_records.as_mut_slice() {
                    record.index = chunk_index;
                    chunk_index += 1;
                    debug!("CONVERT record stats: chunk {}", record.chunk_index());
                    let stats = record.stats();
                    for (key, value) in &stats {
                        debug!("   |- {:<28}: {}", key, value);
                    }
                }

                let batch_proofs = batch_records
                        .par_iter()
                        .zip(batch_pks.par_iter())
                        .flat_map(|(record, pk)| {
                            let start_chunk = Instant::now();
                            let proof = debug_span!(parent: &convert_span, "prove_ensemble", chunk_index = record.chunk_index()).in_scope(||{
                                self
                                .base_machine
                                .prove_ensemble(pk, std::slice::from_ref(record))
                            });
                            debug!(
                                "--- Prove convert chunk {} in {:?}",
                                record.chunk_index(),
                                start_chunk.elapsed()
                            );
                            proof
                        })
                        .collect::<Vec<_>>();

                    all_proofs.extend(batch_proofs);
                    all_vks.extend(batch_vks);

                debug!(
                        "--- Finish convert chunk {} in {:?}",
                        chunk_index,
                        start.elapsed()
                    );

                // construct meta proof
                debug!("CONVERT chip log degrees:");
                all_proofs.iter().enumerate().for_each(|(i, proof)| {
                    debug!("Proof {}", i);
                    proof
                        .main_chip_ordering
                        .iter()
                        .for_each(|(chip_name, idx)| {
                            debug!(
                                "   |- {:<20} main: {:<8}",
                                chip_name,
                                proof.opened_values.chips_opened_values[*idx].log_main_degree,
                            );
                        });
                });

                MetaProof::new(all_proofs.into(), all_vks.into(), None)
            }

            pub fn prove_with_index_cuda(
                &self,
                chunk_index: u32,
                proving_witness: &ProvingWitness<
                    $recur_sc,
                    C,
                    ConvertStdin<$riscv_sc, RiscvChipType<Val<$riscv_sc>>>,
                >,
                stream: &'static CudaStream,
                mem_pool: & CudaMemPool,
                dev_id: usize,
            ) -> MetaProof<$recur_sc>
            where
                C: for<'a> Air<
                        DebugConstraintFolder<
                            'a,
                            <$recur_sc as StarkGenericConfig>::Val,
                            <$recur_sc as StarkGenericConfig>::Challenge,
                        >,
                    > + Air<ProverConstraintFolder<$recur_sc>>,
            {
                // setup
                let mut emulator = $emul_name::setup_convert(proving_witness, self.base_machine());
                let mut all_proofs = vec![];
                let mut all_vks = vec![];

                let mut chunk_index = chunk_index + 1;
                info!("chunk_index in prove_with_index: {}", chunk_index);

                let convert_span = debug_span!(parent: &tracing::Span::current(), "convert prove").entered();
                let start = Instant::now();

                let (mut batch_records, batch_vks, done, batch_pks_cuda) =
                    debug_span!("emulate_batch_records").in_scope(|| {emulator.next_record_keys_batch_cuda(stream, mem_pool, dev_id)});

                assert_eq!(batch_records.len(), 1);
                assert_eq!(batch_pks_cuda.len(), 1);
                assert_eq!(batch_vks.len(), 1);
                assert_eq!(done, true);

                debug_span!("complement_record").in_scope(|| {self.complement_record(batch_records.as_mut_slice())});

                info!(
                        "--- Generate convert records, chunk {}-{} in {:?}",
                        chunk_index,
                        chunk_index + batch_records.len() as u32 - 1,
                        start.elapsed()
                    );

                // set index for each record
                for record in batch_records.as_mut_slice() {
                    record.index = chunk_index;
                    chunk_index += 1;
                    debug!("CONVERT record stats: chunk {}", record.chunk_index());
                    let stats = record.stats();
                    for (key, value) in &stats {
                        debug!("   |- {:<28}: {}", key, value);
                    }
                }

                let batch_proofs = batch_records
                    .iter()
                    .zip(batch_pks_cuda.iter())
                    .flat_map(|(record, pk_cuda)| {
                        let start_chunk = Instant::now();
                        let proof = debug_span!(parent: &convert_span, "prove_ensemble", chunk_index = record.chunk_index()).in_scope(||{
                            self
                            .base_machine
                            .prove_ensemble_cuda(std::slice::from_ref(record), pk_cuda, stream, mem_pool, dev_id)
                        });
                        debug!(
                            "--- Prove convert chunk {} in {:?}",
                            record.chunk_index(),
                            start_chunk.elapsed()
                        );
                        proof
                    })
                    .collect::<Vec<_>>();

                all_proofs.extend(batch_proofs);
                all_vks.extend(batch_vks);

                debug!(
                        "--- Finish convert chunk {} in {:?}",
                        chunk_index,
                        start.elapsed()
                    );

                // construct meta proof
                debug!("CONVERT chip log degrees:");
                all_proofs.iter().enumerate().for_each(|(i, proof)| {
                    debug!("Proof {}", i);
                    proof
                        .main_chip_ordering
                        .iter()
                        .for_each(|(chip_name, idx)| {
                            debug!(
                                "   |- {:<20} main: {:<8}",
                                chip_name,
                                proof.opened_values.chips_opened_values[*idx].log_main_degree,
                            );
                        });
                });

                MetaProof::new(all_proofs.into(), all_vks.into(), None)
            }
        }
    }
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

impl_indexed_convert_machine!(
    BabyBearMetaEmulator,
    BabyBearPoseidon2,
    BabyBearSimple,
    BabyBearPoseidon2
);

impl_indexed_convert_machine!(
    KoalaBearMetaEmulator,
    KoalaBearPoseidon2,
    KoalaBearSimple,
    KoalaBearPoseidon2
);
