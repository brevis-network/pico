use crate::{
    compiler::recursion::{
        circuit::constraints::RecursiveVerifierConstraintFolder, program::RecursionProgram,
    },
    configs::{
        config::{Com, FieldGenericConfig, PcsProverData, StarkGenericConfig, Val},
        field_config::{BabyBearSimple, KoalaBearSimple},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    cuda_adaptor::setup_keys_gm::BaseProvingKeyCuda,
    emulator::{
        emulator::{BabyBearMetaEmulator, KoalaBearMetaEmulator},
        record::RecordBehavior,
        recursion::{emulator::RecursionRecord, public_values::RecursionPublicValues},
        stdin::EmulatorStdin,
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            shapes::recursion_shape::RecursionShapeConfig,
            vk_merkle::{
                stdin::RecursionStdinVariant, vk_verification_enabled, HasStaticVkManager,
            },
        },
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
    primitives::consts::{COMBINE_SIZE, DIGEST_SIZE},
};
use anyhow::Result;
use cudart::{memory_pools::CudaMemPool, stream::CudaStream};
use p3_air::Air;
use p3_field::FieldAlgebra;
use p3_maybe_rayon::prelude::*;
use std::{any::type_name, borrow::Borrow, sync::Arc, time::Instant};
use tracing::{debug, debug_span, info, instrument};

pub struct CombineMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
        Val<SC>,
        Program = RecursionProgram<Val<SC>>,
        Record = RecursionRecord<Val<SC>>,
    >,
{
    base_machine: BaseMachine<SC, C>,
}

macro_rules! impl_combine_machine {
    ($emul_name:ident, $recur_cc:ident, $recur_sc:ident) => {
        impl<C> MachineBehavior<$recur_sc, C, RecursionStdinVariant<'_, $recur_sc, C>>
            for CombineMachine<$recur_sc, C>
        where
            C: Send + Sync
                + ChipBehavior<
                    Val<$recur_sc>,
                    Program = RecursionProgram<Val<$recur_sc>>,
                    Record = RecursionRecord<Val<$recur_sc>>,
                > + Air<ProverConstraintFolder<$recur_sc>>
                + for<'b> Air<VerifierConstraintFolder<'b, $recur_sc>>
                + for<'b> Air<RecursiveVerifierConstraintFolder<'b, $recur_cc>>,
        {
            /// Get the name of the machine.
            fn name(&self) -> String {
                format!("Combine Machine <{}>", type_name::<$recur_sc>())
            }

            /// Get the base machine.
            fn base_machine(&self) -> &BaseMachine<$recur_sc, C> {
                &self.base_machine
            }

            /// Get the prover of the machine.
            #[instrument(name = "COMBINE MACHINE PROVE", level = "debug", skip_all)]
            fn prove(
                &self,
                proving_witness: &ProvingWitness<$recur_sc, C, RecursionStdinVariant<$recur_sc, C>>,
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
                let mut recursion_emulator = $emul_name::<
                    _,
                    _,
                    _,
                    _,
                >::setup_combine(
                    proving_witness, self.base_machine()
                );
                let mut recursion_witness;
                let mut recursion_stdin;

                let mut all_proofs = vec![];
                let mut all_vks = vec![];
                let mut last_vk = proving_witness.vk.clone();
                let mut last_proof = proving_witness.proof.clone();

                let mut chunk_index = 1;
                let mut layer_index = 1;
                // TODO: move recursion_shape_config creation in higher level functions
                let vk_manager = <$recur_sc as HasStaticVkManager>::static_vk_manager();
                let recursion_shape_config = RecursionShapeConfig::<
                    Val<$recur_sc>,
                    RecursionChipType<Val<$recur_sc>>,
                >::default();

                loop {
                    let mut batch_num = 1;
                    let start_layer = Instant::now();
                    let layer_span = debug_span!(parent: &tracing::Span::current(), "combine layer", layer_index).entered();
                    loop {
                        let loop_span = debug_span!(parent: &tracing::Span::current(), "combine batch prove loop", batch_num).entered();
                        let start_batch = Instant::now();
                        if proving_witness.flag_empty_stdin {
                            break;
                        }

                        let (mut batch_records, batch_pks, batch_vks, done) =
                        debug_span!("emulate_batch_records", layer_index).in_scope(|| { recursion_emulator.next_record_keys_batch() });


                        debug_span!("complement record").in_scope(|| {self.complement_record(batch_records.as_mut_slice())});

                        debug!(
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
                            debug!("COMBINE record stats: chunk {}", record.chunk_index());
                            let stats = record.stats();
                            for (key, value) in &stats {
                                debug!("   |- {:<28}: {}", key, value);
                            }
                        }

                        // prove records in parallel
                        let batch_proofs = batch_records
                            .par_iter()
                            .zip(batch_pks.par_iter())
                            .flat_map(|(record, pk)| {
                                let start_chunk = Instant::now();
                                let proof = debug_span!(parent: &loop_span, "prove_ensemble", layer_index, chunk_index = record.chunk_index()).in_scope(|| {
                                self
                                    .base_machine
                                    .prove_ensemble(pk, std::slice::from_ref(record))});
                                debug!(
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

                        debug!(
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

                    debug!(
                        "--- Finish combine layer {} in {:?}",
                        layer_index,
                        start_layer.elapsed()
                    );

                    if last_proof.is_some() {
                        all_vks.push(last_vk.unwrap());
                        all_proofs.push(last_proof.unwrap());
                    }

                    if all_proofs.len() == 1 {
                        break;
                    }

                    layer_index += 1;
                    chunk_index = 1;

                    // more than one proofs, need to combine another round
                    (recursion_stdin, last_vk, last_proof) = EmulatorStdin::setup_for_combine::<
                        <$recur_cc as FieldGenericConfig>::F,
                        $recur_cc,
                    >(
                        proving_witness.vk_root.unwrap(),
                        &all_vks,
                        &all_proofs,
                        self.base_machine(),
                        COMBINE_SIZE,
                        all_proofs.len() <= COMBINE_SIZE,
                        &vk_manager,
                        Some(&recursion_shape_config),
                    );

                    recursion_witness = ProvingWitness::setup_for_combine(
                        proving_witness.vk_root.unwrap(),
                        recursion_stdin,
                        last_vk,
                        last_proof,
                        self.config(),
                        proving_witness.opts.unwrap(),
                    );

                    recursion_emulator =
                        $emul_name::setup_combine(&recursion_witness, self.base_machine());

                    last_proof = recursion_witness.proof.clone();
                    last_vk = recursion_witness.vk.clone();

                    all_proofs.clear();
                    all_vks.clear();
                    layer_span.exit();
                }

                // proof stats
                info!("COMBINE chip log degrees:");
                all_proofs
                    .iter()
                    .enumerate()
                    .for_each(|(i, proof)| {
                        info!("Proof {}", i);
                        proof.main_chip_ordering.iter().for_each(|(chip_name, idx)| {
                            info!(
                                "   |- {:<20} main: {:<8}",
                                chip_name,
                                proof.opened_values.chips_opened_values[*idx].log_main_degree,
                            );
                        });
                    });

                // construct meta proof
                MetaProof::new(all_proofs.into(), all_vks.into(), None)
            }

            fn prove_cuda(
                &self,
                proving_witness: &ProvingWitness<$recur_sc, C, RecursionStdinVariant<$recur_sc, C>>,
                _pk_cuda: Option<&BaseProvingKeyCuda<$recur_sc>>,
                stream: &'static CudaStream,
                mem_pool: & CudaMemPool,
                dev_id: usize,
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
                let mut recursion_emulator = $emul_name::<
                    _,
                    _,
                    _,
                    _,
                >::setup_combine(
                    proving_witness, self.base_machine()
                );
                let mut recursion_witness;
                let mut recursion_stdin;

                let mut all_proofs = vec![];
                let mut all_vks = vec![];
                let mut last_vk = proving_witness.vk.clone();
                let mut last_proof = proving_witness.proof.clone();

                let mut chunk_index = 1;
                let mut layer_index = 1;
                // TODO: move recursion_shape_config creation in higher level functions
                let vk_manager = <$recur_sc as HasStaticVkManager>::static_vk_manager();
                let recursion_shape_config = RecursionShapeConfig::<
                    Val<$recur_sc>,
                    RecursionChipType<Val<$recur_sc>>,
                >::default();

                loop {
                    let mut batch_num = 1;
                    let start_layer = Instant::now();
                    let layer_span = debug_span!(parent: &tracing::Span::current(), "combine layer", layer_index).entered();
                    loop {
                        let loop_span = debug_span!(parent: &tracing::Span::current(), "combine batch prove loop", batch_num).entered();
                        let start_batch = Instant::now();
                        if proving_witness.flag_empty_stdin {
                            break;
                        }

                        let (mut batch_records, batch_vks, done, batch_pks_cuda) =
                        debug_span!("emulate_batch_records", layer_index).in_scope(|| { recursion_emulator.next_record_keys_batch_cuda(stream, mem_pool, dev_id) });


                        debug_span!("complement record").in_scope(|| {self.complement_record(batch_records.as_mut_slice())});

                        debug!(
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
                            debug!("COMBINE record stats: chunk {}", record.chunk_index());
                            let stats = record.stats();
                            for (key, value) in &stats {
                                debug!("   |- {:<28}: {}", key, value);
                            }
                        }

                        // prove records in parallel
                        let batch_proofs = batch_records
                            .iter()
                            .zip(batch_pks_cuda.iter())
                            .flat_map(|(record, pk_cuda)| {
                                let start_chunk = Instant::now();
                                let proof = debug_span!(parent: &loop_span, "prove_ensemble", layer_index, chunk_index = record.chunk_index()).in_scope(|| {
                                self
                                    .base_machine
                                    .prove_ensemble_cuda(std::slice::from_ref(record), pk_cuda, stream, mem_pool, dev_id)});
                                debug!(
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

                        debug!(
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

                    debug!(
                        "--- Finish combine layer {} in {:?}",
                        layer_index,
                        start_layer.elapsed()
                    );

                    if last_proof.is_some() {
                        all_vks.push(last_vk.unwrap());
                        all_proofs.push(last_proof.unwrap());
                    }

                    if all_proofs.len() == 1 {
                        break;
                    }

                    layer_index += 1;
                    chunk_index = 1;

                    // more than one proofs, need to combine another round
                    (recursion_stdin, last_vk, last_proof) = EmulatorStdin::setup_for_combine::<
                        <$recur_cc as FieldGenericConfig>::F,
                        $recur_cc,
                    >(
                        proving_witness.vk_root.unwrap(),
                        &all_vks,
                        &all_proofs,
                        self.base_machine(),
                        COMBINE_SIZE,
                        all_proofs.len() <= COMBINE_SIZE,
                        &vk_manager,
                        Some(&recursion_shape_config),
                    );

                    recursion_witness = ProvingWitness::setup_for_combine(
                        proving_witness.vk_root.unwrap(),
                        recursion_stdin,
                        last_vk,
                        last_proof,
                        self.config(),
                        proving_witness.opts.unwrap(),
                    );

                    recursion_emulator =
                        $emul_name::setup_combine(&recursion_witness, self.base_machine());

                    last_proof = recursion_witness.proof.clone();
                    last_vk = recursion_witness.vk.clone();

                    all_proofs.clear();
                    all_vks.clear();
                    layer_span.exit();
                }

                // proof stats
                debug!("COMBINE chip log degrees:");
                all_proofs
                    .iter()
                    .enumerate()
                    .for_each(|(i, proof)| {
                        debug!("Proof {}", i);
                        proof.main_chip_ordering.iter().for_each(|(chip_name, idx)| {
                            debug!(
                                "   |- {:<20} main: {:<8}",
                                chip_name,
                                proof.opened_values.chips_opened_values[*idx].log_main_degree,
                            );
                        });
                    });

                // construct meta proof
                MetaProof::new(all_proofs.into(), all_vks.into(), None)
            }

            /// Verify the proof.
            fn verify(&self, proof: &MetaProof<$recur_sc>, riscv_vk: &dyn HashableKey<Val<$recur_sc>>) -> Result<()> {
                assert_eq!(proof.proofs().len(), 1);

                // assert completion
                let public_values: &RecursionPublicValues<_> =
                    proof.proofs[0].public_values.as_ref().borrow();

                if public_values.flag_complete != <Val<$recur_sc>>::ONE {
                    panic!("flag_complete is not 1");
                }

                assert_recursion_public_values_valid(self.config().as_ref(), public_values);
                assert_riscv_vk_digest(proof, riscv_vk);

                // Vk Verification
                assert_eq!(proof.vks().len(), 1);
                let vk_manager = <$recur_sc as HasStaticVkManager>::static_vk_manager();
                let combine_vk = proof.vks().first().unwrap();
                if vk_manager.vk_verification_enabled(){
                    assert!(vk_manager.is_vk_allowed(combine_vk.hash_field()), "Recursion Vk Verification failed");
                    assert_eq!(public_values.vk_root, vk_manager.merkle_root, "Recursion circuit vk_root mismatch!")
                }

                // Defer Proofs Digest Verification
                assert_eq!(public_values.start_reconstruct_deferred_digest, [Val::<$recur_sc>::ZERO; DIGEST_SIZE]);
                assert_eq!(public_values.deferred_proofs_digest, public_values.end_reconstruct_deferred_digest);

                // verify
                self.base_machine
                    .verify_ensemble(combine_vk, &proof.proofs())?;

                Ok(())
            }
        }
    };
}

impl_combine_machine!(BabyBearMetaEmulator, BabyBearSimple, BabyBearPoseidon2);
impl_combine_machine!(KoalaBearMetaEmulator, KoalaBearSimple, KoalaBearPoseidon2);

impl<SC, C> CombineMachine<SC, C>
where
    SC: StarkGenericConfig + 'static,
    C: ChipBehavior<
        Val<SC>,
        Program = RecursionProgram<Val<SC>>,
        Record = RecursionRecord<Val<SC>>,
    >,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>, num_public_values: usize) -> Self {
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}

macro_rules! impl_indexed_combine_machine {
    ($emul_name:ident, $recur_cc:ident, $recur_sc:ident) => {
        impl<C> CombineMachine<$recur_sc, C>
        where
            C: Send
                + Sync
                + ChipBehavior<
                    Val<$recur_sc>,
                    Program = RecursionProgram<Val<$recur_sc>>,
                    Record = RecursionRecord<Val<$recur_sc>>,
                > + Air<ProverConstraintFolder<$recur_sc>>
                + for<'b> Air<VerifierConstraintFolder<'b, $recur_sc>>
                + for<'b> Air<RecursiveVerifierConstraintFolder<'b, $recur_cc>>,
        {
            // TODO: rename
            #[instrument(name = "PROVE TWO META PROOFS", level = "debug", skip_all)]
            pub fn prove_two(
                &self,
                meta_a: Arc<MetaProof<$recur_sc>>,
                meta_b: Arc<MetaProof<$recur_sc>>,
                is_complete: bool,
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
                // Step 1: validate inputs & pull out inner proofs
                assert_eq!(
                    meta_a.proofs.len(),
                    1,
                    "The first MetaProof must wrap exactly one BaseProof",
                );
                assert_eq!(
                    meta_b.proofs.len(),
                    1,
                    "The second MetaProof must wrap exactly one BaseProof",
                );
                assert_eq!(
                    meta_a.vks.len(),
                    1,
                    "The first MetaProof must wrap exactly one VK",
                );
                assert_eq!(
                    meta_b.vks.len(),
                    1,
                    "The second MetaProof must wrap exactly one VK",
                );
                let mut all_proofs = vec![meta_a.proofs[0].clone(), meta_b.proofs[0].clone()];
                let mut all_vks = vec![meta_a.vks[0].clone(), meta_b.vks[0].clone()];
                // Step 2: prepare recursion witness & emulator
                // TODO: update to use VK_VERIFICATION flag
                let vk_manager = <$recur_sc as HasStaticVkManager>::static_vk_manager();
                let (vk_root, recursion_shape_config) = if vk_verification_enabled() {
                    (
                        vk_manager.merkle_root,
                        Some(RecursionShapeConfig::<
                            Val<$recur_sc>,
                            RecursionChipType<Val<$recur_sc>>,
                        >::default()),
                    )
                } else {
                    ([Val::<$recur_sc>::ZERO; DIGEST_SIZE], None)
                };

                let (recursion_stdin, last_vk, last_proof) = EmulatorStdin::setup_for_combine::<
                    <$recur_cc as FieldGenericConfig>::F,
                    $recur_cc,
                >(
                    vk_root,
                    &all_vks,
                    &all_proofs,
                    self.base_machine(),
                    COMBINE_SIZE,
                    is_complete,
                    &vk_manager,
                    recursion_shape_config.as_ref(),
                );

                // TODO: opts
                let recursion_witness = ProvingWitness::setup_for_combine(
                    vk_root,
                    recursion_stdin,
                    last_vk,
                    last_proof,
                    self.config(),
                    Default::default(),
                );
                let mut recursion_emulator =
                    $emul_name::setup_combine(&recursion_witness, self.base_machine());

                // Step 3: generate + complete record batch
                let (mut batch_records, batch_pks, batch_vks, _done) =
                    recursion_emulator.next_record_keys_batch();
                self.complement_record(batch_records.as_mut_slice());

                // Step 4: prove the batch in parallel
                let batch_proofs = batch_records
                    .par_iter()
                    .zip(batch_pks.par_iter())
                    .flat_map(|(record, pk)| {
                        self.base_machine
                            .prove_ensemble(pk, std::slice::from_ref(record))
                    })
                    .collect::<Vec<_>>();

                // Step 5: assemble & return the new MetaProof
                all_proofs = batch_proofs;
                all_vks = batch_vks;

                MetaProof::new(all_proofs.into(), all_vks.into(), None)
            }

            pub fn prove_two_cuda(
                &self,
                meta_a: Arc<MetaProof<$recur_sc>>,
                meta_b: Arc<MetaProof<$recur_sc>>,
                is_complete: bool,
                stream: &'static CudaStream,
                mem_pool: &CudaMemPool,
                dev_id: usize,
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
                let start = Instant::now();
                // Step 1: validate inputs & pull out inner proofs
                assert_eq!(
                    meta_a.proofs.len(),
                    1,
                    "The first MetaProof must wrap exactly one BaseProof",
                );
                assert_eq!(
                    meta_b.proofs.len(),
                    1,
                    "The second MetaProof must wrap exactly one BaseProof",
                );
                assert_eq!(
                    meta_a.vks.len(),
                    1,
                    "The first MetaProof must wrap exactly one VK",
                );
                assert_eq!(
                    meta_b.vks.len(),
                    1,
                    "The second MetaProof must wrap exactly one VK",
                );
                let mut all_proofs = vec![meta_a.proofs[0].clone(), meta_b.proofs[0].clone()];
                let mut all_vks = vec![meta_a.vks[0].clone(), meta_b.vks[0].clone()];
                // Step 2: prepare recursion witness & emulator
                // TODO: update to use VK_VERIFICATION flag
                let vk_manager = <$recur_sc as HasStaticVkManager>::static_vk_manager();
                let (vk_root, recursion_shape_config) = if vk_verification_enabled() {
                    (
                        vk_manager.merkle_root,
                        Some(RecursionShapeConfig::<
                            Val<$recur_sc>,
                            RecursionChipType<Val<$recur_sc>>,
                        >::default()),
                    )
                } else {
                    ([Val::<$recur_sc>::ZERO; DIGEST_SIZE], None)
                };

                let (recursion_stdin, last_vk, last_proof) = EmulatorStdin::setup_for_combine::<
                    <$recur_cc as FieldGenericConfig>::F,
                    $recur_cc,
                >(
                    vk_root,
                    &all_vks,
                    &all_proofs,
                    self.base_machine(),
                    COMBINE_SIZE,
                    is_complete,
                    &vk_manager,
                    recursion_shape_config.as_ref(),
                );
                println!("-- Combine prepare: {:?}", start.elapsed());

                // TODO: opts
                let start = Instant::now();
                let recursion_witness = ProvingWitness::setup_for_combine(
                    vk_root,
                    recursion_stdin,
                    last_vk,
                    last_proof,
                    self.config(),
                    Default::default(),
                );
                let mut recursion_emulator =
                    $emul_name::setup_combine(&recursion_witness, self.base_machine());

                // Step 3: generate + complete record batch
                let (mut batch_records, batch_vks, done, batch_pks_cuda) =
                    recursion_emulator.next_record_keys_batch_cuda(stream, mem_pool, dev_id);

                println!(
                    "-- Combine next_record_keys_batch_cuda: {:?}",
                    start.elapsed()
                );

                let start = Instant::now();
                self.complement_record(batch_records.as_mut_slice());
                println!("-- Combine complement_record: {:?}", start.elapsed());

                // Step 4: prove the batch in parallel
                let start = Instant::now();
                let batch_proofs = batch_records
                    .iter()
                    .zip(batch_pks_cuda.iter())
                    .flat_map(|(record, pk_cuda)| {
                        self.base_machine.prove_ensemble_cuda(
                            std::slice::from_ref(record),
                            pk_cuda,
                            stream,
                            mem_pool,
                            dev_id,
                        )
                    })
                    .collect::<Vec<_>>();
                println!(
                    "-- Combine self.base_machine.prove_ensemble_cuda: {:?}",
                    start.elapsed()
                );

                // Step 5: assemble & return the new MetaProof
                all_proofs = batch_proofs;
                all_vks = batch_vks;

                MetaProof::new(all_proofs.into(), all_vks.into(), None)
            }
        }
    };
}

impl_indexed_combine_machine!(BabyBearMetaEmulator, BabyBearSimple, BabyBearPoseidon2);
impl_indexed_combine_machine!(KoalaBearMetaEmulator, KoalaBearSimple, KoalaBearPoseidon2);
