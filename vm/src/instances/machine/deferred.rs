use crate::{
    compiler::recursion::{circuit::hash::FieldHasher, program::RecursionProgram},
    configs::{
        config::{Com, PcsProof, PcsProverData, StarkGenericConfig, Val},
        field_config::KoalaBearSimple,
        stark_config::KoalaBearPoseidon2,
    },
    emulator::{
        emulator::KoalaBearMetaEmulator, record::RecordBehavior,
        recursion::emulator::RecursionRecord,
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{riscv_circuit::stdin::DeferredStdin, vk_merkle::HasStaticVkManager},
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseVerifyingKey, HashableKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
    primitives::consts::EXTENSION_DEGREE,
};
use cudart::{memory_pools::CudaMemPool, stream::CudaStream};
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{extension::BinomiallyExtendable, PrimeField32, TwoAdicField};
use p3_maybe_rayon::prelude::*;
use std::any::type_name;
use tracing::{debug, debug_span, instrument};

pub struct DeferredMachine<SC, C>
where
    SC: StarkGenericConfig + 'static,
    C: ChipBehavior<
        Val<SC>,
        Program = RecursionProgram<Val<SC>>,
        Record = RecursionRecord<Val<SC>>,
    >,
{
    base_machine: BaseMachine<SC, C>,
}

impl<F, SC, C> MachineBehavior<SC, C, DeferredStdin<SC, C>> for DeferredMachine<SC, C>
where
    F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + TwoAdicField,
    SC: StarkGenericConfig<Val = F, Domain = TwoAdicMultiplicativeCoset<F>>
        + Send
        + Sync
        + FieldHasher<Val<SC>>
        + HasStaticVkManager
        + 'static,
    Val<SC>: PrimeField32,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
    PcsProof<SC>: Send + Sync,
    BaseVerifyingKey<SC>: HashableKey<SC::Val> + Send + Sync,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + Air<ProverConstraintFolder<SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + Send
        + Sync,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("Deferred Machine <{}>", type_name::<SC>())
    }

    /// Get the base machine
    fn base_machine(&self) -> &BaseMachine<SC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    #[instrument(name = "Deferred MACHINE PROVE", level = "debug", skip_all)]
    fn prove(&self, _witness: &ProvingWitness<SC, C, DeferredStdin<SC, C>>) -> MetaProof<SC>
    where
        C: for<'c> Air<
            DebugConstraintFolder<
                'c,
                <SC as StarkGenericConfig>::Val,
                <SC as StarkGenericConfig>::Challenge,
            >,
        >,
    {
        unreachable!("use prove_with_deferred instead");
    }

    /// Verify the proof.
    fn verify(
        &self,
        _proof: &MetaProof<SC>,
        _riscv_vk: &dyn HashableKey<SC::Val>,
    ) -> anyhow::Result<()> {
        unreachable!("use prove_with_deferred instead");
    }

    fn prove_cuda(
        &self,
        witness: &ProvingWitness<SC, C, DeferredStdin<SC, C>>,
        pk_cuda: Option<&BaseProvingKeyCuda<SC>>,
        stream: &'static CudaStream,
        mem_pool: &CudaMemPool,
        dev_id: usize,
    ) -> MetaProof<SC>
    where
        C: for<'a> Air<DebugConstraintFolder<'a, SC::Val, SC::Challenge>>
            + Air<ProverConstraintFolder<SC>>,
    {
        todo!()
    }
}

impl<SC, C> DeferredMachine<SC, C>
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

use crate::{
    compiler::recursion::circuit::constraints::RecursiveVerifierConstraintFolder,
    configs::{field_config::BabyBearSimple, stark_config::BabyBearPoseidon2},
    cuda_adaptor::setup_keys_gm::BaseProvingKeyCuda,
    emulator::emulator::BabyBearMetaEmulator,
};
use std::time::Instant;

macro_rules! impl_deferred_machine {
    ($emul_name:ident, $recur_cc:ident, $recur_sc:ident) => {
        impl<C> DeferredMachine<$recur_sc, C>
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
            #[instrument(name = "Deferred MACHINE PROVE", level = "debug", skip_all)]
            pub fn prove_with_deferred(
                &self,
                proving_witness: &ProvingWitness<
                    $recur_sc,
                    C,
                    DeferredStdin<$recur_sc, RecursionChipType<Val<$recur_sc>>>,
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
                let mut emulator = $emul_name::setup_deferred(proving_witness, self.base_machine());
                let mut all_proofs = vec![];
                let mut all_vks = vec![];

                let mut batch_num = 1;
                let mut chunk_index = 1;
                loop {
                    let loop_span = debug_span!(parent: &tracing::Span::current(), "Deferred batch prove loop", batch_num).entered();
                    let start = Instant::now();
                    let (mut batch_records, batch_pks, batch_vks, done) =
                    debug_span!("emulate_batch_records").in_scope(|| {emulator.next_record_keys_batch()});

                    debug_span!("complement_record").in_scope(|| {self.complement_record(batch_records.as_mut_slice())});

                    debug!(
                        "--- Generate Deferred records for batch {}, chunk {}-{} in {:?}",
                        batch_num,
                        chunk_index,
                        chunk_index + batch_records.len() as u32 - 1,
                        start.elapsed()
                    );

                    // set index for each record
                    for record in batch_records.as_mut_slice() {
                        record.index = chunk_index;
                        chunk_index += 1;
                        debug!("Deferred record stats: chunk {}", record.chunk_index());
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
                                "--- Prove Deferred chunk {} in {:?}",
                                record.chunk_index(),
                                start_chunk.elapsed()
                            );
                            proof
                        })
                        .collect::<Vec<_>>();

                    all_proofs.extend(batch_proofs);
                    all_vks.extend(batch_vks);

                    debug!(
                        "--- Finish Deferred batch {} in {:?}",
                        batch_num,
                        start.elapsed()
                    );
                    batch_num += 1;

                    if done {
                        break;
                    }

                    loop_span.exit();
                }

                MetaProof::new(all_proofs.into(), all_vks.into(), None)
            }
        }
    };
}

impl_deferred_machine!(KoalaBearMetaEmulator, KoalaBearSimple, KoalaBearPoseidon2);
impl_deferred_machine!(BabyBearMetaEmulator, BabyBearSimple, BabyBearPoseidon2);
