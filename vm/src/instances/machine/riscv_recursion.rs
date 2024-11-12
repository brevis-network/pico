use crate::{
    compiler::recursion::program::RecursionProgram,
    configs::config::{StarkGenericConfig, Val},
    emulator::{emulator::MetaEmulator, record::RecordBehavior},
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        compiler::riscv_circuit::stdin::RiscvRecursionStdin,
        configs::{recur_config::StarkConfig as RecursionSC, riscv_config::StarkConfig as RiscvSC},
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    recursion::{air::RecursionPublicValues, runtime::RecursionRecord},
};
use anyhow::Result;
use log::{debug, info};
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::Field;
use std::{any::type_name, borrow::Borrow, time::Instant};

pub struct RiscvRecursionMachine<SC, C>
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

impl<'a, C>
    MachineBehavior<RecursionSC, C, RiscvRecursionStdin<'a, RiscvSC, RiscvChipType<Val<RiscvSC>>>>
    for RiscvRecursionMachine<RecursionSC, C>
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
        format!("Riscv Compress Machine <{}>", type_name::<RecursionSC>())
    }

    /// Get the base machine.
    fn base_machine(&self) -> &BaseMachine<RecursionSC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    fn prove(
        &self,
        pk: &BaseProvingKey<RecursionSC>,
        witness: &ProvingWitness<
            RecursionSC,
            C,
            RiscvRecursionStdin<RiscvSC, RiscvChipType<Val<RiscvSC>>>,
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
        info!("PERF-machine=recursion");
        let begin = Instant::now();

        // First
        // Generate batch records and commit to challenger

        let mut chunk_index = 1;
        let mut recursion_emulator = MetaEmulator::setup_riscv_compress(witness, 1);
        let mut all_proofs = vec![];

        // used for collect all records for debugging
        #[cfg(feature = "debug")]
        let mut all_records = Vec::new();

        loop {
            let (record, done) = recursion_emulator.next();
            let mut records = vec![record];

            // read slice of records and complement them
            self.complement_record(records.as_mut_slice());

            #[cfg(feature = "debug")]
            {
                debug!("record stats");
                let stats = records[0].stats();
                for (key, value) in &stats {
                    debug!("{:<25}: {}", key, value);
                }
                all_records.extend_from_slice(&records);
            }

            info!("PERF-phase=1-chunk={chunk_index}");

            let commitment = self.base_machine.commit(&records[0]);

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

        #[cfg(feature = "debug")]
        {
            use crate::machine::debug::constraints::debug_all_constraints;
            let mut debug_challenger = self.config().challenger();
            debug_all_constraints(self.chips(), pk, &all_records, &mut debug_challenger);
        }

        #[cfg(feature = "debug-lookups")]
        {
            use crate::machine::debug::lookups::DebugLookup;
            DebugLookup::debug_all_lookups(self.chips(), pk, &all_records, None);
        }

        info!("PERF-step=prove-user_time={}", begin.elapsed().as_millis(),);

        // construct meta proof
        let proof = MetaProof::new(all_proofs);
        let proof_size = bincode::serialize(&proof).unwrap().len();
        info!("PERF-step=proof_size-{}", proof_size);

        proof
    }

    /// Verify the proof.
    fn verify(
        &self,
        vk: &BaseVerifyingKey<RecursionSC>,
        proof: &MetaProof<RecursionSC>,
    ) -> Result<()> {
        info!("PERF-machine=recursion");
        let begin = Instant::now();

        for each_proof in proof.proofs().iter() {
            let public_values: &RecursionPublicValues<_> =
                each_proof.public_values.as_slice().borrow();

            debug!("public values: {:?}", public_values);

            let mut challenger = self.config().challenger();
            // observe all preprocessed and main commits and pv's
            vk.observed_by(&mut challenger);
            challenger.observe(each_proof.commitments.main_commit);
            challenger.observe_slice(&each_proof.public_values[..self.num_public_values()]);

            self.base_machine
                .verify_plain(vk, &mut challenger, each_proof)?;
        }

        // compute sum of each proof.cumulative_sum() and add them up and judge if it is zero
        let sum = proof
            .proofs()
            .iter()
            .map(|proof| proof.cumulative_sum())
            .sum::<<RecursionSC as StarkGenericConfig>::Challenge>();

        if !sum.is_zero() {
            panic!("verify_ensemble:lookup cumulative sum is not zero");
        }

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis(),);

        Ok(())
    }
}

impl<SC, C> RiscvRecursionMachine<SC, C>
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
        info!("PERF-machine=recursion");
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
