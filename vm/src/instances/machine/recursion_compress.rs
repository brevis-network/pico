use crate::{
    compiler::recursion::program::RecursionProgram,
    configs::config::{StarkGenericConfig, Val},
    emulator::record::RecordBehavior,
    instances::{
        compiler::recursion_circuit::stdin::RecursionStdin,
        configs::{recur_config::StarkConfig as RecursionSC, riscv_config::StarkConfig as RiscvSC},
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey, HashableKey},
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    recursion::{air::RecursionPublicValues, runtime::RecursionRecord},
};
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::AbstractField;
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{info, instrument, trace};

pub struct RecursionCompressMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    vk: BaseVerifyingKey<RiscvSC>, // this is for the riscv pk

    base_machine: BaseMachine<SC, C>,
}

impl<'a, C> MachineBehavior<RecursionSC, C, RecursionStdin<'a, RecursionSC, C>>
    for RecursionCompressMachine<RecursionSC, C>
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
        format!(
            "Compress Recursion Machine <{}>",
            type_name::<RecursionSC>()
        )
    }

    /// Get the base machine
    fn base_machine(&self) -> &BaseMachine<RecursionSC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    #[instrument(name = "compress_prove", level = "debug", skip_all)]
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
        info!("PERF-machine=compress");
        let begin = Instant::now();

        // used for collect all records for debugging
        #[cfg(feature = "debug")]
        let mut all_records = Vec::new();

        let mut records = witness.records().to_vec();

        // let mut recursion_emulator = MetaEmulator::setup_recursion(witness, 1);
        //
        // let (record, _) = recursion_emulator.next();
        // let mut records = vec![record];

        self.complement_record(&mut records);

        #[cfg(feature = "debug")]
        {
            tracing::debug!("record stats");
            let stats = records[0].stats();
            for (key, value) in &stats {
                tracing::debug!("{:<25}: {}", key, value);
            }
            all_records.extend_from_slice(&records);
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

        info!("PERF-step=prove-user_time={}", begin.elapsed().as_millis(),);

        // construct meta proof
        let proof = MetaProof::new(vec![proof]);
        let proof_size = bincode::serialize(&proof).unwrap().len();
        info!("PERF-step=proof_size-{}", proof_size);

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

        proof
    }

    /// Verify the proof.
    fn verify(
        &self,
        vk: &BaseVerifyingKey<RecursionSC>, // note that this is the vk of riscv machine
        proof: &MetaProof<RecursionSC>,
    ) -> anyhow::Result<()> {
        info!("PERF-machine=compress");
        let begin = Instant::now();

        assert_eq!(proof.num_proofs(), 1);

        let public_values: &RecursionPublicValues<_> =
            proof.proofs[0].public_values.as_slice().borrow();
        trace!("public values: {:?}", public_values);

        // assert completion
        if public_values.flag_complete != <Val<RecursionSC>>::one() {
            panic!("flag_complete is not 1");
        }

        // assert riscv vk
        if public_values.riscv_vk_digest != self.get_vk().hash_babybear() {
            panic!("riscv_vk is not equal to vk");
        }

        // verify
        self.base_machine.verify_ensemble(vk, proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis());

        Ok(())
    }
}

impl<SC, C> RecursionCompressMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub fn new(
        config: SC,
        chips: Vec<MetaChip<Val<SC>, C>>,
        num_public_values: usize,
        vk: BaseVerifyingKey<RiscvSC>,
    ) -> Self {
        info!("PERF-machine=compress");
        Self {
            vk,
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }

    pub fn get_vk(&self) -> &BaseVerifyingKey<RiscvSC> {
        &self.vk
    }
}
