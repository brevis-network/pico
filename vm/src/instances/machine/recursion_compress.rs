#[cfg(feature = "debug")]
use crate::machine::debug::constraints::IncrementalConstraintDebugger;
#[cfg(feature = "debug-lookups")]
use crate::machine::debug::lookups::IncrementalLookupDebugger;
use crate::{
    compiler::recursion_v2::program::RecursionProgram,
    configs::config::{Com, PcsProverData, StarkGenericConfig, Val},
    emulator::{emulator_v2::MetaEmulator, record::RecordBehavior, riscv::stdin::EmulatorStdin},
    instances::{
        compiler_v2::recursion_circuit::stdin::RecursionStdin,
        configs::recur_config::StarkConfig as RecursionSC,
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
    base_machine: BaseMachine<SC, C>,
}

impl<'a, C> MachineBehavior<RecursionSC, C, RecursionStdin<'_, RecursionSC, C>>
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
        // todo: keys
        let pk = witness.pk();

        info!("PERF-machine=compress");
        let begin = Instant::now();

        // used for collect all records for debugging
        #[cfg(feature = "debug")]
        let mut debug_challenger = self.config().challenger();
        #[cfg(feature = "debug")]
        let mut constraint_debugger = IncrementalConstraintDebugger::new(pk, &mut debug_challenger);
        #[cfg(feature = "debug-lookups")]
        let mut lookup_debugger = IncrementalLookupDebugger::new(pk, None);

        let mut records = witness.records().to_vec();
        self.complement_record(&mut records);

        #[cfg(feature = "debug")]
        constraint_debugger.debug_incremental(self.chips(), &records);
        #[cfg(feature = "debug-lookups")]
        lookup_debugger.debug_incremental(self.chips(), &records);

        debug!("recursion compress record stats");
        let stats = records[0].stats();
        for (key, value) in &stats {
            debug!("   |- {:<28}: {}", key, value);
        }

        let proofs = self.base_machine.prove_ensemble(pk, &records);
        info!("PERF-step=prove-user_time={}", begin.elapsed().as_millis());

        // construct meta proof
        // todo: keys
        let vks = vec![witness.vk.clone().unwrap()].into();
        let proof = MetaProof::new(proofs.into(), vks);
        let proof_size = bincode::serialize(proof.proofs()).unwrap().len();
        //
        // let proof = MetaProof::new(proofs);
        // let proof_size = bincode::serialize(&proof).unwrap().len();
        info!("PERF-step=proof_size-{}", proof_size);

        /*
                #[cfg(feature = "debug")]
                constraint_debugger.print_results();
                #[cfg(feature = "debug-lookups")]
                lookup_debugger.print_results();
        */

        proof
    }

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<RecursionSC>) -> anyhow::Result<()> {
        // todo: keys
        let vk = proof.vks().first().unwrap();

        info!("PERF-machine=compress");
        let begin = Instant::now();

        assert_eq!(proof.num_proofs(), 1);

        let public_values: &RecursionPublicValues<_> =
            proof.proofs[0].public_values.as_ref().borrow();
        trace!("public values: {:?}", public_values);

        // assert completion
        if public_values.flag_complete != <Val<RecursionSC>>::ONE {
            panic!("flag_complete is not 1");
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
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>, num_public_values: usize) -> Self {
        info!("PERF-machine=compress");
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
