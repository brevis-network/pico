use crate::{
    compiler::recursion_v2::program::RecursionProgram,
    configs::config::{Com, PcsProverData, StarkGenericConfig, Val},
    emulator::{
        record::RecordBehavior,
        recursion::{emulator::RecursionRecord, public_values::RecursionPublicValues},
    },
    instances::{
        compiler_v2::vk_merkle::stdin::RecursionVkStdin,
        configs::recur_config::StarkConfig as RecursionSC,
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
};
use p3_air::Air;
use p3_field::FieldAlgebra;
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{debug, info, instrument, trace};

pub struct CompressVkMachine<SC, C>
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

impl<C> MachineBehavior<RecursionSC, C, RecursionVkStdin<'_, RecursionSC, C>>
    for CompressVkMachine<RecursionSC, C>
where
    C: ChipBehavior<
        Val<RecursionSC>,
        Program = RecursionProgram<Val<RecursionSC>>,
        Record = RecursionRecord<Val<RecursionSC>>,
    >,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!(
            "CompressVk Recursion Machine <{}>",
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
        witness: &ProvingWitness<RecursionSC, C, RecursionVkStdin<RecursionSC, C>>,
    ) -> MetaProof<RecursionSC>
    where
        C: for<'a> Air<
                DebugConstraintFolder<
                    'a,
                    <RecursionSC as StarkGenericConfig>::Val,
                    <RecursionSC as StarkGenericConfig>::Challenge,
                >,
            > + for<'a> Air<ProverConstraintFolder<'a, RecursionSC>>,
    {
        let mut records = witness.records().to_vec();
        self.complement_record(&mut records);

        debug!("recursion compress record stats");
        let stats = records[0].stats();
        for (key, value) in &stats {
            debug!("   |- {:<28}: {}", key, value);
        }

        let proofs = self.base_machine.prove_ensemble(witness.pk(), &records);

        info!("COMPRESS_VK chip log degrees:");
        proofs.iter().enumerate().for_each(|(i, proof)| {
            info!("Proof {}", i);
            proof
                .main_chip_ordering
                .iter()
                .for_each(|(chip_name, idx)| {
                    info!(
                        "   |- {:<20} main: {:<8}",
                        chip_name, proof.opened_values.chips_opened_values[*idx].log_main_degree,
                    );
                });
        });

        // construct meta proof
        let vks = vec![witness.vk.clone().unwrap()].into();
        MetaProof::new(proofs.into(), vks, None)
    }

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<RecursionSC>) -> anyhow::Result<()>
    where
        C: for<'a> Air<VerifierConstraintFolder<'a, RecursionSC>>,
    {
        let vk = proof.vks().first().unwrap();

        info!("PERF-machine=convert");
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
        self.base_machine.verify_ensemble(vk, &proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis());

        Ok(())
    }
}

impl<SC, C> CompressVkMachine<SC, C>
where
    SC: StarkGenericConfig,
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
